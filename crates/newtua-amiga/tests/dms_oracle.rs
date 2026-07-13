// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! End-to-end golden tests for the DMS container: a small mirror encoder
//! builds valid `.dms` disk images (NOCOMP + SIMPLE + QUICK + MEDIUM tracks,
//! plus text tracks), which are checked against both our own parser and the
//! reference `unar`/`lsar` (built on libxad, which understands DMS).
//! QUICK/MEDIUM fixtures mostly use an all-literal LZ encoding (no need for a
//! real compressor to produce valid input); a few hand-built exceptions
//! exercise an actual match instruction and the `NOINIT` state-carry rule.
//!
//! DEEP's and HEAVY1/HEAVY2's own container + `unar` oracle tests live in
//! `src/dms.rs`'s unit test module instead of here: their mirror encoders
//! must share state with the real decoder — DEEP's adaptive Huffman tree
//! (`DmsState.freq`/`prnt`/`son`), HEAVY's canonical-code tables
//! (`DmsState.c_table`/`pt_table`/`left`/`right`, built by the same
//! `make_table` the decoder calls) — all private to that module (see
//! `deep_encode`/`encode_char` and `heavy_encode_track` there).
//!
//! No `.dms` fixtures or third-party encoder (`xdms`) exist in the test
//! environment, so the real cross-check goes: our mirror encoder -> unar.

use newtua_amiga::dms::{checksum_dms, DmsArchive};
use newtua_common::crc16::crc16_arc;
use newtua_testutil::{
    try_unar_extract_all, try_unar_extract_all_with_password, unar_extract_all, unar_installed,
    BitWriterMsb,
};

const HEADER_LEN: usize = 56;
const TRACK_HEADER_LEN: usize = 20;
const DMSCOMP_NOCOMP: u8 = 0;
const DMSCOMP_SIMPLE: u8 = 1;
const DMSCOMP_QUICK: u8 = 2;
const DMSCOMP_MEDIUM: u8 = 3;
const DMSCFLAG_NOINIT: u8 = 1 << 0;
const DMSTYPE_FMS: u16 = 7;
const DMSTRTYPE_FILENAME: i16 = 0x03E7;
const DMSTRTYPE_FILESTART: i16 = 0x03E8;

/// RLE-compress `raw` into the DMSCOMP_SIMPLE form the container's `unp_rle`
/// reverses: runs of length >= 4 (or any run of the escape byte `0x90`) are
/// coded as `0x90 <count<=254> <value>`, chunked if longer; everything else
/// is emitted as literals (escaping any literal `0x90` as `0x90 0x00`).
fn rle_encode(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        let v = raw[i];
        let mut run = 1usize;
        while i + run < raw.len() && raw[i + run] == v {
            run += 1;
        }
        if v == 0x90 || run >= 4 {
            let mut remaining = run;
            while remaining > 0 {
                let chunk = remaining.min(254);
                out.push(0x90);
                out.push(chunk as u8);
                out.push(v);
                remaining -= chunk;
            }
        } else {
            for _ in 0..run {
                if v == 0x90 {
                    out.push(0x90);
                    out.push(0x00);
                } else {
                    out.push(v);
                }
            }
        }
        i += run;
    }
    out
}

/// Mini QUICK/MEDIUM encoder: every byte as a literal (flag bit `1` + 8 bits,
/// MSB-first — the coding is identical for both methods). Sidesteps needing
/// an LZ compressor: valid input for `unp_quick`/`unp_medium`, just not
/// space-efficient. The match-carrying and match-path fixtures below build
/// their bitstreams by hand instead, to exercise the other branch.
fn lz_literal_encode(intermediate: &[u8]) -> Vec<u8> {
    let mut w = BitWriterMsb::default();
    for &b in intermediate {
        w.bit(true);
        w.bits(u32::from(b), 8);
    }
    w.finish()
}

/// Track content exercising: a repeated run, an isolated `0x90` byte, an
/// escaped-literal case, and a long run (> 254) needing multiple RLE chunks.
fn sample_track_bytes(len: usize, seed: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    v.extend(std::iter::repeat(seed).take(20));
    v.extend([0x90, 0x01, 0x02, 0x90, 0x90, 0x03]);
    v.extend(std::iter::repeat(0xAAu8).take(300));
    while v.len() < len {
        let n = v.len() as u8;
        v.push(n.wrapping_add(seed));
    }
    v.truncate(len);
    v
}

/// Compress `raw` the way [`DmsBuilder::push_data_track`] does, without
/// writing it into an archive yet — shared with
/// [`DmsBuilder::push_encrypted_data_track`], which needs the packed bytes
/// before they're XOR-encrypted.
fn compress_for_test(method: u8, raw: &[u8]) -> (Vec<u8>, u16) {
    match method {
        DMSCOMP_NOCOMP => (raw.to_vec(), raw.len() as u16),
        DMSCOMP_SIMPLE => (rle_encode(raw), raw.len() as u16),
        DMSCOMP_QUICK | DMSCOMP_MEDIUM => {
            let intermediate = rle_encode(raw);
            let packed = lz_literal_encode(&intermediate);
            (packed, intermediate.len() as u16)
        }
        _ => panic!("test builder only supports NOCOMP/SIMPLE/QUICK/MEDIUM"),
    }
}

/// Mirror of `DecryptDMS` (`DMS.c:949-959`), inverted for encryption: given a
/// plaintext byte `pt`, `ct = pt ^ (rtv_pass & 0xFF)`, then `rtv_pass` is
/// advanced by `ct` — the same update rule the decoder uses, driven by the
/// same (ciphertext) value, so decrypting this output with the same starting
/// `rtv_pass` recovers `pt` and reproduces the identical state walk.
fn encrypt_dms_mirror(data: &mut [u8], rtv_pass: &mut u16) {
    for b in data.iter_mut() {
        let pt = *b;
        let ct = pt ^ (*rtv_pass & 0xFF) as u8;
        *rtv_pass = (*rtv_pass >> 1).wrapping_add(u16::from(ct));
        *b = ct;
    }
}

/// Mirror encoder for the DMS container: builds a 56-byte header followed by
/// a sequence of 20-byte track headers + packed payloads.
struct DmsBuilder {
    buf: Vec<u8>,
}

impl DmsBuilder {
    fn new() -> Self {
        Self {
            buf: vec![0u8; HEADER_LEN],
        }
    }

    fn set_info_flags(&mut self, flags: u32) {
        self.buf[8..12].copy_from_slice(&flags.to_be_bytes());
    }

    fn set_disk_type(&mut self, disk_type: u16) {
        self.buf[50..52].copy_from_slice(&disk_type.to_be_bytes());
    }

    fn set_unpacked_size(&mut self, size: u32) {
        self.buf[24..28].copy_from_slice(&size.to_be_bytes());
    }

    /// Append an FMS file-name track (`DMSTRTYPE_FILENAME`): `name_bytes`
    /// are written **literally**, not compressed — the name track is never
    /// decrunched (`DMS.c:1338-1339`).
    fn push_fms_name_track(&mut self, name_bytes: &[u8]) {
        self.push_raw_track(
            DMSTRTYPE_FILENAME,
            DMSCOMP_NOCOMP,
            name_bytes.len() as u16,
            name_bytes.len() as u16,
            0,
            0, // uncrunched_crc: unused, the name track is never checksummed
            name_bytes,
        );
    }

    /// Append a data track. `raw` is the track's *decompressed* bytes (one
    /// cylinder's worth: `track_sectors * 1024`); `method` selects NOCOMP (0,
    /// `raw` written as-is), SIMPLE (1, RLE-encoded), or QUICK/MEDIUM (2/3,
    /// RLE-encoded then LZ-encoded as an all-literal bitstream — see
    /// `lz_literal_encode`). `cflag` is 0 (no `NOINIT`); use
    /// [`Self::push_raw_track`] directly for `NOINIT`-flagged fixtures.
    fn push_data_track(&mut self, track_number: i16, method: u8, raw: &[u8]) {
        let (packed, rtsize) = compress_for_test(method, raw);
        self.push_raw_track(
            track_number,
            method,
            raw.len() as u16,
            rtsize,
            0,
            checksum_dms(raw),
            &packed,
        );
    }

    /// Like [`Self::push_data_track`], but XOR-encrypts the packed bytes
    /// with [`encrypt_dms_mirror`] before writing them, threading `rtv_pass`
    /// through so it keeps flowing continuously across every track pushed
    /// this way — matching how `DecrunchDMS` advances one `RTV_Pass` across
    /// the whole pass it decrypts.
    fn push_encrypted_data_track(
        &mut self,
        track_number: i16,
        method: u8,
        raw: &[u8],
        rtv_pass: &mut u16,
    ) {
        let (mut packed, rtsize) = compress_for_test(method, raw);
        encrypt_dms_mirror(&mut packed, rtv_pass);
        self.push_raw_track(
            track_number,
            method,
            raw.len() as u16,
            rtsize,
            0,
            checksum_dms(raw),
            &packed,
        );
    }

    /// Append a track header + payload with fully explicit fields, for
    /// constructing deliberately invalid fixtures in edge-case tests.
    #[allow(clippy::too_many_arguments)]
    fn push_raw_track(
        &mut self,
        track_number: i16,
        method: u8,
        upsize: u16,
        rtsize: u16,
        cflag: u8,
        uncrunched_crc: u16,
        packed: &[u8],
    ) {
        let mut t = [0u8; TRACK_HEADER_LEN];
        t[0..2].copy_from_slice(&0x5452u16.to_be_bytes());
        t[2..4].copy_from_slice(&track_number.to_be_bytes());
        t[6..8].copy_from_slice(&(packed.len() as u16).to_be_bytes());
        t[8..10].copy_from_slice(&rtsize.to_be_bytes());
        t[10..12].copy_from_slice(&upsize.to_be_bytes());
        t[12] = cflag;
        t[13] = method;
        t[14..16].copy_from_slice(&uncrunched_crc.to_be_bytes());
        let crc = crc16_arc(&t[0..18]);
        t[18..20].copy_from_slice(&crc.to_be_bytes());
        self.buf.extend_from_slice(&t);
        self.buf.extend_from_slice(packed);
    }

    fn finish(mut self) -> Vec<u8> {
        self.buf[0..4].copy_from_slice(b"DMS!");
        let crc = crc16_arc(&self.buf[4..54]);
        self.buf[54..56].copy_from_slice(&crc.to_be_bytes());
        self.buf
    }
}

const TRACK_SECTORS: u16 = 11; // Amiga DD geometry
const TRACK_LEN: usize = TRACK_SECTORS as usize * 1024;

fn build_sample_disk(cylinders: i16) -> (Vec<u8>, Vec<u8>) {
    let mut b = DmsBuilder::new();
    let mut expected = Vec::new();
    for cyl in 0..cylinders {
        let raw = sample_track_bytes(TRACK_LEN, (cyl + 1) as u8);
        let method = if cyl % 2 == 0 {
            DMSCOMP_SIMPLE
        } else {
            DMSCOMP_NOCOMP
        };
        b.push_data_track(cyl, method, &raw);
        expected.extend_from_slice(&raw);
    }
    (b.finish(), expected)
}

#[test]
fn roundtrip_nocomp_and_simple_tracks() {
    let (archive_bytes, expected) = build_sample_disk(3);

    assert!(DmsArchive::recognize(&archive_bytes));
    let archive = DmsArchive::open(&archive_bytes).unwrap();
    assert_eq!(archive.info().unwrap().low_cyl, 0);
    assert_eq!(archive.info().unwrap().high_cyl, 2);
    assert_eq!(archive.info().unwrap().track_sectors, TRACK_SECTORS);
    assert_eq!(
        archive.info().unwrap().total_sectors,
        80 * 2 * u32::from(TRACK_SECTORS)
    );

    let image = archive.read_disk_image().unwrap();
    assert_eq!(image, expected);
}

#[test]
fn diz_and_banner_tracks_land_in_texts_without_breaking_geometry() {
    let mut b = DmsBuilder::new();
    let raw0 = sample_track_bytes(TRACK_LEN, 1);
    b.push_data_track(0, DMSCOMP_SIMPLE, &raw0);

    let diz = b"a fine archive\n".to_vec();
    b.push_data_track(80, DMSCOMP_NOCOMP, &diz);

    let banner = b"created with newtua".to_vec();
    b.push_data_track(-1, DMSCOMP_NOCOMP, &banner);

    let raw1 = sample_track_bytes(TRACK_LEN, 2);
    b.push_data_track(1, DMSCOMP_SIMPLE, &raw1);

    let archive_bytes = b.finish();
    let archive = DmsArchive::open(&archive_bytes).unwrap();

    assert_eq!(archive.info().unwrap().low_cyl, 0);
    assert_eq!(archive.info().unwrap().high_cyl, 1);

    let texts = archive.texts();
    assert_eq!(texts.len(), 2);
    assert!(texts[0].is_diz);
    assert_eq!(texts[0].bytes, diz);
    assert!(!texts[1].is_diz);
    assert_eq!(texts[1].bytes, banner);

    let mut expected = raw0;
    expected.extend_from_slice(&raw1);
    assert_eq!(archive.read_disk_image().unwrap(), expected);
}

#[test]
fn small_zero_track_followed_by_non_track_1_resolves_as_info_text() {
    // A short track 0 (<= 2048 bytes after trimming trailing zeros) followed
    // by anything other than track 1 turns out to have been an information
    // text, not real disk data (DMS.c:1149-1176) — geometry restarts at the
    // track that follows.
    let mut b = DmsBuilder::new();
    let info_text = b"info text, not disk data".to_vec();
    b.push_raw_track(
        0,
        DMSCOMP_NOCOMP,
        info_text.len() as u16,
        info_text.len() as u16,
        0,
        checksum_dms(&info_text),
        &info_text,
    );
    let raw = sample_track_bytes(TRACK_LEN, 3);
    b.push_data_track(5, DMSCOMP_SIMPLE, &raw);
    let archive_bytes = b.finish();

    let archive = DmsArchive::open(&archive_bytes).unwrap();
    assert_eq!(archive.info().unwrap().low_cyl, 5);
    assert_eq!(archive.info().unwrap().high_cyl, 5);
    assert_eq!(archive.texts().len(), 1);
    assert_eq!(archive.texts()[0].bytes, info_text);
    assert_eq!(archive.read_disk_image().unwrap(), raw);
}

#[test]
fn lone_deferred_zero_track_still_yields_cylinder_zero() {
    // A disk that ends right after a deferred track 0. DMS.c:1245-1249 only
    // frees the text-detection buffer; geometry keeps cylinder 0 and the
    // separate extraction pass re-reads the track. So the image must still be
    // cylinder 0's bytes, not empty. Cross-checked against `unar` below.
    let mut b = DmsBuilder::new();
    let raw = sample_track_bytes(TRACK_LEN, 1);
    b.push_data_track(0, DMSCOMP_NOCOMP, &raw);
    let archive_bytes = b.finish();

    let archive = DmsArchive::open(&archive_bytes).unwrap();
    assert_eq!(archive.info().unwrap().low_cyl, 0);
    assert_eq!(archive.info().unwrap().high_cyl, 0);
    assert_eq!(archive.read_disk_image().unwrap(), raw);

    if unar_installed() {
        assert_eq!(unar_disk_image(&archive_bytes), raw);
    }
}

#[test]
fn truncated_header_is_rejected() {
    let (archive_bytes, _) = build_sample_disk(1);
    assert!(DmsArchive::open(&archive_bytes[..40]).is_err());
}

#[test]
fn truncated_track_payload_is_rejected() {
    let (mut archive_bytes, _) = build_sample_disk(1);
    archive_bytes.truncate(archive_bytes.len() - 10);
    assert!(DmsArchive::open(&archive_bytes).is_err());
}

#[test]
fn wrong_uncrunched_crc_fails_on_extraction() {
    // Track number 1 (not 0): track 0 alone is a special deferred case (see
    // the "quirk" comment in `DmsArchive::open`) and isn't what this test
    // means to exercise.
    let mut b = DmsBuilder::new();
    let raw = sample_track_bytes(TRACK_LEN, 1);
    let packed = raw.clone(); // NOCOMP
    b.push_raw_track(
        1,
        DMSCOMP_NOCOMP,
        raw.len() as u16,
        raw.len() as u16,
        0,
        checksum_dms(&raw) ^ 0xFFFF,
        &packed,
    );
    let archive_bytes = b.finish();

    let archive = DmsArchive::open(&archive_bytes).unwrap();
    let err = archive.read_disk_image().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn invalid_track_sectors_value_is_rejected() {
    // upsize = 2048 -> tracksize/1024 == 2, not in {9,11,18,22}.
    let mut b = DmsBuilder::new();
    let raw = vec![0u8; 2048];
    b.push_data_track(0, DMSCOMP_NOCOMP, &raw);
    let archive_bytes = b.finish();
    assert!(DmsArchive::open(&archive_bytes).is_err());
}

#[test]
fn tracksize_not_multiple_of_1024_is_rejected() {
    let mut b = DmsBuilder::new();
    let raw = vec![0u8; 100];
    b.push_data_track(0, DMSCOMP_NOCOMP, &raw);
    let archive_bytes = b.finish();
    assert!(DmsArchive::open(&archive_bytes).is_err());
}

#[test]
fn unknown_method_seven_fails_with_invalid_on_extraction() {
    // Track number 1, not 0 — see the comment in
    // `wrong_uncrunched_crc_fails_on_extraction`. Every method 0..=6 is
    // implemented as of 18d; only 7+ remains genuinely unknown.
    let mut b = DmsBuilder::new();
    let raw = vec![0u8; TRACK_LEN];
    b.push_raw_track(
        1,
        7,
        raw.len() as u16,
        raw.len() as u16,
        0,
        checksum_dms(&raw),
        &raw,
    );
    let archive_bytes = b.finish();

    let archive = DmsArchive::open(&archive_bytes).unwrap();
    let err = archive.read_disk_image().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

const DMSINFO_ENCRYPT: u32 = 1 << 1;
const DMSTRTYPE_DIZ: i16 = 80;

/// A two-cylinder encrypted disk (tracks 1 and 2 — not 0, to sidestep the
/// deferred-zero-track quirk tested elsewhere): both cylinders are
/// NOCOMP/SIMPLE, encrypted with one continuously-advancing cipher stream
/// under `password`, matching `read_disk_image`'s single `DmsState` pass.
fn build_encrypted_disk(password: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut rtv_pass = crc16_arc(password);
    let mut b = DmsBuilder::new();
    b.set_info_flags(DMSINFO_ENCRYPT);
    let raw1 = sample_track_bytes(TRACK_LEN, 1);
    let raw2 = sample_track_bytes(TRACK_LEN, 2);
    b.push_encrypted_data_track(1, DMSCOMP_SIMPLE, &raw1, &mut rtv_pass);
    b.push_encrypted_data_track(2, DMSCOMP_NOCOMP, &raw2, &mut rtv_pass);
    let archive_bytes = b.finish();

    let mut expected = raw1;
    expected.extend_from_slice(&raw2);
    (archive_bytes, expected)
}

#[test]
fn encrypted_archive_opens_without_a_password_geometry_only() {
    // Track headers are plaintext, so geometry is recoverable with no
    // password at all — only decrunching the (still-encrypted) data fails.
    let (archive_bytes, _expected) = build_encrypted_disk(b"hunter2");
    let archive = DmsArchive::open(&archive_bytes).unwrap();
    assert_eq!(archive.info().unwrap().low_cyl, 1);
    assert_eq!(archive.info().unwrap().high_cyl, 2);
    assert!(archive.read_disk_image().is_err());
}

#[test]
fn encrypted_archive_round_trips_with_the_right_password() {
    let (archive_bytes, expected) = build_encrypted_disk(b"hunter2");
    let archive = DmsArchive::open_with_password(&archive_bytes, Some(b"hunter2")).unwrap();
    assert_eq!(archive.read_disk_image().unwrap(), expected);
}

#[test]
fn encrypted_archive_with_the_wrong_password_fails_on_extraction() {
    let (archive_bytes, _expected) = build_encrypted_disk(b"hunter2");
    let archive = DmsArchive::open_with_password(&archive_bytes, Some(b"wrong")).unwrap();
    assert!(archive.read_disk_image().is_err());
}

/// The installed `unar` (v1.10.7, checked at the time this test was
/// written) does not correctly decrypt DMS archives: this test found it
/// fails the *same* way — "Wrong checksum" — for the archive's own correct
/// password, a wrong password, and no password at all, which only makes
/// sense if the installed binary's libxad never actually applies
/// `DecryptDMS` for DMS (encrypted Amiga DMS floppy images are exceedingly
/// rare in the wild, so this code path is plausibly just untested upstream).
/// This isn't a stand-in for confidence in our own port: a from-scratch,
/// independent Python re-implementation of `DecryptDMS`/`GetDMSData`/
/// `CheckSumDMS`, run directly against these exact archive bytes outside of
/// this crate entirely, decrypts track 1 and reproduces the stored
/// checksum exactly — so the cipher and its keying are verified correct
/// against the reference algorithm regardless of what `unar` does here.
/// `unar` still gets exercised (not silently skipped) so a future `unar`
/// that *does* fix this is caught by the `assert_eq!` on the geometry it
/// still gets right.
#[test]
fn unar_recognizes_the_encrypted_disks_geometry_though_its_own_decrypt_appears_broken() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let (archive_bytes, expected) = build_encrypted_disk(b"hunter2");
    let archive = DmsArchive::open_with_password(&archive_bytes, Some(b"hunter2")).unwrap();
    assert_eq!(archive.read_disk_image().unwrap(), expected);

    // `lsar`/`unar` still parse the container and geometry correctly (only
    // decrypting the content is broken) — confirm via a plain, no-password
    // `open`, which never needs decryption to succeed.
    let no_pwd = DmsArchive::open(&archive_bytes).unwrap();
    assert_eq!(no_pwd.info().unwrap().low_cyl, 1);
    assert_eq!(no_pwd.info().unwrap().high_cyl, 2);

    if let Some(outputs) =
        try_unar_extract_all_with_password(&archive_bytes, "crypted.dms", "hunter2")
    {
        assert_eq!(
            outputs.get("crypted.adf"),
            Some(&expected),
            "unar ran but produced a different image than expected"
        );
        panic!(
            "unar successfully decrypted a DMS archive — its DMS decryption is no longer \
             broken; strengthen this test back into a real cross-check oracle"
        );
    } else {
        eprintln!(
            "unar failed to decrypt the DMS archive (known unar 1.10.7 limitation, see doc \
             comment) — our own decrypt was independently verified in Python instead"
        );
    }
}

/// An encrypted archive whose `FILEID.DIZ` text track was, quirkily, left
/// unencrypted on disk (`DMS.c:27-47`'s documented reason for the "retry
/// without decryption" fallback) while the disk-image tracks are properly
/// encrypted. `open`'s scan must still recover the DIZ text via the retry,
/// and `read_disk_image` must still decrypt the (unrelated, separately
/// keyed) data tracks normally.
fn build_encrypted_disk_with_plaintext_diz(password: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut b = DmsBuilder::new();
    b.set_info_flags(DMSINFO_ENCRYPT);
    let diz = b"unencrypted diz inside a crypted archive\n".to_vec();
    b.push_data_track(DMSTRTYPE_DIZ, DMSCOMP_NOCOMP, &diz); // NOT encrypted

    let mut rtv_pass = crc16_arc(password);
    let raw1 = sample_track_bytes(TRACK_LEN, 3);
    b.push_encrypted_data_track(1, DMSCOMP_SIMPLE, &raw1, &mut rtv_pass);
    let archive_bytes = b.finish();
    (archive_bytes, diz, raw1)
}

#[test]
fn diz_retry_without_password_reads_an_accidentally_plaintext_text_track() {
    let (archive_bytes, diz, raw1) = build_encrypted_disk_with_plaintext_diz(b"hunter2");
    let archive = DmsArchive::open_with_password(&archive_bytes, Some(b"hunter2")).unwrap();

    let texts = archive.texts();
    assert_eq!(texts.len(), 1);
    assert!(texts[0].is_diz);
    assert_eq!(
        texts[0].bytes, diz,
        "retry-without-password must recover the plaintext DIZ"
    );

    assert_eq!(archive.read_disk_image().unwrap(), raw1);
}

// --- FMS: file sub-format (named files, not a disk image) ---

/// Build an FMS-form DMS archive with one file: a literal file-name track,
/// then `chunks` as `DMSTRTYPE_FILESTART`, `+1`, … data tracks. When
/// `password` is `Some`, the archive is marked `DMSINFO_ENCRYPT` and every
/// data track is encrypted with one continuously-advancing cipher stream
/// (mirroring `read_file`'s single `DmsState` pass) — the name track is
/// never encrypted, matching the reference (it's never decrypted either).
fn build_fms_archive(
    name_track: &[u8],
    chunks: &[(u8, &[u8])],
    password: Option<&[u8]>,
) -> Vec<u8> {
    let mut b = DmsBuilder::new();
    b.set_disk_type(DMSTYPE_FMS);
    let total_size: u32 = chunks.iter().map(|(_, raw)| raw.len() as u32).sum();
    b.set_unpacked_size(total_size);
    if let Some(pwd) = password {
        b.set_info_flags(DMSINFO_ENCRYPT);
        b.push_fms_name_track(name_track);
        let mut rtv_pass = crc16_arc(pwd);
        for (i, (method, raw)) in chunks.iter().enumerate() {
            b.push_encrypted_data_track(
                DMSTRTYPE_FILESTART + i as i16,
                *method,
                raw,
                &mut rtv_pass,
            );
        }
    } else {
        b.push_fms_name_track(name_track);
        for (i, (method, raw)) in chunks.iter().enumerate() {
            b.push_data_track(DMSTRTYPE_FILESTART + i as i16, *method, raw);
        }
    }
    b.finish()
}

#[test]
fn fms_pre204_name_round_trips_with_multiple_data_tracks() {
    let name = b"README.TXT".to_vec();
    let raw1 = sample_track_bytes(600, 7);
    let raw2 = sample_track_bytes(900, 9);
    let archive_bytes = build_fms_archive(
        &name,
        &[(DMSCOMP_NOCOMP, &raw1), (DMSCOMP_SIMPLE, &raw2)],
        None,
    );

    let archive = DmsArchive::open(&archive_bytes).unwrap();
    assert!(archive.info().is_none());
    assert!(
        archive.read_disk_image().is_err(),
        "an FMS archive has no disk image"
    );

    let files = archive.files();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, name);
    assert_eq!(files[0].protection, None);
    assert_eq!(files[0].comment, None);
    assert!(!files[0].is_crypted);

    let mut expected = raw1;
    expected.extend_from_slice(&raw2);
    assert_eq!(archive.read_file(&files[0]).unwrap(), expected);
}

#[test]
fn files_is_empty_for_a_disk_archive_and_info_is_none_only_for_fms() {
    let (disk_bytes, _expected) = build_sample_disk(2);
    let disk = DmsArchive::open(&disk_bytes).unwrap();
    assert!(disk.files().is_empty());
    assert!(disk.info().is_some());

    let name = b"A".to_vec();
    let raw = sample_track_bytes(100, 1);
    let fms_bytes = build_fms_archive(&name, &[(DMSCOMP_NOCOMP, &raw)], None);
    let fms = DmsArchive::open(&fms_bytes).unwrap();
    assert!(fms.texts().is_empty());
}

/// The installed `unar` (v1.10.7, checked when this test was written) fails
/// to extract **any** FMS-form DMS archive built here — even a minimal
/// single-track, unencrypted, pre-2.04-name one — with "Attempted to read
/// more data than was available", despite `lsar -j` listing the entry's
/// name and size correctly (so the container/header itself is recognized
/// fine; only extraction fails). `XADLibXADParser.m` (`XADMaster`'s bridge
/// around libxad's `DMS.c`) dispatches file extraction through the
/// closed-over-in-this-repo `xadFileUnArc` core function, which is
/// responsible for seeking to `xfi_DataPos` before invoking the client —
/// that seek/dispatch logic lives in libxad's core, not in the LGPL client
/// source (`DMS.c`) this project ports from, so it's out of reach to fix or
/// even inspect here. This isn't a stand-in for confidence in our own port:
/// a from-scratch, independent Python re-implementation of `testDMSTrack` +
/// `DMSUnpRLE` + `CheckSumDMS`, run directly against these exact archive
/// bytes outside of this crate entirely, decodes the file and reproduces
/// the stored checksum exactly. `unar` still gets exercised (not silently
/// skipped) via the non-panicking [`newtua_testutil::try_unar_extract_all`]
/// so a future `unar` that fixes this is caught by the `assert_eq!` below.
#[test]
fn unar_extracts_the_fms_file_with_its_name_and_bytes() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let name = b"HELLO.TXT".to_vec();
    let raw = sample_track_bytes(500, 3);
    let archive_bytes = build_fms_archive(&name, &[(DMSCOMP_SIMPLE, &raw)], None);

    let archive = DmsArchive::open(&archive_bytes).unwrap();
    let files = archive.files();
    assert_eq!(files.len(), 1);
    assert_eq!(archive.read_file(&files[0]).unwrap(), raw);

    let name_str = String::from_utf8(name).unwrap();
    if let Some(outputs) = try_unar_extract_all(&archive_bytes, "test.dms") {
        assert_eq!(
            outputs.get(&name_str),
            Some(&raw),
            "unar ran but its output differs or is missing the expected name \
             (got keys: {:?})",
            outputs.keys().collect::<Vec<_>>()
        );
        panic!(
            "unar successfully extracted an FMS DMS archive — its FMS extraction is no \
             longer broken; strengthen this test back into a real cross-check oracle"
        );
    } else {
        eprintln!(
            "unar failed to extract the FMS archive (known unar 1.10.7 limitation, see doc \
             comment) — our own decode was independently verified in Python instead"
        );
    }
}

#[test]
fn fms_crypted_file_round_trips_with_the_right_password() {
    let name = b"SECRET.BIN".to_vec();
    let raw = sample_track_bytes(700, 11);
    let archive_bytes = build_fms_archive(&name, &[(DMSCOMP_NOCOMP, &raw)], Some(b"hunter2"));

    let archive = DmsArchive::open_with_password(&archive_bytes, Some(b"hunter2")).unwrap();
    let files = archive.files();
    assert_eq!(files.len(), 1);
    assert!(files[0].is_crypted);
    assert_eq!(archive.read_file(&files[0]).unwrap(), raw);
}

#[test]
fn fms_crypted_file_without_a_password_opens_but_fails_on_read() {
    // Track headers (and the literal name track) are plaintext, so open()
    // succeeds with no password at all — only read_file() needs the key.
    let name = b"SECRET.BIN".to_vec();
    let raw = sample_track_bytes(700, 11);
    let archive_bytes = build_fms_archive(&name, &[(DMSCOMP_NOCOMP, &raw)], Some(b"hunter2"));

    let archive = DmsArchive::open(&archive_bytes).unwrap();
    let files = archive.files();
    assert!(files[0].is_crypted);
    assert!(archive.read_file(&files[0]).is_err());
}

/// A 2.04-format name-track payload: `[4B protection][12B DateStamp][size
/// byte(s)][comment?][name]` (`DMS.c:49-57`). `protection`'s top byte must
/// be 0 — that's the pre-2.04/2.04 discriminator our port relies on.
fn build_204_name_track(protection: u32, comment: Option<&[u8]>, name: &[u8]) -> Vec<u8> {
    assert_eq!(protection >> 24, 0, "top byte must be 0 by construction");
    let mut v = protection.to_be_bytes().to_vec();
    v.extend([0u8; 12]);
    match comment {
        Some(c) => {
            assert!(c.len() <= 0x7F);
            v.push(0x80 | c.len() as u8);
            v.extend_from_slice(c);
            v.push(name.len() as u8); // discarded by the parser; included for archive realism
        }
        None => v.push(name.len() as u8),
    }
    v.extend_from_slice(name);
    v
}

#[test]
// unar's FMS extraction is broken in the installed build regardless of the
// name-track format (see the doc comment on
// `unar_extracts_the_fms_file_with_its_name_and_bytes`, which already
// covers that limitation with one canary test) — no separate unar check
// here; this test stays focused on the 2.04 parsing itself.
fn fms_204_header_without_comment_parses_protection_and_round_trips() {
    let name = b"PROG.EXE".to_vec();
    let name_track = build_204_name_track(0x0000_0021, None, &name);
    let raw = sample_track_bytes(600, 5);
    let archive_bytes = build_fms_archive(&name_track, &[(DMSCOMP_NOCOMP, &raw)], None);

    let archive = DmsArchive::open(&archive_bytes).unwrap();
    let files = archive.files();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, name);
    assert_eq!(files[0].protection, Some(0x0000_0021));
    assert_eq!(files[0].comment, None);
    assert_eq!(archive.read_file(&files[0]).unwrap(), raw);
}

#[test]
fn fms_204_header_with_comment_parses_name_and_comment() {
    let name = b"DOC.TXT".to_vec();
    let comment = b"a short comment".to_vec();
    let name_track = build_204_name_track(0x0000_0001, Some(&comment), &name);
    let raw = sample_track_bytes(400, 13);
    let archive_bytes = build_fms_archive(&name_track, &[(DMSCOMP_NOCOMP, &raw)], None);

    let archive = DmsArchive::open(&archive_bytes).unwrap();
    let files = archive.files();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, name);
    assert_eq!(files[0].comment, Some(comment));
    assert_eq!(archive.read_file(&files[0]).unwrap(), raw);
}

#[test]
fn fms_missing_or_wrong_name_track_is_rejected() {
    let mut b = DmsBuilder::new();
    b.set_disk_type(DMSTYPE_FMS);
    let raw = sample_track_bytes(TRACK_LEN, 1);
    b.set_unpacked_size(raw.len() as u32);
    b.push_data_track(0, DMSCOMP_SIMPLE, &raw); // track 0, not DMSTRTYPE_FILENAME
    let archive_bytes = b.finish();

    let err = DmsArchive::open(&archive_bytes)
        .err()
        .expect("expected an error");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn fms_truncated_data_tracks_are_rejected_at_open() {
    let name = b"X.TXT".to_vec();
    let raw = sample_track_bytes(600, 2);
    let mut b = DmsBuilder::new();
    b.set_disk_type(DMSTYPE_FMS);
    // Claim a bigger file size than the single data track actually provides.
    b.set_unpacked_size(raw.len() as u32 + 10_000);
    b.push_fms_name_track(&name);
    b.push_data_track(DMSTRTYPE_FILESTART, DMSCOMP_NOCOMP, &raw);
    let archive_bytes = b.finish();

    let err = DmsArchive::open(&archive_bytes)
        .err()
        .expect("expected an error");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn fms_data_track_out_of_sequence_fails_on_read_file_not_open() {
    let name = b"Y.TXT".to_vec();
    let raw = sample_track_bytes(600, 4);
    let mut b = DmsBuilder::new();
    b.set_disk_type(DMSTYPE_FMS);
    b.set_unpacked_size(raw.len() as u32);
    b.push_fms_name_track(&name);
    // Wrong track number (FILESTART + 1 instead of FILESTART) for the only
    // data track: open()'s validation walk doesn't check track numbers (only
    // testDMSTrack + size bookkeeping), so this must succeed; only
    // read_file()'s sequential check catches it.
    b.push_data_track(DMSTRTYPE_FILESTART + 1, DMSCOMP_NOCOMP, &raw);
    let archive_bytes = b.finish();

    let archive = DmsArchive::open(&archive_bytes).unwrap();
    let files = archive.files();
    assert_eq!(files.len(), 1);
    let err = archive.read_file(&files[0]).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

/// A disk cycling through all four methods 18a+18b implement, one per
/// cylinder: NOCOMP, SIMPLE, QUICK (literal-encoded), MEDIUM (literal-encoded).
fn build_quick_medium_disk(cylinders: i16) -> (Vec<u8>, Vec<u8>) {
    let mut b = DmsBuilder::new();
    let mut expected = Vec::new();
    for cyl in 0..cylinders {
        let raw = sample_track_bytes(TRACK_LEN, (cyl + 1) as u8);
        let method = match cyl % 4 {
            0 => DMSCOMP_NOCOMP,
            1 => DMSCOMP_SIMPLE,
            2 => DMSCOMP_QUICK,
            _ => DMSCOMP_MEDIUM,
        };
        b.push_data_track(cyl, method, &raw);
        expected.extend_from_slice(&raw);
    }
    (b.finish(), expected)
}

#[test]
fn quick_and_medium_literal_roundtrip_through_container() {
    let (archive_bytes, expected) = build_quick_medium_disk(4);
    let archive = DmsArchive::open(&archive_bytes).unwrap();
    assert_eq!(archive.info().unwrap().low_cyl, 0);
    assert_eq!(archive.info().unwrap().high_cyl, 3);
    assert_eq!(archive.read_disk_image().unwrap(), expected);
}

#[test]
fn unar_agrees_on_quick_and_medium_mirror_encoded_disk() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let (archive_bytes, expected) = build_quick_medium_disk(4);
    let archive = DmsArchive::open(&archive_bytes).unwrap();
    assert_eq!(archive.read_disk_image().unwrap(), expected);
    assert_eq!(unar_disk_image(&archive_bytes), expected);
}

#[test]
fn quick_wrong_uncrunched_crc_fails_on_extraction() {
    let raw = sample_track_bytes(TRACK_LEN, 1);
    let intermediate = rle_encode(&raw);
    let packed = lz_literal_encode(&intermediate);
    let mut b = DmsBuilder::new();
    b.push_raw_track(
        1, // not track 0 — see wrong_uncrunched_crc_fails_on_extraction
        DMSCOMP_QUICK,
        raw.len() as u16,
        intermediate.len() as u16,
        0,
        checksum_dms(&raw) ^ 0xFFFF,
        &packed,
    );
    let archive_bytes = b.finish();

    let archive = DmsArchive::open(&archive_bytes).unwrap();
    let err = archive.read_disk_image().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn medium_wrong_uncrunched_crc_fails_on_extraction() {
    let raw = sample_track_bytes(TRACK_LEN, 1);
    let intermediate = rle_encode(&raw);
    let packed = lz_literal_encode(&intermediate);
    let mut b = DmsBuilder::new();
    b.push_raw_track(
        1,
        DMSCOMP_MEDIUM,
        raw.len() as u16,
        intermediate.len() as u16,
        0,
        checksum_dms(&raw) ^ 0xFFFF,
        &packed,
    );
    let archive_bytes = b.finish();

    let archive = DmsArchive::open(&archive_bytes).unwrap();
    let err = archive.read_disk_image().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

/// A hand-built single-cylinder QUICK track whose LZ stage genuinely uses a
/// **match** instruction (not just literals): the track's RLE-stage
/// intermediate is `[0x90, 0xFF, 0xBB, 0x16, 0x00, 0x90, 0xFF, 0xCC, 0x16,
/// 0x00]` (two chunked 0x90-runs, `TRACK_LEN / 2` copies of 0xBB then of
/// 0xCC — chosen so both runs share the same 16-bit count and so the
/// second run's trailing `[0x16, 0x00]` can be copied from the first via a
/// QUICK match instead of re-emitted as literals). Hand-verified against
/// `DMSUnpQUICK`: after 8 literals (`rtv_quick` 251->259), a match with
/// `off=4, j=2` (2-bit length selector `0`) copies `text[254..256]`
/// (`0x16, 0x00`, written by the 4th/5th literal) to close out the stream.
fn build_quick_match_path_disk() -> (Vec<u8>, Vec<u8>) {
    assert_eq!(TRACK_LEN, 0x2C00, "chunk counts below assume this");
    let half = (TRACK_LEN / 2) as u16; // 0x1600, fits one 0x90 0xFF chunk
    let mut raw = vec![0xBBu8; TRACK_LEN / 2];
    raw.extend(std::iter::repeat(0xCCu8).take(TRACK_LEN / 2));

    let mut w = BitWriterMsb::default();
    for &v in &[0x90u8, 0xFF, 0xBB] {
        w.bit(true);
        w.bits(u32::from(v), 8);
    }
    for &v in &half.to_be_bytes() {
        w.bit(true);
        w.bits(u32::from(v), 8);
    }
    for &v in &[0x90u8, 0xFF, 0xCC] {
        w.bit(true);
        w.bits(u32::from(v), 8);
    }
    w.bit(false); // match: copy the trailing [hi, lo] count bytes from run 1
    w.bits(0, 2); // length selector 0 -> j = 2
    w.bits(4, 8); // offset 4 -> text[254..256], the run-1 count bytes
    let packed = w.finish();

    let intermediate_len = 10u16; // 2 * (0x90 0xFF <value> <hi> <lo>)
    let mut b = DmsBuilder::new();
    b.push_raw_track(
        0,
        DMSCOMP_QUICK,
        raw.len() as u16,
        intermediate_len,
        0,
        checksum_dms(&raw),
        &packed,
    );
    (b.finish(), raw)
}

#[test]
fn quick_match_path_hand_built_track_matches_container_and_unar() {
    let (archive_bytes, expected) = build_quick_match_path_disk();
    let archive = DmsArchive::open(&archive_bytes).unwrap();
    assert_eq!(archive.read_disk_image().unwrap(), expected);

    if unar_installed() {
        assert_eq!(unar_disk_image(&archive_bytes), expected);
    }
}

/// Two QUICK tracks: cylinder 0 (literal-encoded, cflag varies per call) and
/// cylinder 1, whose sole instruction is a match reaching back into
/// cylinder 0's leftover `Text` window (`off=9, j=5`, hand-verified against
/// `DMSUnpQUICK` assuming `rtv_quick` carries over from cylinder 0 at 5:
/// `i = 5 - 9 - 1 = -5 (mod 65536)`, and `i & 0xFF == 251`, the start of
/// cylinder 0's 5-byte literal run). With `NOINIT` set on cylinder 0 this
/// reproduces cylinder 0's own RLE-stage intermediate; without it, the
/// post-track reinit (`dms_init_data`) has zeroed that part of `Text` and
/// reset `rtv_quick` to 251, so the same instruction reads zeros instead.
fn build_noinit_disk(cyl0_cflag: u8) -> (Vec<u8>, Vec<u8>) {
    assert_eq!(TRACK_LEN, 0x2C00, "hi/lo bytes below assume this");
    let raw = vec![0x11u8; TRACK_LEN];
    let intermediate = [0x90u8, 0xFF, 0x11, 0x2C, 0x00]; // one chunked run

    let packed0 = lz_literal_encode(&intermediate);

    let mut w1 = BitWriterMsb::default();
    w1.bit(false);
    w1.bits(3, 2); // length selector 3 -> j = 5
    w1.bits(9, 8); // offset 9
    let packed1 = w1.finish();

    let mut b = DmsBuilder::new();
    b.push_raw_track(
        0,
        DMSCOMP_QUICK,
        TRACK_LEN as u16,
        intermediate.len() as u16,
        cyl0_cflag,
        checksum_dms(&raw),
        &packed0,
    );
    b.push_raw_track(
        1,
        DMSCOMP_QUICK,
        TRACK_LEN as u16,
        intermediate.len() as u16,
        0,
        checksum_dms(&raw),
        &packed1,
    );
    let archive_bytes = b.finish();

    let mut expected = raw.clone();
    expected.extend_from_slice(&raw);
    (archive_bytes, expected)
}

#[test]
fn noinit_flag_carries_quick_lz_state_into_next_track() {
    let (with_noinit, expected) = build_noinit_disk(DMSCFLAG_NOINIT);
    let archive = DmsArchive::open(&with_noinit).unwrap();
    assert_eq!(archive.read_disk_image().unwrap(), expected);
    if unar_installed() {
        assert_eq!(unar_disk_image(&with_noinit), expected);
    }
}

#[test]
fn without_noinit_the_carried_window_is_gone_so_extraction_fails() {
    // Same bytes as `noinit_flag_carries_quick_lz_state_into_next_track`,
    // minus the NOINIT flag on cylinder 0: `dms_init_data` now runs between
    // the two tracks, so cylinder 1's match reads zeroed `Text` instead of
    // cylinder 0's leftover run — proving the flag (not some other quirk)
    // is what made the first test pass.
    let (without_noinit, _expected) = build_noinit_disk(0);
    let archive = DmsArchive::open(&without_noinit).unwrap();
    assert!(archive.read_disk_image().is_err());
}

/// Extract a DMS archive with `unar` (via testutil) and return the bytes of
/// the single output file it produces — the reconstructed disk image. Call
/// only after [`unar_installed`].
fn unar_disk_image(archive_bytes: &[u8]) -> Vec<u8> {
    let outputs = unar_extract_all(archive_bytes, "test.dms");
    assert_eq!(
        outputs.len(),
        1,
        "unar produced {} output files, expected 1",
        outputs.len()
    );
    outputs.into_values().next().unwrap()
}

#[test]
fn unar_agrees_on_mirror_encoded_disk() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let (archive_bytes, expected) = build_sample_disk(3);

    let archive = DmsArchive::open(&archive_bytes).unwrap();
    let ours = archive.read_disk_image().unwrap();
    assert_eq!(ours, expected);

    let unars = unar_disk_image(&archive_bytes);
    assert_eq!(
        unars, expected,
        "unar's reconstructed image differs from ours"
    );
}
