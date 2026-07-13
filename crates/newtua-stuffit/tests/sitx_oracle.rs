// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! StuffItX container tests: a mirror encoder that builds valid `.sitx` archives
//! for round-trips through [`SitxArchive`], plus the `unar` oracle over both our
//! own fixtures and a real corpus (`NEWTUA_SITX_CORPUS`).
//!
//! The mirror `Writer` reproduces the reference reader's bit/byte interleaving
//! exactly: bits are packed LSB-first; a P2 value that ends mid-byte is padded to
//! the next byte boundary before any raw payload (raw reads start at
//! `offsetInFile`, past the partial byte); big-endian integers and `ReadSitxData`
//! continue the bitstream without padding. Getting this wrong would desync the
//! parser, so a green round-trip is a strong check on the low-level reader too.

use std::collections::BTreeMap;

use newtua_common::{crc32, deflate, rc4::Rc4};
use newtua_stuffit::sitx::SitxArchive;

// === mirror bit/byte writer ===================================================

#[derive(Default)]
struct Writer {
    out: Vec<u8>,
    cur: u8,
    nbits: u8,
}

impl Writer {
    fn bit(&mut self, b: u32) {
        if b & 1 != 0 {
            self.cur |= 1 << self.nbits;
        }
        self.nbits += 1;
        if self.nbits == 8 {
            self.out.push(self.cur);
            self.cur = 0;
            self.nbits = 0;
        }
    }

    /// One byte through the bit path (mirrors `readBitsLE:8` / `ReadSitxData`).
    fn byte(&mut self, b: u8) {
        for i in 0..8 {
            self.bit(u32::from(b >> i));
        }
    }

    /// A big-endian `u32` through the bit path (`ReadSitxUInt32`).
    fn write_u32_be(&mut self, v: u32) {
        for b in v.to_be_bytes() {
            self.byte(b);
        }
    }

    /// A big-endian `u64` through the bit path (`ReadSitxUInt64`).
    fn write_u64_be(&mut self, v: u64) {
        for b in v.to_be_bytes() {
            self.byte(b);
        }
    }

    /// The P2 variable-length integer (inverse of `Reader::read_p2`).
    fn write_p2(&mut self, result: u64) {
        let value = result + 1;
        let n = value.count_ones();
        for _ in 0..n - 1 {
            self.bit(1);
        }
        self.bit(0);
        let hb = 63 - value.leading_zeros();
        for i in 0..=hb {
            self.bit(((value >> i) & 1) as u32);
        }
    }

    /// Pad the current partial byte to a byte boundary (mirrors `flushReadBits`
    /// plus the reader advancing `offsetInFile` past a partial byte).
    fn flush(&mut self) {
        if self.nbits > 0 {
            self.out.push(self.cur);
            self.cur = 0;
            self.nbits = 0;
        }
    }

    /// Append raw bytes; must be on a byte boundary.
    fn raw(&mut self, data: &[u8]) {
        assert_eq!(self.nbits, 0, "raw write off a byte boundary");
        self.out.extend_from_slice(data);
    }

    /// A length-prefixed string (inverse of `Reader::read_string`).
    fn write_string(&mut self, s: &[u8]) {
        self.write_p2(s.len() as u64);
        self.flush();
        self.raw(s);
    }

    fn finish(mut self) -> Vec<u8> {
        self.flush();
        self.out
    }
}

// === element builders =========================================================

/// Write an element's `(something, type, attribs, alglist)` header. Attribute and
/// algorithm entries are `(type, value)` pairs. Does **not** flush — callers
/// decide whether a data area (flushed to `dataoffset`) or an inline P2 (the fork
/// type, continuing the bitstream) follows.
fn write_header(w: &mut Writer, typ: u64, attribs: &[(u64, u64)], alglist: &[(u64, u64)]) {
    w.bit(0); // something
    w.write_p2(typ);
    for &(t, v) in attribs {
        w.write_p2(t);
        w.write_p2(v);
    }
    w.write_p2(0); // end attribs
    for &(t, v) in alglist {
        w.write_p2(t);
        w.write_p2(v);
    }
    w.write_p2(0); // end alglist
}

fn write_file(w: &mut Writer, id: u64, parent: Option<u64>) {
    let mut attribs = vec![(1u64, id)];
    if let Some(p) = parent {
        attribs.push((2, p));
    }
    write_header(w, 2, &attribs, &[]);
    w.flush();
}

fn write_dir(w: &mut Writer, id: u64, parent: Option<u64>) {
    let mut attribs = vec![(1u64, id)];
    if let Some(p) = parent {
        attribs.push((2, p));
    }
    write_header(w, 4, &attribs, &[]);
    w.flush();
}

/// A fork element. `fork_type` (0 data, 1 resource) is read inline right after the
/// header, continuing the bitstream (no flush before it).
fn write_fork(w: &mut Writer, entry: u64, stream: u64, index: u64, length: u64, fork_type: u64) {
    write_header(
        w,
        3,
        &[(2, entry), (3, stream), (4, index), (5, length)],
        &[],
    );
    w.write_p2(fork_type);
    w.flush();
}

/// Write a data area: a single block holding `payload`, its zero terminator, then
/// the tail (an optional four-byte CRC block).
fn write_data_area(w: &mut Writer, payload: &[u8], crc: Option<u32>) {
    w.flush(); // align to dataoffset
               // One block.
    w.write_p2(payload.len() as u64);
    w.flush();
    w.raw(payload);
    w.write_p2(0); // block terminator
    w.flush();
    // Tail. A CRC block is four raw byte-aligned bytes (`readUInt32BE` reads raw,
    // so the P2 length is padded to a byte boundary before them).
    match crc {
        Some(c) => {
            w.write_p2(4);
            w.flush();
            w.raw(&c.to_be_bytes());
            w.write_p2(0);
        }
        None => w.write_p2(0),
    }
    w.flush();
}

/// Element type 1 (data). `alglist` carries compression/checksum/preprocess; the
/// block payload already includes any codec header byte(s).
fn write_data(
    w: &mut Writer,
    objid: u64,
    uncompsize: u64,
    alglist: &[(u64, u64)],
    payload: &[u8],
    crc: Option<u32>,
) {
    write_header(w, 1, &[(1, objid), (5, uncompsize)], alglist);
    write_data_area(w, payload, crc);
}

/// Element type 5 (catalog). `catalog` is the decoded catalog stream; here it is
/// stored uncompressed (compression -1), so the block payload is `catalog` itself.
fn write_catalog(w: &mut Writer, catalog: &[u8]) {
    write_header(w, 5, &[(5, catalog.len() as u64)], &[]);
    write_data_area(w, catalog, None);
}

fn write_end(w: &mut Writer) {
    write_header(w, 0, &[], &[]);
}

/// Build a catalog stream giving each entry (in declaration order) a name.
fn build_catalog(names: &[&[u8]]) -> Vec<u8> {
    let mut c = Writer::default();
    for name in names {
        c.write_p2(1); // key: filename
        c.write_string(name);
        c.write_p2(0); // end of entry
        c.flush();
    }
    c.finish()
}

fn archive(build: impl FnOnce(&mut Writer)) -> Vec<u8> {
    let mut w = Writer::default();
    w.raw(b"StuffIt!");
    build(&mut w);
    w.finish()
}

/// Read every entry of `arc` into a path->bytes map (data forks under their path,
/// resource forks under `<path>/..namedfork/rsrc`, matching `unar`).
fn extract_all(arc: &SitxArchive) -> BTreeMap<String, Vec<u8>> {
    let mut map = BTreeMap::new();
    for (i, e) in arc.entries().iter().enumerate() {
        if e.is_directory() {
            continue;
        }
        let mut key = String::from_utf8_lossy(e.name()).into_owned();
        if e.is_resource_fork() {
            key.push_str("/..namedfork/rsrc");
        }
        let mut buf = Vec::new();
        arc.read_entry(i, &mut buf).unwrap();
        map.insert(key, buf);
    }
    map
}

// === round-trip tests (always run) ============================================

#[test]
fn recognizes_stuffitx_banner() {
    assert!(SitxArchive::recognize(b"StuffIt!blahblah"));
    assert!(SitxArchive::recognize(b"StuffIt?blahblah"));
    assert!(!SitxArchive::recognize(b"StuffIt5blah"));
    assert!(!SitxArchive::recognize(b"SIT!"));
}

#[test]
fn base_n_body_is_unsupported() {
    // The `?` marker means a base-N encoded body; parsing bails at the marker.
    let err = SitxArchive::open(b"StuffIt?padding".to_vec())
        .err()
        .expect("base-N body must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
}

#[test]
fn recovery_style_desync_reports_unsupported() {
    // An attribute type > 10 (here 24, matching the corpus's observed "attrib
    // type too big: 24") is the signature of a recovery-record/redundancy
    // element our container doesn't model. Followed immediately by a truncated
    // stream (no further elements, no `write_end`), this reproduces the desync
    // 19i targets: the reference logs the same "too big" line and eventually
    // runs off the end of the file too.
    let data = archive(|w| {
        write_header(w, 2, &[(1, 1), (24, 99)], &[]);
    });

    let err = SitxArchive::open(data)
        .err()
        .expect("a desynced, truncated stream must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    assert!(
        err.to_string().contains("recovery"),
        "unexpected error message: {err}"
    );
}

#[test]
fn plain_truncation_without_unknown_fields_stays_unexpected_eof() {
    // No oversized attribute/algorithm type was ever seen, so a truncated
    // stream must keep reporting the raw UnexpectedEof — regression guard
    // against over-eager relabeling of ordinary corrupt/short archives.
    let data = archive(|_w| {});

    let err = SitxArchive::open(data)
        .err()
        .expect("a truncated stream must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
}

#[test]
fn stored_single_file_round_trips() {
    let content = b"the quick brown fox, stored uncompressed".to_vec();
    let data = archive(|w| {
        write_file(w, 1, None);
        write_fork(w, 1, 1, 0, content.len() as u64, 0);
        write_catalog(w, &build_catalog(&[b"fox.txt"]));
        // compression -1 (none), no checksum, no preprocess.
        write_data(w, 1, content.len() as u64, &[], &content, None);
        write_end(w);
    });
    let arc = SitxArchive::open(data).unwrap();
    let files = extract_all(&arc);
    assert_eq!(files.get("fox.txt").map(Vec::as_slice), Some(&content[..]));
}

#[test]
fn deflate_file_round_trips_with_crc() {
    let content = b"deflate me: repeat repeat repeat repeat repeat".repeat(6);
    let mut payload = vec![15u8]; // window-size byte
    payload.extend_from_slice(&deflate::deflate_dynamic_sitx(
        &content,
        &deflate::ZIP_ORDER,
    ));
    let crc = crc32::crc32_ieee(&content);
    let data = archive(|w| {
        write_file(w, 1, None);
        write_fork(w, 1, 1, 0, content.len() as u64, 0);
        write_catalog(w, &build_catalog(&[b"z.bin"]));
        // compression 3 (deflate), checksum 0 (CRC32), no preprocess.
        write_data(
            w,
            1,
            content.len() as u64,
            &[(1, 3), (2, 0)],
            &payload,
            Some(crc),
        );
        write_end(w);
    });
    let arc = SitxArchive::open(data).unwrap();
    assert_eq!(
        extract_all(&arc).get("z.bin").map(Vec::as_slice),
        Some(&content[..])
    );
}

#[test]
fn bad_crc_is_rejected() {
    let content = b"content whose crc will be wrong".to_vec();
    let data = archive(|w| {
        write_file(w, 1, None);
        write_fork(w, 1, 1, 0, content.len() as u64, 0);
        write_catalog(w, &build_catalog(&[b"bad.txt"]));
        write_data(
            w,
            1,
            content.len() as u64,
            &[(2, 0)],
            &content,
            Some(0xdead_beef),
        );
        write_end(w);
    });
    let arc = SitxArchive::open(data).unwrap();
    let mut buf = Vec::new();
    let err = arc.read_entry(0, &mut buf).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn rc4_file_round_trips() {
    let content = b"no compression, only RC4 obfuscation over the bytes".to_vec();
    let key = [0x42u8];
    let mut cipher = content.clone();
    Rc4::new(&key).apply(&mut cipher);
    let mut payload = vec![0u8, 0u8, key[0]]; // two skipped bytes, then the key
    payload.extend_from_slice(&cipher);
    let data = archive(|w| {
        write_file(w, 1, None);
        write_fork(w, 1, 1, 0, content.len() as u64, 0);
        write_catalog(w, &build_catalog(&[b"secret.txt"]));
        write_data(w, 1, content.len() as u64, &[(1, 5)], &payload, None);
        write_end(w);
    });
    let arc = SitxArchive::open(data).unwrap();
    assert_eq!(
        extract_all(&arc).get("secret.txt").map(Vec::as_slice),
        Some(&content[..])
    );
}

#[test]
fn catalog_metadata_is_parsed() {
    // A catalog entry carrying a name, timestamps, Finder info, POSIX owner and a
    // comment. Uses a directory so no fork/data stream is needed.
    let finder: [u8; 32] = std::array::from_fn(|i| i as u8);
    let mut catalog = Writer::default();
    catalog.write_p2(1); // filename
    catalog.write_string(b"meta");
    catalog.write_p2(2); // mtime (FILETIME ticks)
    catalog.write_u64_be(132_000_000_000_000_000);
    catalog.write_p2(8); // ctime
    catalog.write_u64_be(131_000_000_000_000_000);
    catalog.write_p2(4); // Finder info
    for b in finder {
        catalog.byte(b);
    }
    catalog.write_p2(6); // permissions + owner
    catalog.byte(1); // hasowner
    catalog.write_u32_be(0o644);
    catalog.write_u32_be(501);
    catalog.write_u32_be(20);
    catalog.write_p2(9); // comment
    catalog.write_string(b"a comment");
    catalog.write_p2(0); // end of entry
    catalog.flush();
    let catalog = catalog.finish();

    let data = archive(|w| {
        write_dir(w, 1, None);
        write_catalog(w, &catalog);
        // A data element is needed to flush out the fork-less directory entry.
        write_file(w, 2, None);
        write_fork(w, 2, 2, 0, 1, 0);
        write_data(w, 2, 1, &[], b"x", None);
        write_end(w);
    });
    let arc = SitxArchive::open(data).unwrap();
    let dir = arc.entries().iter().find(|e| e.is_directory()).unwrap();
    assert_eq!(dir.name(), b"meta");
    assert_eq!(dir.modification_filetime(), Some(132_000_000_000_000_000));
    assert_eq!(dir.creation_filetime(), Some(131_000_000_000_000_000));
    assert_eq!(dir.finder_info(), Some(&finder));
    assert_eq!(dir.posix_permissions(), Some(0o644));
    assert_eq!(dir.posix_uid(), Some(501));
    assert_eq!(dir.posix_gid(), Some(20));
    assert_eq!(dir.comment(), Some(&b"a comment"[..]));
}

#[test]
fn symlink_finder_info_marks_a_link() {
    let mut catalog = Writer::default();
    catalog.write_p2(1);
    catalog.write_string(b"link");
    catalog.write_p2(4); // Finder info beginning with the symlink magic
    for &b in b"slnkrhap" {
        catalog.byte(b);
    }
    for _ in 8..32 {
        catalog.byte(0);
    }
    catalog.write_p2(0);
    catalog.flush();
    let catalog = catalog.finish();

    let data = archive(|w| {
        write_dir(w, 1, None);
        write_catalog(w, &catalog);
        write_file(w, 2, None);
        write_fork(w, 2, 2, 0, 1, 0);
        write_data(w, 2, 1, &[], b"x", None);
        write_end(w);
    });
    let arc = SitxArchive::open(data).unwrap();
    let link = arc.entries().iter().find(|e| e.name() == b"link").unwrap();
    assert!(link.is_link());
    assert_eq!(link.finder_info(), None); // the magic is consumed, not stored
}

#[test]
fn x86_preprocessor_is_wired_into_the_chain() {
    // Data with no E8/E9 bytes: the x86 pass is the identity, so it proves the
    // preprocessor dispatch works without needing an x86 filter encoder here.
    let content: Vec<u8> = (0..300u32).map(|i| ((i % 200) as u8).min(0xe7)).collect();
    let data = archive(|w| {
        write_file(w, 1, None);
        write_fork(w, 1, 1, 0, content.len() as u64, 0);
        write_catalog(w, &build_catalog(&[b"code.bin"]));
        // compression -1 (none), preprocess 2 (x86).
        write_data(w, 1, content.len() as u64, &[(3, 2)], &content, None);
        write_end(w);
    });
    let arc = SitxArchive::open(data).unwrap();
    assert_eq!(
        extract_all(&arc).get("code.bin").map(Vec::as_slice),
        Some(&content[..])
    );
}

#[test]
fn directory_and_child_build_nested_paths() {
    let content = b"inside a directory".to_vec();
    let data = archive(|w| {
        write_dir(w, 1, None); // entry 0: the directory
        write_file(w, 2, Some(1)); // entry 1: file, parent = dir 1
        write_fork(w, 2, 1, 0, content.len() as u64, 0);
        write_catalog(w, &build_catalog(&[b"folder", b"child.txt"]));
        write_data(w, 1, content.len() as u64, &[], &content, None);
        write_end(w);
    });
    let arc = SitxArchive::open(data).unwrap();
    // The directory is emitted first (fork-less), then the file's data fork.
    let dir = &arc.entries()[0];
    assert!(dir.is_directory());
    assert_eq!(dir.name(), b"folder");
    let files = extract_all(&arc);
    assert_eq!(
        files.get("folder/child.txt").map(Vec::as_slice),
        Some(&content[..])
    );
}

#[test]
fn replicated_fork_serves_multiple_files() {
    // Two files sharing one fork slot (same stream index, same length): the fork
    // carries both entry ids, and both files decode the same bytes.
    let content = b"shared payload for two files".to_vec();
    let n = content.len() as u64;
    let data = archive(|w| {
        write_file(w, 1, None);
        write_file(w, 2, None);
        write_fork(w, 1, 1, 0, n, 0); // fork slot 0 for entry 1
        write_fork(w, 2, 1, 0, n, 0); // same slot 0 -> replication onto entry 2
        write_catalog(w, &build_catalog(&[b"a.txt", b"b.txt"]));
        write_data(w, 1, n, &[], &content, None);
        write_end(w);
    });
    let arc = SitxArchive::open(data).unwrap();
    let files = extract_all(&arc);
    assert_eq!(files.get("a.txt").map(Vec::as_slice), Some(&content[..]));
    assert_eq!(files.get("b.txt").map(Vec::as_slice), Some(&content[..]));
}

#[test]
fn replicated_fork_length_mismatch_is_rejected() {
    let data = archive(|w| {
        write_file(w, 1, None);
        write_file(w, 2, None);
        write_fork(w, 1, 1, 0, 10, 0);
        write_fork(w, 2, 1, 0, 20, 0); // same slot, different length -> error
        write_catalog(w, &build_catalog(&[b"a", b"b"]));
        write_data(w, 1, 10, &[], &[0u8; 10], None);
        write_end(w);
    });
    let err = SitxArchive::open(data)
        .err()
        .expect("length mismatch must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn resource_and_data_forks_both_extract() {
    let dataf = b"data fork bytes".to_vec();
    let rsrc = b"resource fork bytes".to_vec();
    // Two forks in one stream: index 0 (data) then index 1 (resource). The stream
    // holds them concatenated, so the payload is data ++ rsrc.
    let mut payload = dataf.clone();
    payload.extend_from_slice(&rsrc);
    let data = archive(|w| {
        write_file(w, 1, None);
        write_fork(w, 1, 1, 0, dataf.len() as u64, 0); // data fork
        write_fork(w, 1, 1, 1, rsrc.len() as u64, 1); // resource fork
        write_catalog(w, &build_catalog(&[b"both"]));
        write_data(w, 1, (dataf.len() + rsrc.len()) as u64, &[], &payload, None);
        write_end(w);
    });
    let arc = SitxArchive::open(data).unwrap();
    let files = extract_all(&arc);
    assert_eq!(files.get("both").map(Vec::as_slice), Some(&dataf[..]));
    assert_eq!(
        files.get("both/..namedfork/rsrc").map(Vec::as_slice),
        Some(&rsrc[..])
    );
}

#[test]
fn unsupported_codec_parses_but_read_fails() {
    // An unknown compression method number is not supported: the archive
    // parses (metadata is available) but reading the fork returns
    // Unsupported. Method 4 (Blend) and method 6 (Iron) were the examples
    // here through 19d/19e; both gained support since (19e, 19f).
    let content = vec![0u8; 8];
    let data = archive(|w| {
        write_file(w, 1, None);
        write_fork(w, 1, 1, 0, content.len() as u64, 0);
        write_catalog(w, &build_catalog(&[b"c.bin"]));
        write_data(w, 1, content.len() as u64, &[(1, 9)], &content, None);
        write_end(w);
    });
    let arc = SitxArchive::open(data).unwrap();
    assert_eq!(arc.entries()[0].name(), b"c.bin");
    assert_eq!(arc.entries()[0].compression_name(), "Method 9");
    let mut buf = Vec::new();
    let err = arc.read_entry(0, &mut buf).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
}

// === unar oracle over our fixtures ============================================

#[test]
fn stored_archive_matches_unar() {
    if !newtua_testutil::unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let content = b"cross-checked against The Unarchiver".to_vec();
    let data = archive(|w| {
        write_file(w, 1, None);
        write_fork(w, 1, 1, 0, content.len() as u64, 0);
        write_catalog(w, &build_catalog(&[b"hello.txt"]));
        write_data(
            w,
            1,
            content.len() as u64,
            &[(2, 0)],
            &content,
            Some(crc32::crc32_ieee(&content)),
        );
        write_end(w);
    });
    let ours = SitxArchive::open(data.clone()).unwrap();
    let ours_files = extract_all(&ours);
    let theirs = newtua_testutil::unar_extract_all(&data, "fixture.sitx");
    assert_eq!(
        ours_files.get("hello.txt"),
        theirs.get("hello.txt"),
        "our vs unar"
    );
}

#[test]
fn deflate_archive_matches_unar() {
    if !newtua_testutil::unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let content = b"deflate cross-check payload payload payload".repeat(5);
    let mut payload = vec![15u8];
    payload.extend_from_slice(&deflate::deflate_dynamic_sitx(
        &content,
        &deflate::ZIP_ORDER,
    ));
    let data = archive(|w| {
        write_file(w, 1, None);
        write_fork(w, 1, 1, 0, content.len() as u64, 0);
        write_catalog(w, &build_catalog(&[b"d.bin"]));
        write_data(
            w,
            1,
            content.len() as u64,
            &[(1, 3), (2, 0)],
            &payload,
            Some(crc32::crc32_ieee(&content)),
        );
        write_end(w);
    });
    let ours = SitxArchive::open(data.clone()).unwrap();
    let theirs = newtua_testutil::unar_extract_all(&data, "fixture.sitx");
    assert_eq!(extract_all(&ours).get("d.bin"), theirs.get("d.bin"));
}

// === real corpus + unar (skips without NEWTUA_SITX_CORPUS) ====================

#[test]
fn corpus_files_match_unar() {
    let Some(dir) = newtua_testutil::sitx_corpus_dir() else {
        eprintln!("skipping: NEWTUA_SITX_CORPUS not set");
        return;
    };
    if !newtua_testutil::unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }

    let mut checked = 0usize;
    let mut skipped_unsupported = 0usize;
    let mut skipped_unar_cant = 0usize;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        let bytes = std::fs::read(&path).unwrap();
        if !SitxArchive::recognize(&bytes) {
            continue; // classic / SIT5 under .sit, not StuffItX
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();

        // Only cross-check against archives `unar` itself can parse; the corpus
        // includes recovery-record files the reference decoder also rejects.
        let theirs = match newtua_testutil::try_unar_extract_all(&bytes, &name) {
            Some(t) => t,
            None => {
                skipped_unar_cant += 1;
                continue;
            }
        };

        // `unar` handled it, so we must too — unless it uses a codec 19a doesn't
        // support yet (surfacing as Unsupported on open or read).
        let arc = match SitxArchive::open(bytes.clone()) {
            Ok(a) => a,
            Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
                skipped_unsupported += 1;
                continue;
            }
            Err(e) => panic!("unar parsed but we failed to open {name}: {e}"),
        };

        let mut ours = BTreeMap::new();
        let mut unsupported = false;
        for (i, en) in arc.entries().iter().enumerate() {
            if en.is_directory() {
                continue;
            }
            let mut buf = Vec::new();
            match arc.read_entry(i, &mut buf) {
                Ok(()) => {
                    let mut key = String::from_utf8_lossy(en.name()).into_owned();
                    if en.is_resource_fork() {
                        key.push_str("/..namedfork/rsrc");
                    }
                    ours.insert(key, buf);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
                    unsupported = true;
                    break;
                }
                Err(e) => panic!("read error in {name}: {e}"),
            }
        }
        if unsupported {
            skipped_unsupported += 1;
            continue;
        }

        for (k, v) in &ours {
            assert_eq!(Some(v), theirs.get(k), "mismatch on {k} in {name}");
        }
        checked += 1;
    }
    eprintln!(
        "corpus: {checked} archives verified, {skipped_unsupported} skipped (unsupported codecs), \
		 {skipped_unar_cant} skipped (unar cannot parse)"
    );
}

/// Recovery-record (mac "recoverability") and redundancy (win) archives (19i).
/// There's no oracle for these — `unar` itself rejects them too (that's why
/// `corpus_files_match_unar`, above, skips them via `skipped_unar_cant`) — so
/// this only checks that `SitxArchive::open` reports `Unsupported` rather than
/// a raw `UnexpectedEof`. Forward-compatible: filters by filename
/// (`recoverability`/`redundancy`), so 0 matches in the corpus is a pass, not a
/// skip — no `unar` dependency here, only the corpus itself.
#[test]
fn recovery_and_redundancy_archives_report_unsupported() {
    let Some(dir) = newtua_testutil::sitx_corpus_dir() else {
        eprintln!("skipping: NEWTUA_SITX_CORPUS not set");
        return;
    };

    let mut checked = 0usize;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !(name.contains("recoverability") || name.contains("redundancy")) {
            continue;
        }
        let bytes = std::fs::read(&path).unwrap();
        if !SitxArchive::recognize(&bytes) {
            continue; // e.g. the corpus's .as/.bin/.hqx wrappers around the same fixture
        }

        let err = SitxArchive::open(bytes)
            .err()
            .unwrap_or_else(|| panic!("{name} unexpectedly opened successfully"));
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::Unsupported,
            "{name}: expected Unsupported, got {err:?}"
        );
        checked += 1;
    }
    eprintln!("recovery/redundancy corpus: {checked} archives checked");
}

/// Like `corpus_files_match_unar`, but counts and cross-checks Cyanide
/// (compression method 1) members specifically, matching the per-codec table
/// 19a's corpus survey used (`report-19a-sitx-container.md`, "Обзор методов
/// корпуса"). Member selection uses our own parser's `compression_name()`
/// (already exercised by 19a for unsupported codecs) rather than shelling out
/// to `lsar -j` a second time.
#[test]
fn cyanide_corpus_members_match_unar() {
    let Some(dir) = newtua_testutil::sitx_corpus_dir() else {
        eprintln!("skipping: NEWTUA_SITX_CORPUS not set");
        return;
    };
    if !newtua_testutil::unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }

    let mut members_checked = 0usize;
    let mut members_mismatched = 0usize;
    let mut archives_unar_cant = 0usize;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        let bytes = std::fs::read(&path).unwrap();
        if !SitxArchive::recognize(&bytes) {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();

        let arc = match SitxArchive::open(bytes.clone()) {
            Ok(a) => a,
            Err(_) => continue, // not a Cyanide-relevant failure; the general oracle covers this
        };
        let has_cyanide = arc
            .entries()
            .iter()
            .any(|e| e.compression_name().starts_with("Cyanide"));
        if !has_cyanide {
            continue;
        }

        let Some(theirs) = newtua_testutil::try_unar_extract_all(&bytes, &name) else {
            archives_unar_cant += 1;
            continue;
        };

        for (i, en) in arc.entries().iter().enumerate() {
            if en.is_directory() || !en.compression_name().starts_with("Cyanide") {
                continue;
            }
            let mut buf = Vec::new();
            arc.read_entry(i, &mut buf)
                .unwrap_or_else(|e| panic!("Cyanide member in {name} failed to decode: {e}"));
            let mut key = String::from_utf8_lossy(en.name()).into_owned();
            if en.is_resource_fork() {
                key.push_str("/..namedfork/rsrc");
            }
            members_checked += 1;
            if theirs.get(&key) != Some(&buf) {
                members_mismatched += 1;
                eprintln!("cyanide mismatch: {name}:{key}");
            }
        }
    }
    eprintln!(
        "cyanide corpus: {members_checked} members checked, {members_mismatched} mismatched, \
		 {archives_unar_cant} archives unar could not parse"
    );
    assert_eq!(members_mismatched, 0, "Cyanide output diverged from unar");
}

/// Like `cyanide_corpus_members_match_unar`, but for Darkhorse (compression
/// method 2, 19d).
#[test]
fn darkhorse_corpus_members_match_unar() {
    let Some(dir) = newtua_testutil::sitx_corpus_dir() else {
        eprintln!("skipping: NEWTUA_SITX_CORPUS not set");
        return;
    };
    if !newtua_testutil::unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }

    let mut members_checked = 0usize;
    let mut members_mismatched = 0usize;
    let mut archives_unar_cant = 0usize;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        let bytes = std::fs::read(&path).unwrap();
        if !SitxArchive::recognize(&bytes) {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();

        let arc = match SitxArchive::open(bytes.clone()) {
            Ok(a) => a,
            Err(_) => continue, // not a Darkhorse-relevant failure; the general oracle covers this
        };
        let has_darkhorse = arc
            .entries()
            .iter()
            .any(|e| e.compression_name().starts_with("Darkhorse"));
        if !has_darkhorse {
            continue;
        }

        let Some(theirs) = newtua_testutil::try_unar_extract_all(&bytes, &name) else {
            archives_unar_cant += 1;
            continue;
        };

        for (i, en) in arc.entries().iter().enumerate() {
            if en.is_directory() || !en.compression_name().starts_with("Darkhorse") {
                continue;
            }
            let mut buf = Vec::new();
            arc.read_entry(i, &mut buf)
                .unwrap_or_else(|e| panic!("Darkhorse member in {name} failed to decode: {e}"));
            let mut key = String::from_utf8_lossy(en.name()).into_owned();
            if en.is_resource_fork() {
                key.push_str("/..namedfork/rsrc");
            }
            members_checked += 1;
            if theirs.get(&key) != Some(&buf) {
                members_mismatched += 1;
                eprintln!("darkhorse mismatch: {name}:{key}");
            }
        }
    }
    eprintln!(
        "darkhorse corpus: {members_checked} members checked, {members_mismatched} mismatched, \
		 {archives_unar_cant} archives unar could not parse"
    );
    assert_eq!(members_mismatched, 0, "Darkhorse output diverged from unar");
}

/// Like `cyanide_corpus_members_match_unar`, but for Iron (compression method 6,
/// 19e). If the corpus holds no Iron members, this still runs (0 checked) rather
/// than being skipped, so the "0 skipped" bar in the report is meaningful: the
/// gate is on the corpus/`unar` being available at all, not on Iron members
/// existing within it.
#[test]
fn iron_corpus_members_match_unar() {
    let Some(dir) = newtua_testutil::sitx_corpus_dir() else {
        eprintln!("skipping: NEWTUA_SITX_CORPUS not set");
        return;
    };
    if !newtua_testutil::unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }

    let mut members_checked = 0usize;
    let mut members_mismatched = 0usize;
    let mut archives_unar_cant = 0usize;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        let bytes = std::fs::read(&path).unwrap();
        if !SitxArchive::recognize(&bytes) {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();

        let arc = match SitxArchive::open(bytes.clone()) {
            Ok(a) => a,
            Err(_) => continue, // not an Iron-relevant failure; the general oracle covers this
        };
        let has_iron = arc
            .entries()
            .iter()
            .any(|e| e.compression_name().starts_with("Iron"));
        if !has_iron {
            continue;
        }

        let Some(theirs) = newtua_testutil::try_unar_extract_all(&bytes, &name) else {
            archives_unar_cant += 1;
            continue;
        };

        for (i, en) in arc.entries().iter().enumerate() {
            if en.is_directory() || !en.compression_name().starts_with("Iron") {
                continue;
            }
            let mut buf = Vec::new();
            arc.read_entry(i, &mut buf)
                .unwrap_or_else(|e| panic!("Iron member in {name} failed to decode: {e}"));
            let mut key = String::from_utf8_lossy(en.name()).into_owned();
            if en.is_resource_fork() {
                key.push_str("/..namedfork/rsrc");
            }
            members_checked += 1;
            if theirs.get(&key) != Some(&buf) {
                members_mismatched += 1;
                eprintln!("iron mismatch: {name}:{key}");
            }
        }
    }
    eprintln!(
        "iron corpus: {members_checked} members checked, {members_mismatched} mismatched, \
		 {archives_unar_cant} archives unar could not parse"
    );
    assert_eq!(members_mismatched, 0, "Iron output diverged from unar");
}

/// Like `cyanide_corpus_members_match_unar`, but for the English preprocessor
/// (`preprocessalgorithm == 0`, 19h). Unlike the other corpus tests, English is
/// a *preprocessor* layered on top of whatever compression codec the entry
/// uses, so membership is keyed on `compression_name().contains("+English")`
/// rather than a codec prefix. The corpus is not known to contain any
/// English-preprocessed members (real-world `.sitx` archives rarely use it),
/// so this test is forward-looking: it exercises the full pipeline against any
/// English members the corpus might gain, and 0 members checked is an expected,
/// passing outcome today. Only compiled with the `english-dict` feature, since
/// decoding an English member requires the embedded dictionary.
#[cfg(feature = "english-dict")]
#[test]
fn english_corpus_members_match_unar() {
    let Some(dir) = newtua_testutil::sitx_corpus_dir() else {
        eprintln!("skipping: NEWTUA_SITX_CORPUS not set");
        return;
    };
    if !newtua_testutil::unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }

    let mut members_checked = 0usize;
    let mut members_mismatched = 0usize;
    let mut archives_unar_cant = 0usize;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        let bytes = std::fs::read(&path).unwrap();
        if !SitxArchive::recognize(&bytes) {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();

        let arc = match SitxArchive::open(bytes.clone()) {
            Ok(a) => a,
            Err(_) => continue, // not an English-relevant failure; the general oracle covers this
        };
        let has_english = arc
            .entries()
            .iter()
            .any(|e| e.compression_name().contains("+English"));
        if !has_english {
            continue;
        }

        let Some(theirs) = newtua_testutil::try_unar_extract_all(&bytes, &name) else {
            archives_unar_cant += 1;
            continue;
        };

        for (i, en) in arc.entries().iter().enumerate() {
            if en.is_directory() || !en.compression_name().contains("+English") {
                continue;
            }
            let mut buf = Vec::new();
            arc.read_entry(i, &mut buf)
                .unwrap_or_else(|e| panic!("English member in {name} failed to decode: {e}"));
            let mut key = String::from_utf8_lossy(en.name()).into_owned();
            if en.is_resource_fork() {
                key.push_str("/..namedfork/rsrc");
            }
            members_checked += 1;
            if theirs.get(&key) != Some(&buf) {
                members_mismatched += 1;
                eprintln!("english mismatch: {name}:{key}");
            }
        }
    }
    eprintln!(
        "english corpus: {members_checked} members checked, {members_mismatched} mismatched, \
		 {archives_unar_cant} archives unar could not parse (forward-looking: no known English \
		 fixtures in the corpus today)"
    );
    assert_eq!(members_mismatched, 0, "English output diverged from unar");
}

/// Like `iron_corpus_members_match_unar`, but for Blend (compression method 4,
/// 19f). If the corpus holds no Blend members, this still runs (0 checked)
/// rather than being skipped, so the "0 skipped" bar in the report is
/// meaningful: the gate is on the corpus/`unar` being available at all, not on
/// Blend members existing within it.
#[test]
fn blend_corpus_members_match_unar() {
    let Some(dir) = newtua_testutil::sitx_corpus_dir() else {
        eprintln!("skipping: NEWTUA_SITX_CORPUS not set");
        return;
    };
    if !newtua_testutil::unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }

    let mut members_checked = 0usize;
    let mut members_mismatched = 0usize;
    let mut archives_unar_cant = 0usize;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        let bytes = std::fs::read(&path).unwrap();
        if !SitxArchive::recognize(&bytes) {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();

        let arc = match SitxArchive::open(bytes.clone()) {
            Ok(a) => a,
            Err(_) => continue, // not a Blend-relevant failure; the general oracle covers this
        };
        let has_blend = arc
            .entries()
            .iter()
            .any(|e| e.compression_name().starts_with("Blend"));
        if !has_blend {
            continue;
        }

        let Some(theirs) = newtua_testutil::try_unar_extract_all(&bytes, &name) else {
            archives_unar_cant += 1;
            continue;
        };

        for (i, en) in arc.entries().iter().enumerate() {
            if en.is_directory() || !en.compression_name().starts_with("Blend") {
                continue;
            }
            let mut buf = Vec::new();
            arc.read_entry(i, &mut buf)
                .unwrap_or_else(|e| panic!("Blend member in {name} failed to decode: {e}"));
            let mut key = String::from_utf8_lossy(en.name()).into_owned();
            if en.is_resource_fork() {
                key.push_str("/..namedfork/rsrc");
            }
            members_checked += 1;
            if theirs.get(&key) != Some(&buf) {
                members_mismatched += 1;
                eprintln!("blend mismatch: {name}:{key}");
            }
        }
    }
    eprintln!(
        "blend corpus: {members_checked} members checked, {members_mismatched} mismatched, \
		 {archives_unar_cant} archives unar could not parse"
    );
    assert_eq!(members_mismatched, 0, "Blend output diverged from unar");
}
