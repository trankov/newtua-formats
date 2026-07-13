// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! End-to-end oracle for the BinHex 4.0 container and its three-layer codec
//! (hqx 6->8, then RLE90).
//!
//! Fixtures are assembled by a mirror encoder (the inverse of our decoder):
//! build the decoded stream (header + CRCs + both forks + CRCs), RLE90-encode
//! it, hqx-encode that, and wrap it in the ASCII envelope. The mirror-only
//! assertions pin our encoder/decoder pair and run everywhere.
//!
//! Two independent oracles cross-check our reading of the real format:
//!   * `unar` — decodes our fixtures and must yield the same fork bytes. The
//!     data fork lands as the output file; the resource fork is read back from
//!     the macOS named fork (`<file>/..namedfork/rsrc`). Skipped when `unar` is
//!     absent.
//!   * Apple's `/usr/bin/binhex` — a third-party *encoder*. It produces a real
//!     `.hqx` from a data fork that our crate must decode back unchanged.
//!     Skipped when the tool is absent.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use newtua_mac::binhex::BinHexArchive;
use newtua_testutil::unar_installed;

// --- mirror encoder -----------------------------------------------------------

const ALPHABET: &[u8] = b"!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr";

fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// RLE90-encode: runs of >=2 identical bytes become `b 0x90 count`; a literal
/// `0x90` becomes `0x90 0x00`.
fn rle90_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        let mut run = 1;
        while i + run < data.len() && data[i + run] == b && run < 255 {
            run += 1;
        }
        if b == 0x90 {
            out.extend_from_slice(&[0x90, 0x00]);
        } else {
            out.push(b);
        }
        if run >= 2 {
            out.extend_from_slice(&[0x90, run as u8]);
        }
        i += run;
    }
    out
}

/// Pack bytes into 6-bit codes rendered as alphabet characters.
fn hqx_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let sym = |v: u8| ALPHABET[v as usize];
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        out.push(sym(b0 >> 2));
        match (chunk.get(1), chunk.get(2)) {
            (Some(&b1), Some(&b2)) => {
                out.push(sym(((b0 & 3) << 4) | (b1 >> 4)));
                out.push(sym(((b1 & 0xF) << 2) | (b2 >> 6)));
                out.push(sym(b2 & 0x3F));
            }
            (Some(&b1), None) => {
                out.push(sym(((b0 & 3) << 4) | (b1 >> 4)));
                out.push(sym((b1 & 0xF) << 2));
            }
            (None, _) => {
                out.push(sym((b0 & 3) << 4));
            }
        }
    }
    out
}

fn build_hqx(
    name: &[u8],
    ftype: &[u8; 4],
    creator: &[u8; 4],
    flags: u16,
    data: &[u8],
    resource: &[u8],
) -> Vec<u8> {
    let mut header = Vec::new();
    header.push(name.len() as u8);
    header.extend_from_slice(name);
    header.push(0); // version
    header.extend_from_slice(ftype);
    header.extend_from_slice(creator);
    header.extend_from_slice(&flags.to_be_bytes());
    header.extend_from_slice(&(data.len() as u32).to_be_bytes());
    header.extend_from_slice(&(resource.len() as u32).to_be_bytes());

    let mut stream = header.clone();
    stream.extend_from_slice(&crc16_ccitt(&header).to_be_bytes());
    stream.extend_from_slice(data);
    stream.extend_from_slice(&crc16_ccitt(data).to_be_bytes());
    stream.extend_from_slice(resource);
    stream.extend_from_slice(&crc16_ccitt(resource).to_be_bytes());

    let mut out = Vec::new();
    out.extend_from_slice(b"(This file must be converted with BinHex 4.0)\r\n:");
    out.extend_from_slice(&hqx_encode(&rle90_encode(&stream)));
    out.push(b':');
    out
}

fn our_fork(hqx: &[u8], idx: usize) -> Vec<u8> {
    let arc = BinHexArchive::open(hqx).unwrap();
    let mut out = Vec::new();
    arc.read_entry(idx, &mut out).unwrap();
    out
}

// --- test fixtures ------------------------------------------------------------

/// A data fork with no runs and no `0x90`, so the RLE90 layer is a pass-through.
const PLAIN_DATA: &[u8] = b"The quick brown fox jumps over the lazy dog. 0123456789";
const PLAIN_RSRC: &[u8] = b"resource: icon, version, finder bits";

/// A fork that forces the RLE90 layer to work: a long run, a literal `0x90`,
/// then another run of a different byte.
fn rle_data() -> Vec<u8> {
    let mut v = vec![b'A'; 40];
    v.push(0x90); // literal marker byte -> 0x90 0x00
    v.extend_from_slice(b"middle");
    v.extend(std::iter::repeat(0x42).take(17));
    v.push(0x90);
    v.push(0x90); // a run of two 0x90 -> 0x90 0x00, 0x90 0x02
    v
}

// --- mirror-only assertions (always run) --------------------------------------

#[test]
fn mirror_roundtrip_plain() {
    let hqx = build_hqx(b"plain.txt", b"TEXT", b"ttxt", 0, PLAIN_DATA, PLAIN_RSRC);
    assert_eq!(our_fork(&hqx, 0), PLAIN_DATA);
    assert_eq!(our_fork(&hqx, 1), PLAIN_RSRC);
}

#[test]
fn mirror_roundtrip_with_rle() {
    let data = rle_data();
    let resource = {
        let mut r = vec![0x90, 0x00];
        r.extend(std::iter::repeat(b'Z').take(30));
        r
    };
    let hqx = build_hqx(b"rle.bin", b"BINA", b"____", 0, &data, &resource);
    assert_eq!(our_fork(&hqx, 0), data);
    assert_eq!(our_fork(&hqx, 1), resource);
}

// --- unar oracle (gated) ------------------------------------------------------

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "newtua_binhex_{}_{}_{}",
        std::process::id(),
        n,
        tag
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run `unar` on `hqx` and return the data fork (the output file) and the
/// resource fork (read from the macOS named fork), keyed by the BinHex
/// internal `name`.
fn unar_forks(hqx: &[u8], name: &str, tag: &str) -> (Vec<u8>, Vec<u8>) {
    let dir = temp_dir(tag);
    let archive = dir.join(format!("{tag}.hqx"));
    fs::write(&archive, hqx).unwrap();

    let status = Command::new("unar")
        .args(["-quiet", "-force-overwrite", "-no-directory"])
        .arg("-output-directory")
        .arg(&dir)
        .arg(&archive)
        .status()
        .expect("run unar");
    assert!(status.success(), "unar failed for {tag}");

    let file = dir.join(name);
    let data = fs::read(&file).unwrap();
    let rsrc_path = file.join("..namedfork/rsrc");
    let rsrc = fs::read(&rsrc_path).unwrap_or_default();

    let _ = fs::remove_dir_all(&dir);
    (data, rsrc)
}

#[test]
fn unar_matches_plain() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let hqx = build_hqx(b"plain.txt", b"TEXT", b"ttxt", 0, PLAIN_DATA, PLAIN_RSRC);
    let (data, rsrc) = unar_forks(&hqx, "plain.txt", "plain");
    assert_eq!(data, PLAIN_DATA, "unar data fork mismatch");
    assert_eq!(rsrc, PLAIN_RSRC, "unar resource fork mismatch");
}

#[test]
fn unar_matches_with_rle() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let data = rle_data();
    let resource = {
        let mut r = vec![0x90, 0x00];
        r.extend(std::iter::repeat(b'Z').take(30));
        r
    };
    let hqx = build_hqx(b"rle.bin", b"BINA", b"____", 0, &data, &resource);
    let (got_data, got_rsrc) = unar_forks(&hqx, "rle.bin", "rle");
    assert_eq!(got_data, data, "unar data fork mismatch (RLE)");
    assert_eq!(got_rsrc, resource, "unar resource fork mismatch (RLE)");
}

// --- Apple binhex oracle: independent third-party ENCODER (gated) -------------

fn apple_binhex() -> Option<&'static str> {
    let path = "/usr/bin/binhex";
    if Path::new(path).exists() {
        Some(path)
    } else {
        None
    }
}

#[test]
fn decodes_real_apple_binhex_output() {
    let Some(binhex) = apple_binhex() else {
        eprintln!("skipping: /usr/bin/binhex not present");
        return;
    };

    let dir = temp_dir("apple");
    let src = dir.join("greeting.txt");
    let payload = b"Encoded by Apple's binhex, decoded by newtua-mac.\nLine 2.\n";
    fs::write(&src, payload).unwrap();

    let out = dir.join("greeting.hqx");
    // The output path is in a fresh temp dir, so no -force/overwrite is needed
    // (and this build of binhex rejects -f).
    let status = Command::new(binhex)
        .arg("encode")
        .arg("-o")
        .arg(&out)
        .arg(&src)
        .status()
        .expect("run binhex encode");
    assert!(status.success(), "binhex encode failed");

    let hqx = fs::read(&out).unwrap();
    assert!(
        BinHexArchive::recognize(&hqx),
        "did not recognise Apple .hqx"
    );

    let arc = BinHexArchive::open(&hqx[..]).unwrap();
    let mut decoded = Vec::new();
    arc.read_entry(0, &mut decoded).unwrap();
    assert_eq!(decoded, payload, "decoded data fork != original");

    let _ = fs::remove_dir_all(&dir);
}
