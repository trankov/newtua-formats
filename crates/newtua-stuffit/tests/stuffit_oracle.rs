// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! End-to-end oracle for the classic StuffIt container and its store / RLE90 /
//! Unix-compress / StuffIt-Huffman codecs.
//!
//! No common tool writes classic `.sit`, so — as for Compact Pro and PackIt —
//! this test assembles archives with mirror encoders (independent inverses of
//! our decoders) and checks two things:
//!
//!   1. Our own decoder round-trips every fixture (runs everywhere): store,
//!      RLE90, compress (LZW), Huffman, both forks, a nested folder, and the
//!      empty-file quirk.
//!   2. The reference `unar` decodes the same fixtures to the same fork bytes
//!      (skipped when `unar` is absent). Data forks are the extracted file; a
//!      resource fork is read through `<file>/..namedfork/rsrc`.
//!
//! All fixtures are small on purpose; in particular the LZW fixtures stay within
//! the 9-bit code width.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use newtua_common::crc16::crc16_arc;
use newtua_stuffit::stuffit::StuffItArchive;
use newtua_testutil::unar_installed;

const FILE_HEADER_SIZE: usize = 112;
const ARCHIVE_HEADER_SIZE: usize = 22;
const START_FOLDER: u8 = 0x20;
const END_FOLDER: u8 = 0x21;

// === mirror StuffIt-Huffman encoder (balanced tree) ==========================

struct BitW {
    out: Vec<u8>,
    acc: u8,
    n: u8,
}
impl BitW {
    fn new() -> Self {
        BitW {
            out: Vec::new(),
            acc: 0,
            n: 0,
        }
    }
    fn put_bit(&mut self, b: u32) {
        self.acc = (self.acc << 1) | (b as u8 & 1);
        self.n += 1;
        if self.n == 8 {
            self.out.push(self.acc);
            self.acc = 0;
            self.n = 0;
        }
    }
    fn put_bits(&mut self, val: u32, bits: u32) {
        for i in (0..bits).rev() {
            self.put_bit((val >> i) & 1);
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.acc <<= 8 - self.n;
            self.out.push(self.acc);
        }
        self.out
    }
}

fn write_tree(w: &mut BitW, symbols: &[u8]) {
    if symbols.len() == 1 {
        w.put_bit(1);
        w.put_bits(u32::from(symbols[0]), 8);
        return;
    }
    let mid = symbols.len() / 2;
    w.put_bit(0);
    write_tree(w, &symbols[..mid]);
    write_tree(w, &symbols[mid..]);
}

fn walk_codes(symbols: &[u8], prefix: u32, len: u32, codes: &mut HashMap<u8, (u32, u32)>) {
    if symbols.len() == 1 {
        codes.insert(symbols[0], (prefix, len));
        return;
    }
    let mid = symbols.len() / 2;
    walk_codes(&symbols[..mid], prefix << 1, len + 1, codes);
    walk_codes(&symbols[mid..], (prefix << 1) | 1, len + 1, codes);
}

fn huffman_encode(content: &[u8]) -> Vec<u8> {
    let mut symbols: Vec<u8> = content.to_vec();
    symbols.sort_unstable();
    symbols.dedup();
    let mut w = BitW::new();
    write_tree(&mut w, &symbols);
    let mut codes = HashMap::new();
    walk_codes(&symbols, 0, 0, &mut codes);
    for &b in content {
        let (c, l) = codes[&b];
        w.put_bits(c, l);
    }
    w.finish()
}

// === mirror Unix-compress (LZW) encoder ======================================

/// Greedy block-mode LZW mirroring `CompressReader`; fixtures stay at 9 bits.
/// The shared LSB-first [`newtua_testutil::BitWriter`] matches the reader's bit
/// order.
fn lzw_encode(input: &[u8]) -> Vec<u8> {
    let mut dict: HashMap<Vec<u8>, u32> = HashMap::new();
    for b in 0..=255u32 {
        dict.insert(vec![b as u8], b);
    }
    let mut next_code = 257u32; // 256 reserved as the block-mode clear code
    let mut bits = newtua_testutil::BitWriter::default();
    if input.is_empty() {
        return bits.finish();
    }
    let mut current = vec![input[0]];
    for &c in &input[1..] {
        let mut cand = current.clone();
        cand.push(c);
        if dict.contains_key(&cand) {
            current = cand;
        } else {
            bits.bits(dict[&current], 9);
            dict.insert(cand, next_code);
            next_code += 1;
            assert!(next_code < 512, "lzw fixture too large; width would grow");
            current = vec![c];
        }
    }
    bits.bits(dict[&current], 9);
    bits.finish()
}

// === mirror container builder =================================================

struct ForkSpec {
    method: u8,
    content: Vec<u8>,
}

fn fork(method: u8, content: &[u8]) -> ForkSpec {
    ForkSpec {
        method,
        content: content.to_vec(),
    }
}

fn compress(method: u8, content: &[u8]) -> Vec<u8> {
    match method & 0x0f {
        0 => content.to_vec(),
        1 => content.to_vec(), // RLE90 identity (no 0x90 byte)
        2 => lzw_encode(content),
        3 => huffman_encode(content),
        m => panic!("mirror builder cannot compress method {m}"),
    }
}

struct FileSpec {
    name: &'static [u8],
    rsrc: Option<ForkSpec>,
    data: Option<ForkSpec>,
}

enum Node {
    Dir(&'static [u8], Vec<Node>),
    File(FileSpec),
}

#[allow(clippy::too_many_arguments)]
fn make_header(
    rsrcmethod: u8,
    datamethod: u8,
    name: &[u8],
    rsrclength: u32,
    datalength: u32,
    rsrccomplen: u32,
    datacomplen: u32,
    rsrccrc: u16,
    datacrc: u16,
) -> Vec<u8> {
    let mut h = vec![0u8; FILE_HEADER_SIZE];
    h[0] = rsrcmethod;
    h[1] = datamethod;
    let namelen = name.len().min(31);
    h[2] = namelen as u8;
    h[3..3 + namelen].copy_from_slice(&name[..namelen]);
    h[66..70].copy_from_slice(b"TEXT");
    h[70..74].copy_from_slice(b"ttxt");
    h[84..88].copy_from_slice(&rsrclength.to_be_bytes());
    h[88..92].copy_from_slice(&datalength.to_be_bytes());
    h[92..96].copy_from_slice(&rsrccomplen.to_be_bytes());
    h[96..100].copy_from_slice(&datacomplen.to_be_bytes());
    h[100..102].copy_from_slice(&rsrccrc.to_be_bytes());
    h[102..104].copy_from_slice(&datacrc.to_be_bytes());
    let crc = crc16_arc(&h[0..110]);
    h[110..112].copy_from_slice(&crc.to_be_bytes());
    h
}

fn emit_nodes(nodes: &[Node], out: &mut Vec<u8>) {
    for node in nodes {
        match node {
            Node::Dir(name, children) => {
                out.extend_from_slice(&make_header(0, START_FOLDER, name, 0, 0, 0, 0, 0, 0));
                emit_nodes(children, out);
                out.extend_from_slice(&make_header(0, END_FOLDER, b"", 0, 0, 0, 0, 0, 0));
            }
            Node::File(f) => {
                let rcomp = f.rsrc.as_ref().map(|r| compress(r.method, &r.content));
                let dcomp = f.data.as_ref().map(|d| compress(d.method, &d.content));
                let rsrclength = f.rsrc.as_ref().map_or(0, |r| r.content.len()) as u32;
                let datalength = f.data.as_ref().map_or(0, |d| d.content.len()) as u32;
                let rsrccomplen = rcomp.as_ref().map_or(0, |c| c.len()) as u32;
                let datacomplen = dcomp.as_ref().map_or(0, |c| c.len()) as u32;
                let rsrcmethod = f.rsrc.as_ref().map_or(0, |r| r.method);
                let datamethod = f.data.as_ref().map_or(0, |d| d.method);
                let rsrccrc = f.rsrc.as_ref().map_or(0, |r| crc16_arc(&r.content));
                let datacrc = f.data.as_ref().map_or(0, |d| crc16_arc(&d.content));
                out.extend_from_slice(&make_header(
                    rsrcmethod,
                    datamethod,
                    f.name,
                    rsrclength,
                    datalength,
                    rsrccomplen,
                    datacomplen,
                    rsrccrc,
                    datacrc,
                ));
                if let Some(c) = rcomp {
                    out.extend_from_slice(&c);
                }
                if let Some(c) = dcomp {
                    out.extend_from_slice(&c);
                }
            }
        }
    }
}

fn build_archive(nodes: &[Node]) -> Vec<u8> {
    let mut out = vec![0u8; ARCHIVE_HEADER_SIZE];
    out[0..4].copy_from_slice(b"SIT!");
    out[10..14].copy_from_slice(b"rLau");
    emit_nodes(nodes, &mut out);
    let totalsize = out.len() as u32;
    out[6..10].copy_from_slice(&totalsize.to_be_bytes());
    out
}

fn our_fork(arc: &[u8], idx: usize) -> Vec<u8> {
    let a = StuffItArchive::open(arc).unwrap();
    let mut out = Vec::new();
    a.read_entry(idx, &mut out).unwrap();
    out
}

// === mirror-only round-trips (always run) ====================================

const DATA: &[u8] = b"StuffIt data fork: the quick brown fox jumps over the lazy dog.";
const RSRC: &[u8] = b"StuffIt resource fork: icon plus version data.";

#[test]
fn mirror_roundtrip_store_both_forks() {
    let arc = build_archive(&[Node::File(FileSpec {
        name: b"store",
        rsrc: Some(fork(0, RSRC)),
        data: Some(fork(0, DATA)),
    })]);
    assert!(StuffItArchive::recognize(&arc));
    assert_eq!(our_fork(&arc, 0), RSRC); // resource first
    assert_eq!(our_fork(&arc, 1), DATA);
}

#[test]
fn mirror_roundtrip_rle90() {
    let arc = build_archive(&[Node::File(FileSpec {
        name: b"rle",
        rsrc: None,
        data: Some(fork(1, DATA)),
    })]);
    assert_eq!(our_fork(&arc, 0), DATA);
}

#[test]
fn mirror_roundtrip_compress() {
    let arc = build_archive(&[Node::File(FileSpec {
        name: b"lzw",
        rsrc: None,
        data: Some(fork(2, DATA)),
    })]);
    assert_eq!(our_fork(&arc, 0), DATA);
}

#[test]
fn mirror_roundtrip_huffman() {
    let arc = build_archive(&[Node::File(FileSpec {
        name: b"huff",
        rsrc: None,
        data: Some(fork(3, DATA)),
    })]);
    assert_eq!(our_fork(&arc, 0), DATA);
}

#[test]
fn mirror_roundtrip_empty_file() {
    let arc = build_archive(&[Node::File(FileSpec {
        name: b"empty",
        rsrc: None,
        data: None,
    })]);
    let a = StuffItArchive::open(&arc[..]).unwrap();
    assert_eq!(a.entries().len(), 1);
    assert_eq!(our_fork(&arc, 0), b"");
}

#[test]
fn mirror_roundtrip_nested_folder() {
    let arc = build_archive(&[Node::Dir(
        b"folder",
        vec![Node::File(FileSpec {
            name: b"inner",
            rsrc: None,
            data: Some(fork(3, DATA)),
        })],
    )]);
    let a = StuffItArchive::open(&arc[..]).unwrap();
    assert_eq!(a.entries().len(), 2);
    assert_eq!(a.entries()[1].name(), b"folder/inner");
    assert_eq!(our_fork(&arc, 1), DATA);
}

// === unar oracle (gated) =====================================================

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("newtua_sit_{}_{}_{}", std::process::id(), n, tag));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run `unar` on `archive`, then read the extracted file at `rel` and its
/// resource named fork.
fn unar_forks(archive: &[u8], rel: &str, tag: &str) -> (Vec<u8>, Vec<u8>) {
    let dir = temp_dir(tag);
    let path = dir.join(format!("{tag}.sit"));
    fs::write(&path, archive).unwrap();

    let status = Command::new("unar")
        .args(["-quiet", "-force-overwrite", "-no-directory"])
        .arg("-output-directory")
        .arg(&dir)
        .arg(&path)
        .status()
        .expect("run unar");
    assert!(status.success(), "unar failed for {tag}");

    let out = dir.join(rel);
    let data = fs::read(&out).unwrap();
    let rsrc = fs::read(out.join("..namedfork/rsrc")).unwrap_or_default();
    let _ = fs::remove_dir_all(&dir);
    (data, rsrc)
}

#[test]
fn unar_matches_store_both_forks() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let arc = build_archive(&[Node::File(FileSpec {
        name: b"storefile",
        rsrc: Some(fork(0, RSRC)),
        data: Some(fork(0, DATA)),
    })]);
    let (data, rsrc) = unar_forks(&arc, "storefile", "store");
    assert_eq!(data, DATA);
    assert_eq!(rsrc, RSRC);
}

#[test]
fn unar_matches_rle90() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let arc = build_archive(&[Node::File(FileSpec {
        name: b"rlefile",
        rsrc: None,
        data: Some(fork(1, DATA)),
    })]);
    let (data, _rsrc) = unar_forks(&arc, "rlefile", "rle");
    assert_eq!(data, DATA);
}

#[test]
fn unar_matches_compress() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let arc = build_archive(&[Node::File(FileSpec {
        name: b"lzwfile",
        rsrc: None,
        data: Some(fork(2, DATA)),
    })]);
    let (data, _rsrc) = unar_forks(&arc, "lzwfile", "lzw");
    assert_eq!(data, DATA);
}

#[test]
fn unar_matches_huffman_both_forks() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let arc = build_archive(&[Node::File(FileSpec {
        name: b"hufffile",
        rsrc: Some(fork(3, RSRC)),
        data: Some(fork(3, DATA)),
    })]);
    let (data, rsrc) = unar_forks(&arc, "hufffile", "huff");
    assert_eq!(data, DATA);
    assert_eq!(rsrc, RSRC);
}

#[test]
fn unar_matches_nested_folder() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let arc = build_archive(&[Node::Dir(
        b"folder",
        vec![Node::File(FileSpec {
            name: b"inner",
            rsrc: None,
            data: Some(fork(0, DATA)),
        })],
    )]);
    let (data, _rsrc) = unar_forks(&arc, "folder/inner", "nested");
    assert_eq!(data, DATA);
}
