// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! End-to-end oracle for the Compact Pro container and its RLE + LZH codecs.
//!
//! No common tool writes `.cpt`, so — as for Zoo, ARJ and BinHex — this test
//! assembles archives with a mirror encoder (the inverse of our decoders) and
//! checks two things:
//!
//!   1. Our own decoder round-trips every fixture (runs everywhere). This pins
//!      the encoder/decoder pair for RLE-only forks, LZH+RLE forks, both forks
//!      on one file, and a nested directory.
//!   2. The reference `unar` decodes the same fixtures to the same fork bytes
//!      (skipped when `unar` is absent). The data fork lands as the output file;
//!      the resource fork is read back from the macOS named fork
//!      (`<file>/..namedfork/rsrc`), exactly as in the MacBinary / AppleSingle
//!      oracles.
//!
//! All fixtures are small and single-block on purpose: the fragile multi-block
//! byte-alignment quirk is covered cheaply by unit tests in `compactpro.rs` that
//! drive the LZH reader directly with a tiny block size.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use newtua_common::crc32::crc32_ieee;
use newtua_mac::compactpro::CompactProArchive;
use newtua_testutil::unar_installed;

// --- mirror MSB-first bit writer ---------------------------------------------

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

// --- mirror single-block LZH encoder -----------------------------------------

#[derive(Clone)]
enum Tok {
    Lit(u8),
    #[allow(dead_code)]
    Match {
        offset: usize,
        length: usize,
    },
}

fn equal_length(k: usize) -> u32 {
    let mut l = 1u32;
    while (1usize << l) < k {
        l += 1;
    }
    l
}

fn canonical(present: &BTreeSet<u32>) -> std::collections::BTreeMap<u32, (u32, u32)> {
    let mut map = std::collections::BTreeMap::new();
    if present.is_empty() {
        return map;
    }
    let l = equal_length(present.len());
    for (code, &s) in present.iter().enumerate() {
        map.insert(s, (code as u32, l));
    }
    map
}

fn write_table(w: &mut BitW, present: &BTreeSet<u32>) {
    if present.is_empty() {
        w.put_bits(0, 8);
        return;
    }
    let max = *present.iter().max().unwrap() as usize;
    let numbytes = max / 2 + 1;
    let l = equal_length(present.len()) as u8;
    let mut lens = vec![0u8; numbytes * 2];
    for &s in present {
        lens[s as usize] = l;
    }
    w.put_bits(numbytes as u32, 8);
    for i in 0..numbytes {
        let val = (lens[2 * i] << 4) | lens[2 * i + 1];
        w.put_bits(u32::from(val), 8);
    }
}

/// Encode `tokens` as a single Compact Pro LZH block (enough for small fixtures).
fn encode_lzh(tokens: &[Tok]) -> Vec<u8> {
    let mut lit = BTreeSet::new();
    let mut len = BTreeSet::new();
    let mut off = BTreeSet::new();
    for t in tokens {
        match t {
            Tok::Lit(b) => {
                lit.insert(u32::from(*b));
            }
            Tok::Match { offset, length } => {
                len.insert(*length as u32);
                off.insert((*offset >> 6) as u32);
            }
        }
    }
    let mut w = BitW::new();
    write_table(&mut w, &lit);
    write_table(&mut w, &len);
    write_table(&mut w, &off);
    let lit_codes = canonical(&lit);
    let len_codes = canonical(&len);
    let off_codes = canonical(&off);
    for t in tokens {
        match t {
            Tok::Lit(b) => {
                w.put_bit(1);
                let (c, n) = lit_codes[&u32::from(*b)];
                w.put_bits(c, n);
            }
            Tok::Match { offset, length } => {
                w.put_bit(0);
                let (c, n) = len_codes[&(*length as u32)];
                w.put_bits(c, n);
                let (c, n) = off_codes[&((*offset >> 6) as u32)];
                w.put_bits(c, n);
                w.put_bits((*offset & 0x3f) as u32, 6);
            }
        }
    }
    w.finish()
}

// --- mirror container builder -------------------------------------------------

/// `!crc32_ieee` — the raw (un-inverted) accumulator Compact Pro stores.
fn raw_crc(x: &[u8]) -> u32 {
    !crc32_ieee(x)
}

struct Fork {
    compressed: Vec<u8>,
    content: Vec<u8>,
    lzh: bool,
}

fn rle_fork(content: &[u8]) -> Fork {
    Fork {
        compressed: content.to_vec(),
        content: content.to_vec(),
        lzh: false,
    }
}

fn lzh_fork(content: &[u8]) -> Fork {
    let toks: Vec<Tok> = content.iter().map(|&b| Tok::Lit(b)).collect();
    Fork {
        compressed: encode_lzh(&toks),
        content: content.to_vec(),
        lzh: true,
    }
}

struct File {
    name: &'static [u8],
    resource: Option<Fork>,
    data: Option<Fork>,
}

enum Node {
    Dir(&'static [u8], Vec<Node>),
    File(File),
}

fn count_nodes(nodes: &[Node]) -> usize {
    let mut n = 0;
    for node in nodes {
        n += 1;
        if let Node::Dir(_, children) = node {
            n += count_nodes(children);
        }
    }
    n
}

fn flatten(nodes: &[Node], cursor: &mut usize, body: &mut Vec<u8>, offsets: &mut Vec<usize>) {
    for node in nodes {
        match node {
            Node::Dir(_, children) => {
                offsets.push(0);
                flatten(children, cursor, body, offsets);
            }
            Node::File(f) => {
                let fileoffs = *cursor;
                if let Some(r) = &f.resource {
                    body.extend_from_slice(&r.compressed);
                    *cursor += r.compressed.len();
                }
                if let Some(d) = &f.data {
                    body.extend_from_slice(&d.compressed);
                    *cursor += d.compressed.len();
                }
                offsets.push(fileoffs);
            }
        }
    }
}

fn self_crc(f: &File) -> u32 {
    match (&f.resource, &f.data) {
        (Some(_), Some(_)) => 0,
        (Some(r), None) => raw_crc(&r.content),
        (None, Some(d)) => raw_crc(&d.content),
        (None, None) => raw_crc(b""),
    }
}

fn flags_for(f: &File) -> u16 {
    let mut flags = 0u16;
    if f.resource.as_ref().map(|r| r.lzh).unwrap_or(false) {
        flags |= 2;
    }
    if f.data.as_ref().map(|d| d.lzh).unwrap_or(false) {
        flags |= 4;
    }
    flags
}

fn emit_nodes(nodes: &[Node], offsets: &[usize], idx: &mut usize, meta: &mut Vec<u8>) {
    for node in nodes {
        match node {
            Node::Dir(name, children) => {
                *idx += 1;
                meta.push(0x80 | (name.len() as u8));
                meta.extend_from_slice(name);
                meta.extend_from_slice(&(count_nodes(children) as u16).to_be_bytes());
                emit_nodes(children, offsets, idx, meta);
            }
            Node::File(f) => {
                let fileoffs = offsets[*idx];
                *idx += 1;
                let rcomp = f.resource.as_ref().map_or(0, |r| r.compressed.len()) as u32;
                let dcomp = f.data.as_ref().map_or(0, |d| d.compressed.len()) as u32;
                let rlen = f.resource.as_ref().map_or(0, |r| r.content.len()) as u32;
                let dlen = f.data.as_ref().map_or(0, |d| d.content.len()) as u32;

                meta.push(f.name.len() as u8);
                meta.extend_from_slice(f.name);
                meta.push(0); // volume
                meta.extend_from_slice(&(fileoffs as u32).to_be_bytes());
                meta.extend_from_slice(b"TEXT"); // type
                meta.extend_from_slice(b"ttxt"); // creator
                meta.extend_from_slice(&0u32.to_be_bytes()); // creation date
                meta.extend_from_slice(&0u32.to_be_bytes()); // modification date
                meta.extend_from_slice(&0u16.to_be_bytes()); // finder flags
                meta.extend_from_slice(&self_crc(f).to_be_bytes());
                meta.extend_from_slice(&flags_for(f).to_be_bytes());
                meta.extend_from_slice(&rlen.to_be_bytes());
                meta.extend_from_slice(&dlen.to_be_bytes());
                meta.extend_from_slice(&rcomp.to_be_bytes());
                meta.extend_from_slice(&dcomp.to_be_bytes());
            }
        }
    }
}

fn build_archive(nodes: &[Node]) -> Vec<u8> {
    let mut body = Vec::new();
    let mut offsets = Vec::new();
    let mut cursor = 8usize;
    flatten(nodes, &mut cursor, &mut body, &mut offsets);

    let mut meta = Vec::new();
    meta.extend_from_slice(&(count_nodes(nodes) as u16).to_be_bytes());
    meta.push(0); // no comment
    let mut idx = 0;
    emit_nodes(nodes, &offsets, &mut idx, &mut meta);

    let catalog_offset = 8 + body.len();
    let mut out = vec![0u8; 8];
    out[0] = 1; // marker
    out[4..8].copy_from_slice(&(catalog_offset as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&raw_crc(&meta).to_be_bytes());
    out.extend_from_slice(&meta);
    out
}

fn our_fork(arc: &[u8], idx: usize) -> Vec<u8> {
    let a = CompactProArchive::open(arc).unwrap();
    let mut out = Vec::new();
    a.read_entry(idx, &mut out).unwrap();
    out
}

// --- mirror-only round-trips (always run) ------------------------------------

const DATA: &[u8] = b"Compact Pro data fork: the quick brown fox.";
const RSRC: &[u8] = b"Compact Pro resource fork: icon + version.";

#[test]
fn mirror_roundtrip_rle_only() {
    let arc = build_archive(&[Node::File(File {
        name: b"plain.txt",
        resource: None,
        data: Some(rle_fork(DATA)),
    })]);
    assert!(CompactProArchive::recognize(&arc));
    assert_eq!(our_fork(&arc, 0), DATA);
}

#[test]
fn mirror_roundtrip_lzh() {
    let content = b"abcabcabcabcabcabc-compress-me-compress-me";
    let arc = build_archive(&[Node::File(File {
        name: b"lzh.txt",
        resource: None,
        data: Some(lzh_fork(content)),
    })]);
    assert!(CompactProArchive::recognize(&arc));
    assert_eq!(our_fork(&arc, 0), content);
}

#[test]
fn mirror_roundtrip_both_forks() {
    let arc = build_archive(&[Node::File(File {
        name: b"both.txt",
        resource: Some(rle_fork(RSRC)),
        data: Some(lzh_fork(DATA)),
    })]);
    let a = CompactProArchive::open(&arc[..]).unwrap();
    assert!(a.entries()[0].is_resource_fork());
    assert!(!a.entries()[1].is_resource_fork());
    assert_eq!(our_fork(&arc, 0), RSRC);
    assert_eq!(our_fork(&arc, 1), DATA);
}

#[test]
fn mirror_roundtrip_nested_directory() {
    let arc = build_archive(&[Node::Dir(
        b"folder",
        vec![Node::File(File {
            name: b"inner.txt",
            resource: None,
            data: Some(rle_fork(DATA)),
        })],
    )]);
    let a = CompactProArchive::open(&arc[..]).unwrap();
    assert!(a.entries()[0].is_directory());
    assert_eq!(a.entries()[1].name(), b"folder/inner.txt");
    assert_eq!(our_fork(&arc, 1), DATA);
}

// --- unar oracle (gated) ------------------------------------------------------

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("newtua_cpt_{}_{}_{}", std::process::id(), n, tag));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run `unar` on `archive`, then read the extracted file at `rel` (relative path
/// under the output dir) and its resource named fork.
fn unar_forks(archive: &[u8], rel: &str, tag: &str) -> (Vec<u8>, Vec<u8>) {
    let dir = temp_dir(tag);
    let path = dir.join(format!("{tag}.cpt"));
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
fn unar_matches_both_forks() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let arc = build_archive(&[Node::File(File {
        name: b"myfile",
        resource: Some(rle_fork(RSRC)),
        data: Some(lzh_fork(DATA)),
    })]);
    let (data, rsrc) = unar_forks(&arc, "myfile", "both");
    assert_eq!(data, DATA, "unar data fork mismatch");
    assert_eq!(rsrc, RSRC, "unar resource fork mismatch");
}

#[test]
fn unar_matches_lzh_data_fork() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let content = b"LZH compressed payload, repeated repeated repeated.";
    let arc = build_archive(&[Node::File(File {
        name: b"lzhonly",
        resource: None,
        data: Some(lzh_fork(content)),
    })]);
    let (data, _rsrc) = unar_forks(&arc, "lzhonly", "lzh");
    assert_eq!(data, content, "unar LZH data fork mismatch");
}

#[test]
fn unar_matches_nested_directory() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let arc = build_archive(&[Node::Dir(
        b"folder",
        vec![Node::File(File {
            name: b"inner",
            resource: None,
            data: Some(rle_fork(DATA)),
        })],
    )]);
    let (data, _rsrc) = unar_forks(&arc, "folder/inner", "nested");
    assert_eq!(data, DATA, "unar nested data fork mismatch");
}
