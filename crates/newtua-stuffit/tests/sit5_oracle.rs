//! End-to-end oracle for the StuffIt 5 container.
//!
//! No common tool *writes* StuffIt 5, so — as for the classic StuffIt codecs —
//! this test assembles archives with a mirror container builder and checks two
//! things:
//!
//!   1. Our own parser round-trips them through the real path
//!      (`StuffIt5Archive::open` + `read_entry`); runs everywhere.
//!   2. The reference `unar` extracts the same archive to the same fork bytes —
//!      data fork as the file itself, resource fork via `<file>/..namedfork/rsrc`
//!      (skipped when `unar` is absent). This is the real cross-check on the
//!      container layout: banner, entry-tree offsets, both forks, and the
//!      method-15 CRC rule all have to match the reference, not merely our own
//!      inverse.
//!
//! The builder is a focused copy of the machinery in `sit5.rs`'s unit tests,
//! kept separate per the house oracle convention rather than hoisted into
//! `newtua-testutil`; `unar`, not this copy, is the real check. It compresses
//! forks with methods 0 (store) and 3 (StuffIt-Huffman) — enough to drive a real
//! codec through the container end to end.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use newtua_common::crc16::crc16_arc;
use newtua_stuffit::sit5::StuffIt5Archive;
use newtua_testutil::unar_installed;

const SIT5_ID: u32 = 0xA5A5_A5A5;
const HEADER_LEN: usize = 100;
const DIRECTORY: u8 = 0x40;

const BANNER: &[u8] =
    b"StuffIt (c)1997-\xFF\xFF\xFF\xFF Aladdin Systems, Inc., http://www.aladdinsys.com/StuffIt/\x0d\x0a";

// === mirror StuffIt-Huffman encoder (balanced tree) ===========================

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

fn compress(method: u8, content: &[u8]) -> Vec<u8> {
    match method & 0x0f {
        0 => content.to_vec(),
        3 => huffman_encode(content),
        m => panic!("oracle builder cannot compress method {m}"),
    }
}

// === mirror StuffIt 5 container builder =======================================

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
fn entry_prefix(
    flags: u8,
    diroffs: u32,
    namelen: usize,
    datalength: u32,
    datacomplen: u32,
    datacrc: u16,
    method_or_numfiles: u16,
) -> Vec<u8> {
    let mut h = vec![0u8; 48];
    h[0..4].copy_from_slice(&SIT5_ID.to_be_bytes());
    h[4] = 1; // version
    let headersize = (48 + namelen) as u16;
    h[6..8].copy_from_slice(&headersize.to_be_bytes());
    h[9] = flags;
    h[26..30].copy_from_slice(&diroffs.to_be_bytes());
    h[30..32].copy_from_slice(&(namelen as u16).to_be_bytes());
    h[34..38].copy_from_slice(&datalength.to_be_bytes());
    h[38..42].copy_from_slice(&datacomplen.to_be_bytes());
    h[42..44].copy_from_slice(&datacrc.to_be_bytes());
    if flags & DIRECTORY != 0 {
        h[46..48].copy_from_slice(&method_or_numfiles.to_be_bytes());
    } else {
        h[46] = method_or_numfiles as u8;
        h[47] = 0;
    }
    h
}

fn second_block(rsrc: Option<(u32, u32, u16, u8)>) -> Vec<u8> {
    let mut b = Vec::new();
    let something: u16 = if rsrc.is_some() { 0x01 } else { 0x00 };
    b.extend_from_slice(&something.to_be_bytes());
    b.extend_from_slice(&[0, 0]);
    b.extend_from_slice(b"TEXT"); // file type
    b.extend_from_slice(b"ttxt"); // creator
    b.extend_from_slice(&0u16.to_be_bytes()); // finder flags
    b.extend_from_slice(&[0u8; 22]); // version-1 filler
    if let Some((len, complen, crc, method)) = rsrc {
        b.extend_from_slice(&len.to_be_bytes());
        b.extend_from_slice(&complen.to_be_bytes());
        b.extend_from_slice(&crc.to_be_bytes());
        b.extend_from_slice(&[0, 0]);
        b.push(method);
        b.push(0);
    }
    b
}

/// CRC-16/ARC of `content`, except 0 for method 15 (Arsenic has its own CRC).
fn crc16(content: &[u8], method: u8) -> u16 {
    if method & 0x0f == 15 {
        0
    } else {
        crc16_arc(content)
    }
}

fn emit(node: &Node, parent_offs: u32, records: &mut Vec<u8>) {
    let offs = (HEADER_LEN + records.len()) as u32;
    match node {
        Node::Dir(name, children) => {
            records.extend_from_slice(&entry_prefix(
                DIRECTORY,
                parent_offs,
                name.len(),
                0,
                0,
                0,
                children.len() as u16,
            ));
            records.extend_from_slice(name);
            records.extend_from_slice(&second_block(None));
            for child in children {
                emit(child, offs, records);
            }
        }
        Node::File(f) => {
            let rcomp = f.rsrc.as_ref().map(|r| compress(r.method, &r.content));
            let dcomp = f.data.as_ref().map(|d| compress(d.method, &d.content));
            let rlen = f.rsrc.as_ref().map_or(0, |r| r.content.len()) as u32;
            let dlen = f.data.as_ref().map_or(0, |d| d.content.len()) as u32;
            let rcomplen = rcomp.as_ref().map_or(0, |c| c.len()) as u32;
            let dcomplen = dcomp.as_ref().map_or(0, |c| c.len()) as u32;
            let rmethod = f.rsrc.as_ref().map_or(0, |r| r.method);
            let dmethod = f.data.as_ref().map_or(0, |d| d.method);
            let rcrc = f.rsrc.as_ref().map_or(0, |r| crc16(&r.content, r.method));
            let dcrc = f.data.as_ref().map_or(0, |d| crc16(&d.content, d.method));

            records.extend_from_slice(&entry_prefix(
                0,
                parent_offs,
                f.name.len(),
                dlen,
                dcomplen,
                dcrc,
                dmethod as u16,
            ));
            records.extend_from_slice(f.name);
            let rsrc_desc = f.rsrc.as_ref().map(|_| (rlen, rcomplen, rcrc, rmethod));
            records.extend_from_slice(&second_block(rsrc_desc));
            if let Some(c) = rcomp {
                records.extend_from_slice(&c);
            }
            if let Some(c) = dcomp {
                records.extend_from_slice(&c);
            }
        }
    }
}

fn build_archive(nodes: &[Node]) -> Vec<u8> {
    let mut records = Vec::new();
    for node in nodes {
        emit(node, 0, &mut records);
    }
    let mut arc = vec![0u8; HEADER_LEN];
    let mut banner = BANNER.to_vec();
    for (i, b) in banner.iter_mut().enumerate() {
        if *b == 0xFF {
            *b = b"2000"[i - 16];
        }
    }
    arc[..banner.len()].copy_from_slice(&banner);
    arc[82] = 5; // version
    arc[83] = 0; // archive flags
    arc[92..94].copy_from_slice(&(nodes.len() as u16).to_be_bytes());
    arc[94..98].copy_from_slice(&(HEADER_LEN as u32).to_be_bytes());
    arc.extend_from_slice(&records);
    let totalsize = arc.len() as u32;
    arc[84..88].copy_from_slice(&totalsize.to_be_bytes());
    arc
}

/// A folder with one two-fork file (data = Huffman, resource = store) plus a
/// top-level store file — exercises the tree, both forks, and two methods.
fn sample_tree() -> Vec<Node> {
    vec![
        Node::Dir(
            b"docs",
            vec![Node::File(FileSpec {
                name: b"readme",
                data: Some(fork(3, b"huffman huffman data data data fork")),
                rsrc: Some(fork(0, b"resource fork bytes")),
            })],
        ),
        Node::File(FileSpec {
            name: b"top",
            data: Some(fork(0, b"top level store")),
            rsrc: None,
        }),
    ]
}

fn our_fork(arc: &[u8], idx: usize) -> Vec<u8> {
    let a = StuffIt5Archive::open(arc).unwrap();
    let mut out = Vec::new();
    a.read_entry(idx, &mut out).unwrap();
    out
}

// === mirror round-trip (always runs) ==========================================

#[test]
fn mirror_roundtrip_tree_both_forks() {
    let arc = build_archive(&sample_tree());
    assert!(StuffIt5Archive::recognize(&arc));
    let a = StuffIt5Archive::open(&arc[..]).unwrap();

    let names: Vec<&[u8]> = a.entries().iter().map(|e| e.name()).collect();
    assert_eq!(
        names,
        vec![
            &b"docs"[..],
            &b"docs/readme"[..], // resource fork
            &b"docs/readme"[..], // data fork
            &b"top"[..],
        ]
    );
    assert!(a.entries()[1].is_resource_fork());
    assert_eq!(our_fork(&arc, 1), b"resource fork bytes");
    assert_eq!(our_fork(&arc, 2), b"huffman huffman data data data fork");
    assert_eq!(our_fork(&arc, 3), b"top level store");
}

// === unar oracle (gated) ======================================================

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("newtua_sit5_{}_{}_{}", std::process::id(), n, tag));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn unar_matches_tree_both_forks() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let arc = build_archive(&sample_tree());
    let dir = temp_dir("tree");
    let path = dir.join("tree.sit");
    fs::write(&path, &arc).unwrap();

    let status = Command::new("unar")
        .args(["-quiet", "-force-overwrite", "-no-directory"])
        .arg("-output-directory")
        .arg(&dir)
        .arg(&path)
        .status()
        .expect("run unar");
    assert!(status.success(), "unar failed");

    // Data forks are the files themselves; the resource fork is the named fork.
    let readme = dir.join("docs/readme");
    let data = fs::read(&readme).unwrap();
    assert_eq!(data, b"huffman huffman data data data fork");

    let rsrc = fs::read(readme.join("..namedfork/rsrc")).unwrap();
    assert_eq!(rsrc, b"resource fork bytes");

    let top = fs::read(dir.join("top")).unwrap();
    assert_eq!(top, b"top level store");

    let _ = fs::remove_dir_all(&dir);
}
