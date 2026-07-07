//! End-to-end oracle for classic StuffIt compression method 5 (LZAH).
//!
//! As for the other StuffIt codecs, no common tool *writes* classic `.sit`, so
//! this test assembles a one-file archive with a mirror encoder for method 5 and
//! checks two things:
//!
//!   1. Our own decoder round-trips the fixture through the real container path
//!      (`StuffItArchive::open` + `read_entry`); runs everywhere.
//!   2. The reference `unar` decodes the same archive to the same data-fork bytes
//!      (skipped when `unar` is absent). This is the real cross-check: it proves
//!      our LZAH understanding — the pre-fill pattern, the MSB bit order, the
//!      adaptive literal/length tree with its rebuild, and the static distance
//!      code — matches the reference, not merely our own inverse.
//!
//! The mirror keeps an *identical* adaptive tree, evolved in lockstep with the
//! decoder, so it emits exactly the bits the decoder reads. It is a faithful
//! copy of the machinery in `stuffit5.rs` — kept separate per the house oracle
//! convention (Compact Pro, PackIt, StuffIt, Crunch) rather than hoisted into
//! `newtua-testutil`; `unar`, not this copy, is the real cross-check.

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
const WINDOW_SIZE: usize = 4096;
const NUM_LEAVES: usize = 314;
const NUM_NODES: usize = NUM_LEAVES * 2 - 1;
const RECONSTRUCT_FREQ: i32 = 0x8000;

#[rustfmt::skip]
const DISTANCE_LENGTHS: [u32; 64] = [
    3,4,4,4,5,5,5,5,5,5,5,5,6,6,6,6,
    6,6,6,6,6,6,6,6,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
];

// === MSB-first bit writer =====================================================

#[derive(Default)]
struct MsbWriter {
    bytes: Vec<u8>,
    acc: u32,
    nbits: u32,
}

impl MsbWriter {
    fn bit(&mut self, b: bool) {
        self.acc = (self.acc << 1) | u32::from(b);
        self.nbits += 1;
        if self.nbits == 8 {
            self.bytes.push(self.acc as u8);
            self.acc = 0;
            self.nbits = 0;
        }
    }
    fn bits(&mut self, val: u32, n: u32) {
        for i in (0..n).rev() {
            self.bit((val >> i) & 1 != 0);
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            self.bytes.push((self.acc << (8 - self.nbits)) as u8);
        }
        self.bytes
    }
}

// === pre-fill pattern (resetLZSSHandle) =======================================

fn initial_window() -> Vec<u8> {
    let mut w = vec![0u8; WINDOW_SIZE];
    for i in 0..256 {
        for byte in w[i * 13 + 18..i * 13 + 18 + 13].iter_mut() {
            *byte = i as u8;
        }
    }
    for i in 0..256 {
        w[256 * 13 + 18 + i] = i as u8;
    }
    for i in 0..256 {
        w[256 * 13 + 256 + 18 + i] = (255 - i) as u8;
    }
    for byte in w[256 * 13 + 512 + 18..256 * 13 + 512 + 18 + 128].iter_mut() {
        *byte = 0;
    }
    for byte in w[256 * 13 + 512 + 128 + 18..256 * 13 + 512 + 128 + 18 + (128 - 18)].iter_mut() {
        *byte = b' ';
    }
    w
}

// === adaptive tree (mirror of AdaptiveTree in stuffit5.rs) ====================

#[derive(Default)]
struct NodeData {
    parent: Option<usize>,
    left: Option<usize>,
    right: Option<usize>,
    index: usize,
    freq: i32,
    value: i32,
}

struct AdaptiveTree {
    storage: Vec<NodeData>,
    nodes: Vec<usize>,
}

impl AdaptiveTree {
    fn new() -> Self {
        let mut storage: Vec<NodeData> = (0..NUM_NODES).map(|_| NodeData::default()).collect();
        let nodes: Vec<usize> = (0..NUM_NODES).collect();
        for i in 0..NUM_LEAVES {
            let idx = NUM_NODES - 1 - i;
            storage[idx].index = idx;
            storage[idx].freq = 1;
            storage[idx].value = i as i32;
        }
        for i in (0..=NUM_LEAVES - 2).rev() {
            storage[i].index = i;
            storage[i].left = Some(2 * i + 1);
            storage[i].right = Some(2 * i + 2);
            storage[2 * i + 1].parent = Some(i);
            storage[2 * i + 2].parent = Some(i);
            storage[i].freq = storage[2 * i + 1].freq + storage[2 * i + 2].freq;
        }
        Self { storage, nodes }
    }

    fn update_node(&mut self, mut node: usize) {
        if self.storage[0].freq == RECONSTRUCT_FREQ {
            self.reconstruct_tree();
        }
        loop {
            self.storage[node].freq += 1;
            if self.storage[node].parent.is_none() {
                break;
            }
            self.rearrange_node(node);
            node = self.storage[node].parent.unwrap();
        }
    }

    fn rearrange_node(&mut self, p: usize) {
        let p_index = self.storage[p].index;
        let p_freq = self.storage[p].freq;
        let mut q_index = p_index;
        while q_index > 0 && self.storage[self.nodes[q_index - 1]].freq < p_freq {
            q_index -= 1;
        }
        if q_index < p_index {
            let q = self.nodes[q_index];
            let pp = self.storage[p].parent.unwrap();
            let qp = self.storage[q].parent.unwrap();
            let p_is_right = self.storage[pp].right == Some(p);
            let q_is_right = self.storage[qp].right == Some(q);
            if p_is_right {
                self.storage[pp].right = Some(q);
            } else {
                self.storage[pp].left = Some(q);
            }
            if q_is_right {
                self.storage[qp].right = Some(p);
            } else {
                self.storage[qp].left = Some(p);
            }
            self.storage[p].parent = Some(qp);
            self.storage[q].parent = Some(pp);
            self.nodes[p_index] = q;
            self.storage[q].index = p_index;
            self.nodes[q_index] = p;
            self.storage[p].index = q_index;
        }
    }

    fn reconstruct_tree(&mut self) {
        let mut leafs: Vec<usize> = Vec::with_capacity(NUM_LEAVES);
        for i in 0..NUM_NODES {
            let s = self.nodes[i];
            if self.storage[s].left.is_none() && self.storage[s].right.is_none() {
                self.storage[s].freq = (self.storage[s].freq + 1) / 2;
                leafs.push(s);
            }
        }
        let mut leaf_index: i32 = NUM_LEAVES as i32 - 1;
        let mut branch_index: i32 = NUM_LEAVES as i32 - 2;
        let mut node_index: i32 = NUM_NODES as i32 - 1;
        let mut pair_index: i32 = NUM_NODES as i32 - 2;
        while node_index >= 0 {
            while node_index >= pair_index {
                let leaf = leafs[leaf_index as usize];
                self.nodes[node_index as usize] = leaf;
                self.storage[leaf].index = node_index as usize;
                node_index -= 1;
                leaf_index -= 1;
            }
            let branch = branch_index as usize;
            branch_index -= 1;
            let l = self.nodes[pair_index as usize];
            let r = self.nodes[(pair_index + 1) as usize];
            self.storage[branch].left = Some(l);
            self.storage[branch].right = Some(r);
            self.storage[l].parent = Some(branch);
            self.storage[r].parent = Some(branch);
            self.storage[branch].freq = self.storage[l].freq + self.storage[r].freq;
            while leaf_index >= 0
                && self.storage[leafs[leaf_index as usize]].freq <= self.storage[branch].freq
            {
                let leaf = leafs[leaf_index as usize];
                self.nodes[node_index as usize] = leaf;
                self.storage[leaf].index = node_index as usize;
                node_index -= 1;
                leaf_index -= 1;
            }
            self.nodes[node_index as usize] = branch;
            self.storage[branch].index = node_index as usize;
            node_index -= 1;
            pair_index -= 2;
        }
        self.storage[self.nodes[0]].parent = None;
    }
}

// === mirror encoder ===========================================================

fn distance_codes() -> HashMap<usize, (u32, u32)> {
    let mut map = HashMap::new();
    let mut code = 0u32;
    for length in 1..=8u32 {
        for (i, &len) in DISTANCE_LENGTHS.iter().enumerate() {
            if len == length {
                map.insert(i, (code, length));
                code += 1;
            }
        }
        code <<= 1;
    }
    map
}

fn encode_symbol(tree: &mut AdaptiveTree, w: &mut MsbWriter, value: i32) {
    let leaf = NUM_NODES - 1 - value as usize;
    let mut path = Vec::new();
    let mut node = leaf;
    while let Some(p) = tree.storage[node].parent {
        path.push(tree.storage[p].left == Some(node));
        node = p;
    }
    for &bit in path.iter().rev() {
        w.bit(bit);
    }
    tree.update_node(leaf);
}

#[derive(Clone, Copy)]
enum Op {
    Lit(u8),
    Match { dist: usize, len: usize },
}

fn encode(ops: &[Op]) -> Vec<u8> {
    let mut tree = AdaptiveTree::new();
    let dcodes = distance_codes();
    let mut w = MsbWriter::default();
    for op in ops {
        match *op {
            Op::Lit(b) => encode_symbol(&mut tree, &mut w, i32::from(b)),
            Op::Match { dist, len } => {
                encode_symbol(&mut tree, &mut w, (len as i32) - 3 + 0x100);
                let highbits = (dist - 1) >> 6;
                let (c, l) = dcodes[&highbits];
                w.bits(c, l);
                w.bits(((dist - 1) & 0x3f) as u32, 6);
            }
        }
    }
    w.finish()
}

fn expand(ops: &[Op]) -> Vec<u8> {
    let mut buf = initial_window();
    let mut pos = 0usize;
    let mut out = Vec::new();
    for op in ops {
        let count = match *op {
            Op::Lit(_) => 1,
            Op::Match { len, .. } => len,
        };
        for _ in 0..count {
            let byte = match *op {
                Op::Lit(b) => b,
                Op::Match { dist, .. } => buf[pos.wrapping_sub(dist) & (WINDOW_SIZE - 1)],
            };
            buf[pos & (WINDOW_SIZE - 1)] = byte;
            pos += 1;
            out.push(byte);
        }
    }
    out
}

// === single-file container builder (method-5 data fork) =======================

/// Build a one-file `.sit` whose data fork is `ops` compressed with method 5.
/// Returns the archive bytes and the expected decompressed content.
fn build_method5_sit(name: &[u8], ops: &[Op]) -> (Vec<u8>, Vec<u8>) {
    let content = expand(ops);
    let compressed = encode(ops);

    let mut h = vec![0u8; FILE_HEADER_SIZE];
    h[0] = 0; // resource method (no resource fork)
    h[1] = 5; // data method
    let namelen = name.len().min(31);
    h[2] = namelen as u8;
    h[3..3 + namelen].copy_from_slice(&name[..namelen]);
    h[66..70].copy_from_slice(b"TEXT");
    h[70..74].copy_from_slice(b"ttxt");
    h[88..92].copy_from_slice(&(content.len() as u32).to_be_bytes());
    h[96..100].copy_from_slice(&(compressed.len() as u32).to_be_bytes());
    h[102..104].copy_from_slice(&crc16_arc(&content).to_be_bytes());
    let crc = crc16_arc(&h[0..110]);
    h[110..112].copy_from_slice(&crc.to_be_bytes());

    let mut arc = vec![0u8; ARCHIVE_HEADER_SIZE];
    arc[0..4].copy_from_slice(b"SIT!");
    arc[10..14].copy_from_slice(b"rLau");
    arc.extend_from_slice(&h);
    arc.extend_from_slice(&compressed);
    let totalsize = arc.len() as u32;
    arc[6..10].copy_from_slice(&totalsize.to_be_bytes());
    (arc, content)
}

/// Ops exercising literals, a match needing distance extra bits, and an
/// overlapping run — the full method-5 path in one fixture.
fn sample_ops() -> Vec<Op> {
    let mut ops: Vec<Op> = b"abcdefgh".iter().map(|&b| Op::Lit(b)).collect();
    ops.push(Op::Match { dist: 100, len: 6 }); // reaches into the pre-fill, extra bits
    ops.push(Op::Lit(b'Z'));
    ops.push(Op::Match { dist: 1, len: 20 }); // overlapping run of 'Z'
    ops
}

fn our_fork(arc: &[u8], idx: usize) -> Vec<u8> {
    let a = StuffItArchive::open(arc).unwrap();
    let mut out = Vec::new();
    a.read_entry(idx, &mut out).unwrap();
    out
}

// === mirror round-trip (always runs) =========================================

#[test]
fn mirror_roundtrip_method5() {
    let ops = sample_ops();
    let (arc, content) = build_method5_sit(b"lzah", &ops);
    assert!(StuffItArchive::recognize(&arc));
    assert_eq!(our_fork(&arc, 0), content);
}

// === unar oracle (gated) =====================================================

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("newtua_sit5_{}_{}_{}", std::process::id(), n, tag));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn unar_data_fork(archive: &[u8], rel: &str, tag: &str) -> Vec<u8> {
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

    let data = fs::read(dir.join(rel)).unwrap();
    let _ = fs::remove_dir_all(&dir);
    data
}

#[test]
fn unar_matches_method5() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let ops = sample_ops();
    let (arc, content) = build_method5_sit(b"lzahfile", &ops);
    let data = unar_data_fork(&arc, "lzahfile", "lzah");
    assert_eq!(data, content);
}

// === tree reconstruction (large input) =======================================

/// A literal stream long enough that the root frequency saturates at
/// `0x8000` and the adaptive tree is rebuilt at least once — the only way to
/// cover `reconstruct_tree`.
fn reconstruct_ops() -> Vec<Op> {
    (0..50_000u32).map(|i| Op::Lit((i % 251) as u8)).collect()
}

#[test]
fn reconstruct_mirror_roundtrip() {
    let ops = reconstruct_ops();
    let (arc, content) = build_method5_sit(b"big", &ops);
    assert_eq!(our_fork(&arc, 0), content);
}

#[test]
fn reconstruct_matches_unar() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let ops = reconstruct_ops();
    let (arc, content) = build_method5_sit(b"bigfile", &ops);
    let data = unar_data_fork(&arc, "bigfile", "big");
    assert_eq!(data, content);
}
