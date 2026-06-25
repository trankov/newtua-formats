//! End-to-end oracle for ARC method 0x0b (Distilled).
//!
//! There is no committed `.arc` fixture for Distilled because no common tool
//! emits it; instead this test builds a valid Distilled member from a small,
//! self-contained encoder, then asserts that BOTH our crate AND the reference
//! `unar` decode it to the same bytes. `unar` is the independent check: if our
//! encoder/decoder shared a misreading of the format, `unar` would disagree.
//! Skipped when `unar` is absent.

use std::collections::BTreeMap;

use newtua_common::crc16::crc16_arc;
use newtua_dos::arc::ArcArchive;
use newtua_testutil::{unar_extract_all, unar_installed};

// ---------------------------------------------------------------------------
// Minimal Distilled encoder (test-only; mirrors XADARCDistillHandle's format).
// ---------------------------------------------------------------------------

const OFFSET_LENGTHS: [u32; 0x40] = [
    3, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, //
    6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, //
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, //
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, //
];
const OFFSET_CODES: [u32; 0x40] = [
    0x00, 0x02, 0x04, 0x0c, 0x01, 0x06, 0x0a, 0x0e, //
    0x11, 0x16, 0x1a, 0x1e, 0x05, 0x09, 0x0d, 0x15, //
    0x19, 0x1d, 0x25, 0x29, 0x2d, 0x35, 0x39, 0x3d, //
    0x03, 0x07, 0x0b, 0x13, 0x17, 0x1b, 0x23, 0x27, //
    0x2b, 0x33, 0x37, 0x3b, 0x43, 0x47, 0x4b, 0x53, //
    0x57, 0x5b, 0x63, 0x67, 0x6b, 0x73, 0x77, 0x7b, //
    0x0f, 0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x6f, 0x7f, //
    0x8f, 0x9f, 0xaf, 0xbf, 0xcf, 0xdf, 0xef, 0xff, //
];

fn extra_offset_bits(pos: u64) -> u32 {
    const BIAS: u64 = 0x3c;
    for (i, edge) in [0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000]
        .into_iter()
        .enumerate()
    {
        if pos < edge - BIAS {
            return i as u32;
        }
    }
    7
}

enum Tree {
    Leaf(i32),
    Node(Box<Tree>, Box<Tree>),
}

enum Tok {
    Lit(u8),
    Match { distance: usize, length: usize },
    End,
}

#[derive(Default)]
struct BitWriter {
    bytes: Vec<u8>,
    cur: u8,
    nbits: u8,
}

impl BitWriter {
    fn bit(&mut self, b: bool) {
        if b {
            self.cur |= 1 << self.nbits;
        }
        self.nbits += 1;
        if self.nbits == 8 {
            self.bytes.push(self.cur);
            self.cur = 0;
            self.nbits = 0;
        }
    }
    fn bits(&mut self, val: u32, n: u32) {
        for i in 0..n {
            self.bit((val >> i) & 1 != 0);
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            self.bytes.push(self.cur);
        }
        self.bytes
    }
}

fn count_internal(t: &Tree) -> usize {
    match t {
        Tree::Leaf(_) => 0,
        Tree::Node(l, r) => 1 + count_internal(l) + count_internal(r),
    }
}

fn serialise(t: &Tree) -> Vec<u32> {
    let numnodes = (2 * count_internal(t)) as u32;
    let mut pairs: Vec<[u32; 2]> = Vec::new();
    fn alloc(t: &Tree, numnodes: u32, pairs: &mut Vec<[u32; 2]>) -> u32 {
        match t {
            Tree::Leaf(v) => numnodes + *v as u32,
            Tree::Node(l, r) => {
                let lc = alloc(l, numnodes, pairs);
                let rc = alloc(r, numnodes, pairs);
                pairs.push([lc, rc]);
                ((pairs.len() - 1) * 2) as u32
            }
        }
    }
    alloc(t, numnodes, &mut pairs);
    pairs.into_iter().flatten().collect()
}

fn code_table(t: &Tree) -> BTreeMap<i32, Vec<bool>> {
    fn walk(t: &Tree, prefix: &mut Vec<bool>, map: &mut BTreeMap<i32, Vec<bool>>) {
        match t {
            Tree::Leaf(v) => {
                map.insert(*v, prefix.clone());
            }
            Tree::Node(l, r) => {
                prefix.push(false);
                walk(l, prefix, map);
                prefix.pop();
                prefix.push(true);
                walk(r, prefix, map);
                prefix.pop();
            }
        }
    }
    let mut map = BTreeMap::new();
    walk(t, &mut Vec::new(), &mut map);
    map
}

fn encode(tree: &Tree, toks: &[Tok]) -> Vec<u8> {
    let nodes = serialise(tree);
    let codes = code_table(tree);
    let maxval = *nodes.iter().max().unwrap();
    let codelength = (32 - maxval.leading_zeros()).max(1);

    let mut out = (nodes.len() as u16).to_le_bytes().to_vec();
    out.push(codelength as u8);

    let mut bw = BitWriter::default();
    for &v in &nodes {
        bw.bits(v, codelength);
    }

    let sym = |bw: &mut BitWriter, s: i32| {
        for &b in &codes[&s] {
            bw.bit(b);
        }
    };
    let mut pos = 0u64;
    for tok in toks {
        match tok {
            Tok::Lit(b) => {
                sym(&mut bw, *b as i32);
                pos += 1;
            }
            Tok::Match { distance, length } => {
                sym(&mut bw, *length as i32 - 3 + 0x101);
                let extralen = extra_offset_bits(pos);
                let v = *distance as u32 - 1;
                let offsym = (v >> extralen) as usize;
                bw.bits(OFFSET_CODES[offsym], OFFSET_LENGTHS[offsym]);
                bw.bits(v & ((1 << extralen) - 1), extralen);
                pos += *length as u64;
            }
            Tok::End => sym(&mut bw, 256),
        }
    }
    out.extend_from_slice(&bw.finish());
    out
}

/// Wrap a Distilled payload in a single-member ARC archive.
fn distilled_archive(name: &[u8], payload: &[u8], content: &[u8]) -> Vec<u8> {
    let mut e = vec![0x1A, 0x0b];
    let mut nm = [0u8; 13];
    nm[..name.len()].copy_from_slice(name);
    e.extend_from_slice(&nm);
    e.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // compressed size
    e.extend_from_slice(&[0, 0, 0, 0]); // date, time
    e.extend_from_slice(&crc16_arc(content).to_le_bytes());
    e.extend_from_slice(&(content.len() as u32).to_le_bytes()); // uncompressed size
    e.extend_from_slice(payload);
    e.extend_from_slice(&[0x1A, 0x00]); // end marker
    e
}

fn alphabet_tree(symbols: &[i32]) -> Box<Tree> {
    let mut it = symbols.iter().rev();
    let mut t = Box::new(Tree::Leaf(*it.next().unwrap()));
    for &s in it {
        t = Box::new(Tree::Node(Box::new(Tree::Leaf(s)), t));
    }
    t
}

fn ours(data: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let arc = ArcArchive::open(data).unwrap();
    let mut map = BTreeMap::new();
    for (i, entry) in arc.entries().iter().enumerate() {
        let mut out = Vec::new();
        arc.read_entry(i, &mut out).unwrap();
        map.insert(String::from_utf8(entry.name().to_vec()).unwrap(), out);
    }
    map
}

#[test]
fn distilled_member_matches_unar() {
    if !unar_installed() {
        eprintln!("skipping: `unar` not installed");
        return;
    }

    // "DISTILL " (8 bytes) then one long distance-8 match replicating it to 64
    // copies. The payload must stay well under the uncompressed size or ARC's
    // recognizer rejects it (`compsize > uncompsize`), so the content is large
    // and highly repetitive.
    const UNIT: &[u8] = b"DISTILL ";
    let content: Vec<u8> = UNIT.iter().copied().cycle().take(UNIT.len() * 64).collect();
    let match_len = content.len() - UNIT.len(); // 504
    let len_sym = match_len as i32 - 3 + 0x101;
    let tree = alphabet_tree(&[
        b'D' as i32,
        b'I' as i32,
        b'S' as i32,
        b'T' as i32,
        b'L' as i32,
        b' ' as i32,
        len_sym,
        256,
    ]);
    let mut toks: Vec<Tok> = UNIT.iter().map(|&b| Tok::Lit(b)).collect();
    toks.push(Tok::Match {
        distance: 8,
        length: match_len,
    });
    toks.push(Tok::End);

    let payload = encode(&tree, &toks);
    assert!(
        payload.len() < content.len(),
        "payload must be smaller than content"
    );
    let archive = distilled_archive(b"distill.txt", &payload, &content);

    // Our decode must equal the input content...
    let mine = ours(&archive);
    assert_eq!(
        mine.get("distill.txt").map(Vec::as_slice),
        Some(&content[..])
    );

    // ...and must agree with the independent reference decoder.
    assert_eq!(
        mine,
        unar_extract_all(&archive, "distill.arc"),
        "our distilled decode disagrees with unar"
    );
}
