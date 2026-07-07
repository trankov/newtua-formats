//! End-to-end oracle for classic StuffIt compression method 15 (Arsenic).
//!
//! No common tool *writes* classic `.sit`, so — as for the other StuffIt codecs
//! — this test assembles a one-file archive with a mirror encoder for method 15
//! and checks two things:
//!
//!   1. Our own decoder round-trips the fixture through the real container path
//!      (`StuffItArchive::open` + `read_entry`); runs everywhere.
//!   2. The reference `unar` decodes the same archive to the same data-fork bytes
//!      (skipped when `unar` is absent). This is the real cross-check: it proves
//!      our Arsenic understanding — the range coder, adaptive models, zero-RLE
//!      selectors, MTF, inverse BWT and final RLE — matches the reference, not
//!      merely our own inverse.
//!
//! The mirror keeps *identical* adaptive models (evolved in lockstep with the
//! decoder) and inverts the whole pipeline (`final-RLE → forward BWT →
//! MTF → zero-RLE + selectors → range encoder`). Fixtures use `randomized = 0`
//! (the encoder does not implement randomization; the decoder supports it). It is
//! a faithful copy of the machinery in `stuffit15.rs` — kept separate per the
//! house oracle convention (Compact Pro, PackIt, StuffIt, Crunch) rather than
//! hoisted into `newtua-testutil`; `unar`, not this copy, is the real check.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use newtua_common::crc16::crc16_arc;
use newtua_common::crc32::crc32_ieee;
use newtua_stuffit::stuffit::StuffItArchive;
use newtua_testutil::unar_installed;

const FILE_HEADER_SIZE: usize = 112;
const ARCHIVE_HEADER_SIZE: usize = 22;

const NUM_BITS: u32 = 26;
const ONE: u32 = 1 << (NUM_BITS - 1);
const HALF: u32 = 1 << (NUM_BITS - 2);
const TOP: u64 = 1 << NUM_BITS;

// === adaptive arithmetic model (mirror of Model in stuffit15.rs) ==============

struct Model {
    first: i32,
    increment: i32,
    frequency_limit: i32,
    total_frequency: i32,
    freqs: Vec<i32>,
}

impl Model {
    fn new(first: i32, last: i32, increment: i32, frequency_limit: i32) -> Self {
        let num = (last - first + 1) as usize;
        let mut model = Self {
            first,
            increment,
            frequency_limit,
            total_frequency: 0,
            freqs: vec![0; num],
        };
        model.reset();
        model
    }

    fn reset(&mut self) {
        self.total_frequency = self.increment * self.freqs.len() as i32;
        for f in &mut self.freqs {
            *f = self.increment;
        }
    }

    fn increase(&mut self, index: usize) {
        self.freqs[index] += self.increment;
        self.total_frequency += self.increment;
        if self.total_frequency > self.frequency_limit {
            self.total_frequency = 0;
            for f in &mut self.freqs {
                *f += 1;
                *f >>= 1;
                self.total_frequency += *f;
            }
        }
    }
}

// === carry-aware range encoder ================================================

struct ArithEncoder {
    low: u64,
    range: u32,
    bits: Vec<bool>,
}

impl ArithEncoder {
    fn new() -> Self {
        Self {
            low: 0,
            range: ONE,
            bits: Vec::new(),
        }
    }

    fn carry(&mut self) {
        let mut i = self.bits.len();
        while i > 0 {
            i -= 1;
            if !self.bits[i] {
                self.bits[i] = true;
                return;
            }
            self.bits[i] = false;
        }
        panic!("arithmetic encoder: carry past start of stream");
    }

    fn encode(&mut self, symlow: u32, symsize: u32, symtot: u32, is_last: bool) {
        let renorm_factor = self.range / symtot;
        let lowincr = renorm_factor * symlow;
        self.low += u64::from(lowincr);
        if self.low >= TOP {
            self.low -= TOP;
            self.carry();
        }
        if is_last {
            self.range -= lowincr;
        } else {
            self.range = symsize * renorm_factor;
        }
        while self.range <= HALF {
            self.bits.push((self.low >> (NUM_BITS - 1)) & 1 != 0);
            self.low = (self.low << 1) & (TOP - 1);
            self.range <<= 1;
        }
    }

    fn finish(mut self) -> Vec<u8> {
        for _ in 0..NUM_BITS {
            self.bits.push((self.low >> (NUM_BITS - 1)) & 1 != 0);
            self.low = (self.low << 1) & (TOP - 1);
        }
        let mut bytes = Vec::new();
        for chunk in self.bits.chunks(8) {
            let mut b = 0u8;
            for (k, &bit) in chunk.iter().enumerate() {
                if bit {
                    b |= 1 << (7 - k);
                }
            }
            bytes.push(b);
        }
        bytes
    }
}

fn enc_symbol(enc: &mut ArithEncoder, model: &mut Model, value: i32) {
    let n = (value - model.first) as usize;
    let cumulative: i32 = model.freqs[..n].iter().sum();
    let symsize = model.freqs[n];
    let is_last = n == model.freqs.len() - 1;
    enc.encode(
        cumulative as u32,
        symsize as u32,
        model.total_frequency as u32,
        is_last,
    );
    model.increase(n);
}

fn enc_bitstring(enc: &mut ArithEncoder, model: &mut Model, value: u32, nbits: u32) {
    for i in 0..nbits {
        enc_symbol(enc, model, ((value >> i) & 1) as i32);
    }
}

// === BWT / MTF forward transforms =============================================

fn inverse_bwt(block: &[u8]) -> Vec<u32> {
    let n = block.len();
    let mut counts = [0u32; 256];
    for &b in block {
        counts[b as usize] += 1;
    }
    let mut cumulative = [0u32; 256];
    let mut total = 0u32;
    for b in 0..256 {
        cumulative[b] = total;
        total += counts[b];
        counts[b] = 0;
    }
    let mut transform = vec![0u32; n];
    for (i, &byte) in block.iter().enumerate() {
        let b = byte as usize;
        transform[(cumulative[b] + counts[b]) as usize] = i as u32;
        counts[b] += 1;
    }
    transform
}

fn bwt_decode(block: &[u8], index: usize) -> Vec<u8> {
    let t = inverse_bwt(block);
    let mut idx = index;
    (0..block.len())
        .map(|_| {
            idx = t[idx] as usize;
            block[idx]
        })
        .collect()
}

fn forward_bwt(s: &[u8]) -> (Vec<u8>, usize) {
    let n = s.len();
    let mut rot: Vec<usize> = (0..n).collect();
    rot.sort_by(|&a, &b| {
        for k in 0..n {
            let ca = s[(a + k) % n];
            let cb = s[(b + k) % n];
            if ca != cb {
                return ca.cmp(&cb);
            }
        }
        std::cmp::Ordering::Equal
    });
    let block: Vec<u8> = rot.iter().map(|&r| s[(r + n - 1) % n]).collect();
    for idx in 0..n {
        if bwt_decode(&block, idx) == s {
            return (block, idx);
        }
    }
    panic!("forward_bwt: no index reproduces the input");
}

fn mtf_encode_block(block: &[u8]) -> Vec<usize> {
    let mut table: [u16; 256] = core::array::from_fn(|i| i as u16);
    block
        .iter()
        .map(|&b| {
            let sym = table.iter().position(|&x| x == u16::from(b)).unwrap();
            let res = table[sym];
            for i in (1..=sym).rev() {
                table[i] = table[i - 1];
            }
            table[0] = res;
            sym
        })
        .collect()
}

// === zero-RLE / selectors / final RLE =========================================

fn rle_encode(content: &[u8]) -> Vec<u8> {
    let mut s = Vec::new();
    let mut i = 0;
    while i < content.len() {
        let b = content[i];
        let mut j = i;
        while j < content.len() && content[j] == b {
            j += 1;
        }
        let mut run = j - i;
        while run > 0 {
            if run < 4 {
                for _ in 0..run {
                    s.push(b);
                }
                run = 0;
            } else {
                for _ in 0..4 {
                    s.push(b);
                }
                let l = (run - 4).min(255);
                s.push(l as u8);
                run -= 4 + l;
            }
        }
        i = j;
    }
    s
}

fn selector_for(sym: usize) -> (i32, usize) {
    match sym {
        2..=3 => (3, 0),
        4..=7 => (4, 1),
        8..=15 => (5, 2),
        16..=31 => (6, 3),
        32..=63 => (7, 4),
        64..=127 => (8, 5),
        _ => (9, 6),
    }
}

fn encode_zero_run(enc: &mut ArithEncoder, selector: &mut Model, mut z: usize) {
    while z > 0 {
        if z & 1 == 1 {
            enc_symbol(enc, selector, 0);
            z = (z - 1) / 2;
        } else {
            enc_symbol(enc, selector, 1);
            z = (z - 2) / 2;
        }
    }
}

fn encode_block_symbols(
    enc: &mut ArithEncoder,
    selector: &mut Model,
    mtfm: &mut [Model; 7],
    msyms: &[usize],
) {
    let mut i = 0;
    loop {
        let mut z = 0usize;
        while i < msyms.len() && msyms[i] == 0 {
            z += 1;
            i += 1;
        }
        if z > 0 {
            encode_zero_run(enc, selector, z);
        }
        if i == msyms.len() {
            enc_symbol(enc, selector, 10);
            break;
        }
        let sym = msyms[i];
        i += 1;
        if sym == 1 {
            enc_symbol(enc, selector, 2);
        } else {
            let (sel, k) = selector_for(sym);
            enc_symbol(enc, selector, sel);
            enc_symbol(enc, &mut mtfm[k], sym as i32);
        }
    }
}

fn encode_fork(content: &[u8]) -> Vec<u8> {
    let s = rle_encode(content);
    let (block, transformindex) = forward_bwt(&s);
    let msyms = mtf_encode_block(&block);

    let mut blockbits = 9u32;
    while (1usize << blockbits) < s.len() {
        blockbits += 1;
    }
    assert!(blockbits <= 24, "fixture too large for a single block");

    let mut enc = ArithEncoder::new();
    let mut initial = Model::new(0, 1, 1, 256);
    let mut selector = Model::new(0, 10, 8, 1024);
    let mut mtfm = [
        Model::new(2, 3, 8, 1024),
        Model::new(4, 7, 4, 1024),
        Model::new(8, 15, 4, 1024),
        Model::new(16, 31, 4, 1024),
        Model::new(32, 63, 2, 1024),
        Model::new(64, 127, 2, 1024),
        Model::new(128, 255, 1, 1024),
    ];

    enc_bitstring(&mut enc, &mut initial, u32::from(b'A'), 8);
    enc_bitstring(&mut enc, &mut initial, u32::from(b's'), 8);
    enc_bitstring(&mut enc, &mut initial, blockbits - 9, 4);
    enc_symbol(&mut enc, &mut initial, 0);

    enc_symbol(&mut enc, &mut initial, 0); // randomized = 0
    enc_bitstring(&mut enc, &mut initial, transformindex as u32, blockbits);
    encode_block_symbols(&mut enc, &mut selector, &mut mtfm, &msyms);

    selector.reset();
    for m in &mut mtfm {
        m.reset();
    }

    enc_symbol(&mut enc, &mut initial, 1); // last block
    enc_bitstring(&mut enc, &mut initial, crc32_ieee(content), 32);

    enc.finish()
}

// === single-file container builder (method-15 data fork) ======================

fn build_method15_sit(name: &[u8], content: &[u8]) -> Vec<u8> {
    let compressed = encode_fork(content);

    let mut h = vec![0u8; FILE_HEADER_SIZE];
    h[0] = 0; // resource method (no resource fork)
    h[1] = 15; // data method
    let namelen = name.len().min(31);
    h[2] = namelen as u8;
    h[3..3 + namelen].copy_from_slice(&name[..namelen]);
    h[66..70].copy_from_slice(b"TEXT");
    h[70..74].copy_from_slice(b"ttxt");
    h[88..92].copy_from_slice(&(content.len() as u32).to_be_bytes());
    h[96..100].copy_from_slice(&(compressed.len() as u32).to_be_bytes());
    h[102..104].copy_from_slice(&crc16_arc(content).to_be_bytes());
    let crc = crc16_arc(&h[0..110]);
    h[110..112].copy_from_slice(&crc.to_be_bytes());

    let mut arc = vec![0u8; ARCHIVE_HEADER_SIZE];
    arc[0..4].copy_from_slice(b"SIT!");
    arc[10..14].copy_from_slice(b"rLau");
    arc.extend_from_slice(&h);
    arc.extend_from_slice(&compressed);
    let totalsize = arc.len() as u32;
    arc[6..10].copy_from_slice(&totalsize.to_be_bytes());
    arc
}

/// A fixture that drives the whole chain: repeated English text (non-trivial
/// BWT/MTF selectors) plus a long byte run (final RLE).
fn sample_content() -> Vec<u8> {
    let mut c = Vec::new();
    for _ in 0..6 {
        c.extend_from_slice(b"the cat sat on the mat, the cat ran to the hat. ");
    }
    c.extend_from_slice(&[b'#'; 120]);
    c.extend_from_slice(b" done.");
    c
}

fn our_fork(arc: &[u8], idx: usize) -> Vec<u8> {
    let a = StuffItArchive::open(arc).unwrap();
    let mut out = Vec::new();
    a.read_entry(idx, &mut out).unwrap();
    out
}

// === mirror round-trip (always runs) =========================================

#[test]
fn mirror_roundtrip_method15() {
    let content = sample_content();
    let arc = build_method15_sit(b"arsenic", &content);
    assert!(StuffItArchive::recognize(&arc));
    assert_eq!(our_fork(&arc, 0), content);
}

// === unar oracle (gated) =====================================================

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("newtua_sit15_{}_{}_{}", std::process::id(), n, tag));
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
fn unar_matches_method15() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let content = sample_content();
    let arc = build_method15_sit(b"arsenicfile", &content);
    let data = unar_data_fork(&arc, "arsenicfile", "arsenic");
    assert_eq!(data, content);
}
