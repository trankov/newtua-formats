//! End-to-end oracle for classic StuffIt compression method 13 (LZ + Huffman).
//!
//! No common tool writes classic `.sit`, so — as for the other StuffIt codecs —
//! this test assembles a one-file archive with a mirror encoder for method 13
//! and checks two things:
//!
//!   1. Our own decoder round-trips the fixture through the real container path
//!      (`StuffItArchive::open` + `read_entry`); runs everywhere.
//!   2. The reference `unar` decodes the same archive to the same data-fork
//!      bytes (skipped when `unar` is absent). This is the real cross-check: it
//!      proves our method-13 understanding — the meta-code, `parse_code`, the
//!      LZSS offset/length math and the two-context Huffman switch — matches the
//!      reference, not merely our own inverse.
//!
//! The mirror encoder uses a dynamic header (mode 0, `secondcode` shared with
//! `firstcode`) so `unar` exercises the full dynamic table path. It is a copy of
//! the one in `stuffit13.rs`'s unit tests — kept separate per the house oracle
//! convention (Compact Pro, PackIt, StuffIt) rather than hoisted into the
//! generic `newtua-testutil`; `unar`, not this copy, is the real cross-check.
//! The static tables are generated from the reference source and spot-checked,
//! so they are not re-validated here.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use newtua_common::crc16::crc16_arc;
use newtua_stuffit::stuffit::StuffItArchive;
use newtua_testutil::{unar_installed, BitWriter};

const FILE_HEADER_SIZE: usize = 112;
const ARCHIVE_HEADER_SIZE: usize = 22;
const NUM_LITERAL_SYMBOLS: usize = 321;

// === method-13 meta-code (copied from the reference, as in stuffit13.rs) ======

#[rustfmt::skip]
const META_CODES: [u32; 37] = [
    0x5d8, 0x058, 0x040, 0x0c0, 0x000, 0x078, 0x02b, 0x014,
    0x00c, 0x01c, 0x01b, 0x00b, 0x010, 0x020, 0x038, 0x018,
    0x0d8, 0xbd8, 0x180, 0x680, 0x380, 0xf80, 0x780, 0x480,
    0x080, 0x280, 0x3d8, 0xfd8, 0x7d8, 0x9d8, 0x1d8, 0x004,
    0x001, 0x002, 0x007, 0x003, 0x008,
];

#[rustfmt::skip]
const META_CODE_LENGTHS: [u32; 37] = [
    11, 8, 8, 8, 8, 7, 6, 5, 5, 5, 5,
    6, 5, 6, 7, 7, 9, 12, 10, 11, 11, 12,
    12, 11, 11, 11, 12, 12, 12, 12, 12, 5, 2,
    2, 3, 4, 5,
];

// === method-13 mirror encoder (dynamic header) ================================

fn canonical_codes(lengths: &[u32]) -> HashMap<usize, (u32, u32)> {
    let mut map = HashMap::new();
    let mut code = 0u32;
    for length in 1..=32u32 {
        for (i, &len) in lengths.iter().enumerate() {
            if len != length {
                continue;
            }
            map.insert(i, (code, length));
            code += 1;
        }
        code <<= 1;
    }
    map
}

fn write_canonical(w: &mut BitWriter, code: u32, length: u32) {
    for bitpos in (0..length).rev() {
        w.bit((code >> bitpos) & 1 != 0);
    }
}

fn write_meta(w: &mut BitWriter, sym: usize) {
    w.bits(META_CODES[sym], META_CODE_LENGTHS[sym]);
}

fn write_length_table(w: &mut BitWriter, lengths: &[u32]) {
    for &l in lengths {
        if l == 0 {
            write_meta(w, 31);
        } else {
            write_meta(w, (l - 1) as usize);
        }
    }
}

fn ceil_log2(n: usize) -> u32 {
    if n <= 1 {
        0
    } else {
        32 - (n as u32 - 1).leading_zeros()
    }
}

#[derive(Clone, Copy)]
enum Op {
    Lit(u8),
    Match { dist: usize, len: usize },
}

fn length_symbol(len: usize) -> usize {
    if len <= 64 {
        0x100 + (len - 3)
    } else if len - 65 < 1024 {
        0x13e
    } else {
        0x13f
    }
}

fn offset_fields(dist: usize) -> (usize, u32, u8) {
    match dist {
        1 => (0, 0, 0),
        2 => (1, 0, 0),
        d => {
            let x = (d - 1) as u32;
            let bl_minus_1 = 31 - x.leading_zeros();
            let extra = x - (1 << bl_minus_1);
            ((bl_minus_1 + 1) as usize, extra, bl_minus_1 as u8)
        }
    }
}

fn encode_dynamic(ops: &[Op]) -> Vec<u8> {
    let mut data_syms: Vec<usize> = Vec::new();
    let mut off_syms: Vec<usize> = Vec::new();
    for op in ops {
        match *op {
            Op::Lit(b) => data_syms.push(b as usize),
            Op::Match { dist, len } => {
                data_syms.push(length_symbol(len));
                off_syms.push(offset_fields(dist).0);
            }
        }
    }
    data_syms.sort_unstable();
    data_syms.dedup();
    off_syms.sort_unstable();
    off_syms.dedup();

    let data_bits = ceil_log2(data_syms.len()).max(1);
    let off_bits = ceil_log2(off_syms.len()).max(1);

    let mut first_lengths = vec![0u32; NUM_LITERAL_SYMBOLS];
    for &s in &data_syms {
        first_lengths[s] = data_bits;
    }
    const OFF_SIZE: usize = 17; // val & 0x07 == 7 -> 10 + 7
    let mut off_lengths = vec![0u32; OFF_SIZE];
    for &s in &off_syms {
        off_lengths[s] = off_bits;
    }

    let first_codes = canonical_codes(&first_lengths);
    let off_codes = canonical_codes(&off_lengths);

    let mut w = BitWriter::default();
    w.bits(0x0F, 8); // dynamic; share second=first; offset size 17
    write_length_table(&mut w, &first_lengths);
    write_length_table(&mut w, &off_lengths);

    for op in ops {
        match *op {
            Op::Lit(b) => {
                let (c, l) = first_codes[&(b as usize)];
                write_canonical(&mut w, c, l);
            }
            Op::Match { dist, len } => {
                let sym = length_symbol(len);
                let (c, l) = first_codes[&sym];
                write_canonical(&mut w, c, l);
                if sym == 0x13e {
                    w.bits((len - 65) as u32, 10);
                } else if sym == 0x13f {
                    w.bits((len - 65) as u32, 15);
                }
                let (osym, extra, ebits) = offset_fields(dist);
                let (oc, ol) = off_codes[&osym];
                write_canonical(&mut w, oc, ol);
                if ebits > 0 {
                    w.bits(extra, ebits as u32);
                }
            }
        }
    }
    w.finish()
}

fn expand(ops: &[Op]) -> Vec<u8> {
    let mut out = Vec::new();
    for op in ops {
        match *op {
            Op::Lit(b) => out.push(b),
            Op::Match { dist, len } => {
                for _ in 0..len {
                    let src = out.len() - dist;
                    out.push(out[src]);
                }
            }
        }
    }
    out
}

// === single-file container builder (method-13 data fork) ======================

/// Build a one-file `.sit` whose data fork is `ops` compressed with method 13.
/// Returns the archive bytes and the expected decompressed content.
fn build_method13_sit(name: &[u8], ops: &[Op]) -> (Vec<u8>, Vec<u8>) {
    let content = expand(ops);
    let compressed = encode_dynamic(ops);

    let mut h = vec![0u8; FILE_HEADER_SIZE];
    h[0] = 0; // resource method (no resource fork)
    h[1] = 13; // data method
    let namelen = name.len().min(31);
    h[2] = namelen as u8;
    h[3..3 + namelen].copy_from_slice(&name[..namelen]);
    h[66..70].copy_from_slice(b"TEXT");
    h[70..74].copy_from_slice(b"ttxt");
    // rsrclength @84 = 0, datalength @88
    h[88..92].copy_from_slice(&(content.len() as u32).to_be_bytes());
    // rsrccomplen @92 = 0, datacomplen @96
    h[96..100].copy_from_slice(&(compressed.len() as u32).to_be_bytes());
    // rsrccrc @100 = 0, datacrc @102
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

/// Ops that exercise literals, a match with offset extra bits, and an
/// overlapping run — the full dynamic method-13 path in one fixture.
fn sample_ops() -> Vec<Op> {
    let mut ops: Vec<Op> = b"abcdefgh".iter().map(|&b| Op::Lit(b)).collect();
    ops.push(Op::Match { dist: 8, len: 8 }); // copy "abcdefgh" (offset extra bits)
    ops.push(Op::Lit(b'Z'));
    ops.push(Op::Match { dist: 1, len: 12 }); // overlapping run of 'Z'
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
fn mirror_roundtrip_method13() {
    let ops = sample_ops();
    let (arc, content) = build_method13_sit(b"lzhuff", &ops);
    assert!(StuffItArchive::recognize(&arc));
    assert_eq!(our_fork(&arc, 0), content);
}

// === unar oracle (gated) =====================================================

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("newtua_sit13_{}_{}_{}", std::process::id(), n, tag));
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
fn unar_matches_method13() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let ops = sample_ops();
    let (arc, content) = build_method13_sit(b"lzhfile", &ops);
    let data = unar_data_fork(&arc, "lzhfile", "lzh");
    assert_eq!(data, content);
}
