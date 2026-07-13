// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! End-to-end oracle for the CP/M Crunch container + LZW codec (type 0xfe).
//!
//! `unar` only *decodes* Crunch, so each test builds a valid stream with a
//! small encoder that mirrors the decoder's exact table/code-width evolution,
//! then asserts that BOTH our crate AND the reference `unar` decode it to the
//! same bytes. `unar` is the independent check: a shared misreading of the
//! format would make `unar` disagree. Skipped when `unar` is absent.

use newtua_dos::crunch_cpm::CrunchArchive;
use newtua_testutil::{unar_extract_one, unar_installed};

// ---------------------------------------------------------------------------
// MSB-first bit writer (Crunch reads codes most-significant-bit first).
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MsbWriter {
    bytes: Vec<u8>,
    acc: u32,
    nbits: u32,
}

impl MsbWriter {
    fn bits(&mut self, val: u32, n: u32) {
        self.acc = (self.acc << n) | (val & ((1 << n) - 1));
        self.nbits += n;
        while self.nbits >= 8 {
            self.nbits -= 8;
            self.bytes.push((self.acc >> self.nbits) as u8);
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            self.bytes.push((self.acc << (8 - self.nbits)) as u8);
        }
        self.bytes
    }
}

// ---------------------------------------------------------------------------
// Container + new-variant ("LZW 2.0") literal encoder.
// ---------------------------------------------------------------------------

/// Wrap a compressed body in a Crunch file with internal name `name`.
fn container(ctype: u8, name: &str, version2: u8, errordetection: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![0x76, ctype];
    v.extend_from_slice(name.as_bytes());
    v.push(0);
    v.push(0x20); // version1
    v.push(version2);
    v.push(errordetection);
    v.push(0); // reserved
    v.extend_from_slice(body);
    v
}

/// Encode `pre_rle` (the bytes the LZW layer must emit, before RLE90) as a
/// new-variant stream of literal codes, tracking the same `entry`/`codlen`
/// growth the decoder performs.
fn encode_new(pre_rle: &[u8]) -> Vec<u8> {
    let mut bw = MsbWriter::default();
    let mut entry: u32 = 260;
    let mut codlen: u32 = 9;
    for (i, &b) in pre_rle.iter().enumerate() {
        bw.bits(b as u32, codlen);
        if i >= 1 {
            entry += 1;
            if entry >= (1u32 << codlen) - 1 && codlen < 12 {
                codlen += 1;
            }
        }
    }
    bw.bits(0x100, codlen); // EOF
    bw.finish()
}

/// Append the 16-bit byte-sum checksum (little-endian) used when errordetection
/// is 0.
fn with_checksum(mut file: Vec<u8>, content: &[u8]) -> Vec<u8> {
    let sum: u32 = content.iter().map(|&b| b as u32).sum();
    file.extend_from_slice(&((sum & 0xffff) as u16).to_le_bytes());
    file
}

fn ours(file: &[u8]) -> Vec<u8> {
    let arc = CrunchArchive::open(file).unwrap();
    let mut out = Vec::new();
    arc.read_entry(0, &mut out).unwrap();
    out
}

#[test]
fn new_literals_with_code_width_growth_match_unar() {
    if !unar_installed() {
        eprintln!("skipping: `unar` not installed");
        return;
    }
    // ~900 bytes (no 0x90) drives `entry` past 511 and 1023, so the code width
    // grows 9→10→11 — exercising the variable-width path. RLE90 is identity.
    let content: Vec<u8> = (0..900u32).map(|i| ((i % 89) + 1) as u8).collect();
    assert!(!content.contains(&0x90));

    let file = container(0xfe, "oracle", 0x20, 1, &encode_new(&content));
    assert_eq!(ours(&file), content, "our decode must equal the input");
    assert_eq!(
        ours(&file),
        unar_extract_one(&file, "oracle.crunch"),
        "our decode disagrees with unar"
    );
}

#[test]
fn new_backreference_matches_unar() {
    if !unar_installed() {
        eprintln!("skipping: `unar` not installed");
        return;
    }
    // The hand-derived "ABAB" body emits code 260 = the freshly-entered string
    // "AB": a genuine back-reference, decoded independently of our encoder.
    let body = [0x20, 0x90, 0xA0, 0x90, 0x00];
    let file = container(0xfe, "oracle", 0x20, 1, &body);
    assert_eq!(ours(&file), b"ABAB");
    assert_eq!(ours(&file), unar_extract_one(&file, "oracle.crunch"));
}

#[test]
fn new_rle90_expansion_and_checksum_match_unar() {
    if !unar_installed() {
        eprintln!("skipping: `unar` not installed");
        return;
    }
    // Pre-RLE90 bytes 'X' 0x90 0x05 expand (type-2 RLE90) to five 'X'. This
    // cross-checks our RLE90-type-2 layer and the byte-sum checksum vs unar.
    let pre_rle = [b'X', 0x90, 0x05];
    let expanded = vec![b'X'; 5];

    let file = with_checksum(
        container(0xfe, "oracle", 0x20, 0, &encode_new(&pre_rle)),
        &expanded,
    );
    assert_eq!(ours(&file), expanded);
    assert_eq!(ours(&file), unar_extract_one(&file, "oracle.crunch"));
}

// ---------------------------------------------------------------------------
// Old-variant ("LZW 1.0") literal encoder: replicate CRUNCHenterxOLD to learn
// which fixed-12-bit code each atomic byte was assigned.
// ---------------------------------------------------------------------------

const TABLE_SIZE: usize = 4096;
const NOPRED: u16 = 0x3fff;
const EMPTY: u16 = 0x8000;

struct OldInit {
    table_pred: Vec<u16>,
    xlatbl: Vec<u16>,
}

impl OldInit {
    /// Replicates `CRUNCHenterxOLD`, returning the slot the entry landed in.
    fn enter(&mut self, pred: u16, suff: u8) -> usize {
        let mut hashval: i32 = if pred == NOPRED && suff == 0 {
            0x800
        } else {
            let a = ((i32::from(pred) + i32::from(suff)) | 0x800) & 0x1FFF;
            let h = a >> 1;
            ((h * (h + (a & 1))) >> 4) & 0xfff
        };
        while self.xlatbl[hashval as usize] != EMPTY {
            hashval = self.xlatbl[hashval as usize] as i32;
        }
        if self.table_pred[hashval as usize] != EMPTY {
            let lasthash = hashval as usize;
            hashval = (hashval + 101) & 0xfff;
            let mut a = 0;
            while self.table_pred[hashval as usize] != EMPTY && a < TABLE_SIZE as i32 {
                hashval = (hashval + 1) & 0xfff;
                a += 1;
            }
            self.xlatbl[lasthash] = hashval as u16;
        }
        self.table_pred[hashval as usize] = pred;
        hashval as usize
    }
}

/// Encode `pre_rle` as an old-variant (fixed 12-bit) stream of atomic codes.
fn encode_old(pre_rle: &[u8]) -> Vec<u8> {
    let mut init = OldInit {
        table_pred: {
            let mut t = vec![EMPTY; TABLE_SIZE];
            t[0] = NOPRED;
            t
        },
        xlatbl: vec![EMPTY; TABLE_SIZE],
    };
    let mut slot_of = [0usize; 256];
    for i in 0..256u16 {
        slot_of[i as usize] = init.enter(NOPRED, i as u8);
    }

    let mut bw = MsbWriter::default();
    for &b in pre_rle {
        bw.bits(slot_of[b as usize] as u32, 12);
    }
    bw.bits(0, 12); // old-variant EOF is code 0
    bw.finish()
}

#[test]
fn old_variant_matches_unar() {
    if !unar_installed() {
        eprintln!("skipping: `unar` not installed");
        return;
    }
    let content = b"CP/M Crunch old variant: fixed 12-bit LZW codes.".to_vec();
    assert!(!content.contains(&0x90));

    // version2 high nibble 0x10 selects the old variant.
    let file = container(0xfe, "oracle", 0x10, 1, &encode_old(&content));
    assert_eq!(
        ours(&file),
        content,
        "our old-variant decode must equal input"
    );
    assert_eq!(
        ours(&file),
        unar_extract_one(&file, "oracle.crunch"),
        "our old-variant decode disagrees with unar"
    );
}
