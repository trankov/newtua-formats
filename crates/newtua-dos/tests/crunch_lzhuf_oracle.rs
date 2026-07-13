// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! End-to-end oracle for the CP/M Crunch LZHUF codec (type `0xfd`, "CrLZH").
//!
//! `unar` only *decodes* Crunch, so each test builds a valid LZHUF stream with a
//! small encoder that mirrors `DecrAMPK3`'s exact adaptive-Huffman tree
//! evolution, then asserts that BOTH our crate AND the reference `unar` decode
//! it to the same bytes. `unar` is the independent check: a shared misreading of
//! the format would make `unar` disagree. Skipped when `unar` is absent.

use newtua_dos::crunch_cpm::{CrunchArchive, CrunchLzhufReader};
use newtua_testutil::{unar_extract_one, unar_installed};

// --- format constants (mirror DecrAMPK3) -----------------------------------

const THRESHOLD: usize = 2;
const LZ_N: usize = 4096;
const LZ_F: usize = 60;
const N_CHAR: usize = 256 + 1 - THRESHOLD + LZ_F; // 315
const LZ_T: usize = N_CHAR * 2 - 1; // 629
const LZ_R: usize = LZ_T - 1; // 628
const MAX_FREQ: u16 = 0x8000;
const K_INIT: usize = LZ_N - LZ_F; // 4036

// Position decode tables, copied verbatim from XADMaster (AMPK3_d_code / d_len).
#[rustfmt::skip]
const D_CODE: [u8; 256] = [
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
	3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,
	6,6,6,6,6,6,6,6,7,7,7,7,7,7,7,7,8,8,8,8,8,8,8,8,9,9,9,9,9,9,9,9,
	10,10,10,10,10,10,10,10,11,11,11,11,11,11,11,11,
	12,12,12,12,13,13,13,13,14,14,14,14,15,15,15,15,
	16,16,16,16,17,17,17,17,18,18,18,18,19,19,19,19,
	20,20,20,20,21,21,21,21,22,22,22,22,23,23,23,23,
	24,24,25,25,26,26,27,27,28,28,29,29,30,30,31,31,
	32,32,33,33,34,34,35,35,36,36,37,37,38,38,39,39,
	40,40,41,41,42,42,43,43,44,44,45,45,46,46,47,47,
	48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,
];
#[rustfmt::skip]
const D_LEN: [u8; 256] = [
	3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,
	4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,
	4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
	5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
	5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
	6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
	7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
	7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
];

// --- MSB-first bit writer ---------------------------------------------------

#[derive(Default)]
struct MsbWriter {
    bytes: Vec<u8>,
    acc: u32,
    nbits: u32,
}

impl MsbWriter {
    fn bits(&mut self, val: u32, n: u32) {
        if n == 0 {
            return;
        }
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

// --- adaptive-Huffman encoder mirroring DecrAMPK3 ---------------------------

/// Mirrors `DecrAMPK3`'s tree (`freq`/`son`/`parent`) plus the 4096-byte
/// window, so it emits exactly the codes the decoder will read back.
struct LzhufEnc {
    freq: Vec<u16>,
    son: Vec<u16>,
    parent: Vec<u16>,
    window: Vec<u8>,
    k: usize,
    bitnum: u32,
    w: MsbWriter,
    output: Vec<u8>,
}

impl LzhufEnc {
    fn new(old: bool) -> Self {
        // type = old ? 1 : 2; threshold is 2 either way, only bitnum differs.
        let bitnum = if old { 6 } else { 5 };
        let mut e = LzhufEnc {
            freq: vec![0; LZ_T + 1],
            son: vec![0; LZ_T],
            parent: vec![0; LZ_T + N_CHAR],
            window: vec![0; LZ_N],
            k: K_INIT,
            bitnum,
            w: MsbWriter::default(),
            output: Vec::new(),
        };
        for i in 0..N_CHAR {
            e.freq[i] = 1;
            e.son[i] = (LZ_T + i) as u16;
            e.parent[LZ_T + i] = i as u16;
        }
        let mut j = 0;
        for i in N_CHAR..=LZ_R {
            e.freq[i] = e.freq[j] + e.freq[j + 1];
            e.son[i] = j as u16;
            e.parent[j] = i as u16;
            e.parent[j + 1] = i as u16;
            j += 2;
        }
        e.freq[LZ_T] = MAX_FREQ;
        for b in e.window[..K_INIT].iter_mut() {
            *b = b' ';
        }
        e
    }

    fn reconstruct(&mut self) {
        let mut dst = 0usize;
        for n in 0..LZ_T {
            if self.son[n] as usize >= LZ_T {
                self.freq[dst] = (self.freq[n] + 1) >> 1;
                self.son[dst] = self.son[n];
                dst += 1;
            }
        }
        let mut n = 0usize;
        for jj in N_CHAR..LZ_T {
            let f = self.freq[n] + self.freq[n + 1];
            self.freq[jj] = f;
            let mut l = jj as i32 - 1;
            while f < self.freq[l as usize] {
                l -= 1;
            }
            l += 1;
            let lu = l as usize;
            let mut m = jj - 1;
            while m >= lu {
                self.freq[m + 1] = self.freq[m];
                self.son[m + 1] = self.son[m];
                if m == lu {
                    break;
                }
                m -= 1;
            }
            self.freq[lu] = f;
            self.son[lu] = n as u16;
            n += 2;
        }
        for n in 0..LZ_T {
            let jx = self.son[n] as usize;
            self.parent[jx] = n as u16;
            if jx < LZ_T {
                self.parent[jx + 1] = n as u16;
            }
        }
    }

    fn update(&mut self, leaf_value: usize) {
        let mut o = self.parent[leaf_value] as usize;
        loop {
            self.freq[o] += 1;
            let j = self.freq[o];
            if j > self.freq[o + 1] {
                let mut l = o + 1;
                while j > self.freq[l + 1] {
                    l += 1;
                }
                self.freq[o] = self.freq[l];
                self.freq[l] = j;
                let son_o = self.son[o] as usize;
                self.parent[son_o] = l as u16;
                if son_o < LZ_T {
                    self.parent[son_o + 1] = l as u16;
                }
                let m = self.son[l] as usize;
                self.son[l] = son_o as u16;
                self.parent[m] = o as u16;
                if m < LZ_T {
                    self.parent[m + 1] = o as u16;
                }
                self.son[o] = m as u16;
                o = l;
            }
            o = self.parent[o] as usize;
            if o == 0 {
                break;
            }
        }
    }

    /// Emit the Huffman code for symbol `sym`, then evolve the tree exactly as
    /// the decoder does after reading that symbol.
    fn put_sym(&mut self, sym: usize) {
        let mut code = 0u32;
        let mut len = 0u32;
        let mut k = self.parent[LZ_T + sym] as usize;
        loop {
            code >>= 1;
            if k & 1 != 0 {
                code |= 0x8000;
            }
            len += 1;
            k = self.parent[k] as usize;
            if k == LZ_R {
                break;
            }
        }
        self.w.bits(code >> (16 - len), len);

        if self.freq[LZ_R] == MAX_FREQ {
            self.reconstruct();
        }
        self.update(LZ_T + sym);
    }

    /// Emit a back-reference position (`pos` = distance − 1), inverting the
    /// `d_code`/`d_len` decode tables: a `d_len`-bit high-part prefix then the
    /// low `bitnum` bits raw.
    fn put_position(&mut self, pos: u32) {
        let hi = (pos >> self.bitnum) as u8;
        let l8 = D_CODE.iter().position(|&c| c == hi).expect("hi in table");
        let len = u32::from(D_LEN[l8]);
        self.w.bits((l8 as u32) >> (8 - len), len);
        self.w.bits(pos & ((1 << self.bitnum) - 1), self.bitnum);
    }

    /// Encode a literal byte.
    fn literal(&mut self, b: u8) {
        self.put_sym(b as usize);
        self.window[self.k] = b;
        self.k = (self.k + 1) & 0xFFF;
        self.output.push(b);
    }

    /// Encode a match of `len` bytes (3..=LZ_F) at back-distance `pos + 1`.
    fn matchref(&mut self, len: usize, pos: u32) {
        self.put_sym(len + (256 - THRESHOLD));
        self.put_position(pos);
        let src = (self.k as u32).wrapping_sub(pos).wrapping_sub(1);
        for j in 0..len {
            let b = self.window[((src.wrapping_add(j as u32)) & 0xFFF) as usize];
            self.window[self.k] = b;
            self.k = (self.k + 1) & 0xFFF;
            self.output.push(b);
        }
    }

    /// Emit the end-of-stream indicator and return the finished bit stream.
    fn finish(mut self) -> Vec<u8> {
        self.put_sym(0x100);
        self.w.finish()
    }
}

// --- helpers ----------------------------------------------------------------

/// Encode `data` as a literal-only LZHUF body.
fn encode_literals(data: &[u8], old: bool) -> Vec<u8> {
    let mut e = LzhufEnc::new(old);
    for &b in data {
        e.literal(b);
    }
    e.finish()
}

/// Wrap a compressed body in a Crunch file (`version2` high nibble selects the
/// old variant; `errordetection == 0` means a trailing checksum follows).
fn container(name: &str, version2: u8, errordetection: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![0x76, 0xfd];
    v.extend_from_slice(name.as_bytes());
    v.push(0);
    v.push(0x20); // version1
    v.push(version2);
    v.push(errordetection);
    v.push(0); // reserved
    v.extend_from_slice(body);
    v
}

fn with_checksum(mut file: Vec<u8>, content: &[u8]) -> Vec<u8> {
    let sum: u32 = content.iter().map(|&b| b as u32).sum();
    file.extend_from_slice(&((sum & 0xffff) as u16).to_le_bytes());
    file
}

fn decode_reader(body: &[u8], old: bool) -> Vec<u8> {
    use std::io::Read;
    let mut out = Vec::new();
    CrunchLzhufReader::new(body, old)
        .unwrap()
        .read_to_end(&mut out)
        .unwrap();
    out
}

fn ours(file: &[u8]) -> Vec<u8> {
    let arc = CrunchArchive::open(file).unwrap();
    let mut out = Vec::new();
    arc.read_entry(0, &mut out).unwrap();
    out
}

// --- Cycle 1: literals ------------------------------------------------------

#[test]
fn new_variant_literals_round_trip() {
    let data = b"Hello, CP/M LZHUF world!".to_vec();
    assert_eq!(decode_reader(&encode_literals(&data, false), false), data);
}

#[test]
fn new_variant_literals_match_unar() {
    if !unar_installed() {
        eprintln!("skipping: `unar` not installed");
        return;
    }
    let data = b"Adaptive Huffman literals decoded by the real unar.".to_vec();
    let body = encode_literals(&data, false);
    let file = container("oracle", 0x20, 1, &body);
    assert_eq!(decode_reader(&body, false), data, "decode must equal input");
    assert_eq!(
        decode_reader(&body, false),
        unar_extract_one(&file, "oracle.crlzh"),
        "our decode disagrees with unar"
    );
}

#[test]
fn tree_reconstruct_is_triggered_and_matches_unar() {
    if !unar_installed() {
        eprintln!("skipping: `unar` not installed");
        return;
    }
    // Far more than MAX_FREQ (0x8000) symbols, so the root frequency saturates
    // and the tree is rebuilt at least once — exercising the reconstruct block.
    let data: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
    let body = encode_literals(&data, false);
    let file = container("oracle", 0x20, 1, &body);
    assert_eq!(decode_reader(&body, false), data, "decode must equal input");
    assert_eq!(
        decode_reader(&body, false),
        unar_extract_one(&file, "oracle.crlzh"),
        "our decode disagrees with unar after tree reconstruct"
    );
}

// --- Cycle 2: matches (LZSS window) -----------------------------------------

#[test]
fn new_variant_self_overlapping_run_round_trip() {
    // 'A' then a length-8 match at distance 1 (pos 0): a self-overlapping run
    // that expands to nine 'A's.
    let mut e = LzhufEnc::new(false);
    e.literal(b'A');
    e.matchref(8, 0);
    assert_eq!(decode_reader(&e.finish(), false), b"AAAAAAAAA".to_vec());
}

#[test]
fn new_variant_back_copy_round_trip() {
    // Distinct literals then a length-5 match at distance 5 copies them back.
    let mut e = LzhufEnc::new(false);
    for &b in b"WORLD" {
        e.literal(b);
    }
    e.matchref(5, 4); // distance 5 → pos 4
    assert_eq!(decode_reader(&e.finish(), false), b"WORLDWORLD".to_vec());
}

// --- Cycle 3: container wiring (checksum, truncation) -----------------------

#[test]
fn container_decodes_lzhuf_member() {
    let data = b"library member via the Crunch container".to_vec();
    let file = container("member.txt", 0x20, 1, &encode_literals(&data, false));
    assert_eq!(ours(&file), data);
}

#[test]
fn container_verifies_checksum() {
    let data = b"checksummed CrLZH payload".to_vec();
    let good = with_checksum(
        container("member.txt", 0x20, 0, &encode_literals(&data, false)),
        &data,
    );
    assert_eq!(ours(&good), data);

    // Corrupt the trailing checksum: read_entry must reject it.
    let mut bad = good.clone();
    let n = bad.len();
    bad[n - 1] ^= 0xff;
    let arc = CrunchArchive::open(&bad[..]).unwrap();
    let mut out = Vec::new();
    assert!(arc.read_entry(0, &mut out).is_err());
}

#[test]
fn container_truncated_body_errors() {
    let data = b"some payload that we will cut short".to_vec();
    let mut file = container("member.txt", 0x20, 1, &encode_literals(&data, false));
    file.truncate(file.len() - 4); // drop the end indicator's bits
    let arc = CrunchArchive::open(&file[..]).unwrap();
    let mut out = Vec::new();
    assert!(arc.read_entry(0, &mut out).is_err());
}

// --- Cycle 4: full e2e oracle vs unar (matches, both variants) --------------

/// Build a payload mixing literals and back-references, returning the finished
/// LZHUF body and the exact bytes it decodes to.
fn mixed_payload(old: bool) -> (Vec<u8>, Vec<u8>) {
    let mut e = LzhufEnc::new(old);
    for &b in b"the quick brown fox " {
        e.literal(b);
    }
    e.matchref(10, 19); // repeat "the quick " (distance 20)
    for &b in b"jumps" {
        e.literal(b);
    }
    e.matchref(4, 3); // self-overlapping run from "umps"
    (e.output.clone(), e.finish())
}

#[test]
fn new_variant_matches_match_unar() {
    if !unar_installed() {
        eprintln!("skipping: `unar` not installed");
        return;
    }
    let (expected, body) = mixed_payload(false);
    let file = with_checksum(container("oracle", 0x20, 0, &body), &expected);
    assert_eq!(ours(&file), expected, "our decode must equal the input");
    assert_eq!(
        ours(&file),
        unar_extract_one(&file, "oracle.crlzh"),
        "our decode disagrees with unar"
    );
}

#[test]
fn old_variant_matches_match_unar() {
    if !unar_installed() {
        eprintln!("skipping: `unar` not installed");
        return;
    }
    let (expected, body) = mixed_payload(true);
    // version2 high nibble 0x10 selects the old variant (bitnum = 6).
    let file = with_checksum(container("oracle", 0x10, 0, &body), &expected);
    assert_eq!(
        ours(&file),
        expected,
        "our old-variant decode must equal input"
    );
    assert_eq!(
        ours(&file),
        unar_extract_one(&file, "oracle.crlzh"),
        "our old-variant decode disagrees with unar"
    );
}
