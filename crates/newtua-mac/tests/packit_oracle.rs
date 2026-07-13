// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! End-to-end oracle for the PackIt container and its StuffIt-Huffman + XOR +
//! DES codecs.
//!
//! No common tool writes `.pit`, so — as for Compact Pro, Zoo and ARJ — this
//! test assembles archives with mirror encoders (independent inverses of our
//! decoders) and checks two things:
//!
//!   1. Our own decoder round-trips every fixture (runs everywhere): plain,
//!      Huffman, XOR and DES records, both forks, the empty-file quirk, and
//!      several records back to back.
//!   2. The reference `unar` decodes the same fixtures to the same fork bytes
//!      (skipped when `unar` is absent; encrypted records via `unar -password`).
//!      Because the mirror DES here is an independent textbook implementation and
//!      `unar` decrypts with the real libdes, agreement pins our DES port from
//!      both sides.
//!
//! All fixtures are small on purpose.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use newtua_common::crc16::crc16_ccitt;
use newtua_mac::packit::PackItArchive;
use newtua_testutil::unar_installed;

const HEADER_SIZE: usize = 94;

// === mirror StuffIt-Huffman encoder ==========================================

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

fn huffman_encode(stream: &[u8]) -> Vec<u8> {
    let mut symbols: Vec<u8> = stream.to_vec();
    symbols.sort_unstable();
    symbols.dedup();
    let mut w = BitW::new();
    write_tree(&mut w, &symbols);
    let mut codes = HashMap::new();
    walk_codes(&symbols, 0, 0, &mut codes);
    for &b in stream {
        let (c, l) = codes[&b];
        w.put_bits(c, l);
    }
    w.finish()
}

// === mirror XOR encrypt (PC-1 key) ===========================================

#[rustfmt::skip]
const KEYTR1: [usize; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6,
    61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
];

fn xor_key(password: &[u8]) -> [u8; 8] {
    let mut passbuf = [0u8; 8];
    let n = password.len().min(8);
    passbuf[..n].copy_from_slice(&password[..n]);
    let mut key = [0u8; 8];
    for (i, &kt) in KEYTR1.iter().enumerate() {
        let bitindex = kt - 1;
        let bit = ((u32::from(passbuf[bitindex / 8]) << (bitindex % 8)) & 0x80) >> (i % 8);
        key[i / 8] |= bit as u8;
    }
    key
}

fn pad8(mut v: Vec<u8>) -> Vec<u8> {
    while v.len() % 8 != 0 {
        v.push(0);
    }
    v
}

fn xor_encrypt(stream: &[u8], password: &[u8]) -> Vec<u8> {
    let key = xor_key(password);
    pad8(stream.to_vec())
        .iter()
        .enumerate()
        .map(|(j, &b)| b ^ key[j % 7])
        .collect()
}

// === independent textbook DES (encrypt only) =================================

#[rustfmt::skip]
const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];
#[rustfmt::skip]
const FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];
#[rustfmt::skip]
const E: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];
#[rustfmt::skip]
const P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
];
#[rustfmt::skip]
const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
];
#[rustfmt::skip]
const PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];
const SHIFTS: [u32; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
#[rustfmt::skip]
const S: [[u8; 64]; 8] = [
    [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
     4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
    [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
     0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
    [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
     13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
    [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
     10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
    [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
     4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
    [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
     9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
    [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
     1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
    [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
     7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8, 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
];

fn permute(input: u64, table: &[u8], in_bits: u32) -> u64 {
    let mut out = 0u64;
    for &p in table {
        out = (out << 1) | ((input >> (in_bits - u32::from(p))) & 1);
    }
    out
}

fn rotl28(v: u32, c: u32) -> u32 {
    ((v << c) | (v >> (28 - c))) & 0x0fff_ffff
}

fn des_subkeys(key: &[u8; 8]) -> [u64; 16] {
    let permuted = permute(u64::from_be_bytes(*key), &PC1, 64);
    let mut c = (permuted >> 28) as u32 & 0x0fff_ffff;
    let mut d = permuted as u32 & 0x0fff_ffff;
    let mut ks = [0u64; 16];
    for (round, sk) in ks.iter_mut().enumerate() {
        c = rotl28(c, SHIFTS[round]);
        d = rotl28(d, SHIFTS[round]);
        *sk = permute((u64::from(c) << 28) | u64::from(d), &PC2, 56);
    }
    ks
}

fn feistel(r: u32, subkey: u64) -> u32 {
    let expanded = permute(u64::from(r), &E, 32) ^ subkey;
    let mut sout = 0u32;
    for (i, sbox) in S.iter().enumerate() {
        let six = ((expanded >> (42 - 6 * i)) & 0x3f) as usize;
        let row = ((six & 0x20) >> 4) | (six & 1);
        let col = (six >> 1) & 0x0f;
        sout = (sout << 4) | u32::from(sbox[row * 16 + col]);
    }
    permute(u64::from(sout), &P, 32) as u32
}

/// Encrypt one block (decrypt = false): the inverse of our reader's decrypt.
fn des_encrypt_block(block: [u8; 8], ks: &[u64; 16]) -> [u8; 8] {
    let permuted = permute(u64::from_be_bytes(block), &IP, 64);
    let mut l = (permuted >> 32) as u32;
    let mut r = permuted as u32;
    for &subkey in ks.iter() {
        let next = l ^ feistel(r, subkey);
        l = r;
        r = next;
    }
    let preoutput = (u64::from(r) << 32) | u64::from(l);
    permute(preoutput, &FP, 64).to_be_bytes()
}

fn des_encrypt(stream: &[u8], password: &[u8]) -> Vec<u8> {
    let mut key = [0u8; 8];
    let n = password.len().min(8);
    key[..n].copy_from_slice(&password[..n]);
    let ks = des_subkeys(&key);
    let padded = pad8(stream.to_vec());
    let mut out = Vec::with_capacity(padded.len());
    for chunk in padded.chunks_exact(8) {
        let block: [u8; 8] = chunk.try_into().unwrap();
        out.extend_from_slice(&des_encrypt_block(block, &ks));
    }
    out
}

// === mirror container builder =================================================

struct File {
    name: &'static [u8],
    data: Vec<u8>,
    rsrc: Vec<u8>,
}

impl File {
    fn new(name: &'static [u8], data: &[u8], rsrc: &[u8]) -> Self {
        File {
            name,
            data: data.to_vec(),
            rsrc: rsrc.to_vec(),
        }
    }
}

fn build_header(f: &File) -> Vec<u8> {
    let mut h = vec![0u8; HEADER_SIZE];
    let namelen = f.name.len().min(63);
    h[0] = namelen as u8;
    h[1..1 + namelen].copy_from_slice(&f.name[..namelen]);
    h[64..68].copy_from_slice(b"TEXT");
    h[68..72].copy_from_slice(b"ttxt");
    h[76..80].copy_from_slice(&(f.data.len() as u32).to_be_bytes());
    h[80..84].copy_from_slice(&(f.rsrc.len() as u32).to_be_bytes());
    h
}

fn build_stream(f: &File) -> Vec<u8> {
    let mut s = build_header(f);
    s.extend_from_slice(&f.data);
    s.extend_from_slice(&f.rsrc);
    let mut forks = f.data.clone();
    forks.extend_from_slice(&f.rsrc);
    s.extend_from_slice(&crc16_ccitt(&forks).to_be_bytes());
    s
}

fn record_pmag(f: &File) -> Vec<u8> {
    let mut r = b"PMag".to_vec();
    r.extend_from_slice(&build_stream(f));
    r
}
fn record_pma4(f: &File) -> Vec<u8> {
    let mut r = b"PMa4".to_vec();
    r.extend_from_slice(&huffman_encode(&build_stream(f)));
    r
}
fn record_pma5(f: &File, pw: &[u8]) -> Vec<u8> {
    let mut r = b"PMa5".to_vec();
    r.extend_from_slice(&xor_encrypt(&huffman_encode(&build_stream(f)), pw));
    r
}
fn record_pma6(f: &File, pw: &[u8]) -> Vec<u8> {
    let mut r = b"PMa6".to_vec();
    r.extend_from_slice(&des_encrypt(&huffman_encode(&build_stream(f)), pw));
    r
}

fn archive(records: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for r in records {
        out.extend_from_slice(r);
    }
    out.extend_from_slice(b"PEnd");
    out
}

fn our_fork(arc: &[u8], idx: usize, password: Option<&[u8]>) -> Vec<u8> {
    let a = match password {
        Some(pw) => PackItArchive::open_with_password(arc, pw).unwrap(),
        None => PackItArchive::open(arc).unwrap(),
    };
    let mut out = Vec::new();
    a.read_entry(idx, &mut out).unwrap();
    out
}

// === mirror-only round-trips (always run) ====================================

const DATA: &[u8] = b"PackIt data fork: the quick brown fox jumps.";
const RSRC: &[u8] = b"PackIt resource fork: icon + version data.";

#[test]
fn mirror_roundtrip_pmag_both_forks() {
    let arc = archive(&[record_pmag(&File::new(b"plain", DATA, RSRC))]);
    assert!(PackItArchive::recognize(&arc));
    assert_eq!(our_fork(&arc, 0, None), DATA);
    assert_eq!(our_fork(&arc, 1, None), RSRC);
}

#[test]
fn mirror_roundtrip_pma4() {
    let arc = archive(&[record_pma4(&File::new(b"huff", DATA, RSRC))]);
    assert_eq!(our_fork(&arc, 0, None), DATA);
    assert_eq!(our_fork(&arc, 1, None), RSRC);
}

#[test]
fn mirror_roundtrip_pma5_xor() {
    let pw = b"xorpass";
    let arc = archive(&[record_pma5(&File::new(b"xor", DATA, RSRC), pw)]);
    assert_eq!(our_fork(&arc, 0, Some(pw)), DATA);
    assert_eq!(our_fork(&arc, 1, Some(pw)), RSRC);
}

#[test]
fn mirror_roundtrip_pma6_des() {
    let pw = b"despass1";
    let arc = archive(&[record_pma6(&File::new(b"des", DATA, RSRC), pw)]);
    assert_eq!(our_fork(&arc, 0, Some(pw)), DATA);
    assert_eq!(our_fork(&arc, 1, Some(pw)), RSRC);
}

#[test]
fn mirror_roundtrip_empty_file() {
    let arc = archive(&[record_pmag(&File::new(b"empty", b"", b""))]);
    let a = PackItArchive::open(&arc[..]).unwrap();
    assert_eq!(a.entries().len(), 1);
    assert!(!a.entries()[0].is_resource_fork());
    assert_eq!(our_fork(&arc, 0, None), b"");
}

#[test]
fn mirror_roundtrip_multiple_records() {
    let pw = b"mixpass";
    let arc = archive(&[
        record_pmag(&File::new(b"a", b"alpha", b"")),
        record_pma4(&File::new(b"b", b"bravo bravo bravo", b"")),
        record_pma6(&File::new(b"c", b"charlie payload", b"cres"), pw),
    ]);
    let a = PackItArchive::open_with_password(&arc[..], pw).unwrap();
    assert_eq!(a.entries().len(), 4);
    assert_eq!(our_fork(&arc, 0, Some(pw)), b"alpha");
    assert_eq!(our_fork(&arc, 1, Some(pw)), b"bravo bravo bravo");
    assert_eq!(our_fork(&arc, 2, Some(pw)), b"charlie payload");
    assert_eq!(our_fork(&arc, 3, Some(pw)), b"cres");
}

// === unar oracle (gated) =====================================================

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("newtua_pit_{}_{}_{}", std::process::id(), n, tag));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run `unar` on `archive` (with an optional password), then read the extracted
/// file at `rel` and its resource named fork.
fn unar_forks(archive: &[u8], rel: &str, tag: &str, password: Option<&str>) -> (Vec<u8>, Vec<u8>) {
    let dir = temp_dir(tag);
    let path = dir.join(format!("{tag}.pit"));
    fs::write(&path, archive).unwrap();

    let mut cmd = Command::new("unar");
    cmd.args(["-quiet", "-force-overwrite", "-no-directory"]);
    if let Some(pw) = password {
        cmd.arg("-password").arg(pw);
    }
    cmd.arg("-output-directory").arg(&dir).arg(&path);
    let status = cmd.status().expect("run unar");
    assert!(status.success(), "unar failed for {tag}");

    let out = dir.join(rel);
    let data = fs::read(&out).unwrap();
    let rsrc = fs::read(out.join("..namedfork/rsrc")).unwrap_or_default();
    let _ = fs::remove_dir_all(&dir);
    (data, rsrc)
}

#[test]
fn unar_matches_pmag_both_forks() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let arc = archive(&[record_pmag(&File::new(b"plainfile", DATA, RSRC))]);
    let (data, rsrc) = unar_forks(&arc, "plainfile", "pmag", None);
    assert_eq!(data, DATA);
    assert_eq!(rsrc, RSRC);
}

#[test]
fn unar_matches_pma4_huffman() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let arc = archive(&[record_pma4(&File::new(b"hufffile", DATA, RSRC))]);
    let (data, rsrc) = unar_forks(&arc, "hufffile", "pma4", None);
    assert_eq!(data, DATA);
    assert_eq!(rsrc, RSRC);
}

#[test]
fn unar_matches_pma5_xor() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let pw = "xorpass";
    let arc = archive(&[record_pma5(
        &File::new(b"xorfile", DATA, RSRC),
        pw.as_bytes(),
    )]);
    let (data, rsrc) = unar_forks(&arc, "xorfile", "pma5", Some(pw));
    assert_eq!(data, DATA, "unar XOR data fork mismatch");
    assert_eq!(rsrc, RSRC, "unar XOR resource fork mismatch");
}

#[test]
fn unar_matches_pma6_des() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    // This is the real cross-check of our DES against libdes.
    let pw = "despass1";
    let arc = archive(&[record_pma6(
        &File::new(b"desfile", DATA, RSRC),
        pw.as_bytes(),
    )]);
    let (data, rsrc) = unar_forks(&arc, "desfile", "pma6", Some(pw));
    assert_eq!(data, DATA, "unar DES data fork mismatch");
    assert_eq!(rsrc, RSRC, "unar DES resource fork mismatch");
}
