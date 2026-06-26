//! End-to-end oracle for the ARJ container and its LZH-static codec.
//!
//! No common tool writes `.arj` on this machine (`arj` is absent), so this test
//! assembles archives from a small builder plus a mirror LZH-static encoder
//! (15-bit window, so the distance code's symbol-count field is 5 bits wide),
//! then asserts that BOTH our crate AND the reference `unar` decode them to the
//! same bytes. `unar` is the independent check that our reading of the format
//! (and the CRC-32 it verifies) is correct. The non-`unar` assertions still run
//! everywhere and pin the encoder/decoder pair. Skipped against `unar` when it
//! is absent.

use std::collections::{BTreeMap, BTreeSet};

use newtua_common::crc32::crc32_ieee;
use newtua_dos::arj::ArjArchive;
use newtua_testutil::{unar_extract_all, unar_installed};

// --- mirror LZH-static encoder (window 15) ------------------------------------

#[derive(Clone)]
enum Tok {
    Lit(u8),
    Match { len: usize, dist: usize },
}

/// MSB-first bit writer, matching `BitReaderMsb`'s bit order.
struct BitW {
    out: Vec<u8>,
    acc: u32,
    n: u32,
}

impl BitW {
    fn new() -> Self {
        BitW {
            out: Vec::new(),
            acc: 0,
            n: 0,
        }
    }
    fn put(&mut self, val: u32, bits: u32) {
        for i in (0..bits).rev() {
            self.acc = (self.acc << 1) | ((val >> i) & 1);
            self.n += 1;
            if self.n == 8 {
                self.out.push(self.acc as u8);
                self.acc = 0;
                self.n = 0;
            }
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push((self.acc << (8 - self.n)) as u8);
        }
        self.out
    }
}

/// Equal-length canonical code lengths over the present symbol set (`L =
/// ceil(log2(k))`), sized to `max+1` with absent symbols at length 0.
fn fixed_lengths(present: &BTreeSet<u32>) -> Vec<u32> {
    if present.is_empty() {
        return Vec::new();
    }
    let max = *present.iter().max().unwrap();
    let k = present.len();
    let mut l = 1u32;
    while (1 << l) < k {
        l += 1;
    }
    let mut lengths = vec![0u32; (max + 1) as usize];
    for &s in present {
        lengths[s as usize] = l;
    }
    lengths
}

/// Canonical (code, length) per symbol, identical to `PrefixCode::from_lengths`
/// with `shortest_code_is_zeros = true`.
fn canonical(lengths: &[u32]) -> Vec<(u32, u32)> {
    let max = *lengths.iter().max().unwrap_or(&0);
    let mut codes = vec![(0u32, 0u32); lengths.len()];
    let mut code = 0u32;
    for length in 1..=max {
        for (i, &len) in lengths.iter().enumerate() {
            if len == length {
                codes[i] = (code, length);
                code += 1;
            }
        }
        code <<= 1;
    }
    codes
}

fn emit_symbol(w: &mut BitW, codes: &[(u32, u32)], sym: usize) {
    let (code, len) = codes[sym];
    if len > 0 {
        w.put(code, len);
    }
}

/// Emit one serialized code length (3 bits, with the `== 7` unary extension).
fn emit_length(w: &mut BitW, len: u32) {
    if len < 7 {
        w.put(len, 3);
    } else {
        w.put(7, 3);
        for _ in 0..(len - 7) {
            w.put(1, 1);
        }
        w.put(0, 1);
    }
}

/// `allocAndParseCodeOfWidth` inverse: serialize a code given its present
/// symbols, `width`-bit symbol count, and the special zero-run index.
fn emit_code_of_width(w: &mut BitW, present: &BTreeSet<u32>, width: u32, special: i32) {
    if present.len() <= 1 {
        w.put(0, width); // num = 0 -> single-symbol form
        w.put(present.iter().next().copied().unwrap_or(0), width);
        return;
    }
    let lengths = fixed_lengths(present);
    w.put(lengths.len() as u32, width);
    let mut n = 0i32;
    for &len in &lengths {
        emit_length(w, len);
        n += 1;
        if n == special {
            w.put(0, 2);
        }
    }
}

/// `allocAndParseLiteralCode` inverse: a meta code, then the literal-code
/// lengths run-length coded through it.
fn emit_literal_code(w: &mut BitW, lit_present: &BTreeSet<u32>) {
    if lit_present.len() <= 1 {
        emit_code_of_width(w, &BTreeSet::from([0]), 5, 3); // dummy meta code
        w.put(0, 9);
        w.put(lit_present.iter().next().copied().unwrap_or(0), 9);
        return;
    }

    let lit_lengths = fixed_lengths(lit_present);
    let mut meta_present = BTreeSet::new();
    let mut has_zero = false;
    for &len in &lit_lengths {
        if len == 0 {
            has_zero = true;
        } else {
            meta_present.insert(len + 2);
        }
    }
    if has_zero {
        meta_present.insert(0);
    }
    let meta_lengths = fixed_lengths(&meta_present);
    let meta_codes = canonical(&meta_lengths);

    emit_code_of_width(w, &meta_present, 5, 3);
    w.put(lit_lengths.len() as u32, 9);
    for &len in &lit_lengths {
        let sym = if len == 0 { 0 } else { len + 2 };
        emit_symbol(w, &meta_codes, sym as usize);
    }
}

/// (distance-bit symbol, extra value, extra bit count) for a back-reference of
/// `offset` bytes, inverting `XADLZHStaticHandle`'s offset decoding.
fn dist_encode(offset: usize) -> (u32, u32, u32) {
    match offset {
        1 => (0, 0, 0),
        2 => (1, 0, 0),
        _ => {
            let v = offset - 1;
            let mut b = 1u32;
            while (1usize << b) <= v {
                b += 1;
            }
            let extra = v - (1usize << (b - 1));
            (b, extra as u32, b - 1)
        }
    }
}

/// Encode `tokens` as a single LZH-static block. The distance code's count
/// field is 5 bits wide (window 15), the one difference from Zoo's 13-bit form.
fn encode_lzh(tokens: &[Tok]) -> Vec<u8> {
    let mut lit_present = BTreeSet::new();
    let mut dist_present = BTreeSet::new();
    for t in tokens {
        match t {
            Tok::Lit(b) => {
                lit_present.insert(*b as u32);
            }
            Tok::Match { len, dist } => {
                lit_present.insert(0x100 + (*len - 3) as u32);
                dist_present.insert(dist_encode(*dist).0);
            }
        }
    }

    let lit_codes = canonical(&fixed_lengths(&lit_present));
    let dist_codes = canonical(&fixed_lengths(&dist_present));

    let mut w = BitW::new();
    w.put(tokens.len() as u32, 16);
    emit_literal_code(&mut w, &lit_present);
    emit_code_of_width(&mut w, &dist_present, 5, -1);

    for t in tokens {
        match t {
            Tok::Lit(b) => emit_symbol(&mut w, &lit_codes, *b as usize),
            Tok::Match { len, dist } => {
                emit_symbol(&mut w, &lit_codes, 0x100 + (*len - 3));
                let (b, extra, nbits) = dist_encode(*dist);
                emit_symbol(&mut w, &dist_codes, b as usize);
                if nbits > 0 {
                    w.put(extra, nbits);
                }
            }
        }
    }
    w.finish()
}

/// Apply tokens the way the decoder does, to get the expected output bytes.
fn simulate(tokens: &[Tok]) -> Vec<u8> {
    let mut out = Vec::new();
    for t in tokens {
        match t {
            Tok::Lit(b) => out.push(*b),
            Tok::Match { len, dist } => {
                for _ in 0..*len {
                    out.push(out[out.len() - dist]);
                }
            }
        }
    }
    out
}

// --- ARJ container builder ----------------------------------------------------

struct Member {
    name: &'static str,
    method: u8,
    decoded: Vec<u8>,
    data: Vec<u8>,
}

fn stored(name: &'static str, content: &[u8]) -> Member {
    Member {
        name,
        method: 0,
        decoded: content.to_vec(),
        data: content.to_vec(),
    }
}

fn lzh(name: &'static str, method: u8, tokens: &[Tok]) -> Member {
    Member {
        name,
        method,
        decoded: simulate(tokens),
        data: encode_lzh(tokens),
    }
}

/// Wrap a header region as `0x60 0xea <size> <header> <crc32(header)>`.
fn block(header: &[u8]) -> Vec<u8> {
    let mut b = vec![0x60, 0xea];
    b.extend_from_slice(&(header.len() as u16).to_le_bytes());
    b.extend_from_slice(header);
    b.extend_from_slice(&crc32_ieee(header).to_le_bytes());
    b
}

fn main_header() -> Vec<u8> {
    let mut h = vec![0u8; 28];
    h[0] = 28; // firstsize
    h[3] = 2; // os = Unix
    h[6] = 2; // file type = main header
    h.extend_from_slice(b"archive");
    h.push(0); // name terminator
    h.push(0); // empty comment terminator
    h
}

fn local_header(m: &Member) -> Vec<u8> {
    let mut h = vec![0u8; 28];
    h[0] = 28; // firstsize
    h[3] = 2; // os = Unix
    h[4] = 0x10; // flags: Unix path separator
    h[5] = m.method;
    h[6] = 0; // file type = binary file
    h[12..16].copy_from_slice(&(m.data.len() as u32).to_le_bytes()); // compsize
    h[16..20].copy_from_slice(&(m.decoded.len() as u32).to_le_bytes()); // size
    h[20..24].copy_from_slice(&crc32_ieee(&m.decoded).to_le_bytes()); // crc
    h.extend_from_slice(m.name.as_bytes());
    h.push(0); // filename terminator
    h.push(0); // empty comment terminator
    h
}

fn build_arj(members: &[Member]) -> Vec<u8> {
    let mut out = block(&main_header());
    out.extend_from_slice(&[0, 0]); // main header: extlen = 0
    for m in members {
        out.extend_from_slice(&block(&local_header(m)));
        out.extend_from_slice(&[0, 0]); // local header: extlen = 0
        out.extend_from_slice(&m.data);
    }
    out.extend_from_slice(&[0x60, 0xea, 0, 0]); // zero-size terminating header
    out
}

fn ours(arj: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let arc = ArjArchive::open(arj).unwrap();
    let mut map = BTreeMap::new();
    for (i, e) in arc.entries().iter().enumerate() {
        let mut out = Vec::new();
        arc.read_entry(i, &mut out).unwrap();
        map.insert(String::from_utf8(e.name().to_vec()).unwrap(), out);
    }
    map
}

#[test]
fn stored_and_lzh_members_match_unar() {
    // A literal/length/distance mix exercising real Huffman codes, a match with
    // extra distance bits (offset 5), and an overlapping run (offset 1).
    let mix = vec![
        Tok::Lit(b'A'),
        Tok::Lit(b'R'),
        Tok::Lit(b'J'),
        Tok::Lit(b'!'),
        Tok::Lit(b' '),
        Tok::Match { len: 5, dist: 5 }, // copy "ARJ! "
        Tok::Lit(b'!'),
        Tok::Match { len: 3, dist: 1 }, // overlapping run of '!'
    ];
    // An all-literal member: a larger literal Huffman table, single-symbol
    // (unused) distance code.
    let text = b"the quick brown fox jumps over the lazy dog";
    let text_tokens: Vec<Tok> = text.iter().map(|&b| Tok::Lit(b)).collect();

    let arj = build_arj(&[
        stored("stored.txt", b"ARJ stored member, verbatim.\n"),
        lzh("mix.bin", 1, &mix),          // method 1 (Most)
        lzh("text.bin", 2, &text_tokens), // method 2 (Medium)
    ]);

    let mine = ours(&arj);
    assert_eq!(
        mine.get("stored.txt").unwrap(),
        b"ARJ stored member, verbatim.\n"
    );
    assert_eq!(mine.get("mix.bin").unwrap(), &simulate(&mix));
    assert_eq!(mine.get("text.bin").unwrap(), text);

    if !unar_installed() {
        eprintln!("skipping unar cross-check: `unar` not installed");
        return;
    }
    assert_eq!(
        mine,
        unar_extract_all(&arj, "test.arj"),
        "our ARJ extraction disagrees with unar"
    );
}
