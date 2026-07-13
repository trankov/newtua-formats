// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! End-to-end oracle for the Zoo container and its LZH-static codec.
//!
//! No common tool writes `.zoo`, so this test assembles archives from a small
//! builder plus a mirror LZH-static encoder, then asserts that BOTH our crate
//! AND the reference `unar` decode them to the same bytes. `unar` is the
//! independent check that our reading of the format (and the CRC-16 it verifies)
//! is correct. The non-`unar` assertions still run everywhere and pin the
//! encoder/decoder pair. Skipped against `unar` when it is absent.

use std::collections::{BTreeMap, BTreeSet};

use newtua_common::crc16::crc16_arc;
use newtua_dos::zoo::ZooArchive;
use newtua_testutil::{unar_extract_all, unar_installed, BitWriter};

const MAGIC: [u8; 4] = [0xdc, 0xa7, 0xc4, 0xfd];

// --- mirror LZH-static encoder ------------------------------------------------

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
        return Vec::new(); // unused single-symbol/empty code (e.g. no matches)
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
            w.put(0, 2); // no implied zeros at the special index
        }
    }
}

/// `allocAndParseLiteralCode` inverse: a meta code, then the literal-code
/// lengths run-length coded through it.
fn emit_literal_code(w: &mut BitW, lit_present: &BTreeSet<u32>) {
    if lit_present.len() <= 1 {
        emit_code_of_width(w, &BTreeSet::from([0]), 5, 3); // dummy meta code
        w.put(0, 9); // num = 0 -> single-symbol form
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

/// Encode `tokens` as a single LZH-static block.
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
    w.put(tokens.len() as u32, 16); // block size = token count
    emit_literal_code(&mut w, &lit_present);
    emit_code_of_width(&mut w, &dist_present, 4, -1);

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

// --- mirror LZW (method 1) encoder --------------------------------------------

/// Greedy LZW parse of `input` into a Zoo method-1 bitstream, mirroring the
/// generic LZW table growth: codes from 258, symbol width tracking the
/// decoder's lagging `numsymbols`, terminated with the EOF code 257.
fn lzw_encode(input: &[u8]) -> Vec<u8> {
    use std::collections::HashMap;
    const MAXSYMBOLS: i32 = 8192;

    let mut dict: HashMap<Vec<u8>, i32> = HashMap::new();
    for b in 0..256 {
        dict.insert(vec![b as u8], b);
    }
    let mut next_code = 258i32;
    let mut codes = Vec::new();
    if !input.is_empty() {
        let mut w = vec![input[0]];
        for &c in &input[1..] {
            let mut wc = w.clone();
            wc.push(c);
            if dict.contains_key(&wc) {
                w = wc;
            } else {
                codes.push(dict[&w]);
                if next_code < MAXSYMBOLS {
                    dict.insert(wc, next_code);
                    next_code += 1;
                }
                w = vec![c];
            }
        }
        codes.push(dict[&w]);
    }

    let mut w = BitWriter::default();
    let mut numsymbols = 258i32;
    let mut symbolsize = 9u32;
    for (i, &code) in codes.iter().enumerate() {
        w.bits(code as u32, symbolsize);
        if i >= 1 && numsymbols < MAXSYMBOLS {
            numsymbols += 1;
            if numsymbols != MAXSYMBOLS && (numsymbols & (numsymbols - 1)) == 0 {
                symbolsize += 1;
            }
        }
    }
    w.bits(257, symbolsize); // EOF marker
    w.finish()
}

// --- container builder (type-0, short-named members) --------------------------

struct Member {
    name: &'static str,
    method: u8,
    uncompsize: u32,
    crc16: u16,
    data: Vec<u8>,
}

fn stored(name: &'static str, content: &[u8]) -> Member {
    Member {
        name,
        method: 0,
        uncompsize: content.len() as u32,
        crc16: crc16_arc(content),
        data: content.to_vec(),
    }
}

fn lzh(name: &'static str, tokens: &[Tok]) -> Member {
    let out = simulate(tokens);
    Member {
        name,
        method: 2,
        uncompsize: out.len() as u32,
        crc16: crc16_arc(&out),
        data: encode_lzh(tokens),
    }
}

fn lzw(name: &'static str, content: &[u8]) -> Member {
    Member {
        name,
        method: 1,
        uncompsize: content.len() as u32,
        crc16: crc16_arc(content),
        data: lzw_encode(content),
    }
}

fn build_record(m: &Member) -> Vec<u8> {
    let mut r = vec![0u8; 38];
    r[0..4].copy_from_slice(&MAGIC);
    // type 0, method at 5; next/data offsets patched later.
    r[5] = m.method;
    r[18..20].copy_from_slice(&m.crc16.to_le_bytes());
    r[20..24].copy_from_slice(&m.uncompsize.to_le_bytes());
    r[24..28].copy_from_slice(&(m.data.len() as u32).to_le_bytes());
    let mut short = [0u8; 13];
    short[..m.name.len()].copy_from_slice(m.name.as_bytes());
    r.extend_from_slice(&short);
    r
}

fn build_zoo(members: &[Member]) -> Vec<u8> {
    const HLEN: usize = 0x22;
    let mut recs: Vec<Vec<u8>> = members.iter().map(build_record).collect();

    let mut offs = Vec::new();
    let mut off = HLEN;
    for r in &recs {
        offs.push(off);
        off += r.len();
    }
    let term_off = off;
    let data_start = term_off + 38;

    let mut data_offs = Vec::new();
    let mut doff = data_start;
    for m in members {
        data_offs.push(doff);
        doff += m.data.len();
    }

    for (i, r) in recs.iter_mut().enumerate() {
        let next = if i + 1 < members.len() {
            offs[i + 1]
        } else {
            term_off
        };
        r[6..10].copy_from_slice(&(next as u32).to_le_bytes());
        r[10..14].copy_from_slice(&(data_offs[i] as u32).to_le_bytes());
    }

    let mut out = vec![0u8; HLEN];
    out[0x14..0x18].copy_from_slice(&MAGIC);
    out[0x18..0x1c].copy_from_slice(&(HLEN as u32).to_le_bytes());
    for r in &recs {
        out.extend_from_slice(r);
    }
    let mut term = vec![0u8; 38];
    term[0..4].copy_from_slice(&MAGIC);
    out.extend_from_slice(&term);
    for m in members {
        out.extend_from_slice(&m.data);
    }
    out
}

fn ours(zoo: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let arc = ZooArchive::open(zoo).unwrap();
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
        Tok::Lit(b'Z'),
        Tok::Lit(b'O'),
        Tok::Lit(b'O'),
        Tok::Lit(b'!'),
        Tok::Lit(b' '),
        Tok::Match { len: 5, dist: 5 }, // copy "ZOO! "
        Tok::Lit(b'!'),
        Tok::Match { len: 3, dist: 1 }, // overlapping run of '!'
    ];
    // An all-literal member: a larger literal Huffman table, single-symbol
    // (unused) distance code.
    let text = b"the quick brown fox jumps over the lazy dog";
    let text_tokens: Vec<Tok> = text.iter().map(|&b| Tok::Lit(b)).collect();

    // LZW (method 1) members: repeats (back-references), a single-byte run that
    // drives the KwKwK case, and a long varied input that pushes the symbol
    // width past 9 bits.
    let lzw_repeat = b"TOBEORNOTTOBEORTOBEORNOT#TOBEORNOT".to_vec();
    let lzw_run = vec![b'A'; 64];
    let mut lzw_big = Vec::new();
    for i in 0..2000u32 {
        lzw_big.push((i & 0xff) as u8);
        lzw_big.push(((i >> 8) & 0xff) as u8);
        lzw_big.push((i.wrapping_mul(31) & 0xff) as u8);
    }

    let zoo = build_zoo(&[
        stored("stored.txt", b"Zoo stored member, verbatim.\n"),
        lzh("mix.bin", &mix),
        lzh("text.bin", &text_tokens),
        lzw("lzwrep.bin", &lzw_repeat),
        lzw("lzwrun.bin", &lzw_run),
        lzw("lzwbig.bin", &lzw_big),
    ]);

    let mine = ours(&zoo);
    assert_eq!(
        mine.get("stored.txt").unwrap(),
        b"Zoo stored member, verbatim.\n"
    );
    assert_eq!(mine.get("mix.bin").unwrap(), &simulate(&mix));
    assert_eq!(mine.get("text.bin").unwrap(), text);
    assert_eq!(mine.get("lzwrep.bin").unwrap(), &lzw_repeat);
    assert_eq!(mine.get("lzwrun.bin").unwrap(), &lzw_run);
    assert_eq!(mine.get("lzwbig.bin").unwrap(), &lzw_big);

    if !unar_installed() {
        eprintln!("skipping unar cross-check: `unar` not installed");
        return;
    }
    assert_eq!(
        mine,
        unar_extract_all(&zoo, "test.zoo"),
        "our Zoo extraction disagrees with unar"
    );
}
