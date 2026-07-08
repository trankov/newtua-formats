//! DEFLATE (RFC 1951) inflate, with a parameterisable meta-table order.
//!
//! A faithful port of XADMaster's `XADDeflateHandle` (the Normal variant; the
//! Deflate64 / NSIS / StuffItX variants are intentionally omitted). The one
//! feature the mature `flate2` crate cannot provide is a *non-standard* order for
//! the 19-entry code-length "meta" alphabet: ALZip's method 3 permutes it by a
//! function of the file size to obfuscate the stream. [`inflate`] takes that
//! order as a parameter, so the same decoder serves both plain deflate (with
//! [`ZIP_ORDER`]) and ALZip's obfuscated variant.
//!
//! [`deflate_dynamic`] is the matching minimal encoder used to build fixtures in
//! any meta order — it emits a single literals-only dynamic block, which is all
//! the round-trip and oracle tests need.

use std::io;

use crate::bitreader::BitReaderLsb;
use crate::lzss::LzssWindow;
use crate::prefixcode::PrefixCode;

/// The standard deflate meta-table order (RFC 1951, §3.2.7).
pub const ZIP_ORDER: [u8; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// Deflate's 32 KiB sliding window (the Normal variant; Deflate64 would be 64).
const WINDOW_SIZE: usize = 32768;

/// Base match lengths for literal/length symbols 265..=284 (RFC 1951, §3.2.5).
const BASE_LENGTHS: [u32; 20] = [
    11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227,
];

/// Base match offsets for distance symbols 4..=31 (RFC 1951, §3.2.5).
const BASE_OFFSETS: [u32; 28] = [
    5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073,
    4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153,
];

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

fn truncated() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "deflate: truncated stream")
}

/// Read an `n`-bit little-endian field, erroring on end of input.
fn read_bits(bits: &mut BitReaderLsb<&[u8]>, n: u8) -> io::Result<u32> {
    bits.read_bits(n)?.ok_or_else(truncated)
}

/// Decode the next symbol, erroring on end of input or an invalid code.
fn next_symbol(code: &PrefixCode, bits: &mut BitReaderLsb<&[u8]>) -> io::Result<i32> {
    code.next_symbol_le(bits)?.ok_or_else(truncated)
}

/// Build a prefix code from stream-derived `lengths`. A corrupt stream (e.g.
/// method 3 decoded in the wrong meta order) can over-subscribe the code, which
/// [`PrefixCode::try_from_lengths`] rejects as an error rather than panicking —
/// XADMaster reports the same as a decrunch exception.
fn build_code(lengths: &[u32], max_length: u32) -> io::Result<PrefixCode> {
    PrefixCode::try_from_lengths(lengths, max_length, true)
}

/// One decoded block: stored (with a remaining literal-byte count) or Huffman
/// (with its literal/length and distance codes).
enum Block {
    Stored(usize),
    Huffman(PrefixCode, PrefixCode),
}

/// The fixed literal/length code lengths (RFC 1951, §3.2.6).
fn fixed_literal_code() -> PrefixCode {
    let mut lengths = [0u32; 288];
    lengths[0..144].fill(8);
    lengths[144..256].fill(9);
    lengths[256..280].fill(7);
    lengths[280..288].fill(8);
    PrefixCode::from_lengths(&lengths, 9, true)
}

/// The fixed distance code lengths: all 32 symbols are 5 bits.
fn fixed_distance_code() -> PrefixCode {
    PrefixCode::from_lengths(&[5u32; 32], 5, true)
}

/// Parse a dynamic-Huffman block header: the meta code, then the run-length
/// coded literal and distance code lengths.
fn parse_dynamic_block(bits: &mut BitReaderLsb<&[u8]>, meta_order: &[u8; 19]) -> io::Result<Block> {
    let numliterals = read_bits(bits, 5)? as usize + 257;
    let numdistances = read_bits(bits, 5)? as usize + 1;
    let nummetas = read_bits(bits, 4)? as usize + 4;

    let mut meta_lengths = [0u32; 19];
    for &sym in meta_order.iter().take(nummetas) {
        meta_lengths[sym as usize] = read_bits(bits, 3)?;
    }
    let metacode = build_code(&meta_lengths, 7)?;

    let total = numliterals + numdistances;
    let mut lengths = vec![0u32; total];
    let mut i = 0;
    while i < total {
        let val = next_symbol(&metacode, bits)?;
        if val < 16 {
            lengths[i] = val as u32;
            i += 1;
        } else if val == 16 {
            let repeats = read_bits(bits, 2)? as usize + 3;
            if i == 0 || i + repeats > total {
                return Err(invalid("deflate: bad code-length repeat"));
            }
            let prev = lengths[i - 1];
            for _ in 0..repeats {
                lengths[i] = prev;
                i += 1;
            }
        } else {
            // 17 repeats zeros a short run, 18 a long run.
            let repeats = if val == 17 {
                read_bits(bits, 3)? as usize + 3
            } else {
                read_bits(bits, 7)? as usize + 11
            };
            if i + repeats > total {
                return Err(invalid("deflate: bad zero-length repeat"));
            }
            for _ in 0..repeats {
                lengths[i] = 0;
                i += 1;
            }
        }
    }

    let literalcode = build_code(&lengths[..numliterals], 15)?;
    let distancecode = build_code(&lengths[numliterals..], 15)?;
    Ok(Block::Huffman(literalcode, distancecode))
}

/// Decode a match length from a literal/length symbol `> 256`.
fn decode_length(literal: i32, bits: &mut BitReaderLsb<&[u8]>) -> io::Result<usize> {
    let len = if literal < 265 {
        (literal - 254) as u32
    } else if literal < 285 {
        let size = ((literal - 261) / 4) as u8;
        BASE_LENGTHS[(literal - 265) as usize] + read_bits(bits, size)?
    } else if literal == 285 {
        258
    } else {
        return Err(invalid("deflate: invalid literal/length symbol"));
    };
    Ok(len as usize)
}

/// Decode a match distance from a distance symbol.
fn decode_distance(distance: i32, bits: &mut BitReaderLsb<&[u8]>) -> io::Result<usize> {
    let offset = if distance < 4 {
        (distance + 1) as u32
    } else if (distance - 4) < BASE_OFFSETS.len() as i32 {
        let size = ((distance - 2) / 2) as u8;
        BASE_OFFSETS[(distance - 4) as usize] + read_bits(bits, size)?
    } else {
        return Err(invalid("deflate: invalid distance symbol"));
    };
    Ok(offset as usize)
}

pub fn inflate(input: &[u8], size: usize, meta_order: &[u8; 19]) -> io::Result<Vec<u8>> {
    inflate_impl(input, Some(size), meta_order, false)
}

/// Inflate NSIS's modified deflate variant, decoding until the stream ends.
///
/// A faithful port of `XADDeflateHandle`'s `XADNSISDeflateVariant`. It differs
/// from plain deflate in two ways ([`XADDeflateHandle.m`]):
///
/// 1. **Stored blocks carry no length-complement.** Plain deflate follows the
///    16-bit `LEN` with its one's-complement `NLEN` and checks them; NSIS omits
///    `NLEN` entirely, so it is neither read nor verified.
/// 2. **The stream may end without a final end-of-block symbol.** When the input
///    is exhausted at a block boundary, decoding stops cleanly ("there are a few
///    bytes left" — the reference's own comment) rather than erroring.
///
/// The uncompressed size is not known ahead of time (NSIS relies on the stream
/// ending), so the whole stream is decoded into the returned buffer.
pub fn inflate_nsis(input: &[u8]) -> io::Result<Vec<u8>> {
    inflate_impl(input, None, &ZIP_ORDER, true)
}

/// Read a block header, returning `None` if the input is already exhausted at
/// the `lastblock` bit — the boundary where NSIS's variant stops. A partial
/// header (bits present but too few) is still a truncation error.
fn read_block_header_opt(
    bits: &mut BitReaderLsb<&[u8]>,
    meta_order: &[u8; 19],
    nsis: bool,
) -> io::Result<Option<(Block, bool)>> {
    let lastblock = match bits.read_bit()? {
        Some(b) => b,
        None => return Ok(None),
    };
    let btype = read_bits(bits, 2)?;
    let block = match btype {
        0 => {
            bits.align_to_byte();
            let count = read_bits(bits, 16)?;
            // Plain deflate verifies the complement; NSIS omits it entirely, so
            // for that variant the two complement bytes are not even present.
            if !nsis {
                let ncount = read_bits(bits, 16)?;
                if count != (ncount ^ 0xffff) {
                    return Err(invalid("deflate: stored block length check failed"));
                }
            }
            Block::Stored(count as usize)
        }
        1 => Block::Huffman(fixed_literal_code(), fixed_distance_code()),
        2 => parse_dynamic_block(bits, meta_order)?,
        _ => return Err(invalid("deflate: reserved block type")),
    };
    Ok(Some((block, lastblock)))
}

/// Shared inflate core. `size` bounds the output (plain deflate, known size) or
/// is `None` (NSIS, decode to stream end). When `nsis` is set, input exhaustion
/// at a block boundary or on a literal ends the stream instead of erroring.
fn inflate_impl(
    input: &[u8],
    size: Option<usize>,
    meta_order: &[u8; 19],
    nsis: bool,
) -> io::Result<Vec<u8>> {
    let mut bits = BitReaderLsb::new(input);
    let mut window = LzssWindow::new(WINDOW_SIZE);
    let mut out = Vec::with_capacity(size.unwrap_or(0));

    let (mut block, mut lastblock) = match read_block_header_opt(&mut bits, meta_order, nsis)? {
        Some(header) => header,
        None if nsis => return Ok(out),
        None => return Err(truncated()),
    };

    loop {
        if let Some(size) = size {
            if out.len() >= size {
                break;
            }
        }

        let need_new_block = match &mut block {
            Block::Stored(count) => {
                if *count == 0 {
                    true
                } else {
                    match bits.read_bits(8)? {
                        Some(byte) => {
                            *count -= 1;
                            window.emit_literal(byte as u8, &mut out);
                            false
                        }
                        None if nsis => break,
                        None => return Err(truncated()),
                    }
                }
            }
            Block::Huffman(literalcode, distancecode) => {
                match literalcode.next_symbol_le(&mut bits)? {
                    None if nsis => break,
                    None => return Err(truncated()),
                    Some(256) => true,
                    Some(literal) if literal < 256 => {
                        window.emit_literal(literal as u8, &mut out);
                        false
                    }
                    Some(literal) => {
                        let length = decode_length(literal, &mut bits)?;
                        let distsym = next_symbol(distancecode, &mut bits)?;
                        let distance = decode_distance(distsym, &mut bits)?;
                        window.emit_match(distance, length, &mut out);
                        false
                    }
                }
            }
        };
        if need_new_block {
            if lastblock {
                break;
            }
            match read_block_header_opt(&mut bits, meta_order, nsis)? {
                Some((b, lb)) => {
                    block = b;
                    lastblock = lb;
                }
                None if nsis => break,
                None => return Err(truncated()),
            }
        }
    }

    if let Some(size) = size {
        if out.len() < size {
            return Err(truncated());
        }
        out.truncate(size);
    }
    Ok(out)
}

// --- Minimal encoder -------------------------------------------------------
//
// A single literals-only dynamic block. Every present symbol is given a
// fixed-length code (a valid, if incomplete, canonical prefix code), so no
// Huffman-length computation is needed. That is enough to round-trip against
// [`inflate`] and to be decoded by the reference `unar`, which is the point.

/// Bits needed to give `n` distinct symbols distinct equal-length codes.
fn bits_for(n: usize) -> u32 {
    let mut b = 1;
    while (1usize << b) < n {
        b += 1;
    }
    b
}

/// Assign canonical codes from per-symbol `lengths`, exactly as
/// [`PrefixCode::from_lengths`] with `shortest_code_is_zeros`. Returns
/// `(code, length)` per symbol; length-0 symbols get `(0, 0)` and are unused.
fn canonical_codes(lengths: &[u32], max_length: u32) -> Vec<(u32, u32)> {
    let mut table = vec![(0u32, 0u32); lengths.len()];
    let mut code = 0u32;
    let mut left = lengths.iter().filter(|&&l| l != 0).count();
    'outer: for length in 1..=max_length {
        for (i, &len) in lengths.iter().enumerate() {
            if len != length {
                continue;
            }
            table[i] = (code, length);
            code += 1;
            left -= 1;
            if left == 0 {
                break 'outer;
            }
        }
        code <<= 1;
    }
    table
}

/// Accumulates bits least-significant-first into bytes.
#[derive(Default)]
struct LsbWriter {
    out: Vec<u8>,
    cur: u8,
    nbits: u8,
}

impl LsbWriter {
    fn write_bit(&mut self, bit: u32) {
        if bit & 1 != 0 {
            self.cur |= 1 << self.nbits;
        }
        self.nbits += 1;
        if self.nbits == 8 {
            self.out.push(self.cur);
            self.cur = 0;
            self.nbits = 0;
        }
    }

    /// Write the low `n` bits of `value`, least-significant first.
    fn write_bits(&mut self, value: u32, n: u32) {
        for i in 0..n {
            self.write_bit(value >> i);
        }
    }

    /// Write a canonical code `(code, length)` most-significant bit first, the
    /// order [`PrefixCode::next_symbol_le`] walks the tree.
    fn write_code(&mut self, code: (u32, u32)) {
        for bitpos in (0..code.1).rev() {
            self.write_bit(code.0 >> bitpos);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.nbits != 0 {
            self.out.push(self.cur);
        }
        self.out
    }
}

pub fn deflate_dynamic(data: &[u8], meta_order: &[u8; 19]) -> Vec<u8> {
    // Literal alphabet: every byte that occurs, plus the end-of-block symbol.
    let mut present = [false; 257];
    for &b in data {
        present[b as usize] = true;
    }
    present[256] = true;
    let nlit = present.iter().filter(|&&p| p).count();
    let lit_bits = bits_for(nlit);

    let mut lit_lengths = [0u32; 257];
    for (s, &p) in present.iter().enumerate() {
        if p {
            lit_lengths[s] = lit_bits;
        }
    }
    // A single dummy distance code, length 1 — never emitted (no matches).
    let dist_lengths = [1u32];

    // Meta alphabet: the code-length values that appear in the two sequences.
    let mut clv_present = [false; 19];
    for &len in lit_lengths.iter() {
        clv_present[len as usize] = true;
    }
    clv_present[dist_lengths[0] as usize] = true;
    let nmeta = clv_present.iter().filter(|&&p| p).count();
    let meta_bits = bits_for(nmeta);
    let mut meta_lengths = [0u32; 19];
    for (v, &p) in clv_present.iter().enumerate() {
        if p {
            meta_lengths[v] = meta_bits;
        }
    }

    let meta_table = canonical_codes(&meta_lengths, 7);
    let lit_table = canonical_codes(&lit_lengths, 15);

    let mut w = LsbWriter::default();
    w.write_bit(1); // lastblock
    w.write_bits(2, 2); // type 2: dynamic Huffman
    w.write_bits(0, 5); // numliterals - 257 = 0  (we always use 257)
    w.write_bits(0, 5); // numdistances - 1 = 0    (one dummy distance code)
    w.write_bits(15, 4); // nummetas - 4 = 15       (all 19 written)
    for &sym in meta_order.iter() {
        w.write_bits(meta_lengths[sym as usize], 3);
    }
    // The code-length sequence: 257 literal lengths, then 1 distance length,
    // each emitted literally (no run-length symbols).
    for &len in lit_lengths.iter() {
        w.write_code(meta_table[len as usize]);
    }
    w.write_code(meta_table[dist_lengths[0] as usize]);
    // The data itself, then the end-of-block symbol.
    for &b in data {
        w.write_code(lit_table[b as usize]);
    }
    w.write_code(lit_table[256]);
    w.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip `data` through the encoder and decoder in a given meta order.
    fn round_trip(data: &[u8], order: &[u8; 19]) {
        let comp = deflate_dynamic(data, order);
        let out = inflate(&comp, data.len(), order).unwrap();
        assert_eq!(out, data);
    }

    /// The same permutation ALZip's method 3 uses, for exercising arbitrary
    /// meta orders here without depending on the alz crate.
    fn permute(param: usize) -> [u8; 19] {
        let mut t = [0u8; 19];
        for (i, v) in t.iter_mut().enumerate() {
            *v = i as u8;
        }
        for i in 0..19 {
            let mut sw = (i % 6) * 3 + param;
            if sw > 18 {
                sw %= 18;
            }
            if sw != i {
                t.swap(i, sw);
            }
        }
        t
    }

    #[test]
    fn round_trip_zip_order_basic() {
        round_trip(b"hello deflate hello deflate", &ZIP_ORDER);
    }

    #[test]
    fn round_trip_zip_order_varied_inputs() {
        round_trip(b"", &ZIP_ORDER);
        round_trip(b"x", &ZIP_ORDER);
        round_trip(&[b'a'; 500], &ZIP_ORDER);
        // A pseudo-random-ish spread of byte values.
        let noise: Vec<u8> = (0..600).map(|i| ((i * 37 + 11) % 256) as u8).collect();
        round_trip(&noise, &ZIP_ORDER);
        // Every byte value present (exercises the widest literal alphabet).
        let all: Vec<u8> = (0..=255u8).collect();
        round_trip(&all, &ZIP_ORDER);
    }

    #[test]
    fn round_trip_permuted_orders() {
        let data = b"the quick brown fox jumps over the lazy dog 0123456789";
        for param in 0..16 {
            round_trip(data, &permute(param));
        }
    }

    /// Raw deflate produced by `flate2` at a given compression level.
    fn flate2_deflate(data: &[u8], level: flate2::Compression) -> Vec<u8> {
        use std::io::Read;
        let mut out = Vec::new();
        flate2::read::DeflateEncoder::new(data, level)
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    #[test]
    fn decodes_real_flate2_dynamic_block_with_matches() {
        // Repetitive data compresses to a dynamic block full of LZ matches and
        // distances — the branches the literals-only encoder never touches.
        let data = b"deflate this and this and this over and over again. ".repeat(50);
        let comp = flate2_deflate(&data, flate2::Compression::best());
        let out = inflate(&comp, data.len(), &ZIP_ORDER).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn decodes_real_flate2_stored_block() {
        // No compression forces a stored (type 0) block, exercising the
        // byte-alignment and length-check path.
        let data = b"stored, uncompressed, byte for byte.".to_vec();
        let comp = flate2_deflate(&data, flate2::Compression::none());
        let out = inflate(&comp, data.len(), &ZIP_ORDER).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn decodes_fixed_huffman_block() {
        // A hand-built fixed-Huffman (type 1) block: header bit `lastblock`,
        // type `01`, the fixed 8-bit code for 'A' (0x71), then the 7-bit
        // end-of-block code (0). Encodes the single byte "A".
        let comp = [0x73u8, 0x04, 0x00];
        let out = inflate(&comp, 1, &ZIP_ORDER).unwrap();
        assert_eq!(out, b"A");
    }

    #[test]
    fn truncated_stream_errors() {
        let data = b"content to deflate and then cut in half. ".repeat(20);
        let mut comp = flate2_deflate(&data, flate2::Compression::best());
        comp.truncate(comp.len() / 2);
        assert!(inflate(&comp, data.len(), &ZIP_ORDER).is_err());
    }

    // --- NSIS deflate variant ------------------------------------------------

    /// A plain dynamic block round-trips through `inflate_nsis`: it carries a
    /// proper end-of-block symbol, so the NSIS variant reads it just like plain
    /// deflate (the quirks only matter for streams NSIS actually produces).
    #[test]
    fn nsis_inflate_reads_plain_dynamic_block() {
        let data = b"nsis deflate reads a normal stream fine".to_vec();
        let comp = deflate_dynamic(&data, &ZIP_ORDER);
        assert_eq!(inflate_nsis(&comp).unwrap(), data);
    }

    #[test]
    fn nsis_inflate_reads_real_flate2_stream() {
        let data = b"repeat me repeat me repeat me over and over. ".repeat(40);
        let comp = flate2_deflate(&data, flate2::Compression::best());
        assert_eq!(inflate_nsis(&comp).unwrap(), data);
    }

    /// Build an NSIS stored block: header (`lastblock`, type 0), byte align, the
    /// 16-bit `LEN`, then the literal bytes — and, unlike plain deflate, *no*
    /// `NLEN` complement word.
    fn nsis_stored_block(data: &[u8], lastblock: bool) -> Vec<u8> {
        let mut w = LsbWriter::default();
        w.write_bit(u32::from(lastblock));
        w.write_bits(0, 2); // type 0: stored
        while w.nbits != 0 {
            w.write_bit(0); // align to byte boundary
        }
        w.write_bits(data.len() as u32 & 0xffff, 16); // LEN, no NLEN
        for &b in data {
            w.write_bits(u32::from(b), 8);
        }
        w.finish()
    }

    #[test]
    fn nsis_stored_block_without_complement() {
        let data = b"stored with no NLEN complement word";
        let comp = nsis_stored_block(data, true);
        assert_eq!(inflate_nsis(&comp).unwrap(), data);
        // Plain deflate must reject it: it reads the first data bytes as NLEN and
        // the check fails (or the stream desyncs).
        assert!(inflate(&comp, data.len(), &ZIP_ORDER).is_err());
    }

    #[test]
    fn nsis_stops_at_input_eof_without_final_block() {
        // A non-last stored block whose data ends exactly at input EOF — there is
        // no following block header. The NSIS variant stops cleanly here.
        let data = b"ends at eof, no trailing end-of-block symbol";
        let comp = nsis_stored_block(data, false);
        assert_eq!(inflate_nsis(&comp).unwrap(), data);
    }

    #[test]
    fn nsis_inflate_empty_input_is_empty() {
        assert_eq!(inflate_nsis(&[]).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn wrong_meta_order_does_not_round_trip() {
        // Decoding with a different order than it was encoded in must not
        // reproduce the data (it errors or yields garbage) — this is exactly
        // why method 3's obfuscation works.
        let data = b"obfuscation depends on the meta order matching";
        let comp = deflate_dynamic(data, &permute(3));
        if let Ok(out) = inflate(&comp, data.len(), &permute(7)) {
            assert_ne!(out, data);
        }
    }
}
