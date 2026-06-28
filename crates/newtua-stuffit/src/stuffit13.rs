//! Classic StuffIt compression method 13 (LZ + Huffman).
//!
//! Faithful port of XADMaster's `XADStuffIt13Handle`. An LZSS coder with a
//! 65536-byte window driven by three Huffman code tables — two "literal/length"
//! tables (`firstcode`, used when a literal is expected, and `secondcode`, used
//! right after a match) plus an `offsetcode` giving the bit-length of each match
//! distance. **Every** bit and symbol is read least-significant-bit first.
//!
//! The first byte selects the table set: its high nibble `0` means the three
//! tables are serialised dynamically (a 37-symbol meta-code decodes their code
//! lengths); `1..=5` pick one of five built-in static table sets; `>= 6` is
//! illegal.

use std::io::{self, Read};

use newtua_common::bitreader::BitReaderLsb;
use newtua_common::lzss::LzssWindow;
use newtua_common::prefixcode::PrefixCode;

/// The window is fixed at 65536 bytes (matches the reference).
const WINDOW_SIZE: usize = 65536;
/// `firstcode` / `secondcode` always carry this many symbols.
const NUM_LITERAL_SYMBOLS: usize = 321;

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn truncated() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "stuffit13: truncated stream")
}

/// Which literal/length table the next symbol is read from.
#[derive(Clone, Copy)]
enum Context {
    First,
    Second,
}

/// The three Huffman tables for one fork.
struct Tables {
    first: PrefixCode,
    second: PrefixCode,
    offset: PrefixCode,
}

/// Decode a method-13 (LZ+Huffman) fork: `outlen` decompressed bytes from `src`.
pub(crate) fn decode(src: &[u8], outlen: usize) -> io::Result<Vec<u8>> {
    if outlen == 0 {
        return Ok(Vec::new());
    }

    let mut bits = BitReaderLsb::new(src);
    let tables = read_header(&mut bits)?;

    let mut window = LzssWindow::new(WINDOW_SIZE);
    let mut out = Vec::with_capacity(outlen);
    let mut curr = Context::First;

    while out.len() < outlen {
        let code = match curr {
            Context::First => &tables.first,
            Context::Second => &tables.second,
        };
        let val = next_symbol(code, &mut bits)?;

        if val < 0x100 {
            // Literal: emit the byte; the next symbol comes from `firstcode`.
            curr = Context::First;
            window.emit_literal(val as u8, &mut out);
        } else {
            // Match: the next symbol after this one comes from `secondcode`.
            curr = Context::Second;

            let length = match val {
                _ if val < 0x13e => (val - 0x100 + 3) as usize,
                0x13e => read_bits(&mut bits, 10)? as usize + 65,
                0x13f => read_bits(&mut bits, 15)? as usize + 65,
                // 0x140 is the end marker; reaching it before `outlen` bytes have
                // been produced means the stream was truncated.
                _ => return Err(truncated()),
            };

            let bitlength = next_symbol(&tables.offset, &mut bits)?;
            let offset = match bitlength {
                0 => 1,
                1 => 2,
                bl => (1usize << (bl - 1)) + read_bits(&mut bits, (bl - 1) as u8)? as usize + 1,
            };

            // Stop exactly at `outlen`: the reference produces bytes one at a
            // time, so a match crossing the end yields only the bytes needed.
            let remaining = outlen - out.len();
            window.emit_match(offset, length.min(remaining), &mut out);
        }
    }

    Ok(out)
}

/// Parse the one-byte mode selector and build the three tables.
fn read_header<R: Read>(bits: &mut BitReaderLsb<R>) -> io::Result<Tables> {
    let val = read_bits(bits, 8)?;
    let code = val >> 4;

    if code == 0 {
        // Dynamic: a 37-symbol meta-code spells out each table's code lengths.
        let meta = build_meta_code();
        let first = parse_code(bits, NUM_LITERAL_SYMBOLS, &meta)?;
        let second = if val & 0x08 != 0 {
            first.clone()
        } else {
            parse_code(bits, NUM_LITERAL_SYMBOLS, &meta)?
        };
        let offset = parse_code(bits, (val & 0x07) as usize + 10, &meta)?;
        Ok(Tables {
            first,
            second,
            offset,
        })
    } else if code <= 5 {
        // Static: one of five built-in table sets.
        let t = (code - 1) as usize;
        Ok(Tables {
            first: PrefixCode::from_lengths(FIRST_CODE_LENGTHS[t], 32, true),
            second: PrefixCode::from_lengths(SECOND_CODE_LENGTHS[t], 32, true),
            offset: PrefixCode::from_lengths(OFFSET_CODE_LENGTHS[t], 32, true),
        })
    } else {
        Err(invalid("stuffit13: illegal table selector"))
    }
}

/// Build the 37-symbol meta-code from the fixed `MetaCodes` table.
fn build_meta_code() -> PrefixCode {
    let mut meta = PrefixCode::new();
    for (i, (&code, &len)) in META_CODES.iter().zip(META_CODE_LENGTHS.iter()).enumerate() {
        meta.add_value_low_bit_first(i as i32, code, len);
    }
    meta
}

/// Decode `numcodes` code lengths through `meta`, then build the prefix code.
///
/// Port of `allocAndParseCodeOfSize:metaCode:`. The meta-symbols 31–36 are
/// commands (reset, increment/decrement, single/short/long runs); any other
/// symbol sets the running length directly. As in the C original a length is
/// always written at the end of each iteration, so the run commands "overlap"
/// with that trailing write. The C buffer is a fixed-size stack array; here
/// every write is bounds-checked and overflow is reported as malformed data.
fn parse_code<R: Read>(
    bits: &mut BitReaderLsb<R>,
    numcodes: usize,
    meta: &PrefixCode,
) -> io::Result<PrefixCode> {
    let mut lengths = vec![0i32; numcodes];
    let mut length: i32 = 0;
    let mut i = 0usize;

    while i < numcodes {
        let val = next_symbol(meta, bits)?;
        match val {
            31 => length = -1,
            32 => length += 1,
            33 => length -= 1,
            34 => {
                if read_bit(bits)? {
                    set_length(&mut lengths, i, length)?;
                    i += 1;
                }
            }
            35 => {
                let mut n = read_bits(bits, 3)? + 2;
                while n > 0 {
                    set_length(&mut lengths, i, length)?;
                    i += 1;
                    n -= 1;
                }
            }
            36 => {
                let mut n = read_bits(bits, 6)? + 10;
                while n > 0 {
                    set_length(&mut lengths, i, length)?;
                    i += 1;
                    n -= 1;
                }
            }
            _ => length = val + 1,
        }
        set_length(&mut lengths, i, length)?;
        i += 1;
    }

    // A non-positive length means "symbol absent" (length 0), matching the
    // reference `initWithLengths:`; `from_lengths` then places only lengths 1..=32.
    let lens: Vec<u32> = lengths
        .iter()
        .map(|&l| if l >= 1 { l as u32 } else { 0 })
        .collect();
    Ok(PrefixCode::from_lengths(&lens, 32, true))
}

/// Write a code length, reporting an overflow (a malformed run) as invalid data.
fn set_length(lengths: &mut [i32], i: usize, v: i32) -> io::Result<()> {
    *lengths
        .get_mut(i)
        .ok_or_else(|| invalid("stuffit13: malformed length table"))? = v;
    Ok(())
}

/// Decode one symbol LSB-first; end of input is a truncated stream.
fn next_symbol<R: Read>(code: &PrefixCode, bits: &mut BitReaderLsb<R>) -> io::Result<i32> {
    code.next_symbol_le(bits)?.ok_or_else(truncated)
}

/// Read an `n`-bit field LSB-first; end of input is a truncated stream.
fn read_bits<R: Read>(bits: &mut BitReaderLsb<R>, n: u8) -> io::Result<u32> {
    bits.read_bits(n)?.ok_or_else(truncated)
}

/// Read a single bit LSB-first; end of input is a truncated stream.
fn read_bit<R: Read>(bits: &mut BitReaderLsb<R>) -> io::Result<bool> {
    bits.read_bit()?.ok_or_else(truncated)
}

// === static / meta tables ====================================================

// Generated from XADMaster's XADStuffIt13Handle.m — do not hand-edit.
// Per-symbol Huffman code lengths for the five built-in static table sets,
// the meta-code, and its code lengths. Values are non-negative.

#[rustfmt::skip]
const FIRST_CODE_LENGTHS_1: [u32; 321] = [
    4, 5, 7, 8, 8, 9, 9, 9, 9, 7, 9, 9, 9, 8, 9, 9,
    9, 9, 9, 9, 9, 9, 9, 10, 9, 9, 10, 10, 9, 10, 9, 9,
    5, 9, 9, 9, 9, 10, 9, 9, 9, 9, 9, 9, 9, 9, 7, 9,
    9, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 8, 9, 9, 8, 8, 9, 9, 9, 9, 9, 9, 9, 7, 8, 9,
    7, 9, 9, 7, 7, 9, 9, 9, 9, 10, 9, 10, 10, 10, 9, 9,
    9, 5, 9, 8, 7, 5, 9, 8, 8, 7, 9, 9, 8, 8, 5, 5,
    7, 10, 5, 8, 5, 8, 9, 9, 9, 9, 9, 10, 9, 9, 10, 9,
    9, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 9, 9, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9, 9, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 9, 10, 9, 5,
    6, 5, 5, 8, 9, 9, 9, 9, 9, 9, 10, 10, 10, 9, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 9, 10, 9, 9, 9, 10, 9, 10, 9, 10, 9, 10, 9,
    10, 10, 10, 9, 10, 9, 10, 10, 9, 9, 9, 6, 9, 9, 10, 9,
    5,
];

#[rustfmt::skip]
const FIRST_CODE_LENGTHS_2: [u32; 321] = [
    4, 7, 7, 8, 7, 8, 8, 8, 8, 7, 8, 7, 8, 7, 9, 8,
    8, 8, 9, 9, 9, 9, 10, 10, 9, 10, 10, 10, 10, 10, 9, 9,
    5, 9, 8, 9, 9, 11, 10, 9, 8, 9, 9, 9, 8, 9, 7, 8,
    8, 8, 9, 9, 9, 9, 9, 10, 9, 9, 9, 10, 9, 9, 10, 9,
    8, 8, 7, 7, 7, 8, 8, 9, 8, 8, 9, 9, 8, 8, 7, 8,
    7, 10, 8, 7, 7, 9, 9, 9, 9, 10, 10, 11, 11, 11, 10, 9,
    8, 6, 8, 7, 7, 5, 7, 7, 7, 6, 9, 8, 6, 7, 6, 6,
    7, 9, 6, 6, 6, 7, 8, 8, 8, 8, 9, 10, 9, 10, 9, 9,
    8, 9, 10, 10, 9, 10, 10, 9, 9, 10, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 11, 10, 10, 10, 10, 10, 10, 10, 11, 10, 11, 10, 10,
    9, 11, 10, 10, 10, 10, 10, 10, 9, 9, 10, 11, 10, 11, 10, 11,
    10, 12, 10, 11, 10, 12, 11, 12, 10, 12, 10, 11, 10, 11, 11, 11,
    9, 10, 11, 11, 11, 12, 12, 10, 10, 10, 11, 11, 10, 11, 10, 10,
    9, 11, 10, 11, 10, 11, 11, 11, 10, 11, 11, 12, 11, 11, 10, 10,
    10, 11, 10, 10, 11, 11, 12, 10, 10, 11, 11, 12, 11, 11, 10, 11,
    9, 12, 10, 11, 11, 11, 10, 11, 10, 11, 10, 11, 9, 10, 9, 7,
    3, 5, 6, 6, 7, 7, 8, 8, 8, 9, 9, 9, 11, 10, 10, 10,
    12, 13, 11, 12, 12, 11, 13, 12, 12, 11, 12, 12, 13, 12, 14, 13,
    14, 13, 15, 13, 14, 15, 15, 14, 13, 15, 15, 14, 15, 14, 15, 15,
    14, 15, 13, 13, 14, 15, 15, 14, 14, 16, 16, 15, 15, 15, 12, 15,
    10,
];

#[rustfmt::skip]
const FIRST_CODE_LENGTHS_3: [u32; 321] = [
    6, 6, 6, 6, 6, 9, 8, 8, 4, 9, 8, 9, 8, 9, 9, 9,
    8, 9, 9, 10, 8, 10, 10, 10, 9, 10, 10, 10, 9, 10, 10, 9,
    9, 9, 8, 10, 9, 10, 9, 10, 9, 10, 9, 10, 9, 9, 8, 9,
    8, 9, 9, 9, 10, 10, 10, 10, 9, 9, 9, 10, 9, 10, 9, 9,
    7, 8, 8, 9, 8, 9, 9, 9, 8, 9, 9, 10, 9, 9, 8, 9,
    8, 9, 8, 8, 8, 9, 9, 9, 9, 9, 10, 10, 10, 10, 10, 9,
    8, 8, 9, 8, 9, 7, 8, 8, 9, 8, 10, 10, 8, 9, 8, 8,
    8, 10, 8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 10, 9,
    7, 9, 9, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10, 9,
    9, 10, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 9, 9, 9, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 9,
    8, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9,
    9, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10, 9, 9,
    9, 10, 10, 10, 10, 10, 10, 9, 9, 10, 9, 9, 8, 9, 8, 9,
    4, 6, 6, 6, 7, 8, 8, 9, 9, 10, 10, 10, 9, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 7, 10,
    10, 10, 7, 10, 10, 7, 7, 7, 7, 7, 6, 7, 10, 7, 7, 10,
    7, 7, 7, 6, 7, 6, 6, 7, 7, 6, 6, 9, 6, 9, 10, 6,
    10,
];

#[rustfmt::skip]
const FIRST_CODE_LENGTHS_4: [u32; 321] = [
    2, 6, 6, 7, 7, 8, 7, 8, 7, 8, 8, 9, 8, 9, 9, 9,
    8, 8, 9, 9, 9, 10, 10, 9, 8, 10, 9, 10, 9, 10, 9, 9,
    6, 9, 8, 9, 9, 10, 9, 9, 9, 10, 9, 9, 9, 9, 8, 8,
    8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 10, 10, 9,
    7, 7, 8, 8, 8, 8, 9, 9, 7, 8, 9, 10, 8, 8, 7, 8,
    8, 10, 8, 8, 8, 9, 8, 9, 9, 10, 9, 11, 10, 11, 9, 9,
    8, 7, 9, 8, 8, 6, 8, 8, 8, 7, 10, 9, 7, 8, 7, 7,
    8, 10, 7, 7, 7, 8, 9, 9, 9, 9, 10, 11, 9, 11, 10, 9,
    7, 9, 10, 10, 10, 11, 11, 10, 10, 11, 10, 10, 10, 11, 11, 10,
    9, 10, 10, 11, 10, 11, 10, 11, 10, 10, 10, 11, 10, 11, 10, 10,
    9, 10, 10, 11, 10, 10, 10, 10, 9, 10, 10, 10, 10, 11, 10, 11,
    10, 11, 10, 11, 11, 11, 10, 12, 10, 11, 10, 11, 10, 11, 11, 10,
    8, 10, 10, 11, 10, 11, 11, 11, 10, 11, 10, 11, 10, 11, 11, 11,
    9, 10, 11, 11, 10, 11, 11, 11, 10, 11, 11, 11, 10, 10, 10, 10,
    10, 11, 10, 10, 11, 11, 10, 10, 9, 11, 10, 10, 11, 11, 10, 10,
    10, 11, 10, 10, 10, 10, 10, 10, 9, 11, 10, 10, 8, 10, 8, 6,
    5, 6, 6, 7, 7, 8, 8, 8, 9, 10, 11, 10, 10, 11, 11, 12,
    12, 10, 11, 12, 12, 12, 12, 13, 13, 13, 13, 13, 12, 13, 13, 15,
    14, 12, 14, 15, 16, 12, 12, 13, 15, 14, 16, 15, 17, 18, 15, 17,
    16, 15, 15, 15, 15, 13, 13, 10, 14, 12, 13, 17, 17, 18, 10, 17,
    4,
];

#[rustfmt::skip]
const FIRST_CODE_LENGTHS_5: [u32; 321] = [
    7, 9, 9, 9, 9, 9, 9, 9, 9, 8, 9, 9, 9, 7, 9, 9,
    9, 9, 9, 9, 9, 9, 9, 10, 9, 10, 9, 10, 9, 10, 9, 9,
    5, 9, 7, 9, 9, 9, 9, 9, 7, 7, 7, 9, 7, 7, 8, 7,
    8, 8, 7, 7, 9, 9, 9, 9, 7, 7, 7, 9, 9, 9, 9, 9,
    9, 7, 9, 7, 7, 7, 7, 9, 9, 7, 9, 9, 7, 7, 7, 7,
    7, 9, 7, 8, 7, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 7, 8, 7, 7, 7, 8, 8, 6, 7, 9, 7, 7, 8, 7, 5,
    6, 9, 5, 7, 5, 6, 7, 7, 9, 8, 9, 9, 9, 9, 9, 9,
    9, 9, 10, 9, 10, 10, 10, 9, 9, 10, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10,
    9, 10, 10, 10, 9, 9, 10, 9, 9, 9, 9, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 9, 10, 10, 10, 9, 9, 9, 10, 10, 10, 10, 10,
    9, 10, 9, 10, 10, 9, 10, 10, 9, 10, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 9, 10, 9, 10, 9, 10, 10, 9,
    5, 6, 8, 8, 7, 7, 7, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 5, 10, 8, 9, 8,
    9,
];

#[rustfmt::skip]
const SECOND_CODE_LENGTHS_1: [u32; 321] = [
    4, 5, 6, 6, 7, 7, 6, 7, 7, 7, 6, 8, 7, 8, 8, 8,
    8, 9, 6, 9, 8, 9, 8, 9, 9, 9, 8, 10, 5, 9, 7, 9,
    6, 9, 8, 10, 9, 10, 8, 8, 9, 9, 7, 9, 8, 9, 8, 9,
    8, 8, 6, 9, 9, 8, 8, 9, 9, 10, 8, 9, 9, 10, 8, 10,
    8, 8, 8, 8, 8, 9, 7, 10, 6, 9, 9, 11, 7, 8, 8, 9,
    8, 10, 7, 8, 6, 9, 10, 9, 9, 10, 8, 11, 9, 11, 9, 10,
    9, 8, 9, 8, 8, 8, 8, 10, 9, 9, 10, 10, 8, 9, 8, 8,
    8, 11, 9, 8, 8, 9, 9, 10, 8, 11, 10, 10, 8, 10, 9, 10,
    8, 9, 9, 11, 9, 11, 9, 10, 10, 11, 10, 12, 9, 12, 10, 11,
    10, 11, 9, 10, 10, 11, 10, 11, 10, 11, 10, 11, 10, 10, 10, 9,
    9, 9, 8, 7, 6, 8, 11, 11, 9, 12, 10, 12, 9, 11, 11, 11,
    10, 12, 11, 11, 10, 12, 10, 11, 10, 10, 10, 11, 10, 11, 11, 11,
    9, 12, 10, 12, 11, 12, 10, 11, 10, 12, 11, 12, 11, 12, 11, 12,
    10, 12, 11, 12, 11, 11, 10, 12, 10, 11, 10, 12, 10, 12, 10, 12,
    10, 11, 11, 11, 10, 11, 11, 11, 10, 12, 11, 12, 10, 10, 11, 11,
    9, 12, 11, 12, 10, 11, 10, 12, 10, 11, 10, 12, 10, 11, 10, 7,
    5, 4, 6, 6, 7, 7, 7, 8, 8, 7, 7, 6, 8, 6, 7, 7,
    9, 8, 9, 9, 10, 11, 11, 11, 12, 11, 10, 11, 12, 11, 12, 11,
    12, 12, 12, 12, 11, 12, 12, 11, 12, 11, 12, 11, 13, 11, 12, 10,
    13, 10, 14, 14, 13, 14, 15, 14, 16, 15, 15, 18, 18, 18, 9, 18,
    8,
];

#[rustfmt::skip]
const SECOND_CODE_LENGTHS_2: [u32; 321] = [
    5, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 8, 7, 8, 7, 7,
    7, 8, 8, 8, 8, 9, 8, 9, 8, 9, 9, 9, 7, 9, 8, 8,
    6, 9, 8, 9, 8, 9, 8, 9, 8, 9, 8, 9, 8, 9, 8, 8,
    8, 8, 8, 9, 8, 9, 8, 9, 9, 10, 8, 10, 8, 9, 9, 8,
    8, 8, 7, 8, 8, 9, 8, 9, 7, 9, 8, 10, 8, 9, 8, 9,
    8, 9, 8, 8, 8, 9, 9, 9, 9, 10, 9, 11, 9, 10, 9, 10,
    8, 8, 8, 9, 8, 8, 8, 9, 9, 8, 9, 10, 8, 9, 8, 8,
    8, 11, 8, 7, 8, 9, 9, 9, 9, 10, 9, 10, 9, 10, 9, 8,
    8, 9, 9, 10, 9, 10, 9, 10, 8, 10, 9, 10, 9, 11, 10, 11,
    9, 11, 10, 10, 10, 11, 9, 11, 9, 10, 9, 11, 9, 11, 10, 10,
    9, 10, 9, 9, 8, 10, 9, 11, 9, 9, 9, 11, 10, 11, 9, 11,
    9, 11, 9, 11, 10, 11, 10, 11, 10, 11, 9, 10, 10, 11, 10, 10,
    8, 10, 9, 10, 10, 11, 9, 11, 9, 10, 10, 11, 9, 10, 10, 9,
    9, 10, 9, 10, 9, 10, 9, 10, 9, 11, 9, 11, 10, 10, 9, 10,
    9, 11, 9, 11, 9, 11, 9, 10, 9, 11, 9, 11, 9, 11, 9, 10,
    8, 11, 9, 10, 9, 10, 9, 10, 8, 10, 8, 9, 8, 9, 8, 7,
    4, 4, 5, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 7, 8, 8,
    9, 9, 10, 10, 10, 10, 10, 10, 11, 11, 10, 10, 12, 11, 11, 12,
    12, 11, 12, 12, 11, 12, 12, 12, 12, 12, 12, 11, 12, 11, 13, 12,
    13, 12, 13, 14, 14, 14, 15, 13, 14, 13, 14, 18, 18, 17, 7, 16,
    9,
];

#[rustfmt::skip]
const SECOND_CODE_LENGTHS_3: [u32; 321] = [
    5, 6, 6, 6, 6, 7, 7, 7, 6, 8, 7, 8, 7, 9, 8, 8,
    7, 7, 8, 9, 9, 9, 9, 10, 8, 9, 9, 10, 8, 10, 9, 8,
    6, 10, 8, 10, 8, 10, 9, 9, 9, 9, 9, 10, 9, 9, 8, 9,
    8, 9, 8, 9, 9, 10, 9, 10, 9, 9, 8, 10, 9, 11, 10, 8,
    8, 8, 8, 9, 7, 9, 9, 10, 8, 9, 8, 11, 9, 10, 9, 10,
    8, 9, 9, 9, 9, 8, 9, 9, 10, 10, 10, 12, 10, 11, 10, 10,
    8, 9, 9, 9, 8, 9, 8, 8, 10, 9, 10, 11, 8, 10, 9, 9,
    8, 12, 8, 9, 9, 9, 9, 8, 9, 10, 9, 12, 10, 10, 10, 8,
    7, 11, 10, 9, 10, 11, 9, 11, 7, 11, 10, 12, 10, 12, 10, 11,
    9, 11, 9, 12, 10, 12, 10, 12, 10, 9, 11, 12, 10, 12, 10, 11,
    9, 10, 9, 10, 9, 11, 11, 12, 9, 10, 8, 12, 11, 12, 9, 12,
    10, 12, 10, 13, 10, 12, 10, 12, 10, 12, 10, 9, 10, 12, 10, 9,
    8, 11, 10, 12, 10, 12, 10, 12, 10, 11, 10, 12, 8, 12, 10, 11,
    10, 10, 10, 12, 9, 11, 10, 12, 10, 12, 11, 12, 10, 9, 10, 12,
    9, 10, 10, 12, 10, 11, 10, 11, 10, 12, 8, 12, 9, 12, 8, 12,
    8, 11, 10, 11, 10, 11, 9, 10, 8, 10, 9, 9, 8, 9, 8, 7,
    4, 3, 5, 5, 6, 5, 6, 6, 7, 7, 8, 8, 8, 7, 7, 7,
    9, 8, 9, 9, 11, 9, 11, 9, 8, 9, 9, 11, 12, 11, 12, 12,
    13, 13, 12, 13, 14, 13, 14, 13, 14, 13, 13, 13, 12, 13, 13, 12,
    13, 13, 14, 14, 13, 13, 14, 14, 14, 14, 15, 18, 17, 18, 8, 16,
    10,
];

#[rustfmt::skip]
const SECOND_CODE_LENGTHS_4: [u32; 321] = [
    4, 5, 6, 6, 6, 6, 7, 7, 6, 7, 7, 9, 6, 8, 8, 7,
    7, 8, 8, 8, 6, 9, 8, 8, 7, 9, 8, 9, 8, 9, 8, 9,
    6, 9, 8, 9, 8, 10, 9, 9, 8, 10, 8, 10, 8, 9, 8, 9,
    8, 8, 7, 9, 9, 9, 9, 9, 8, 10, 9, 10, 9, 10, 9, 8,
    7, 8, 9, 9, 8, 9, 9, 9, 7, 10, 9, 10, 9, 9, 8, 9,
    8, 9, 8, 8, 8, 9, 9, 10, 9, 9, 8, 11, 9, 11, 10, 10,
    8, 8, 10, 8, 8, 9, 9, 9, 10, 9, 10, 11, 9, 9, 9, 9,
    8, 9, 8, 8, 8, 10, 10, 9, 9, 8, 10, 11, 10, 11, 11, 9,
    8, 9, 10, 11, 9, 10, 11, 11, 9, 12, 10, 10, 10, 12, 11, 11,
    9, 11, 11, 12, 9, 11, 9, 10, 10, 10, 10, 12, 9, 11, 10, 11,
    9, 11, 11, 11, 10, 11, 11, 12, 9, 10, 10, 12, 11, 11, 10, 11,
    9, 11, 10, 11, 10, 11, 9, 11, 11, 9, 8, 11, 10, 11, 11, 10,
    7, 12, 11, 11, 11, 11, 11, 12, 10, 12, 11, 13, 11, 10, 12, 11,
    10, 11, 10, 11, 10, 11, 11, 11, 10, 12, 11, 11, 10, 11, 10, 10,
    10, 11, 10, 12, 11, 12, 10, 11, 9, 11, 10, 11, 10, 11, 10, 12,
    9, 11, 11, 11, 9, 11, 10, 10, 9, 11, 10, 10, 9, 10, 9, 7,
    4, 5, 5, 5, 6, 6, 7, 6, 8, 7, 8, 9, 9, 7, 8, 8,
    10, 9, 10, 10, 12, 10, 11, 11, 11, 11, 10, 11, 12, 11, 11, 11,
    11, 11, 13, 12, 11, 12, 13, 12, 12, 12, 13, 11, 9, 12, 13, 7,
    13, 11, 13, 11, 10, 11, 13, 15, 15, 12, 14, 15, 15, 15, 6, 15,
    5,
];

#[rustfmt::skip]
const SECOND_CODE_LENGTHS_5: [u32; 321] = [
    8, 10, 11, 11, 11, 12, 11, 11, 12, 6, 11, 12, 10, 5, 12, 12,
    12, 12, 12, 12, 12, 13, 13, 14, 13, 13, 12, 13, 12, 13, 12, 15,
    4, 10, 7, 9, 11, 11, 10, 9, 6, 7, 8, 9, 6, 7, 6, 7,
    8, 7, 7, 8, 8, 8, 8, 8, 8, 9, 8, 7, 10, 9, 10, 10,
    11, 7, 8, 6, 7, 8, 8, 9, 8, 7, 10, 10, 8, 7, 8, 8,
    7, 10, 7, 6, 7, 9, 9, 8, 11, 11, 11, 10, 11, 11, 11, 8,
    11, 6, 7, 6, 6, 6, 6, 8, 7, 6, 10, 9, 6, 7, 6, 6,
    7, 10, 6, 5, 6, 7, 7, 7, 10, 8, 11, 9, 13, 7, 14, 16,
    12, 14, 14, 15, 15, 16, 16, 14, 15, 15, 15, 15, 15, 15, 15, 15,
    14, 15, 13, 14, 14, 16, 15, 17, 14, 17, 15, 17, 12, 14, 13, 16,
    12, 17, 13, 17, 14, 13, 13, 14, 14, 12, 13, 15, 15, 14, 15, 17,
    14, 17, 15, 14, 15, 16, 12, 16, 15, 14, 15, 16, 15, 16, 17, 17,
    15, 15, 17, 17, 13, 14, 15, 15, 13, 12, 16, 16, 17, 14, 15, 16,
    15, 15, 13, 13, 15, 13, 16, 17, 15, 17, 17, 17, 16, 17, 14, 17,
    14, 16, 15, 17, 15, 15, 14, 17, 15, 17, 15, 16, 15, 15, 16, 16,
    14, 17, 17, 15, 15, 16, 15, 17, 15, 14, 16, 16, 16, 16, 16, 12,
    4, 4, 5, 5, 6, 6, 6, 7, 7, 7, 8, 8, 8, 8, 9, 9,
    9, 9, 9, 10, 10, 10, 11, 10, 11, 11, 11, 11, 11, 12, 12, 12,
    13, 13, 12, 13, 12, 14, 14, 12, 13, 13, 13, 13, 14, 12, 13, 13,
    14, 14, 14, 13, 14, 14, 15, 15, 13, 15, 13, 17, 17, 17, 9, 17,
    7,
];

#[rustfmt::skip]
const OFFSET_CODE_LENGTHS_1: [u32; 11] = [
    5, 6, 3, 3, 3, 3, 3, 3, 3, 4, 6,
];

#[rustfmt::skip]
const OFFSET_CODE_LENGTHS_2: [u32; 13] = [
    5, 6, 4, 4, 3, 3, 3, 3, 3, 4, 4, 4, 6,
];

#[rustfmt::skip]
const OFFSET_CODE_LENGTHS_3: [u32; 14] = [
    6, 7, 4, 4, 3, 3, 3, 3, 3, 4, 4, 4, 5, 7,
];

#[rustfmt::skip]
const OFFSET_CODE_LENGTHS_4: [u32; 11] = [
    3, 6, 5, 4, 2, 3, 3, 3, 4, 4, 6,
];

#[rustfmt::skip]
const OFFSET_CODE_LENGTHS_5: [u32; 11] = [
    6, 7, 7, 6, 4, 3, 2, 2, 3, 3, 6,
];

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

const FIRST_CODE_LENGTHS: [&[u32]; 5] = [
    &FIRST_CODE_LENGTHS_1,
    &FIRST_CODE_LENGTHS_2,
    &FIRST_CODE_LENGTHS_3,
    &FIRST_CODE_LENGTHS_4,
    &FIRST_CODE_LENGTHS_5,
];
const SECOND_CODE_LENGTHS: [&[u32]; 5] = [
    &SECOND_CODE_LENGTHS_1,
    &SECOND_CODE_LENGTHS_2,
    &SECOND_CODE_LENGTHS_3,
    &SECOND_CODE_LENGTHS_4,
    &SECOND_CODE_LENGTHS_5,
];
const OFFSET_CODE_LENGTHS: [&[u32]; 5] = [
    &OFFSET_CODE_LENGTHS_1,
    &OFFSET_CODE_LENGTHS_2,
    &OFFSET_CODE_LENGTHS_3,
    &OFFSET_CODE_LENGTHS_4,
    &OFFSET_CODE_LENGTHS_5,
];

#[cfg(test)]
mod tests {
    use super::*;
    use newtua_testutil::BitWriter;
    use std::collections::HashMap;

    // === mirror encoder ======================================================
    //
    // An independent inverse of the decoder. It builds method-13 streams with a
    // dynamic header (mode 0, `secondcode` shared with `firstcode` so a single
    // table covers both contexts) and fixed-length canonical codes (so the Kraft
    // sum never exceeds 1 for any symbol set). A separate helper emits a static
    // (mode 1) literal stream.

    /// Canonical code assignment, replicating `PrefixCode::from_lengths` with
    /// `shortest_code_is_zeros = true`: shortest codes first, high-bit-first.
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

    /// Write a canonical code value high-bit-first (the order the decoder's
    /// tree, built by `add_value_high_bit_first`, walks it).
    fn write_canonical(w: &mut BitWriter, code: u32, length: u32) {
        for bitpos in (0..length).rev() {
            w.bit((code >> bitpos) & 1 != 0);
        }
    }

    /// Emit one meta-symbol (low-bit-first, the way the meta-code is decoded).
    fn write_meta(w: &mut BitWriter, sym: usize) {
        w.bits(META_CODES[sym], META_CODE_LENGTHS[sym]);
    }

    /// Emit the meta-stream that makes `parse_code` reproduce `lengths`: one
    /// "default" symbol per present length, the "no code" symbol (31) per absent.
    fn write_length_table(w: &mut BitWriter, lengths: &[u32]) {
        for &l in lengths {
            if l == 0 {
                write_meta(w, 31);
            } else {
                write_meta(w, (l - 1) as usize);
            }
        }
    }

    /// Smallest `bits` with `2.pow(bits) >= n`.
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

    /// The length symbol for a match length.
    fn length_symbol(len: usize) -> usize {
        if len <= 64 {
            0x100 + (len - 3)
        } else if len - 65 < 1024 {
            0x13e
        } else {
            0x13f
        }
    }

    /// `(bitlength symbol, extra value, extra bit count)` for a distance.
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

    /// Build a dynamic-header method-13 stream from a sequence of ops.
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
        // val & 0x07 == 7  ->  offset table size 10 + 7.
        const OFF_SIZE: usize = 17;
        let mut off_lengths = vec![0u32; OFF_SIZE];
        for &s in &off_syms {
            off_lengths[s] = off_bits;
        }

        let first_codes = canonical_codes(&first_lengths);
        let off_codes = canonical_codes(&off_lengths);

        let mut w = BitWriter::default();
        // Header: high nibble 0 (dynamic), 0x08 (share second=first), 0x07.
        w.bits(0x0F, 8);
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

    /// Build a static-header (mode 1) stream of literals only.
    fn encode_static_literals(content: &[u8]) -> Vec<u8> {
        let codes = canonical_codes(FIRST_CODE_LENGTHS[0]);
        let mut w = BitWriter::default();
        w.bits(0x10, 8); // high nibble 1 -> static table set 0
        for &b in content {
            let (c, l) = codes[&(b as usize)];
            write_canonical(&mut w, c, l);
        }
        w.finish()
    }

    /// The bytes a sequence of ops expands to (the oracle's expected output).
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

    fn roundtrip(ops: &[Op]) {
        let expected = expand(ops);
        let stream = encode_dynamic(ops);
        let got = decode(&stream, expected.len()).unwrap();
        assert_eq!(got, expected);
    }

    // === dynamic-header round-trips ==========================================

    #[test]
    fn dynamic_literals_only() {
        let ops: Vec<Op> = b"hello, dynamic StuffIt world"
            .iter()
            .map(|&b| Op::Lit(b))
            .collect();
        roundtrip(&ops);
    }

    #[test]
    fn dynamic_literal_then_match() {
        // Four literals, then a back-reference copying them (distance 4).
        let ops = [
            Op::Lit(b'a'),
            Op::Lit(b'b'),
            Op::Lit(b'c'),
            Op::Lit(b'd'),
            Op::Match { dist: 4, len: 4 },
        ];
        roundtrip(&ops);
    }

    #[test]
    fn dynamic_match_distance_extra_bits() {
        // Distance 5 -> bitlength 3, so the offset carries extra bits.
        let ops = [
            Op::Lit(b'a'),
            Op::Lit(b'b'),
            Op::Lit(b'c'),
            Op::Lit(b'd'),
            Op::Lit(b'e'),
            Op::Match { dist: 5, len: 5 },
        ];
        roundtrip(&ops);
    }

    #[test]
    fn dynamic_overlapping_run() {
        // Distance 1, long length -> a run-length repeat of one byte.
        let ops = [Op::Lit(b'z'), Op::Match { dist: 1, len: 30 }];
        roundtrip(&ops);
    }

    #[test]
    fn dynamic_length_short_branch() {
        // len 64 is the largest short (val - 0x100 + 3) length.
        let ops = [Op::Lit(b'p'), Op::Match { dist: 1, len: 64 }];
        roundtrip(&ops);
    }

    #[test]
    fn dynamic_length_0x13e_branch() {
        // len 100 -> 100 - 65 = 35 < 1024, the 10-extra-bit branch.
        let ops = [Op::Lit(b'q'), Op::Match { dist: 1, len: 100 }];
        roundtrip(&ops);
    }

    #[test]
    fn dynamic_length_0x13f_branch() {
        // len 1089 -> 1089 - 65 = 1024, the 15-extra-bit branch.
        let ops = [Op::Lit(b'w'), Op::Match { dist: 1, len: 1089 }];
        roundtrip(&ops);
    }

    // === static-header round-trip ============================================

    #[test]
    fn static_table_literals_roundtrip() {
        let content = b"Static StuffIt 13 table, literals only!";
        let stream = encode_static_literals(content);
        let got = decode(&stream, content.len()).unwrap();
        assert_eq!(got, content);
    }

    // === errors and edge cases ===============================================

    #[test]
    fn zero_outlen_returns_empty_without_parsing() {
        // No header is read at all, so even an otherwise-illegal byte is ignored.
        assert_eq!(decode(&[], 0).unwrap(), Vec::<u8>::new());
        assert_eq!(decode(&[0x60], 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn illegal_table_selector_is_invalid_data() {
        // High nibble 6 (>= 6) is illegal.
        let err = decode(&[0x60], 5).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn truncated_stream_is_unexpected_eof() {
        // Drop the tail so the 15 extra length bits cannot be read.
        let ops = [Op::Lit(b'a'), Op::Match { dist: 1, len: 1089 }];
        let mut stream = encode_dynamic(&ops);
        stream.truncate(stream.len() - 2);
        let err = decode(&stream, expand(&ops).len()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
