// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! StuffItX Darkhorse codec (`XADStuffItXDarkhorseHandle`), compression method 2.
//!
//! A windowed LZSS coder where every decision (literal/match flag, literal
//! bits, lengths, distances, recency repeats) is drawn from the shared
//! carryless range coder (`rangecoder.rs`) through adaptive per-context
//! weights. A faithful port of `XADStuffItXDarkhorseHandle.m`.

use std::io;

use newtua_common::lzss::LzssWindow;

use super::rangecoder::RangeCoder;

fn truncated() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "sitx: darkhorse stream truncated",
    )
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// All weights start at the midpoint `0x800` (out of the
/// `next_bit_with_weight2` scale of `0x1000`); `resetLZSSHandle` (`.m:19-59`).
const INITIAL_WEIGHT: u32 = 0x800;

/// The window size `decode()` actually uses for a given header byte
/// (`XADStuffItXParser.m:136-137`): `1<<window_byte`, floored to 1 MiB.
/// `pub(crate)` so Blend's tests (`blend.rs`) can share it when sizing a
/// Darkhorse sub-block fixture through this module's mirror `tests::Encoder`.
pub(crate) fn windowsize_for(window_byte: u8) -> usize {
    (1usize << window_byte).max(0x100000)
}

/// `updateDistanceMemoryWithOldIndex:distance:` (`.m:207-211`): MTF-style
/// shift of the recently used raw distances, shared by the decoder and its
/// test-only mirror encoder.
fn mtf_shift_distance(table: &mut [i64; 4], old_index: usize, distance: i64) {
    for i in (1..=old_index).rev() {
        table[i] = table[i - 1];
    }
    table[0] = distance;
}

/// The next-literal guess position (`.m:100`): `pos-offs-1+len%(offs+1)`,
/// shared by the decoder and its test-only mirror encoder.
fn next_guess_pos(pos: i64, offs: i64, len: i64) -> i64 {
    pos - offs - 1 + len % (offs + 1)
}

/// `readSymbolWithWeights:numberOfBits:` (`.m:233-237`): decode `num` bits one
/// at a time, each conditioned on the accumulator built so far (`weights[val]`
/// doubles as a binary trie of contexts), returning the unsigned value with
/// its leading 1 bit removed.
fn read_symbol(coder: &mut RangeCoder, weights: &mut [u32], num: u32) -> i32 {
    let mut val: u32 = 1;
    for _ in 0..num {
        let bit = coder.next_bit_with_weight2(&mut weights[val as usize]);
        val = (val << 1) | bit;
    }
    val as i32 - (1i32 << num)
}

/// `offsettable[64]` (`.m:148-158`): the base distance for each 6-bit distance
/// symbol >= 4.
const OFFSET_TABLE: [i64; 64] = [
    0, 1, 2, 3, 4, 6, 8, 0xc, 0x10, 0x18, 0x20, 0x30, 0x40, 0x60, 0x80, 0xc0, 0x100, 0x180, 0x200,
    0x300, 0x400, 0x600, 0x800, 0xc00, 0x1000, 0x1800, 0x2000, 0x3000, 0x4000, 0x6000, 0x8000,
    0xc000, 0x10000, 0x18000, 0x20000, 0x30000, 0x40000, 0x60000, 0x80000, 0xc0000, 0x100000,
    0x180000, 0x200000, 0x300000, 0x400000, 0x600000, 0x800000, 0xc00000, 0x1000000, 0x1800000,
    0x2000000, 0x3000000, 0x4000000, 0x6000000, 0x8000000, 0xc000000, 0x10000000, 0x18000000,
    0x20000000, 0x30000000, 0, 0, 0, 0,
];

/// `bitlengthtable[64]` (`.m:159-164`): number of extra bits for each distance
/// symbol >= 4 (split between raw high bits and the low-bit weighted model for
/// symbols >= 14; see `read_distance`).
const BITLENGTH_TABLE: [u32; 64] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 17, 17, 18, 18, 19, 19, 20, 20, 21, 21, 22, 22, 23, 23, 24, 24, 25,
    25, 26, 26, 27, 27, 28, 28, 0, 0, 0, 0,
];

/// One decoded LZSS token (`nextLiteralOrOffset:andLength:atPosition:`'s three
/// possible outcomes: a literal byte, `XADLZSSMatch`, or `XADLZSSEnd`).
enum Symbol {
    Literal(u8),
    Match { offset: usize, length: usize },
    End,
}

/// `XADStuffItXDarkhorseHandle`'s decoder state: the range coder, the LZSS
/// window, the "next literal guess" and every adaptive weight table.
struct Darkhorse<'a> {
    coder: RangeCoder<'a>,
    window: LzssWindow,
    /// `next` (`.m:8`): a predicted next literal byte, or `-1` when there is
    /// none (reset after every literal, set by every match).
    next: i32,
    flagweights: [u32; 4],
    flagweight2: u32,
    litweights: Box<[[u32; 256]; 16]>,
    litweights2: Box<[[[u32; 2]; 256]; 16]>,
    recencyweight1: u32,
    recencyweight2: u32,
    recencyweight3: u32,
    recencyweights: [u32; 4],
    lenweight: u32,
    shortweights: [[u32; 16]; 4],
    longweights: [u32; 256],
    distlenweights: [[u32; 64]; 4],
    distweights: [[u32; 32]; 10],
    distlowbitweights: [u32; 16],
    /// `distancetable[4]` (`.m:16`): MTF-ordered recently used raw distances
    /// (i.e. window distance minus one).
    distancetable: [i64; 4],
}

impl<'a> Darkhorse<'a> {
    /// `resetLZSSHandle` (`.m:19-59`).
    fn new(input: &'a [u8], window_size: usize) -> Self {
        Darkhorse {
            coder: RangeCoder::new(input, false, 0),
            window: LzssWindow::new(window_size),
            next: -1,
            flagweights: [INITIAL_WEIGHT; 4],
            flagweight2: INITIAL_WEIGHT,
            litweights: Box::new([[INITIAL_WEIGHT; 256]; 16]),
            litweights2: Box::new([[[INITIAL_WEIGHT; 2]; 256]; 16]),
            recencyweight1: INITIAL_WEIGHT,
            recencyweight2: INITIAL_WEIGHT,
            recencyweight3: INITIAL_WEIGHT,
            recencyweights: [INITIAL_WEIGHT; 4],
            lenweight: INITIAL_WEIGHT,
            shortweights: [[INITIAL_WEIGHT; 16]; 4],
            longweights: [INITIAL_WEIGHT; 256],
            distlenweights: [[INITIAL_WEIGHT; 64]; 4],
            distweights: [[INITIAL_WEIGHT; 32]; 10],
            distlowbitweights: [INITIAL_WEIGHT; 16],
            distancetable: [0; 4],
        }
    }

    /// `readLiteralWithPrevious:next:` (`.m:106-132`).
    fn read_literal(&mut self, prev: u8, guess: i32) -> u8 {
        let row = (prev / 16) as usize;
        let mut val: u32 = 1;
        if guess == -1 {
            while val < 0x100 {
                let bit = self
                    .coder
                    .next_bit_with_weight2(&mut self.litweights[row][val as usize]);
                val = (val << 1) | bit;
            }
        } else {
            let mut g = guess as u32;
            while val < 0x100 {
                let gbit = (g >> 7) & 1;
                let bit = self
                    .coder
                    .next_bit_with_weight2(&mut self.litweights2[row][val as usize][gbit as usize]);
                val = (val << 1) | bit;
                if bit != gbit {
                    break;
                }
                g <<= 1;
            }
            while val < 0x100 {
                let bit = self
                    .coder
                    .next_bit_with_weight2(&mut self.litweights[row][val as usize]);
                val = (val << 1) | bit;
            }
        }
        (val & 0xff) as u8
    }

    /// `readLengthWithIndex:` (`.m:134-144`).
    fn read_length(&mut self, index: usize) -> i32 {
        if self.coder.next_bit_with_weight2(&mut self.lenweight) == 0 {
            read_symbol(&mut self.coder, &mut self.shortweights[index], 4)
        } else {
            read_symbol(&mut self.coder, &mut self.longweights, 8) + 16
        }
    }

    /// `readDistanceWithLength:` (`.m:146-183`). `len` is the already `+2`'d
    /// match length.
    fn read_distance(&mut self, len: i32) -> i64 {
        let mut lenidx = len - 2;
        if lenidx > 3 {
            lenidx = 3;
        }
        let sym = read_symbol(
            &mut self.coder,
            &mut self.distlenweights[lenidx as usize],
            6,
        ) as usize;

        if sym < 4 {
            sym as i64
        } else if sym < 14 {
            OFFSET_TABLE[sym]
                + i64::from(read_symbol(
                    &mut self.coder,
                    &mut self.distweights[sym - 4],
                    BITLENGTH_TABLE[sym],
                ))
        } else {
            let numbits = BITLENGTH_TABLE[sym];
            let mut val: i64 = 0;
            for i in (4..numbits).rev() {
                val |= i64::from(self.coder.next_bit()) << i;
            }
            val + OFFSET_TABLE[sym]
                + i64::from(read_symbol(&mut self.coder, &mut self.distlowbitweights, 4))
        }
    }

    /// `readRecencyWithIndex:` (`.m:185-198`). Returns `-1` for "repeat the
    /// most recent distance at length 1", else a `distancetable` index.
    fn read_recency(&mut self, index: usize) -> i32 {
        if self.coder.next_bit_with_weight2(&mut self.recencyweight1) == 0 {
            if self
                .coder
                .next_bit_with_weight2(&mut self.recencyweights[index])
                == 0
            {
                -1
            } else {
                0
            }
        } else if self.coder.next_bit_with_weight2(&mut self.recencyweight2) == 0 {
            1
        } else if self.coder.next_bit_with_weight2(&mut self.recencyweight3) == 0 {
            2
        } else {
            3
        }
    }

    /// `nextLiteralOrOffset:andLength:atPosition:` (`.m:61-104`).
    fn next_literal_or_offset(&mut self, pos: i64) -> Symbol {
        let idx = (pos & 3) as usize;
        if self.coder.next_bit_with_weight2(&mut self.flagweights[idx]) == 0 {
            let prev = self.window.byte_at(pos - 1);
            let guess = self.next;
            let byte = self.read_literal(prev, guess);
            self.next = -1;
            Symbol::Literal(byte)
        } else {
            let len: i64;
            let offs: i64;
            if self.coder.next_bit_with_weight2(&mut self.flagweight2) == 0 {
                let l = self.read_length(idx) + 2;
                if l == 0x111 {
                    return Symbol::End;
                }
                offs = self.read_distance(l);
                mtf_shift_distance(&mut self.distancetable, 3, offs);
                len = i64::from(l);
            } else {
                let recency = self.read_recency(idx);
                if recency == -1 {
                    offs = self.distancetable[0];
                    len = 1;
                } else {
                    let o = self.distancetable[recency as usize];
                    mtf_shift_distance(&mut self.distancetable, recency as usize, o);
                    len = i64::from(self.read_length(idx) + 2);
                    offs = o;
                }
            }

            self.next = i32::from(self.window.byte_at(next_guess_pos(pos, offs, len)));

            Symbol::Match {
                offset: (offs + 1) as usize,
                length: len as usize,
            }
        }
    }
}

/// Decode a Darkhorse-compressed stream, also reporting how many bytes of
/// `blocks` were actually consumed — needed by Blend (method 4) to
/// resynchronize its cursor past this sub-block
/// (`CSInputSynchronizeFileOffset`, `XADStuffItXBlendHandle.m:111`).
///
/// `blocks` is the block layer's already unwrapped output
/// (`p2::read_block_stream`), still carrying the two leading bytes the
/// container reads before the range-coded body: the window-size exponent
/// (`blocks[0]`) and one skipped byte (`blocks[1]`,
/// `CSInputSkipBytes(input,1)` inside `resetLZSSHandle`) — see
/// `XADStuffItXParser.m:135-142` and `.m:57-58`. `size` is only used to know
/// when to stop; the stream may also end early via the `len==0x111` marker.
pub(crate) fn decode_framed(blocks: &[u8], size: usize) -> io::Result<(Vec<u8>, usize)> {
    let window_byte = *blocks.first().ok_or_else(truncated)?;
    blocks.get(1).ok_or_else(truncated)?;
    if window_byte >= 31 {
        // Not reachable from a well-formed archive (a >1 GiB window); reject
        // rather than let `1 << window_byte` overflow/panic on hostile input.
        return Err(invalid("sitx: darkhorse window size exponent too large"));
    }
    let mut dh = Darkhorse::new(&blocks[2..], windowsize_for(window_byte));
    let mut out = Vec::with_capacity(size);
    let mut pos: i64 = 0;
    while (pos as usize) < size {
        match dh.next_literal_or_offset(pos) {
            Symbol::Literal(b) => {
                dh.window.emit_literal(b, &mut out);
                pos += 1;
            }
            Symbol::Match { offset, length } => {
                dh.window.emit_match(offset, length, &mut out);
                pos += length as i64;
            }
            Symbol::End => break,
        }
    }
    let consumed = 2 + dh.coder.position();
    Ok((out, consumed))
}

/// Decode a Darkhorse-compressed stream, discarding the consumed count (used
/// by the container's top-level dispatch, which already knows its stream's
/// full length).
pub(crate) fn decode(blocks: &[u8], size: usize) -> io::Result<Vec<u8>> {
    decode_framed(blocks, size).map(|(out, _consumed)| out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The mirror encoder for `RangeCoder::new(_, uselow=false, bottom=0)`
    /// (Darkhorse's coder form): `rangecoder.rs`'s own `CarryEncoder` test
    /// helper, promoted to `pub(crate)` so every codec's tests can share one
    /// carry-propagating encoder instead of re-deriving it.
    use super::super::rangecoder::tests::CarryEncoder as BitEncoder;

    /// Mirror of `read_symbol`: encode `value` (already offset by `1<<num`'s
    /// removal, i.e. the same value `read_symbol` would return) as `num` bits,
    /// MSB first, through the same per-context weight trie.
    fn encode_symbol(enc: &mut BitEncoder, weights: &mut [u32], num: u32, value: i32) {
        let mut val: u32 = 1;
        for i in (0..num).rev() {
            let bit = (value as u32 >> i) & 1;
            enc.encode_bit_with_weight2(bit, &mut weights[val as usize]);
            val = (val << 1) | bit;
        }
    }

    #[test]
    fn read_symbol_round_trips_various_values() {
        // 4-bit symbols: every value in range, sharing one weight context
        // (like `shortweights[index]`) across repeated calls, adaptively.
        let values = [0i32, 15, 7, 1, 14, 8, 0, 15];
        let mut enc = BitEncoder::new();
        let mut enc_weights = [0x800u32; 16];
        for &v in &values {
            encode_symbol(&mut enc, &mut enc_weights, 4, v);
        }
        let bytes = enc.finish();

        let mut coder = RangeCoder::new(&bytes, false, 0);
        let mut dec_weights = [0x800u32; 16];
        let decoded: Vec<i32> = values
            .iter()
            .map(|_| read_symbol(&mut coder, &mut dec_weights, 4))
            .collect();
        assert_eq!(decoded, values);
    }

    #[test]
    fn read_symbol_round_trips_eight_bit_values() {
        let values = [0i32, 255, 128, 64, 200, 1];
        let mut enc = BitEncoder::new();
        let mut enc_weights = [0x800u32; 256];
        for &v in &values {
            encode_symbol(&mut enc, &mut enc_weights, 8, v);
        }
        let bytes = enc.finish();

        let mut coder = RangeCoder::new(&bytes, false, 0);
        let mut dec_weights = [0x800u32; 256];
        let decoded: Vec<i32> = values
            .iter()
            .map(|_| read_symbol(&mut coder, &mut dec_weights, 8))
            .collect();
        assert_eq!(decoded, values);
    }

    // === full mirror encoder: inverse of the whole decode() pipeline =========
    //
    // Unlike Cyanide (19c), which skipped a forward encoder because its
    // ternary-model tie-breaks couldn't be guaranteed to match Allume's, task
    // 19d asks for a real round-trip: the LZSS token stream here (literal /
    // new-match / recency-match / end) is exactly what a real Darkhorse
    // encoder must decide too, and there is no tie-break ambiguity in any of
    // the bit paths below — every one is a direct inverse of a `Darkhorse`
    // decode method.

    /// Inverse of `read_distance`: given a target raw distance (`offs`, i.e.
    /// window distance minus one), find the 6-bit symbol and any extra bits
    /// `read_distance` would need to reproduce it. Table ranges are
    /// contiguous for symbols 4..59 (60..63 are the table's unused zero-filled
    /// tail), so a linear scan is enough.
    fn distance_slot(offs: i64) -> (usize, i64, u32) {
        if offs < 4 {
            return (offs as usize, 0, 0);
        }
        for sym in 4..60 {
            let base = OFFSET_TABLE[sym];
            let numbits = BITLENGTH_TABLE[sym];
            let range = 1i64 << numbits;
            if offs < base + range {
                return (sym, offs - base, numbits);
            }
        }
        panic!("distance {offs} out of table range");
    }

    /// Mirrors `Darkhorse`'s full field set plus an LZSS window and position
    /// counter, so it can replay the exact same adaptive-weight and
    /// window-guess bookkeeping the decoder does while emitting bits instead
    /// of reading them. `pub(crate)` (with a few methods below) so Blend's
    /// tests can build a real Darkhorse sub-block fixture instead of
    /// duplicating this bookkeeping.
    pub(crate) struct Encoder {
        bits: BitEncoder,
        window: LzssWindow,
        pos: i64,
        next: i32,
        flagweights: [u32; 4],
        flagweight2: u32,
        litweights: Box<[[u32; 256]; 16]>,
        litweights2: Box<[[[u32; 2]; 256]; 16]>,
        recencyweight1: u32,
        recencyweight2: u32,
        recencyweight3: u32,
        recencyweights: [u32; 4],
        lenweight: u32,
        shortweights: [[u32; 16]; 4],
        longweights: [u32; 256],
        distlenweights: [[u32; 64]; 4],
        distweights: [[u32; 32]; 10],
        distlowbitweights: [u32; 16],
        distancetable: [i64; 4],
        expected: Vec<u8>,
    }

    impl Encoder {
        pub(crate) fn new(window_size: usize) -> Self {
            Encoder {
                bits: BitEncoder::new(),
                window: LzssWindow::new(window_size),
                pos: 0,
                next: -1,
                flagweights: [INITIAL_WEIGHT; 4],
                flagweight2: INITIAL_WEIGHT,
                litweights: Box::new([[INITIAL_WEIGHT; 256]; 16]),
                litweights2: Box::new([[[INITIAL_WEIGHT; 2]; 256]; 16]),
                recencyweight1: INITIAL_WEIGHT,
                recencyweight2: INITIAL_WEIGHT,
                recencyweight3: INITIAL_WEIGHT,
                recencyweights: [INITIAL_WEIGHT; 4],
                lenweight: INITIAL_WEIGHT,
                shortweights: [[INITIAL_WEIGHT; 16]; 4],
                longweights: [INITIAL_WEIGHT; 256],
                distlenweights: [[INITIAL_WEIGHT; 64]; 4],
                distweights: [[INITIAL_WEIGHT; 32]; 10],
                distlowbitweights: [INITIAL_WEIGHT; 16],
                distancetable: [0; 4],
                expected: Vec::new(),
            }
        }

        fn encode_literal_bits(&mut self, row: usize, guess: i32, target: u8) {
            let mut acc: u32 = 1;
            let target = u32::from(target);
            let mut bit_index: i32 = 7;
            if guess != -1 {
                let mut g = guess as u32;
                while acc < 0x100 {
                    let gbit = (g >> 7) & 1;
                    let bit = (target >> bit_index) & 1;
                    self.bits.encode_bit_with_weight2(
                        bit,
                        &mut self.litweights2[row][acc as usize][gbit as usize],
                    );
                    acc = (acc << 1) | bit;
                    bit_index -= 1;
                    if bit != gbit {
                        break;
                    }
                    g <<= 1;
                }
            }
            while acc < 0x100 {
                let bit = (target >> bit_index) & 1;
                self.bits
                    .encode_bit_with_weight2(bit, &mut self.litweights[row][acc as usize]);
                acc = (acc << 1) | bit;
                bit_index -= 1;
            }
        }

        fn encode_length(&mut self, index: usize, value: i32) {
            if value < 16 {
                self.bits.encode_bit_with_weight2(0, &mut self.lenweight);
                encode_symbol(&mut self.bits, &mut self.shortweights[index], 4, value);
            } else {
                self.bits.encode_bit_with_weight2(1, &mut self.lenweight);
                encode_symbol(&mut self.bits, &mut self.longweights, 8, value - 16);
            }
        }

        fn encode_distance(&mut self, len: i32, offs: i64) {
            let mut lenidx = len - 2;
            if lenidx > 3 {
                lenidx = 3;
            }
            let (sym, extra, numbits) = distance_slot(offs);
            encode_symbol(
                &mut self.bits,
                &mut self.distlenweights[lenidx as usize],
                6,
                sym as i32,
            );
            if sym < 4 {
                // no extra bits
            } else if sym < 14 {
                encode_symbol(
                    &mut self.bits,
                    &mut self.distweights[sym - 4],
                    numbits,
                    extra as i32,
                );
            } else {
                for i in (4..numbits).rev() {
                    let bit = ((extra >> i) & 1) as u32;
                    self.bits.encode_bit(bit);
                }
                encode_symbol(
                    &mut self.bits,
                    &mut self.distlowbitweights,
                    4,
                    (extra & 0xf) as i32,
                );
            }
        }

        fn encode_recency(&mut self, index: usize, value: i32) {
            match value {
                -1 => {
                    self.bits
                        .encode_bit_with_weight2(0, &mut self.recencyweight1);
                    self.bits
                        .encode_bit_with_weight2(0, &mut self.recencyweights[index]);
                }
                0 => {
                    self.bits
                        .encode_bit_with_weight2(0, &mut self.recencyweight1);
                    self.bits
                        .encode_bit_with_weight2(1, &mut self.recencyweights[index]);
                }
                1 => {
                    self.bits
                        .encode_bit_with_weight2(1, &mut self.recencyweight1);
                    self.bits
                        .encode_bit_with_weight2(0, &mut self.recencyweight2);
                }
                2 => {
                    self.bits
                        .encode_bit_with_weight2(1, &mut self.recencyweight1);
                    self.bits
                        .encode_bit_with_weight2(1, &mut self.recencyweight2);
                    self.bits
                        .encode_bit_with_weight2(0, &mut self.recencyweight3);
                }
                _ => {
                    self.bits
                        .encode_bit_with_weight2(1, &mut self.recencyweight1);
                    self.bits
                        .encode_bit_with_weight2(1, &mut self.recencyweight2);
                    self.bits
                        .encode_bit_with_weight2(1, &mut self.recencyweight3);
                }
            }
        }

        /// Common tail of every match token: compute the next-literal guess
        /// exactly as the decoder would, emit the bytes into the mirror
        /// window, and advance `pos`.
        fn finish_match(&mut self, distance: usize, length: usize) {
            let offs = distance as i64 - 1;
            let next_pos = next_guess_pos(self.pos, offs, length as i64);
            self.next = i32::from(self.window.byte_at(next_pos));
            self.window.emit_match(distance, length, &mut self.expected);
            self.pos += length as i64;
        }

        pub(crate) fn literal(&mut self, byte: u8) {
            let idx = (self.pos & 3) as usize;
            self.bits
                .encode_bit_with_weight2(0, &mut self.flagweights[idx]);
            let prev = self.window.byte_at(self.pos - 1);
            let row = (prev / 16) as usize;
            let guess = self.next;
            self.encode_literal_bits(row, guess, byte);
            self.next = -1;
            self.window.emit_literal(byte, &mut self.expected);
            self.pos += 1;
        }

        /// A brand new match: `distance` is the real window distance
        /// (`offs+1`), matching the public LZSS convention.
        fn new_match(&mut self, distance: usize, length: usize) {
            let idx = (self.pos & 3) as usize;
            self.bits
                .encode_bit_with_weight2(1, &mut self.flagweights[idx]);
            self.bits.encode_bit_with_weight2(0, &mut self.flagweight2);
            let offs = distance as i64 - 1;
            self.encode_length(idx, length as i32 - 2);
            self.encode_distance(length as i32, offs);
            mtf_shift_distance(&mut self.distancetable, 3, offs);
            self.finish_match(distance, length);
        }

        /// `recency == -1`: repeat `distancetable[0]` at length 1, no length
        /// code and no memory update.
        fn recency_repeat(&mut self) {
            let idx = (self.pos & 3) as usize;
            self.bits
                .encode_bit_with_weight2(1, &mut self.flagweights[idx]);
            self.bits.encode_bit_with_weight2(1, &mut self.flagweight2);
            self.encode_recency(idx, -1);
            let offs = self.distancetable[0];
            self.finish_match((offs + 1) as usize, 1);
        }

        /// `recency` in `0..=3`: reuse `distancetable[index]`, refresh memory,
        /// then a normal length code.
        fn recency_match(&mut self, index: usize, length: usize) {
            let idx = (self.pos & 3) as usize;
            self.bits
                .encode_bit_with_weight2(1, &mut self.flagweights[idx]);
            self.bits.encode_bit_with_weight2(1, &mut self.flagweight2);
            self.encode_recency(idx, index as i32);
            let offs = self.distancetable[index];
            mtf_shift_distance(&mut self.distancetable, index, offs);
            self.encode_length(idx, length as i32 - 2);
            self.finish_match((offs + 1) as usize, length);
        }

        /// The `len==0x111` end-of-stream marker: a "new match" flag whose
        /// length code decodes to the maximum long-code value.
        fn end(&mut self) {
            let idx = (self.pos & 3) as usize;
            self.bits
                .encode_bit_with_weight2(1, &mut self.flagweights[idx]);
            self.bits.encode_bit_with_weight2(0, &mut self.flagweight2);
            self.encode_length(idx, 0x10f); // + 2 == 0x111
        }

        /// Assemble the final `blocks` slice (`[window_byte, skipped_byte, ..coded bytes..]`)
        /// alongside the plaintext `decode()` should reproduce.
        pub(crate) fn finish(self, window_byte: u8) -> (Vec<u8>, Vec<u8>) {
            let mut blocks = vec![window_byte, 0u8];
            blocks.extend(self.bits.finish());
            (blocks, self.expected)
        }
    }

    #[test]
    fn literals_only_round_trip() {
        let window_byte = 0u8;
        let mut enc = Encoder::new(windowsize_for(window_byte));
        for &b in b"hello darkhorse literal test data, the quick brown fox" {
            enc.literal(b);
        }
        let (blocks, expected) = enc.finish(window_byte);
        let got = decode(&blocks, expected.len()).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn new_match_exercises_all_distance_symbol_branches() {
        let window_byte = 0u8;
        let mut enc = Encoder::new(windowsize_for(window_byte));
        for &b in b"ABCDEFGH" {
            enc.literal(b);
        }
        enc.new_match(1, 3); // offs=0 -> sym<4 branch
        enc.new_match(50, 10); // offs=49 -> sym in [4,13] branch
        enc.new_match(500, 20); // offs=499 -> sym>=14 branch, small numbits
        enc.new_match(900_000, 5); // offs=899_999 -> sym>=14 branch, larger numbits
        let (blocks, expected) = enc.finish(window_byte);
        let got = decode(&blocks, expected.len()).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn length_boundary_between_short_and_long_codes_round_trips() {
        let window_byte = 0u8;
        let mut enc = Encoder::new(windowsize_for(window_byte));
        for &b in b"boundary test data padding" {
            enc.literal(b);
        }
        enc.new_match(4, 17); // longest short-code length (raw value 15)
        enc.new_match(4, 18); // shortest long-code length (raw value 16)
        enc.new_match(4, 272); // longest legal long-code length (raw value 270)
        let (blocks, expected) = enc.finish(window_byte);
        let got = decode(&blocks, expected.len()).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn recency_repeat_reuses_the_most_recent_distance_at_length_one() {
        let window_byte = 0u8;
        let mut enc = Encoder::new(windowsize_for(window_byte));
        for &b in b"XYZXYZXYZ" {
            enc.literal(b);
        }
        enc.new_match(3, 6);
        enc.recency_repeat();
        let (blocks, expected) = enc.finish(window_byte);
        let got = decode(&blocks, expected.len()).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn recency_repeat_as_the_very_first_token_reads_the_zeroed_distance_table() {
        // Boundary case: distancetable[0] is still its reset value (0) here,
        // so this exercises offs=0 (window distance 1) and pos-1 landing on
        // the not-yet-written ring slot (see `byte_at`'s negative-position
        // handling).
        let window_byte = 0u8;
        let mut enc = Encoder::new(windowsize_for(window_byte));
        enc.recency_repeat();
        for &b in b"after" {
            enc.literal(b);
        }
        let (blocks, expected) = enc.finish(window_byte);
        let got = decode(&blocks, expected.len()).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn recency_match_all_four_indices_round_trip() {
        let window_byte = 0u8;
        let mut enc = Encoder::new(windowsize_for(window_byte));
        for &b in b"0123456789abcdef" {
            enc.literal(b);
        }
        enc.new_match(2, 3);
        enc.new_match(5, 3);
        enc.new_match(9, 3);
        enc.new_match(13, 3);
        enc.recency_match(0, 4);
        enc.recency_match(1, 5);
        enc.recency_match(2, 6);
        enc.recency_match(3, 7);
        let (blocks, expected) = enc.finish(window_byte);
        let got = decode(&blocks, expected.len()).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn explicit_end_marker_stops_decoding_before_the_declared_size() {
        let window_byte = 0u8;
        let mut enc = Encoder::new(windowsize_for(window_byte));
        for &b in b"stop here" {
            enc.literal(b);
        }
        let expected_before_end = enc.expected.clone();
        enc.end();
        let (blocks, _) = enc.finish(window_byte);
        // Declare a larger size than actually encoded: decode must stop at
        // the explicit end marker rather than reading past it.
        let got = decode(&blocks, expected_before_end.len() + 100).unwrap();
        assert_eq!(got, expected_before_end);
    }

    #[test]
    fn output_wraps_around_the_one_megabyte_minimum_window() {
        // window_byte=0 forces decode()'s 1 MiB minimum; pushing the output
        // past that exercises real ring wraparound in `byte_at`/`emit_match`
        // (beyond the isolated coverage in newtua-common's own LZSS tests).
        let window_byte = 0u8;
        let mut enc = Encoder::new(windowsize_for(window_byte));
        for &b in b"wraptest" {
            enc.literal(b);
        }
        while (enc.pos as usize) < 0x100000 + 4096 {
            enc.new_match(8, 272);
        }
        let (blocks, expected) = enc.finish(window_byte);
        let got = decode(&blocks, expected.len()).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn illegal_window_byte_is_rejected_without_panicking() {
        let blocks = vec![250u8, 0u8, 0, 0, 0, 0];
        let err = decode(&blocks, 4).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn truncated_header_is_rejected() {
        let blocks = vec![5u8]; // missing the skipped byte
        let err = decode(&blocks, 4).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
