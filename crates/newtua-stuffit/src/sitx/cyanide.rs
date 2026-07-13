// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! StuffItX Cyanide codec (`XADStuffItXCyanideHandle`), compression method 1.
//!
//! A ternary adaptive range coder over three Markov context groups, escaping into
//! a pair of byte-value models for symbols above 1, feeding the inverse MTF-1/FF-2
//! (`decode_m1ffn_block`, order 2) and the inverse BWT (`unsort_bwt`) primitives
//! from 19b. A faithful port of `XADStuffItXCyanideHandle.m`.

use std::io;

use super::bwt::{decode_m1ffn_block, unsort_bwt};
use super::rangecoder::RangeCoder;

fn truncated() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "sitx: cyanide stream truncated",
    )
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// `markovgroups[27]` (`.m:141`): maps a 3-symbol context (`prev3*9+prev2*3+prev`)
/// to one of 14 shared frequency tables.
const MARKOV_GROUPS: [usize; 27] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 3, 9, 10, 3, 4, 5, 11, 11, 8, 6, 2, 5, 6, 7, 8, 12, 12, 13,
];

/// An adaptive frequency model over a small alphabet (`RangeCoderModel`, `.m:88`).
/// `mapping[index]` is the symbol currently ranked at `index`; frequencies stay
/// sorted ascending by construction (`bump` keeps the invariant).
struct RangeCoderModel {
    num: usize,
    frequencies: [u32; 256],
    mapping: [u32; 256],
}

impl RangeCoderModel {
    /// `InitializeRangeCoderModel` (`.m:96`): symbol `i` starts at frequency 1,
    /// ranked in descending symbol order (`num-1-i`).
    fn new(num: usize) -> Self {
        let mut frequencies = [0u32; 256];
        let mut mapping = [0u32; 256];
        for i in 0..num {
            frequencies[i] = 1;
            mapping[i] = (num - 1 - i) as u32;
        }
        Self {
            num,
            frequencies,
            mapping,
        }
    }

    /// `NextIndexFromRangeCoderWithModel` (`.m:127`).
    fn next_index(&self, coder: &mut RangeCoder) -> usize {
        coder.next_symbol(&self.frequencies[..self.num])
    }

    /// `DecodeSymbolForModel` (`.m:132`).
    fn symbol(&self, index: usize) -> u32 {
        self.mapping[index]
    }

    /// `BumpFrequencyInModel` (`.m:106`): halve all frequencies once the total
    /// reaches `maxtotal`, then bump `index`'s frequency, re-sorting it past any
    /// ties by swapping its mapping with the last tied slot.
    fn bump(&mut self, index: usize, maxtotal: u32) -> usize {
        let total: u32 = self.frequencies[..self.num].iter().sum();
        if total >= maxtotal {
            for f in &mut self.frequencies[..self.num] {
                *f = f.div_ceil(2);
            }
        }
        let freq = self.frequencies[index];
        let mut last = index;
        while last < self.num - 1 && self.frequencies[last + 1] == freq {
            last += 1;
        }
        if last != index {
            self.mapping.swap(index, last);
        }
        self.frequencies[last] += 1;
        last
    }
}

/// `CalculateTernaryFrequencies` (`.m:59`): `meanings` is the permutation of
/// `{0,1,2}` sorting `infreqs` ascending (exact tie-break tree from the reference,
/// not a generic sort — see the module doc). `outfreqs` is that ordering, each
/// bumped by one to keep every symbol representable by the range coder.
fn calculate_ternary_frequencies(infreqs: &[u32; 3]) -> ([u32; 3], [usize; 3]) {
    let (a, b, c) = (infreqs[0], infreqs[1], infreqs[2]);
    let meanings: [usize; 3] = if a < b {
        if a < c {
            if b < c {
                [0, 1, 2]
            } else {
                [0, 2, 1]
            }
        } else {
            [2, 0, 1]
        }
    } else if b < c {
        if c < a {
            [1, 2, 0]
        } else {
            [1, 0, 2]
        }
    } else {
        [2, 1, 0]
    };
    let outfreqs = [
        infreqs[meanings[0]] + 1,
        infreqs[meanings[1]] + 1,
        infreqs[meanings[2]] + 1,
    ];
    (outfreqs, meanings)
}

/// `readTernaryCodedBlock:numberOfSymbols:` (`.m:139`): decode `blocksize` MTF
/// symbols (still BWT/MTF-coded) from `coder`.
fn read_ternary_coded_block(
    coder: &mut RangeCoder,
    blocksize: usize,
    numsymbols: usize,
) -> Vec<u8> {
    let mut sorted = vec![0u8; blocksize];
    let mut markovfreqs = [[0u32; 3]; 14];

    // Split `numsymbols` across up to 8 low-bits models, doubling capacity each
    // step until the remainder fits (`.m:150-161`).
    let mut lowbitsmodels: Vec<RangeCoderModel> = Vec::new();
    let mut b = numsymbols;
    let mut shift: u32 = 1;
    while b != 0 {
        let n = if b < (3usize << shift) {
            b
        } else {
            1usize << shift
        };
        lowbitsmodels.push(RangeCoderModel::new(n));
        b -= n;
        shift += 1;
    }
    let mut highbitmodel = RangeCoderModel::new(shift as usize);

    let (mut prev, mut prev2, mut prev3) = (0usize, 0usize, 0usize);
    let mut someflag = true;

    for slot in sorted.iter_mut() {
        let contextindex = prev3 * 9 + prev2 * 3 + prev;
        let markovindex = MARKOV_GROUPS[contextindex];
        let (freqs, meanings) = calculate_ternary_frequencies(&markovfreqs[markovindex]);
        let symbol = coder.next_symbol(&freqs);
        let tresym = meanings[symbol];

        if tresym == 0 && !someflag && markovindex == 0 {
            someflag = true;
            markovfreqs[markovindex][0] >>= 1;
            markovfreqs[markovindex][1] >>= 1;
            markovfreqs[markovindex][2] >>= 1;
            markovfreqs[markovindex][0] += 3;
            *slot = 0;
        } else {
            if tresym != 0 {
                someflag = false;
            }
            let total = freqs[0] + freqs[1] + freqs[2];
            let limit = if someflag { 4096 } else { 128 };
            if total > limit {
                markovfreqs[markovindex][0] >>= 1;
                markovfreqs[markovindex][1] >>= 1;
                markovfreqs[markovindex][2] >>= 1;
            }
            markovfreqs[markovindex][tresym] += 2;

            if tresym <= 1 {
                *slot = tresym as u8;
            } else {
                let highbitindex = highbitmodel.next_index(coder);
                let highbit = highbitmodel.symbol(highbitindex) as usize;
                let newindex = highbitmodel.bump(highbitindex, 0x100);
                highbitmodel.bump(newindex, 0x10000);

                if highbit == 0 {
                    *slot = 2;
                } else {
                    let m = &mut lowbitsmodels[highbit - 1];
                    let lowbitsindex = m.next_index(coder);
                    let lowbits = m.symbol(lowbitsindex);
                    let max = ((m.num as u32) * 128).min(0x4000);
                    m.bump(lowbitsindex, max);
                    *slot = ((1u32 << highbit) + lowbits + 1) as u8;
                }
            }
        }

        prev3 = prev2;
        prev2 = prev;
        prev = tresym;
    }

    sorted
}

fn read_u8(blocks: &[u8], cursor: &mut usize) -> io::Result<u8> {
    let b = *blocks.get(*cursor).ok_or_else(truncated)?;
    *cursor += 1;
    Ok(b)
}

fn read_u32_be(blocks: &[u8], cursor: &mut usize) -> io::Result<u32> {
    let end = cursor.checked_add(4).ok_or_else(truncated)?;
    let bytes = blocks.get(*cursor..end).ok_or_else(truncated)?;
    let v = u32::from_be_bytes(bytes.try_into().unwrap());
    *cursor = end;
    Ok(v)
}

/// Decode a Cyanide-compressed stream, also reporting how many bytes of
/// `blocks` were actually consumed — needed by Blend (method 4) to
/// resynchronize its cursor past this sub-block
/// (`CSInputSynchronizeFileOffset`, `XADStuffItXBlendHandle.m:111`).
///
/// `blocks` is the block layer's already unwrapped output
/// (`p2::read_block_stream`); `size` is only used to size the output buffer
/// (the block markers alone determine when the stream ends).
pub(crate) fn decode_framed(blocks: &[u8], size: usize) -> io::Result<(Vec<u8>, usize)> {
    // `resetBlockStream` (`.m:28`) reads one byte before any block is produced.
    let mut cursor = 1usize;
    let mut out = Vec::with_capacity(size);

    loop {
        let marker = read_u8(blocks, &mut cursor)?;
        if marker == 0xff {
            break;
        }
        if marker != 0x77 {
            return Err(invalid("sitx: illegal cyanide block marker"));
        }

        let blocksize = read_u32_be(blocks, &mut cursor)? as usize;
        let firstindex = read_u32_be(blocks, &mut cursor)? as usize;
        let numsymbols = read_u8(blocks, &mut cursor)? as usize;

        let block_start = cursor;
        let mut coder = RangeCoder::new(&blocks[block_start..], true, 0x10000);
        let mut sorted = read_ternary_coded_block(&mut coder, blocksize, numsymbols);
        cursor = block_start + coder.position();

        decode_m1ffn_block(&mut sorted, 2);
        let block = unsort_bwt(&sorted, firstindex);
        out.extend_from_slice(&block);
    }

    Ok((out, cursor))
}

/// Decode a Cyanide-compressed stream (`produceBlockAtOffset:` driven by
/// `CSBlockStreamHandle`, `.m:26-57`), discarding the consumed count (used by
/// the container's top-level dispatch, which already knows its stream's full
/// length).
pub(crate) fn decode(blocks: &[u8], size: usize) -> io::Result<Vec<u8>> {
    decode_framed(blocks, size).map(|(out, _consumed)| out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // === RangeCoderModel: hand-traced (`.m:88-135`) ===========================

    #[test]
    fn model_new_ranks_symbols_in_descending_mapping_order() {
        let m = RangeCoderModel::new(4);
        assert_eq!(&m.frequencies[..4], &[1, 1, 1, 1]);
        assert_eq!(&m.mapping[..4], &[3, 2, 1, 0]);
    }

    #[test]
    fn model_bump_without_halving_just_increments_and_may_resort() {
        // num=3, all frequencies 1 (tied): bumping index 0 with a high maxtotal
        // (no halving) must walk past every tied higher slot before landing.
        let mut m = RangeCoderModel::new(3);
        let last = m.bump(0, 1000);
        assert_eq!(last, 2, "ties push the bumped symbol to the last tied slot");
        assert_eq!(&m.frequencies[..3], &[1, 1, 2]);
        // mapping[0] and mapping[2] were swapped (2<->0).
        assert_eq!(&m.mapping[..3], &[0, 1, 2]);
    }

    #[test]
    fn model_bump_no_tie_keeps_mapping_and_increments_in_place() {
        let mut m = RangeCoderModel::new(3);
        // Bump index 2 first so its frequency (2) is strictly greater than its
        // neighbours (1, 1); bumping it again must not need to move past a tie.
        m.bump(2, 1000);
        let before = m.mapping;
        let last = m.bump(2, 1000);
        assert_eq!(last, 2);
        assert_eq!(m.frequencies[2], 3);
        assert_eq!(m.mapping, before, "no tie to break: mapping unchanged");
    }

    #[test]
    fn model_bump_halves_all_frequencies_once_total_hits_maxtotal() {
        let mut m = RangeCoderModel::new(2);
        m.frequencies[0] = 50;
        m.frequencies[1] = 50;
        // total=100 >= maxtotal=100 -> halve both to 25/25 (via (f+1)/2), then
        // bump index 1 to 26.
        let last = m.bump(1, 100);
        assert_eq!(last, 1);
        assert_eq!(&m.frequencies[..2], &[25, 26]);
    }

    #[test]
    fn model_symbol_reads_back_the_mapping() {
        let m = RangeCoderModel::new(5);
        for i in 0..5 {
            assert_eq!(m.symbol(i), m.mapping[i]);
        }
    }

    // === calculate_ternary_frequencies: all orderings + ties (`.m:59-85`) =====

    #[test]
    fn ternary_frequencies_strict_orderings() {
        // All six strict permutations of (a,b,c), matching the reference's exact
        // branch tree. `want` is the ascending permutation of indices {0,1,2}.
        let cases: [(u32, u32, u32, [usize; 3]); 6] = [
            (1, 2, 3, [0, 1, 2]), // a<b<c
            (1, 3, 2, [0, 2, 1]), // a<c<b
            (3, 1, 2, [1, 2, 0]), // b<c<a
            (2, 3, 1, [2, 0, 1]), // c<a<b
            (2, 1, 3, [1, 0, 2]), // b<a<c
            (3, 2, 1, [2, 1, 0]), // c<b<a
        ];
        for (a, b, c, want) in cases {
            let (_, got) = calculate_ternary_frequencies(&[a, b, c]);
            assert_eq!(got, want, "a={a} b={b} c={c}");
        }
    }

    #[test]
    fn ternary_frequencies_output_is_sorted_ascending_and_plus_one() {
        let (freqs, meanings) = calculate_ternary_frequencies(&[5, 1, 3]);
        assert_eq!(meanings, [1, 2, 0]); // b=1 < c=3 < a=5
        assert_eq!(freqs, [2, 4, 6]); // infreqs[meanings[i]] + 1
        assert!(freqs[0] <= freqs[1] && freqs[1] <= freqs[2]);
    }

    #[test]
    fn ternary_frequencies_tie_break_matches_reference_tree() {
        // All equal: a<b is false -> b<c is false (equal) -> meanings=[2,1,0].
        let (freqs, meanings) = calculate_ternary_frequencies(&[7, 7, 7]);
        assert_eq!(meanings, [2, 1, 0]);
        assert_eq!(freqs, [8, 8, 8]);

        // a==b<c: a<b false, b<c true, c<a false (c>a) -> meanings=[1,0,2].
        let (_, meanings) = calculate_ternary_frequencies(&[4, 4, 9]);
        assert_eq!(meanings, [1, 0, 2]);

        // a<b==c: a<b true, a<c true, b<c false (equal) -> meanings=[0,2,1].
        let (_, meanings) = calculate_ternary_frequencies(&[1, 9, 9]);
        assert_eq!(meanings, [0, 2, 1]);

        // a==c<b: a<b true, a<c false (equal) -> meanings=[2,0,1].
        let (_, meanings) = calculate_ternary_frequencies(&[3, 9, 3]);
        assert_eq!(meanings, [2, 0, 1]);
    }

    // === decode(): block framing edge cases, no arithmetic content needed =====
    //
    // A full forward encoder (ternary model + BWT-forward) is out of scope for
    // 19c (see task-19c, "Оракулы": no reference encoder, tie-break can't be
    // guaranteed to match Allume's, and a self-mirrored round-trip would only
    // prove internal consistency, not conformance). These edge cases instead use
    // blocksize=0 blocks, which exercise every byte of the block-framing loop
    // (marker parsing, header fields, model *construction* for small
    // `numsymbols`, cursor advancement between blocks, the 0xff terminator)
    // without needing any actual range-coded symbols.

    fn zero_block(blocksize_marker: bool, numsymbols: u8) -> Vec<u8> {
        let mut v = vec![0u8]; // resetBlockStream's skipped byte
        if blocksize_marker {
            v.push(0x77);
            v.extend_from_slice(&0u32.to_be_bytes()); // blocksize
            v.extend_from_slice(&0u32.to_be_bytes()); // firstindex
            v.push(numsymbols);
            v.extend_from_slice(&[0u8; 4]); // a fresh RangeCoder still reads 4 init bytes
        }
        v.push(0xff); // end marker
        v
    }

    #[test]
    fn empty_stream_decodes_to_nothing() {
        let blocks = vec![0u8, 0xff];
        assert_eq!(decode(&blocks, 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn single_empty_block_decodes_to_nothing() {
        let blocks = zero_block(true, 4);
        assert_eq!(decode(&blocks, 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn multiple_empty_blocks_concatenate_to_nothing() {
        let mut blocks = vec![0u8];
        for _ in 0..3 {
            blocks.push(0x77);
            blocks.extend_from_slice(&0u32.to_be_bytes());
            blocks.extend_from_slice(&0u32.to_be_bytes());
            blocks.push(4);
            blocks.extend_from_slice(&[0u8; 4]);
        }
        blocks.push(0xff);
        assert_eq!(decode(&blocks, 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn small_numsymbols_do_not_panic_building_the_lowbits_models() {
        // numsymbols=1 and 2 both hit the "n=b" truncation branch in the
        // lowbitsmodels-sizing loop (`b < (3<<shift)`), which for a small b is
        // true on the very first iteration.
        for numsymbols in [0u8, 1, 2, 3, 255] {
            let blocks = zero_block(true, numsymbols);
            assert_eq!(
                decode(&blocks, 0).unwrap(),
                Vec::<u8>::new(),
                "numsymbols={numsymbols}"
            );
        }
    }

    #[test]
    fn illegal_marker_byte_is_rejected() {
        let blocks = vec![0u8, 0x42];
        let err = decode(&blocks, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn truncated_header_is_rejected() {
        let blocks = vec![0u8, 0x77, 0, 0]; // marker + partial blocksize
        let err = decode(&blocks, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
