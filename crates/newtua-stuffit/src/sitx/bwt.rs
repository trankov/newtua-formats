// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Inverse block-sorting transforms and MTF variants for the StuffItX range
//! codecs (Cyanide / Darkhorse / Iron).
//!
//! A faithful port of XADMaster's `BWT.c`: the inverse Burrows–Wheeler transform
//! (`unsort_bwt`), the inverse Sort-Transform of order 4 (`unsort_st4`), a plain
//! move-to-front decoder, and the MTF-1/FF-N variant (`decode_m1ffn_block`).
//! These are pure, self-contained primitives — the codecs in 19c–19e feed them
//! the range-decoded block plus its primary index.
#![allow(dead_code)] // consumed by the range codecs (19c–19e), landed here first.

/// The LF-mapping of an inverse BWT (`CalculateInverseBWT`, `BWT.c:8`): for each
/// output row, the source index whose symbol precedes it.
fn calculate_inverse_bwt(src: &[u8]) -> Vec<u32> {
    let mut counts = [0u32; 256];
    for &b in src {
        counts[b as usize] += 1;
    }
    // Prefix sums into `cumulative`, then reset `counts` to reuse as running offsets.
    let mut cumulative = [0u32; 256];
    let mut total = 0u32;
    for i in 0..256 {
        cumulative[i] = total;
        total += counts[i];
        counts[i] = 0;
    }

    let mut transform = vec![0u32; src.len()];
    for (i, &b) in src.iter().enumerate() {
        let c = b as usize;
        transform[(cumulative[c] + counts[c]) as usize] = i as u32;
        counts[c] += 1;
    }
    transform
}

/// Inverse Burrows–Wheeler transform (`UnsortBWT`, `BWT.c:29`). `firstindex` is
/// the primary index (the row holding the original string's first rotation).
pub(crate) fn unsort_bwt(src: &[u8], firstindex: usize) -> Vec<u8> {
    let transform = calculate_inverse_bwt(src);
    let mut out = Vec::with_capacity(src.len());
    let mut t = firstindex;
    for _ in 0..src.len() {
        t = transform[t] as usize;
        out.push(src[t]);
    }
    out
}

/// Flag (bit 23) marking an indirect `transform` link in [`unsort_st4`].
const ST4_INDIRECT: u32 = 0x0080_0000;
/// Mask for the 23-bit index stored in a `transform` entry.
const ST4_INDEX: u32 = 0x007f_ffff;

/// Inverse Sort-Transform of order 4 (`UnsortST4`, `BWT.c:41`) — a two-byte
/// context sort transform. A line-for-line port; the scratch buffers the
/// reference threads through its arguments are allocated locally here.
pub(crate) fn unsort_st4(src: &[u8], firstindex: usize) -> Vec<u8> {
    let n = src.len();
    let mut dest = vec![0u8; n];
    if n == 0 {
        return dest;
    }

    let mut counts = [0u32; 256];
    for &b in src {
        counts[b as usize] += 1;
    }

    // Digram frequencies grouped by first byte: array2[(src[base+j]<<8)|i].
    let mut array2 = vec![0u32; 256 * 256];
    let mut total = 0u32;
    for (i, base) in counts.iter_mut().enumerate() {
        let count = *base;
        *base = total;
        for j in 0..count {
            let idx = ((src[(total + j) as usize] as usize) << 8) | i;
            array2[idx] += 1;
        }
        total += count;
    }

    // Bucket-boundary bit vector, one bit per output position.
    let mut bitvec = vec![0u8; n.div_ceil(8)];
    let mut seen = [-1i64; 256]; // "last group in which this byte appeared" (`array3`)
    let counts2_base = counts; // snapshot of the per-byte bases (`counts2`)
    total = 0;
    for &count in &array2 {
        for j in 0..count {
            let byte = src[(total + j) as usize] as usize;
            if seen[byte] != i64::from(total) {
                seen[byte] = i64::from(total);
                let x = counts[byte];
                bitvec[(x >> 3) as usize] |= 1 << (x & 7);
            }
            counts[byte] += 1;
        }
        total += count;
    }

    // Build the linked `transform` (direct next-position, or an indirect back
    // reference flagged with ST4_INDIRECT), with the byte in bits 24..32.
    let mut last = [0u32; 256]; // reused `array3`, now "last direct entry + 1"
    let mut counts2 = counts2_base;
    let mut transform = vec![0u32; n];
    let mut index = 0usize;
    for i in 0..n {
        if bitvec[i / 8] & (1 << (i & 7)) != 0 {
            index = i;
        }
        let byte = src[i] as usize;
        if (index as u32) < last[byte] {
            transform[i] = (last[byte] - 1) | ST4_INDIRECT;
        } else {
            transform[i] = counts2[byte];
            last[byte] = (i + 1) as u32;
        }
        counts2[byte] += 1;
        transform[i] |= (byte as u32) << 24;
    }

    // Walk the chain from the primary index, emitting the top byte each step.
    let mut index = firstindex;
    let mut tval = transform[firstindex];
    for slot in dest.iter_mut() {
        if tval & ST4_INDIRECT != 0 {
            let link = (tval & ST4_INDEX) as usize;
            index = (transform[link] & ST4_INDEX) as usize;
            transform[link] += 1;
        } else {
            transform[index] += 1;
            index = (tval & ST4_INDEX) as usize;
        }
        tval = transform[index];
        *slot = (tval >> 24) as u8;
    }
    dest
}

/// A move-to-front decoder state (`MTFState` / `DecodeMTF`, `BWT.c:165`).
pub(crate) struct MtfState {
    table: [u8; 256],
}

impl MtfState {
    /// A freshly reset decoder (identity table).
    pub(crate) fn new() -> Self {
        let mut table = [0u8; 256];
        for (i, t) in table.iter_mut().enumerate() {
            *t = i as u8;
        }
        Self { table }
    }

    /// Decode one symbol, moving it to the front.
    pub(crate) fn decode(&mut self, symbol: u8) -> u8 {
        let symbol = symbol as usize;
        let res = self.table[symbol];
        for i in (1..=symbol).rev() {
            self.table[i] = self.table[i - 1];
        }
        self.table[0] = res;
        res
    }

    /// The index `byte` currently occupies (test-only: a mirror encoder needs to
    /// invert [`Self::decode`] to find which index would reproduce a target byte).
    #[cfg(test)]
    pub(crate) fn find(&self, byte: u8) -> usize {
        self.table
            .iter()
            .position(|&b| b == byte)
            .expect("every byte value is always present in the table")
    }
}

/// Decode a block with the MTF-1/FF-N variant in place (`DecodeM1FFNBlock`,
/// `BWT.c:185`). A fresh symbol lands at position 1; it only reaches position 0
/// after surviving `order` steps without a `0` reset (Cyanide uses `order = 2`).
pub(crate) fn decode_m1ffn_block(block: &mut [u8], order: usize) {
    let mut table = [0u8; 256];
    for (i, t) in table.iter_mut().enumerate() {
        *t = i as u8;
    }
    let mut lasthead = order.wrapping_sub(1);

    for slot in block.iter_mut() {
        let symbol = *slot as usize;
        *slot = table[symbol];

        if symbol == 0 {
            lasthead = 0;
        } else if symbol == 1 {
            if lasthead >= order {
                table.swap(0, 1);
            }
        } else {
            let val = table[symbol];
            for k in (2..=symbol).rev() {
                table[k] = table[k - 1];
            }
            table[1] = val;
        }
        lasthead = lasthead.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Naive forward BWT: sort the cyclic rotations, return the last column and
    /// the primary index (the sorted position of the rotation starting at 0).
    fn forward_bwt(data: &[u8]) -> (Vec<u8>, usize) {
        let n = data.len();
        let mut rots: Vec<usize> = (0..n).collect();
        rots.sort_by(|&a, &b| {
            for k in 0..n {
                let ca = data[(a + k) % n];
                let cb = data[(b + k) % n];
                if ca != cb {
                    return ca.cmp(&cb);
                }
            }
            a.cmp(&b)
        });
        let last = rots.iter().map(|&r| data[(r + n - 1) % n]).collect();
        let firstindex = rots.iter().position(|&r| r == 0).unwrap();
        (last, firstindex)
    }

    #[test]
    fn bwt_round_trips() {
        for data in [
            &b"banana"[..],
            b"abracadabra",
            b"mississippi river",
            b"aaaaaa",
            b"a",
            b"the quick brown fox jumps over the lazy dog",
        ] {
            let (last, first) = forward_bwt(data);
            assert_eq!(unsort_bwt(&last, first), data, "bwt {data:?}");
        }
    }

    #[test]
    fn bwt_empty_is_empty() {
        assert_eq!(unsort_bwt(&[], 0), Vec::<u8>::new());
    }

    // ST4's `transform[i] = counts2[byte]` (`BWT.c:104`) stores, at each
    // *source* position, the rank a rank-indexed (BWT-style) inverse would
    // store *at* that rank — i.e. it's the forward permutation where BWT's
    // `calculate_inverse_bwt` builds the inverse one, indexed the other way
    // round. Walking it with the same `t = transform[t]` loop BWT uses
    // therefore does not, in general, retrace a plain rotation-sort's rows —
    // confirmed by hand: encoding `"abcdefgh"` as a naive stable sort of its
    // order-4 rotations (last column = preceding byte, matching the BWT
    // convention that round-trips correctly a few lines above) does *not*
    // invert back to `"abcdefgh"` through `unsort_st4`. XADMaster ships no ST4
    // *encoder* to check against (StuffItX archives are read-only there), so
    // there's no reference for the real tie-break/rank convention Allume's
    // encoder uses. Rather than assert a guessed relationship, the vectors
    // below are hand-traced directly against `BWT.c`'s own transcribed steps
    // (see report-19b) — they pin the port's behavior, including the
    // `ST4_INDIRECT` branch, as a regression check. Full encode/decode
    // round-trip validation happens in 19e against real `unar`-verified Iron
    // corpus data.
    #[test]
    fn st4_of_hand_traced_indirect_vector() {
        // src has a repeated byte (1) that lands in the same digram bucket
        // twice, so the second occurrence takes the `ST4_INDIRECT` branch
        // (`BWT.c:98-101`) instead of a fresh `counts2` rank.
        assert_eq!(unsort_st4(&[1, 1, 2, 1], 0), vec![1, 1, 2, 1]);
    }

    #[test]
    fn st4_of_single_byte_is_identity() {
        assert_eq!(unsort_st4(&[42], 0), vec![42]);
    }

    #[test]
    fn st4_empty_is_empty() {
        assert_eq!(unsort_st4(&[], 0), Vec::<u8>::new());
    }

    /// Forward plain MTF: the inverse of [`MtfState::decode`], emitting the index
    /// of each symbol in the running table.
    fn forward_mtf(data: &[u8]) -> Vec<u8> {
        let mut table: Vec<u8> = (0..=255).collect();
        let mut out = Vec::with_capacity(data.len());
        for &b in data {
            let pos = table.iter().position(|&x| x == b).unwrap();
            out.push(pos as u8);
            table.remove(pos);
            table.insert(0, b);
        }
        out
    }

    #[test]
    fn mtf_round_trips() {
        let data = b"mtf move to front round trip test aaa bbb ccc";
        let encoded = forward_mtf(data);
        let mut mtf = MtfState::new();
        let decoded: Vec<u8> = encoded.iter().map(|&s| mtf.decode(s)).collect();
        assert_eq!(&decoded, data);
    }

    /// Forward M1FF2: mirror of [`decode_m1ffn_block`] with `order`, producing the
    /// symbol indices its decode consumes.
    fn forward_m1ffn(data: &[u8], order: usize) -> Vec<u8> {
        let mut table: Vec<u8> = (0..=255).collect();
        let mut lasthead = order.wrapping_sub(1);
        let mut out = Vec::with_capacity(data.len());
        for &b in data {
            let symbol = table.iter().position(|&x| x == b).unwrap();
            out.push(symbol as u8);
            if symbol == 0 {
                lasthead = 0;
            } else if symbol == 1 {
                if lasthead >= order {
                    table.swap(0, 1);
                }
            } else {
                let val = table.remove(symbol);
                table.insert(1, val);
            }
            lasthead = lasthead.wrapping_add(1);
        }
        out
    }

    #[test]
    fn m1ffn_round_trips_order_2() {
        for data in [
            &b"m1ff2 hysteresis test"[..],
            b"aaabbbcccaaabbbccc",
            b"the fresh symbol reaches position zero only after order steps",
            b"\x00\x01\x02\x03\x00\x01\x02\x03",
        ] {
            let mut encoded = forward_m1ffn(data, 2);
            decode_m1ffn_block(&mut encoded, 2);
            assert_eq!(&encoded, data, "m1ff2 {data:?}");
        }
    }

    #[test]
    fn m1ffn_round_trips_other_orders() {
        let data = b"varying the order parameter still inverts cleanly";
        for order in [1usize, 3, 4] {
            let mut encoded = forward_m1ffn(data, order);
            decode_m1ffn_block(&mut encoded, order);
            assert_eq!(&encoded, data, "order {order}");
        }
    }
}
