// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! PPMd's own range coder (`PPMd/RangeCoder.h`/`.c`).
//!
//! Structurally similar to `sitx::rangecoder::RangeCoder` (`CarrylessRangeCoder`,
//! from 19b) — same carryless Subbotin-style core (`current_count`/
//! `remove_subrange`/`normalize`) — but kept as a separate, self-contained
//! port per the task: PPMd's engine owns its own tiny coder in the reference
//! (`PPMd/RangeCoder.c`, distinct from `CarrylessRangeCoder.m`), and the two
//! are not meant to be coupled just because they happen to compute the same
//! thing. Variant G always initializes with `uselow=true` (`VariantG.c:20`),
//! but the `uselow=false` branch is ported anyway for fidelity to the
//! reference's general-purpose coder.

/// `PPMdRangeCoder` (`RangeCoder.h`). Reads bytes off `input`; past-EOF reads
/// return `0` rather than failing, matching `CSInputNextByte`'s behavior as
/// established for the sibling `CarrylessRangeCoder` port (19b) — well-formed
/// streams never actually read past their end, so this is unobservable.
pub(crate) struct PpmdRangeCoder<'a> {
    input: &'a [u8],
    pos: usize,
    low: u32,
    code: u32,
    range: u32,
    bottom: u32,
    uselow: bool,
}

impl<'a> PpmdRangeCoder<'a> {
    /// `InitializePPMdRangeCoder` (`.c:3`): reads four leading big-endian bytes
    /// into `code`.
    pub(crate) fn new(input: &'a [u8], uselow: bool, bottom: u32) -> Self {
        let mut c = PpmdRangeCoder {
            input,
            pos: 0,
            low: 0,
            code: 0,
            range: 0xffff_ffff,
            bottom,
            uselow,
        };
        for _ in 0..4 {
            c.code = (c.code << 8) | u32::from(c.next_byte());
        }
        c
    }

    fn next_byte(&mut self) -> u8 {
        let b = self.input.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        b
    }

    /// Number of input bytes consumed so far (init read + renormalization),
    /// so a framed caller (Blend) can resynchronize its cursor past this
    /// stream's actual consumption (`CSInputSynchronizeFileOffset`).
    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    /// `PPMdRangeCoderCurrentCount` (`.c:17`). Mutates `range` in place,
    /// matching the reference's `self->range/=scale`.
    pub(crate) fn current_count(&mut self, scale: u32) -> u32 {
        self.range /= scale;
        self.code.wrapping_sub(self.low) / self.range
    }

    /// `RemovePPMdRangeCoderSubRange` (`.c:23`).
    pub(crate) fn remove_subrange(&mut self, lowcount: u32, highcount: u32) {
        if self.uselow {
            self.low = self.low.wrapping_add(self.range.wrapping_mul(lowcount));
        } else {
            self.code = self.code.wrapping_sub(self.range.wrapping_mul(lowcount));
        }
        self.range = self.range.wrapping_mul(highcount - lowcount);
        self.normalize();
    }

    /// `NextWeightedBitFromPPMdRangeCoder` (`.c:33`).
    pub(crate) fn next_weighted_bit(&mut self, weight: u32, size: u32) -> u32 {
        let val = self.current_count(size);
        if val < weight {
            self.remove_subrange(0, weight);
            0
        } else {
            self.remove_subrange(weight, size);
            1
        }
    }

    /// `NextWeightedBitFromPPMdRangeCoder2` (`.c:49`): adjusts `range`/`code`
    /// directly instead of going through `remove_subrange`.
    pub(crate) fn next_weighted_bit2(&mut self, weight: u32, shift: u32) -> u32 {
        let threshold = (self.range >> shift).wrapping_mul(weight);
        let bit = if self.code < threshold {
            self.range = threshold;
            0
        } else {
            self.range = self.range.wrapping_sub(threshold);
            self.code = self.code.wrapping_sub(threshold);
            1
        };
        self.normalize();
        bit
    }

    /// `NormalizePPMdRangeCoder` (`.c:72`).
    fn normalize(&mut self) {
        loop {
            if (self.low ^ self.low.wrapping_add(self.range)) >= 0x0100_0000 {
                if self.range >= self.bottom {
                    break;
                }
                self.range = 0u32.wrapping_sub(self.low) & self.bottom.wrapping_sub(1);
            }
            let byte = self.next_byte();
            self.code = (self.code << 8) | u32::from(byte);
            self.range <<= 8;
            self.low <<= 8;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mirror encoder for `uselow=true` (the only mode Brimstone/variant G
    /// actually uses) — real Subbotin carryless coding, no carry bookkeeping
    /// needed since the renormalize condition guarantees a truncated byte can
    /// never be changed by a later carry. Structurally identical to 19b's
    /// `CarrylessEncoder`, kept local rather than shared per the module doc.
    struct MirrorEncoder {
        out: Vec<u8>,
        low: u32,
        range: u32,
        bottom: u32,
    }

    impl MirrorEncoder {
        fn new(bottom: u32) -> Self {
            MirrorEncoder {
                out: Vec::new(),
                low: 0,
                range: 0xffff_ffff,
                bottom,
            }
        }

        fn normalize(&mut self) {
            loop {
                if (self.low ^ self.low.wrapping_add(self.range)) >= 0x0100_0000 {
                    if self.range >= self.bottom {
                        break;
                    }
                    self.range = 0u32.wrapping_sub(self.low) & self.bottom.wrapping_sub(1);
                }
                self.out.push((self.low >> 24) as u8);
                self.range <<= 8;
                self.low <<= 8;
            }
        }

        fn encode(&mut self, lowcount: u32, highcount: u32, total: u32) {
            self.range /= total;
            self.low = self.low.wrapping_add(self.range.wrapping_mul(lowcount));
            self.range = self.range.wrapping_mul(highcount - lowcount);
            self.normalize();
        }

        fn encode_weighted_bit(&mut self, bit: u32, weight: u32, size: u32) {
            if bit == 0 {
                self.encode(0, weight, size);
            } else {
                self.encode(weight, size, size);
            }
        }

        fn encode_weighted_bit2(&mut self, bit: u32, weight: u32, shift: u32) {
            let threshold = (self.range >> shift).wrapping_mul(weight);
            if bit == 0 {
                self.range = threshold;
            } else {
                self.low = self.low.wrapping_add(threshold);
                self.range = self.range.wrapping_sub(threshold);
            }
            self.normalize();
        }

        fn finish(mut self) -> Vec<u8> {
            for _ in 0..4 {
                self.out.push((self.low >> 24) as u8);
                self.low <<= 8;
            }
            self.out
        }
    }

    #[test]
    fn current_count_and_remove_subrange_round_trip_a_symbol_stream() {
        let freqs = [5u32, 3, 1, 7];
        let symbols = [0usize, 3, 2, 1, 3, 3, 0, 1];

        let mut enc = MirrorEncoder::new(0);
        for &s in &symbols {
            let total: u32 = freqs.iter().sum();
            let cumulative: u32 = freqs[..s].iter().sum();
            enc.encode(cumulative, cumulative + freqs[s], total);
        }
        let bytes = enc.finish();

        let mut dec = PpmdRangeCoder::new(&bytes, true, 0);
        for &want in &symbols {
            let total: u32 = freqs.iter().sum();
            let tmp = dec.current_count(total);
            let mut cumulative = 0u32;
            let mut n = 0usize;
            while n < freqs.len() - 1 && cumulative + freqs[n] <= tmp {
                cumulative += freqs[n];
                n += 1;
            }
            dec.remove_subrange(cumulative, cumulative + freqs[n]);
            assert_eq!(n, want);
        }
    }

    #[test]
    fn next_weighted_bit_round_trips() {
        let weight = 0x300u32;
        let size = 0x1000u32;
        let bits = [0u32, 0, 1, 0, 1, 1, 0, 1];

        let mut enc = MirrorEncoder::new(0);
        for &b in &bits {
            enc.encode_weighted_bit(b, weight, size);
        }
        let bytes = enc.finish();

        let mut dec = PpmdRangeCoder::new(&bytes, true, 0);
        let decoded: Vec<u32> = (0..bits.len())
            .map(|_| dec.next_weighted_bit(weight, size))
            .collect();
        assert_eq!(decoded, bits);
    }

    #[test]
    fn next_weighted_bit2_round_trips() {
        let weight = 0x900u32;
        let shift = 14u32; // TOT_BITS for variant G
        let bits = [1u32, 0, 0, 1, 1, 0, 1, 0, 0];

        let mut enc = MirrorEncoder::new(0);
        for &b in &bits {
            enc.encode_weighted_bit2(b, weight, shift);
        }
        let bytes = enc.finish();

        let mut dec = PpmdRangeCoder::new(&bytes, true, 0);
        let decoded: Vec<u32> = (0..bits.len())
            .map(|_| dec.next_weighted_bit2(weight, shift))
            .collect();
        assert_eq!(decoded, bits);
    }

    #[test]
    fn brimstone_bottom_forces_the_underflow_branch() {
        // Brimstone uses bottom=0x10000 (VariantG.c:20), which triggers
        // normalize's underflow rewrite of `range` far more often than
        // bottom=0.
        let bottom = 0x10000u32;
        let freqs = [1u32, 1, 1, 1, 1, 1, 1, 1];
        let symbols = [0usize, 7, 3, 5, 1, 6, 2, 4, 0, 7, 7, 3];

        let mut enc = MirrorEncoder::new(bottom);
        for &s in &symbols {
            let total: u32 = freqs.iter().sum();
            enc.encode(s as u32, s as u32 + 1, total);
        }
        let bytes = enc.finish();

        let mut dec = PpmdRangeCoder::new(&bytes, true, bottom);
        for &want in &symbols {
            let tmp = dec.current_count(8);
            dec.remove_subrange(tmp, tmp + 1);
            assert_eq!(tmp as usize, want);
        }
    }

    #[test]
    fn new_reads_exactly_four_leading_bytes() {
        let bytes = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let dec = PpmdRangeCoder::new(&bytes, true, 0);
        assert_eq!(dec.code, 0x1122_3344);
        assert_eq!(dec.pos, 4);
    }
}
