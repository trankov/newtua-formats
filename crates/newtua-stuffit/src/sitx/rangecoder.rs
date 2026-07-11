//! Carryless (Subbotin-style) range decoder for the StuffItX range-coded
//! codecs (Cyanide / Darkhorse / Iron).
//!
//! A faithful port of XADMaster's `CarrylessRangeCoder.m`, plus the adaptive
//! weighted-bit helpers each codec defines as a local `static` function over
//! it (`XADStuffItXDarkhorseHandle.m:4`, `XADStuffItXIronHandle.m:9`). These
//! are pure primitives — the codecs in 19c–19e own the model tables and just
//! call through this decoder.
#![allow(dead_code)] // consumed by the range codecs (19c–19e), landed here first.

/// `CarrylessRangeCoder` (`CarrylessRangeCoder.h`/`.m`). `uselow` selects
/// which of the two equivalent decoder forms a codec uses: tracking a `low`
/// offset (Cyanide, Iron) vs. subtracting straight from `code` and leaving
/// `low` at zero (Darkhorse). `bottom` is the renormalization floor used by
/// the underflow branch in `normalize`.
pub(crate) struct RangeCoder<'a> {
    input: &'a [u8],
    pos: usize,
    low: u32,
    code: u32,
    range: u32,
    bottom: u32,
    uselow: bool,
}

impl<'a> RangeCoder<'a> {
    /// `InitializeRangeCoder` (`CarrylessRangeCoder.m:4`).
    pub(crate) fn new(input: &'a [u8], uselow: bool, bottom: u32) -> Self {
        let mut coder = RangeCoder {
            input,
            pos: 0,
            low: 0,
            code: 0,
            range: 0xffff_ffff,
            bottom,
            uselow,
        };
        coder.code = coder.next_u32_be();
        coder
    }

    /// Number of input bytes consumed so far (init read + renormalization),
    /// so a block-framed caller can advance its cursor to the next block header.
    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    /// `CSInputNextByte`: past-EOF reads return zero rather than failing —
    /// the reference decoder trusts the block length to stop it in time.
    fn next_byte(&mut self) -> u8 {
        let b = self.input.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        b
    }

    fn next_u32_be(&mut self) -> u32 {
        let mut v = 0u32;
        for _ in 0..4 {
            v = (v << 8) | u32::from(self.next_byte());
        }
        v
    }

    /// `RangeCoderCurrentCount` (`CarrylessRangeCoder.m:18`). Mutates `range`
    /// in place, matching the reference's `self->range/=scale`.
    fn current_count(&mut self, scale: u32) -> u32 {
        self.range /= scale;
        self.code.wrapping_sub(self.low) / self.range
    }

    /// `RemoveRangeCoderSubRange` (`CarrylessRangeCoder.m:24`).
    fn remove_subrange(&mut self, lowcount: u32, highcount: u32) {
        if self.uselow {
            self.low = self.low.wrapping_add(self.range.wrapping_mul(lowcount));
        } else {
            self.code = self.code.wrapping_sub(self.range.wrapping_mul(lowcount));
        }
        self.range = self.range.wrapping_mul(highcount - lowcount);
        self.normalize();
    }

    /// `NormalizeRangeCoder` (`CarrylessRangeCoder.m:105`).
    fn normalize(&mut self) {
        loop {
            if (self.low ^ self.low.wrapping_add(self.range)) >= 0x0100_0000 {
                if self.range >= self.bottom {
                    break;
                }
                self.range = 0u32.wrapping_sub(self.low) & self.bottom.wrapping_sub(1);
            }
            self.code = (self.code << 8) | u32::from(self.next_byte());
            self.range <<= 8;
            self.low <<= 8;
        }
    }

    /// `NextSymbolFromRangeCoder` (`CarrylessRangeCoder.m:35`).
    pub(crate) fn next_symbol(&mut self, freqs: &[u32]) -> usize {
        assert!(!freqs.is_empty());
        let total: u32 = freqs.iter().sum();
        let tmp = self.current_count(total);

        let mut cumulative = 0u32;
        let mut n = 0usize;
        while n < freqs.len() - 1 && cumulative + freqs[n] <= tmp {
            cumulative += freqs[n];
            n += 1;
        }
        self.remove_subrange(cumulative, cumulative + freqs[n]);
        n
    }

    /// `NextBitFromRangeCoder` (`CarrylessRangeCoder.m:53`).
    pub(crate) fn next_bit(&mut self) -> u32 {
        let bit = self.current_count(2);
        if bit == 0 {
            self.remove_subrange(0, 1);
        } else {
            self.remove_subrange(1, 2);
        }
        bit
    }

    /// `NextWeightedBitFromRangeCoder` (`CarrylessRangeCoder.m:63`).
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

    /// `NextWeightedBitFromRangeCoder2` (`CarrylessRangeCoder.m:82`). Unlike
    /// the other primitives this one folds the range update directly instead
    /// of going through `remove_subrange`.
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

    /// Darkhorse's `NextBitWithWeight` (`XADStuffItXDarkhorseHandle.m:4`):
    /// `next_weighted_bit2` with a fixed shift of 12, adapting the weight by
    /// 1/32 of the distance to its bound.
    pub(crate) fn next_bit_with_weight2(&mut self, weight: &mut u32) -> u32 {
        let bit = self.next_weighted_bit2(*weight, 12);
        if bit == 0 {
            *weight += (0x1000 - *weight) >> 5;
        } else {
            *weight -= *weight >> 5;
        }
        bit
    }

    /// Iron's `NextBitWithWeight` (`XADStuffItXIronHandle.m:9`):
    /// `next_weighted_bit` over a fixed size of 0x1000, adapting the weight
    /// by `1/2^shift` of the distance to its bound.
    pub(crate) fn next_bit_with_weight(&mut self, weight: &mut u32, shift: u32) -> u32 {
        let bit = self.next_weighted_bit(*weight, 0x1000);
        if bit == 0 {
            *weight += (0x1000 - *weight) >> shift;
        } else {
            *weight -= *weight >> shift;
        }
        bit
    }

    /// Iron's `NextBitWithDoubleWeights` (`XADStuffItXIronHandle.m:17`): the
    /// bit is drawn from the average of two independently-adapted weights.
    pub(crate) fn next_bit_with_double_weights(
        &mut self,
        weight1: &mut u32,
        shift1: u32,
        weight2: &mut u32,
        shift2: u32,
    ) -> u32 {
        let bit = self.next_weighted_bit((*weight1 + *weight2) / 2, 0x1000);
        if bit == 0 {
            *weight1 += (0x1000 - *weight1) >> shift1;
            *weight2 += (0x1000 - *weight2) >> shift2;
        } else {
            *weight1 -= *weight1 >> shift1;
            *weight2 -= *weight2 >> shift2;
        }
        bit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mirror encoder for the `uselow=true` decoder form (Cyanide, Iron):
    /// real Subbotin carryless coding, where the renormalize condition
    /// `(low^(low+range))>=0x1000000` guarantees a truncated byte can never
    /// be changed by a later carry, so bytes are emitted directly with no
    /// carry-propagation bookkeeping. See [`CarryEncoder`] below for why
    /// `uselow=false` (Darkhorse) needs a differently-shaped mirror.
    struct CarrylessEncoder {
        out: Vec<u8>,
        low: u32,
        range: u32,
        bottom: u32,
    }

    impl CarrylessEncoder {
        fn new(bottom: u32) -> Self {
            CarrylessEncoder {
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

        fn encode_symbol(&mut self, freqs: &[u32], symbol: usize) {
            let total: u32 = freqs.iter().sum();
            let cumulative: u32 = freqs[..symbol].iter().sum();
            self.encode(cumulative, cumulative + freqs[symbol], total);
        }

        fn encode_bit(&mut self, bit: u32) {
            self.encode_symbol(&[1, 1], bit as usize);
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

    /// A mirror encoder for the `uselow=false` decoder form. Unlike
    /// [`CarrylessEncoder`], which never needs to propagate a carry because
    /// its renormalize condition keeps the *true* interval low stable before
    /// truncating a byte, `uselow=false` decodes with `low` pinned at zero
    /// (`RemoveRangeCoderSubRange`'s `else` branch folds the subrange into
    /// `code` instead), so its renormalize condition degenerates to plain
    /// `range < 0x1000000` — the classic LZMA-style threshold, not
    /// Subbotin's carryless one. A byte truncated under that rule can still
    /// be changed by a later carry, so this encoder buffers pending output
    /// bytes (`cache`/`cache_size`) and ripples any carry back through them,
    /// exactly like `LZMA::RangeEncoder::ShiftLow`. The very first byte the
    /// scheme would ever emit is always the fixed value the initial `cache`
    /// carries (there's nothing upstream that could still change it), so —
    /// since our decoder's `new` reads exactly 4 leading bytes rather than
    /// the 5 a textbook LZMA decoder discards the first of — it's dropped
    /// here (`started`) instead of written.
    struct CarryEncoder {
        out: Vec<u8>,
        low: u64,
        range: u32,
        cache: u8,
        cache_size: u64,
        started: bool,
    }

    impl CarryEncoder {
        fn new() -> Self {
            CarryEncoder {
                out: Vec::new(),
                low: 0,
                range: 0xffff_ffff,
                cache: 0,
                cache_size: 1,
                started: false,
            }
        }

        fn shift_low(&mut self) {
            if (self.low as u32) < 0xff00_0000 || (self.low >> 32) != 0 {
                let carry = (self.low >> 32) as u8;
                let mut temp = self.cache;
                let mut pending = self.cache_size;
                loop {
                    if self.started || pending != self.cache_size {
                        self.out.push(temp.wrapping_add(carry));
                    }
                    temp = 0xff;
                    pending -= 1;
                    if pending == 0 {
                        break;
                    }
                }
                self.started = true;
                self.cache = (self.low >> 24) as u8;
                self.cache_size = 0;
            }
            self.cache_size += 1;
            self.low = (self.low << 8) & 0xffff_ffff;
        }

        fn normalize(&mut self) {
            while self.range < 0x0100_0000 {
                self.range <<= 8;
                self.shift_low();
            }
        }

        fn encode(&mut self, lowcount: u32, highcount: u32, total: u32) {
            self.range /= total;
            self.low += u64::from(self.range.wrapping_mul(lowcount));
            self.range = self.range.wrapping_mul(highcount - lowcount);
            self.normalize();
        }

        fn encode_bit(&mut self, bit: u32) {
            let freqs = [1u32, 1];
            let cumulative: u32 = freqs[..bit as usize].iter().sum();
            self.encode(cumulative, cumulative + freqs[bit as usize], 2);
        }

        fn encode_weighted_bit2(&mut self, bit: u32, weight: u32, shift: u32) {
            let threshold = (self.range >> shift).wrapping_mul(weight);
            if bit == 0 {
                self.range = threshold;
            } else {
                self.low += u64::from(threshold);
                self.range = self.range.wrapping_sub(threshold);
            }
            self.normalize();
        }

        fn finish(mut self) -> Vec<u8> {
            for _ in 0..5 {
                self.shift_low();
            }
            self.out
        }
    }

    #[test]
    fn next_symbol_round_trips() {
        let freqs = [5u32, 3, 1, 7];
        let symbols = [0usize, 3, 2, 1, 3, 3, 0, 1];

        let mut enc = CarrylessEncoder::new(0);
        for &s in &symbols {
            enc.encode_symbol(&freqs, s);
        }
        let bytes = enc.finish();

        let mut dec = RangeCoder::new(&bytes, true, 0);
        let decoded: Vec<usize> = (0..symbols.len())
            .map(|_| dec.next_symbol(&freqs))
            .collect();
        assert_eq!(decoded, symbols);
    }

    #[test]
    fn next_bit_round_trips_uselow_true() {
        let bits = [0u32, 1, 1, 0, 0, 0, 1, 1, 1, 0];

        let mut enc = CarrylessEncoder::new(0);
        for &b in &bits {
            enc.encode_bit(b);
        }
        let bytes = enc.finish();

        let mut dec = RangeCoder::new(&bytes, true, 0);
        let decoded: Vec<u32> = (0..bits.len()).map(|_| dec.next_bit()).collect();
        assert_eq!(decoded, bits);
    }

    #[test]
    fn next_bit_round_trips_uselow_false() {
        let bits = [1u32, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1];

        let mut enc = CarryEncoder::new();
        for &b in &bits {
            enc.encode_bit(b);
        }
        let bytes = enc.finish();

        let mut dec = RangeCoder::new(&bytes, false, 0);
        let decoded: Vec<u32> = (0..bits.len()).map(|_| dec.next_bit()).collect();
        assert_eq!(decoded, bits);
    }

    #[test]
    fn next_weighted_bit_round_trips() {
        let weight = 0x300u32;
        let size = 0x1000u32;
        let bits = [0u32, 0, 1, 0, 1, 1, 0, 1];

        let mut enc = CarrylessEncoder::new(0);
        for &b in &bits {
            enc.encode_weighted_bit(b, weight, size);
        }
        let bytes = enc.finish();

        let mut dec = RangeCoder::new(&bytes, true, 0);
        let decoded: Vec<u32> = (0..bits.len())
            .map(|_| dec.next_weighted_bit(weight, size))
            .collect();
        assert_eq!(decoded, bits);
    }

    #[test]
    fn next_weighted_bit2_round_trips_uselow_true() {
        let weight = 0x900u32;
        let shift = 12u32;
        let bits = [1u32, 0, 0, 1, 1, 0, 1, 0, 0];

        let mut enc = CarrylessEncoder::new(0);
        for &b in &bits {
            enc.encode_weighted_bit2(b, weight, shift);
        }
        let bytes = enc.finish();

        let mut dec = RangeCoder::new(&bytes, true, 0);
        let decoded: Vec<u32> = (0..bits.len())
            .map(|_| dec.next_weighted_bit2(weight, shift))
            .collect();
        assert_eq!(decoded, bits);
    }

    #[test]
    fn next_weighted_bit2_round_trips_uselow_false() {
        let weight = 0x900u32;
        let shift = 12u32;
        let bits = [0u32, 1, 1, 0, 0, 1, 0, 1, 1, 0];

        let mut enc = CarryEncoder::new();
        for &b in &bits {
            enc.encode_weighted_bit2(b, weight, shift);
        }
        let bytes = enc.finish();

        let mut dec = RangeCoder::new(&bytes, false, 0);
        let decoded: Vec<u32> = (0..bits.len())
            .map(|_| dec.next_weighted_bit2(weight, shift))
            .collect();
        assert_eq!(decoded, bits);
    }

    #[test]
    fn next_bit_with_weight2_adapts_like_darkhorse() {
        // Encode with a manually-adapted weight (mirrors the decoder's own
        // adaptation so the encoder and decoder agree on every symbol's
        // probability), then check the decoder reproduces both the bits and
        // the final weight.
        let bits = [0u32, 0, 1, 0, 0, 1, 1, 0, 0, 0];
        let mut weight = 0x800u32;

        let mut enc = CarryEncoder::new();
        for &b in &bits {
            enc.encode_weighted_bit2(b, weight, 12);
            if b == 0 {
                weight += (0x1000 - weight) >> 5;
            } else {
                weight -= weight >> 5;
            }
        }
        let expected_weight = weight;
        let bytes = enc.finish();

        let mut dec = RangeCoder::new(&bytes, false, 0);
        let mut decoded_weight = 0x800u32;
        let decoded: Vec<u32> = bits
            .iter()
            .map(|_| dec.next_bit_with_weight2(&mut decoded_weight))
            .collect();

        assert_eq!(decoded, bits);
        assert_eq!(decoded_weight, expected_weight);
    }

    #[test]
    fn next_bit_with_weight_adapts_like_iron() {
        let bits = [1u32, 0, 0, 1, 1, 1, 0, 0, 1, 0];
        let shift = 5u32;
        let mut weight = 0x800u32;

        let mut enc = CarrylessEncoder::new(0);
        for &b in &bits {
            enc.encode_weighted_bit(b, weight, 0x1000);
            if b == 0 {
                weight += (0x1000 - weight) >> shift;
            } else {
                weight -= weight >> shift;
            }
        }
        let expected_weight = weight;
        let bytes = enc.finish();

        let mut dec = RangeCoder::new(&bytes, true, 0);
        let mut decoded_weight = 0x800u32;
        let decoded: Vec<u32> = bits
            .iter()
            .map(|_| dec.next_bit_with_weight(&mut decoded_weight, shift))
            .collect();

        assert_eq!(decoded, bits);
        assert_eq!(decoded_weight, expected_weight);
    }

    #[test]
    fn next_bit_with_double_weights_adapts_like_iron() {
        let bits = [0u32, 1, 0, 0, 1, 0, 1, 1, 0, 0];
        let (shift1, shift2) = (4u32, 6u32);
        let mut w1 = 0x900u32;
        let mut w2 = 0x700u32;

        let mut enc = CarrylessEncoder::new(0);
        for &b in &bits {
            enc.encode_weighted_bit(b, (w1 + w2) / 2, 0x1000);
            if b == 0 {
                w1 += (0x1000 - w1) >> shift1;
                w2 += (0x1000 - w2) >> shift2;
            } else {
                w1 -= w1 >> shift1;
                w2 -= w2 >> shift2;
            }
        }
        let (expected_w1, expected_w2) = (w1, w2);
        let bytes = enc.finish();

        let mut dec = RangeCoder::new(&bytes, true, 0);
        let (mut d1, mut d2) = (0x900u32, 0x700u32);
        let decoded: Vec<u32> = bits
            .iter()
            .map(|_| dec.next_bit_with_double_weights(&mut d1, shift1, &mut d2, shift2))
            .collect();

        assert_eq!(decoded, bits);
        assert_eq!((d1, d2), (expected_w1, expected_w2));
    }

    #[test]
    fn position_starts_at_four_after_the_initial_code_read() {
        let bytes = [0u8; 8];
        let dec = RangeCoder::new(&bytes, true, 0);
        assert_eq!(
            dec.position(),
            4,
            "new() reads exactly the leading code word"
        );
    }

    #[test]
    fn position_advances_monotonically_as_symbols_are_decoded() {
        let freqs = [1u32, 1, 1, 1];
        let symbols = [0usize, 1, 2, 3, 0, 1, 2, 3];

        let mut enc = CarrylessEncoder::new(0);
        for &s in &symbols {
            enc.encode_symbol(&freqs, s);
        }
        let bytes = enc.finish();

        let mut dec = RangeCoder::new(&bytes, true, 0);
        let mut last = dec.position();
        assert_eq!(last, 4);
        for &s in &symbols {
            assert_eq!(dec.next_symbol(&freqs), s);
            let now = dec.position();
            assert!(now >= last, "position must never move backwards");
            last = now;
        }
        assert!(last > 4, "decoding several symbols must consume more input");
    }

    #[test]
    fn nonzero_bottom_forces_underflow_branch() {
        // With a large `bottom` (Cyanide uses 0x10000), the normal
        // termination condition `range>=bottom` fails far more often,
        // exercising the underflow rewrite of `range` in `normalize`.
        let bottom = 0x10000u32;
        let freqs = [1u32, 1, 1, 1, 1, 1, 1, 1];
        let symbols = [0usize, 7, 3, 5, 1, 6, 2, 4, 0, 7, 7, 3];

        let mut enc = CarrylessEncoder::new(bottom);
        for &s in &symbols {
            enc.encode_symbol(&freqs, s);
        }
        let bytes = enc.finish();

        let mut dec = RangeCoder::new(&bytes, true, bottom);
        let decoded: Vec<usize> = (0..symbols.len())
            .map(|_| dec.next_symbol(&freqs))
            .collect();
        assert_eq!(decoded, symbols);
    }
}
