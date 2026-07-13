// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Test-only symmetric encoder for PPMd variant G / Brimstone.
//!
//! There's no PPMd encoder anywhere in XADMaster (the project only ever
//! *reads* archives) and the real StuffItX test corpus doesn't contain a
//! single Brimstone-compressed member (checked directly: `lsar -j` over every
//! `.sitx` in the corpus never reports compression method 0 — see
//! `report-19g-sitx-brimstone-ppmd.md`), so there's no external reference to
//! decode against. This module is the fallback the task allows: a real
//! encoder built from the *same* adaptive model, so a round trip through it
//! and back through the real decoder (`brimstone::decode`) exercises the
//! actual byte-level conformance of every piece — the range coder, the
//! allocator, `RescalePPMdContext`, `UpdateModel`, `MakeRoot` — the same way
//! 19b's `CarrylessEncoder` validated `RangeCoder`.
//!
//! It's cheap to build precisely *because* [`super::context::PpmdCore`] and
//! [`super::variant_g::PpmdModelVariantG`] are generic over the coder
//! backend: every function that doesn't touch the coder directly
//! (`update_context1`/`2`, `rescale_context`, `restart_model`,
//! `update_model`, `make_root`) is reused unchanged with `C =
//! PpmdRangeEncoder` instead of `PpmdRangeCoder`. Only the three functions
//! that *do* talk to the coder (`decode_bin_symbol`, `decode_symbol1`,
//! `decode_symbol2`, plus their thin `*_variant_g` wrappers and
//! `next_byte`/`start`) get an encode-side twin here, each computing from a
//! known target byte the exact sub-range bounds the reference would have
//! read `count` into — the standard symmetric-coding trick.

use super::alloc::BrimstoneAlloc;
use super::context::{
    clear_mask, ctx_flags, ctx_last_state_index, ctx_one_state, ctx_states, ctx_suffix,
    ctx_summ_freq, number_of_states, rescale_context, set_ctx_summ_freq, set_state_freq, state_at,
    state_freq, state_successor, state_symbol, update_context1, update_context2, CtxRef, PpmdCore,
    See2Context, StateRef, INTERVAL, MAX_FREQ, PERIOD_BITS, TOT_BITS,
};
use super::variant_g::{new_model, update_model, PpmdModelVariantG};

/// `PPMdRangeCoder`'s encode-side dual: builds the exact byte stream
/// [`super::rangecoder::PpmdRangeCoder`] (`uselow=true`) would consume.
/// Structurally identical to `rangecoder.rs`'s in-file `MirrorEncoder` test
/// helper — kept separate because this one needs to be reachable from
/// `PpmdCore<PpmdRangeEncoder>` here, not just from `rangecoder.rs`'s own
/// unit tests.
pub(crate) struct PpmdRangeEncoder {
    out: Vec<u8>,
    low: u32,
    range: u32,
    bottom: u32,
}

impl PpmdRangeEncoder {
    pub(crate) fn new(bottom: u32) -> Self {
        PpmdRangeEncoder {
            out: Vec::new(),
            low: 0,
            range: 0xffff_ffff,
            bottom,
        }
    }

    /// Encode-side dual of `PPMdRangeCoderCurrentCount` + `RemovePPMdRangeCoderSubRange`
    /// combined: given the sub-range `[lowcount,highcount)` out of `total` the
    /// decoder is meant to land on, commit it.
    fn encode_range(&mut self, lowcount: u32, highcount: u32, total: u32) {
        self.range /= total;
        self.low = self.low.wrapping_add(self.range.wrapping_mul(lowcount));
        self.range = self.range.wrapping_mul(highcount - lowcount);
        self.normalize();
    }

    /// Dual of `NextWeightedBitFromPPMdRangeCoder`.
    fn encode_weighted_bit(&mut self, bit: u32, weight: u32, size: u32) {
        if bit == 0 {
            self.encode_range(0, weight, size);
        } else {
            self.encode_range(weight, size, size);
        }
    }

    /// Dual of `NextWeightedBitFromPPMdRangeCoder2`.
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

    /// Dual of `NormalizePPMdRangeCoder`: emits instead of reading.
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

    /// Flushes the trailing bytes `PpmdRangeCoder::new`'s four-byte initial
    /// read will consume.
    pub(crate) fn finish(mut self) -> Vec<u8> {
        for _ in 0..4 {
            self.out.push((self.low >> 24) as u8);
            self.low <<= 8;
        }
        self.out
    }
}

const EXP_ESCAPE: [i32; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];

fn get_mean(summ: u32, shift: u32, round: u32) -> u32 {
    (summ + (1 << (shift - round))) >> shift
}

/// Encode-side dual of `PPMdDecodeBinSymbol` (`Context.c:100`): `target ==
/// rs.Symbol` decides the bit instead of reading one.
fn encode_bin_symbol(
    core: &mut PpmdCore<PpmdRangeEncoder>,
    ctx: CtxRef,
    bs: &mut u16,
    freqlimit: i32,
    altnextbit: bool,
    target: u8,
) -> bool {
    let rs = ctx_one_state(ctx);
    let rs_symbol = state_symbol(&core.alloc, rs);
    let bit: u32 = if target == rs_symbol { 0 } else { 1 };

    if altnextbit {
        core.coder.encode_weighted_bit2(bit, *bs as u32, TOT_BITS);
    } else {
        core.coder
            .encode_weighted_bit(bit, *bs as u32, 1u32 << TOT_BITS);
    }

    if bit == 0 {
        core.prev_success = 1;
        core.run_length += 1;
        core.found_state = rs;

        let freq = state_freq(&core.alloc, rs);
        if (freq as i32) < freqlimit {
            set_state_freq(&mut core.alloc, rs, freq + 1);
        }
        let mean = get_mean(*bs as u32, PERIOD_BITS, 2);
        *bs = ((*bs as u32)
            .wrapping_add(INTERVAL as u32)
            .wrapping_sub(mean)) as u16;
        true
    } else {
        core.prev_success = 0;
        core.found_state = StateRef::NULL;
        core.last_mask_index = 0;
        core.char_mask[rs_symbol as usize] = core.esc_count;

        let mean = get_mean(*bs as u32, PERIOD_BITS, 2);
        *bs = (*bs as u32).wrapping_sub(mean) as u16;
        core.init_esc = EXP_ESCAPE[(*bs >> 10) as usize];
        false
    }
}

/// Encode-side dual of `PPMdDecodeSymbol1` (`Context.c:129`): searches for
/// `target` instead of decoding an unknown `count`. Returns whether `target`
/// was found in this context (mirroring `!= -1` from the reference, i.e.
/// `found_state` ends up set).
fn encode_symbol1(
    core: &mut PpmdCore<PpmdRangeEncoder>,
    ctx: CtxRef,
    greaterorequal: bool,
    target: u8,
) -> bool {
    core.scale = ctx_summ_freq(&core.alloc, ctx) as u32;

    let states = ctx_states(&core.alloc, ctx);
    let firstcount = state_freq(&core.alloc, states) as i32;
    let first_symbol = state_symbol(&core.alloc, states);
    let adder = if greaterorequal { 1 } else { 0 };

    if first_symbol == target {
        core.coder.encode_range(0, firstcount as u32, core.scale);
        if 2 * firstcount + adder > core.scale as i32 {
            core.prev_success = 1;
            core.run_length += 1;
        } else {
            core.prev_success = 0;
        }

        core.found_state = states;
        set_state_freq(&mut core.alloc, states, (firstcount + 4) as u8);
        let summ = ctx_summ_freq(&core.alloc, ctx) as i32 + 4;
        set_ctx_summ_freq(&mut core.alloc, ctx, summ as u16);

        if firstcount + 4 > MAX_FREQ {
            rescale_context(core, ctx);
        }
        return true;
    }

    let mut highcount = firstcount;
    core.prev_success = 0;

    let last_state_index = ctx_last_state_index(&core.alloc, ctx) as i32;
    for i in 1..=last_state_index {
        let si = state_at(states, i);
        let freq = state_freq(&core.alloc, si) as i32;
        let sym = state_symbol(&core.alloc, si);
        highcount += freq;
        if sym == target {
            core.coder
                .encode_range((highcount - freq) as u32, highcount as u32, core.scale);
            update_context1(core, ctx, si);
            return true;
        }
    }

    // Total escape: `target` isn't in this context at all.
    core.coder
        .encode_range(highcount as u32, core.scale, core.scale);
    core.last_mask_index = last_state_index as u8;
    core.found_state = StateRef::NULL;
    for i in 0..=last_state_index {
        let si = state_at(states, i);
        let sym = state_symbol(&core.alloc, si);
        core.char_mask[sym as usize] = core.esc_count;
    }
    false
}

/// Encode-side dual of `PPMdDecodeSymbol2` (`Context.c:203`).
fn encode_symbol2(
    core: &mut PpmdCore<PpmdRangeEncoder>,
    ctx: CtxRef,
    see: &mut See2Context,
    target: u8,
) -> bool {
    let n = ctx_last_state_index(&core.alloc, ctx) as i32 - core.last_mask_index as i32;
    let mut ps = [StateRef::NULL; 256];

    let mut total = 0i32;
    let mut state = ctx_states(&core.alloc, ctx);
    for slot in ps.iter_mut().take(n as usize) {
        while core.char_mask[state_symbol(&core.alloc, state) as usize] == core.esc_count {
            state = state_at(state, 1);
        }
        total += state_freq(&core.alloc, state) as i32;
        *slot = state;
        state = state_at(state, 1);
    }

    core.scale += total as u32;

    let mut found_idx = None;
    for (i, &p) in ps.iter().take(n as usize).enumerate() {
        if state_symbol(&core.alloc, p) == target {
            found_idx = Some(i);
            break;
        }
    }

    if let Some(i) = found_idx {
        let mut highcount = 0i32;
        for &p in ps.iter().take(i + 1) {
            highcount += state_freq(&core.alloc, p) as i32;
        }
        let freq_i = state_freq(&core.alloc, ps[i]) as i32;
        core.coder
            .encode_range((highcount - freq_i) as u32, highcount as u32, core.scale);
        see.update();
        update_context2(core, ctx, ps[i]);
        true
    } else {
        core.coder
            .encode_range(total as u32, core.scale, core.scale);
        core.last_mask_index = ctx_last_state_index(&core.alloc, ctx);
        see.summ = see.summ.wrapping_add(core.scale as u16);
        for slot in ps.iter().take(n as usize) {
            let sym = state_symbol(&core.alloc, *slot);
            core.char_mask[sym as usize] = core.esc_count;
        }
        false
    }
}

fn encode_bin_symbol_variant_g(
    model: &mut PpmdModelVariantG<PpmdRangeEncoder>,
    ctx: CtxRef,
    target: u8,
) -> bool {
    let rs = ctx_one_state(ctx);
    let freq = state_freq(&model.core.alloc, rs);
    let suffix = ctx_suffix(&model.core.alloc, ctx);
    let suffix_lsi = ctx_last_state_index(&model.core.alloc, suffix);
    let col = model.core.prev_success as usize + model.ns2bs_indx[suffix_lsi as usize] as usize;
    let row = freq as usize - 1;

    encode_bin_symbol(
        &mut model.core,
        ctx,
        &mut model.bin_summ[row][col],
        128,
        false,
        target,
    )
}

fn encode_symbol1_variant_g(
    model: &mut PpmdModelVariantG<PpmdRangeEncoder>,
    ctx: CtxRef,
    target: u8,
) -> bool {
    encode_symbol1(&mut model.core, ctx, false, target)
}

fn encode_symbol2_variant_g(
    model: &mut PpmdModelVariantG<PpmdRangeEncoder>,
    ctx: CtxRef,
    target: u8,
) -> bool {
    let last_state_index = ctx_last_state_index(&model.core.alloc, ctx) as i32;
    let diff = last_state_index - model.core.last_mask_index as i32;

    if last_state_index != 255 {
        let suffix = ctx_suffix(&model.core.alloc, ctx);
        let suffix_lsi = ctx_last_state_index(&model.core.alloc, suffix) as i32;
        let summ_freq = ctx_summ_freq(&model.core.alloc, ctx) as i32;
        let nstates = number_of_states(&model.core.alloc, ctx);

        let idx = (if diff < suffix_lsi - last_state_index {
            1
        } else {
            0
        }) + (if summ_freq < 11 * nstates { 2 } else { 0 })
            + (if model.core.last_mask_index as i32 + 1 > diff {
                4
            } else {
                0
            });

        let row = model.ns2_indx[(diff - 1) as usize] as usize;
        model.core.scale = model.see2_cont[row][idx].mean_masked();
        encode_symbol2(&mut model.core, ctx, &mut model.see2_cont[row][idx], target)
    } else {
        model.core.scale = 1;
        encode_symbol2(&mut model.core, ctx, &mut model.dummy_see2_cont, target)
    }
}

/// Encode-side dual of `NextPPMdVariantGByte` (`.c:103`), driving the model
/// to encode a *known* byte instead of decoding an unknown one.
fn encode_byte(model: &mut PpmdModelVariantG<PpmdRangeEncoder>, target: u8) -> bool {
    if model.min_context.is_null() {
        return false;
    }

    let mut found = if number_of_states(&model.core.alloc, model.min_context) != 1 {
        encode_symbol1_variant_g(model, model.min_context, target)
    } else {
        encode_bin_symbol_variant_g(model, model.min_context, target)
    };

    while !found {
        loop {
            model.core.order_fall += 1;
            model.min_context = ctx_suffix(&model.core.alloc, model.min_context);
            if model.min_context.is_null() {
                return false;
            }
            if ctx_last_state_index(&model.core.alloc, model.min_context)
                != model.core.last_mask_index
            {
                break;
            }
        }
        found = encode_symbol2_variant_g(model, model.min_context, target);
    }

    let succ = state_successor(&model.core.alloc, model.core.found_state);
    if model.core.order_fall == 0 && ctx_flags(&model.core.alloc, succ) == 0 {
        model.min_context = succ;
        model.med_context = succ;
    } else {
        update_model(model);
        if model.core.esc_count == 0 {
            clear_mask(&mut model.core);
        }
    }

    true
}

/// Encode-side dual of `StartPPMdModelVariantG` (`.c:16`).
fn start_enc(
    alloc_size: u32,
    maxorder: i32,
    brimstone: bool,
) -> PpmdModelVariantG<PpmdRangeEncoder> {
    let bottom = if brimstone { 0x10000 } else { 0x8000 };
    let core = PpmdCore {
        coder: PpmdRangeEncoder::new(bottom),
        alloc: BrimstoneAlloc::new(alloc_size),
        scale: 0,
        found_state: StateRef::NULL,
        order_fall: 0,
        init_esc: 0,
        run_length: 0,
        init_rl: 0,
        char_mask: [0u8; 256],
        last_mask_index: 0,
        esc_count: 1,
        prev_success: 0,
    };
    new_model(core, maxorder, brimstone)
}

/// Encode a whole message with a fresh model, returning the compressed
/// bytes `PpmdRangeCoder`/`NextPPMdVariantGByte` would decode back losslessly
/// — the corpus-less round-trip oracle's entry point (see this module's
/// tests below).
fn encode_message(message: &[u8], alloc_size: u32, order: i32) -> Vec<u8> {
    let mut model = start_enc(alloc_size, order, true);
    for &b in message {
        assert!(
            encode_byte(&mut model, b),
            "encoder ran out of context chain for byte {b}"
        );
    }
    model.core.coder.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_repetitive_text() {
        let message: Vec<u8> = b"the quick brown fox jumps over the lazy dog. "
            .iter()
            .cloned()
            .cycle()
            .take(3000)
            .collect();
        let alloc_size = 1u32 << 16;
        let order = 4;

        let encoded = encode_message(&message, alloc_size, order);
        let decoded = super::super::variant_g::start(&encoded, alloc_size, order, true);
        let mut model = decoded;
        let mut out = Vec::with_capacity(message.len());
        for _ in 0..message.len() {
            let b = super::super::variant_g::next_byte(&mut model);
            assert!(b >= 0, "decoder hit EOF early");
            out.push(b as u8);
        }
        assert_eq!(out, message);
    }

    #[test]
    fn round_trip_via_brimstone_decode_wrapper() {
        // The strongest form of this oracle: go through the actual public
        // `brimstone::decode` entry point the container calls, not just the
        // raw model, so the wrapper's `order`/`alloc_size` plumbing is
        // exercised too.
        let message: Vec<u8> = (0u32..2500)
            .map(|i| (i.wrapping_mul(2654435761) >> 20) as u8)
            .collect();
        let alloc_size = 1u32 << 16;
        let order = 6;

        let encoded = encode_message(&message, alloc_size, order);
        let decoded = super::super::super::brimstone::decode(
            &encoded,
            message.len(),
            order as u32,
            alloc_size as usize,
        )
        .unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn round_trip_single_repeated_byte_forces_rescale() {
        // A long run of one symbol drives its Freq past MAX_FREQ repeatedly,
        // exercising RescalePPMdContext's every-loop-iteration path hard.
        let message = vec![b'x'; 5000];
        let alloc_size = 1u32 << 15;
        let order = 3;

        let encoded = encode_message(&message, alloc_size, order);
        let decoded = super::super::super::brimstone::decode(
            &encoded,
            message.len(),
            order as u32,
            alloc_size as usize,
        )
        .unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn round_trip_short_message() {
        let message = b"AB";
        let alloc_size = 1u32 << 14;
        let order = 4;

        let encoded = encode_message(message, alloc_size, order);
        let decoded = super::super::super::brimstone::decode(
            &encoded,
            message.len(),
            order as u32,
            alloc_size as usize,
        )
        .unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn round_trip_plain_variant_g_not_just_brimstone() {
        // brimstone=false: exercises the other two flag-dependent spots
        // (bottom=0x8000, root SummFreq=257/uniform Freq=1).
        let message: Vec<u8> = b"mississippi river "
            .iter()
            .cloned()
            .cycle()
            .take(1200)
            .collect();
        let alloc_size = 1u32 << 15;
        let order = 4;

        let mut model = start_enc(alloc_size, order, false);
        for &b in &message {
            assert!(encode_byte(&mut model, b));
        }
        let encoded = model.core.coder.finish();

        let mut dec = super::super::variant_g::start(&encoded, alloc_size, order, false);
        let mut out = Vec::with_capacity(message.len());
        for _ in 0..message.len() {
            let b = super::super::variant_g::next_byte(&mut dec);
            assert!(b >= 0);
            out.push(b as u8);
        }
        assert_eq!(out, message);
    }
}
