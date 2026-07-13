// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! PPMd's common model core (`PPMd/Context.h`/`.c`), shared by every PPMd
//! variant (only variant G is ported at this stage).
//!
//! ## The offset trick
//!
//! The reference addresses everything in the sub-allocator's arena through
//! `OffsetToPointer`/`PointerToOffset` (`SubAllocator.h:29-39`) and marks its
//! structs `__attribute__((__packed__))`:
//!
//! ```c
//! typedef struct PPMdState { uint8_t Symbol,Freq; uint32_t Successor; } __attribute__((__packed__)) PPMdState;
//! struct PPMdContext { uint8_t LastStateIndex,Flags; uint16_t SummFreq; uint32_t States; uint32_t Suffix; } __attribute__((__packed__));
//! ```
//!
//! `PPMdState` is packed to exactly 6 bytes (`STATE_SIZE`) and `PPMdContext`
//! to exactly 12 bytes (`alloc::UNIT_SIZE`) — no padding, so a context is
//! always exactly one allocator unit. With `#![forbid(unsafe_code)]` there are
//! no raw pointers to alias these layouts onto; instead [`StateRef`]/[`CtxRef`]
//! are `u32` byte offsets into [`BrimstoneAlloc`]'s arena, and every field
//! access below is an explicit little-endian read/write at a fixed byte
//! offset — a byte-for-byte port of the packed layout, just spelled out.
//!
//! The one genuinely subtle piece of that layout is `PPMdContextOneState`
//! (`Context.c:65`):
//!
//! ```c
//! PPMdState *PPMdContextOneState(PPMdContext *self) { return (PPMdState *)&self->SummFreq; }
//! ```
//!
//! This reinterprets the *last 6 bytes* of a 12-byte context (offset 2..8:
//! `SummFreq` then `States`) as a `PPMdState` — a single-state context stores
//! its one state directly in its own bytes instead of a separate allocation.
//! [`ctx_one_state`] below is the same trick: `StateRef(ctx.0 + 2)`.

use super::alloc::BrimstoneAlloc;
use super::rangecoder::PpmdRangeCoder;

pub(crate) const MAX_O: usize = 255;
pub(crate) const INT_BITS: u32 = 7;
pub(crate) const PERIOD_BITS: u32 = 7;
pub(crate) const TOT_BITS: u32 = INT_BITS + PERIOD_BITS;
pub(crate) const MAX_FREQ: i32 = 124;
pub(crate) const INTERVAL: i32 = 1 << INT_BITS;
pub(crate) const BIN_SCALE: i32 = 1 << TOT_BITS;

const STATE_SIZE: u32 = 6;

// === offsets ================================================================

/// A byte offset into [`BrimstoneAlloc`]'s arena naming a `PPMdContext`. `0`
/// is null (`OffsetToPointer(0) == NULL`).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) struct CtxRef(pub(crate) u32);

impl CtxRef {
    pub(crate) const NULL: CtxRef = CtxRef(0);
    pub(crate) fn is_null(self) -> bool {
        self.0 == 0
    }
}

/// A byte offset into the arena naming a `PPMdState`. `0` is null.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) struct StateRef(pub(crate) u32);

impl StateRef {
    pub(crate) const NULL: StateRef = StateRef(0);
    pub(crate) fn is_null(self) -> bool {
        self.0 == 0
    }
}

/// Index into a `PPMdState` array (`states[i]`, `STATE_SIZE` bytes apart).
pub(crate) fn state_at(base: StateRef, i: i32) -> StateRef {
    StateRef((base.0 as i64 + i as i64 * STATE_SIZE as i64) as u32)
}

// === PPMdState field access =================================================

pub(crate) fn state_symbol(a: &BrimstoneAlloc, s: StateRef) -> u8 {
    a.get_u8(s.0)
}
pub(crate) fn set_state_symbol(a: &mut BrimstoneAlloc, s: StateRef, v: u8) {
    a.put_u8(s.0, v);
}
pub(crate) fn state_freq(a: &BrimstoneAlloc, s: StateRef) -> u8 {
    a.get_u8(s.0 + 1)
}
pub(crate) fn set_state_freq(a: &mut BrimstoneAlloc, s: StateRef, v: u8) {
    a.put_u8(s.0 + 1, v);
}
fn state_successor_raw(a: &BrimstoneAlloc, s: StateRef) -> u32 {
    a.get_u32(s.0 + 2)
}
fn set_state_successor_raw(a: &mut BrimstoneAlloc, s: StateRef, v: u32) {
    a.put_u32(s.0 + 2, v);
}
/// `PPMdStateSuccessor` (`.c:47`).
pub(crate) fn state_successor(a: &BrimstoneAlloc, s: StateRef) -> CtxRef {
    CtxRef(state_successor_raw(a, s))
}
/// `SetPPMdStateSuccessorPointer` (`.c:50`).
pub(crate) fn set_state_successor(a: &mut BrimstoneAlloc, s: StateRef, c: CtxRef) {
    set_state_successor_raw(a, s, c.0);
}

/// Copies a whole `PPMdState` (Symbol+Freq+Successor) from `src` to `dst`,
/// e.g. `states[0]=*(PPMdContextOneState(currcontext));` (`VariantG.c:223`).
pub(crate) fn copy_state(a: &mut BrimstoneAlloc, src: StateRef, dst: StateRef) {
    let (sym, freq, succ) = (
        state_symbol(a, src),
        state_freq(a, src),
        state_successor_raw(a, src),
    );
    set_state_symbol(a, dst, sym);
    set_state_freq(a, dst, freq);
    set_state_successor_raw(a, dst, succ);
}

/// `SWAP` (`Context.h:18`).
pub(crate) fn swap_states(a: &mut BrimstoneAlloc, x: StateRef, y: StateRef) {
    let (sx, fx, cx) = (
        state_symbol(a, x),
        state_freq(a, x),
        state_successor_raw(a, x),
    );
    copy_state(a, y, x);
    set_state_symbol(a, y, sx);
    set_state_freq(a, y, fx);
    set_state_successor_raw(a, y, cx);
}

// === PPMdContext field access ===============================================

pub(crate) fn ctx_last_state_index(a: &BrimstoneAlloc, c: CtxRef) -> u8 {
    a.get_u8(c.0)
}
pub(crate) fn set_ctx_last_state_index(a: &mut BrimstoneAlloc, c: CtxRef, v: u8) {
    a.put_u8(c.0, v);
}
pub(crate) fn ctx_flags(a: &BrimstoneAlloc, c: CtxRef) -> u8 {
    a.get_u8(c.0 + 1)
}
pub(crate) fn set_ctx_flags(a: &mut BrimstoneAlloc, c: CtxRef, v: u8) {
    a.put_u8(c.0 + 1, v);
}
pub(crate) fn ctx_summ_freq(a: &BrimstoneAlloc, c: CtxRef) -> u16 {
    a.get_u16(c.0 + 2)
}
pub(crate) fn set_ctx_summ_freq(a: &mut BrimstoneAlloc, c: CtxRef, v: u16) {
    a.put_u16(c.0 + 2, v);
}
fn ctx_states_raw(a: &BrimstoneAlloc, c: CtxRef) -> u32 {
    a.get_u32(c.0 + 4)
}
fn set_ctx_states_raw(a: &mut BrimstoneAlloc, c: CtxRef, v: u32) {
    a.put_u32(c.0 + 4, v);
}
/// `PPMdContextStates` (`.c:53`).
pub(crate) fn ctx_states(a: &BrimstoneAlloc, c: CtxRef) -> StateRef {
    StateRef(ctx_states_raw(a, c))
}
/// `SetPPMdContextStatesPointer` (`.c:56`).
pub(crate) fn set_ctx_states(a: &mut BrimstoneAlloc, c: CtxRef, s: StateRef) {
    set_ctx_states_raw(a, c, s.0);
}
fn ctx_suffix_raw(a: &BrimstoneAlloc, c: CtxRef) -> u32 {
    a.get_u32(c.0 + 8)
}
fn set_ctx_suffix_raw(a: &mut BrimstoneAlloc, c: CtxRef, v: u32) {
    a.put_u32(c.0 + 8, v);
}
/// `PPMdContextSuffix` (`.c:59`).
pub(crate) fn ctx_suffix(a: &BrimstoneAlloc, c: CtxRef) -> CtxRef {
    CtxRef(ctx_suffix_raw(a, c))
}
/// `SetPPMdContextSuffixPointer` (`.c:62`).
pub(crate) fn set_ctx_suffix(a: &mut BrimstoneAlloc, c: CtxRef, suf: CtxRef) {
    set_ctx_suffix_raw(a, c, suf.0);
}

/// `PPMdContextOneState` (`.c:65`) — see the module doc for the aliasing
/// trick this ports. No arena access: it's pure offset arithmetic.
pub(crate) fn ctx_one_state(c: CtxRef) -> StateRef {
    StateRef(c.0 + 2)
}

/// `NumberOfStates` (`VariantG.c:14`): lives here rather than `variant_g.rs`
/// because every `Context.c` function that inspects a context's state count
/// needs it too.
pub(crate) fn number_of_states(a: &BrimstoneAlloc, c: CtxRef) -> i32 {
    if ctx_flags(a, c) != 0 {
        0
    } else {
        ctx_last_state_index(a, c) as i32 + 1
    }
}

// === SEE2Context =============================================================

/// `SEE2Context` (`Context.h:20`) — a small value type, not arena-resident
/// (it lives in the variant-G model's own fixed-size table), so no offset
/// trick is needed here.
#[derive(Copy, Clone, Default)]
pub(crate) struct See2Context {
    pub(crate) summ: u16,
    pub(crate) shift: u8,
    pub(crate) count: u8,
}

impl See2Context {
    /// `MakeSEE2` (`.c:5`).
    pub(crate) fn make(initval: i32, count: i32) -> Self {
        let shift = (PERIOD_BITS - 4) as u8;
        See2Context {
            summ: ((initval << shift) as u32) as u16,
            shift,
            count: count as u8,
        }
    }

    /// `GetSEE2MeanMasked` (`.c:14`).
    pub(crate) fn mean_masked(&mut self) -> u32 {
        let retval = (self.summ as u32) >> (self.shift as u32);
        self.summ = self.summ.wrapping_sub(retval as u16);
        let retval = retval & 0x03ff;
        if retval == 0 {
            1
        } else {
            retval
        }
    }

    /// `GetSEE2Mean` (`.c:23`).
    #[allow(dead_code)] // no NS2Indx==255 caller reachable from variant G's decode-only path
    pub(crate) fn mean(&mut self) -> u32 {
        let retval = (self.summ as u32) >> (self.shift as u32);
        self.summ = self.summ.wrapping_sub(retval as u16);
        if retval == 0 {
            1
        } else {
            retval
        }
    }

    /// `UpdateSEE2` (`.c:31`).
    pub(crate) fn update(&mut self) {
        if self.shift as u32 >= PERIOD_BITS {
            return;
        }
        self.count -= 1;
        if self.count == 0 {
            self.summ = self.summ.wrapping_mul(2);
            self.count = (3u32 << self.shift) as u8;
            self.shift += 1;
        }
    }
}

// === PpmdCore ================================================================

/// `PPMdCoreModel` (`Context.h:41`), minus the `RescalePPMdContext` function
/// pointer: the reference wires it up per-variant for polymorphism, but since
/// only variant G exists in this port, [`rescale_context`] is called directly.
///
/// Generic over the range-coder backend `C` (normally [`PpmdRangeCoder`]):
/// every function here except [`decode_bin_symbol`], [`decode_symbol1`] and
/// [`decode_symbol2`] never touches `coder` at all — they're pure arena/model
/// bookkeeping — so they stay generic and are reused verbatim by the
/// test-only symmetric encoder (`encoder_mirror.rs`) with `C =
/// PpmdRangeEncoder` instead of duplicating ~150 lines of bookkeeping.
pub(crate) struct PpmdCore<C> {
    pub(crate) coder: C,
    pub(crate) alloc: BrimstoneAlloc,
    pub(crate) scale: u32,
    pub(crate) found_state: StateRef,
    pub(crate) order_fall: i32,
    pub(crate) init_esc: i32,
    pub(crate) run_length: i32,
    pub(crate) init_rl: i32,
    pub(crate) char_mask: [u8; 256],
    pub(crate) last_mask_index: u8,
    pub(crate) esc_count: u8,
    pub(crate) prev_success: u8,
}

/// `NewPPMdContext` (`.c:67`).
pub(crate) fn new_context<C>(core: &mut PpmdCore<C>) -> CtxRef {
    let off = core.alloc.alloc_context();
    let ctx = CtxRef(off);
    if !ctx.is_null() {
        set_ctx_last_state_index(&mut core.alloc, ctx, 0);
        set_ctx_flags(&mut core.alloc, ctx, 0);
        set_ctx_suffix_raw(&mut core.alloc, ctx, 0);
    }
    ctx
}

/// `NewPPMdContextAsChildOf` (`.c:79`).
pub(crate) fn new_context_as_child_of<C>(
    core: &mut PpmdCore<C>,
    suffixcontext: CtxRef,
    suffixstate: StateRef,
    firststate: Option<StateRef>,
) -> CtxRef {
    let off = core.alloc.alloc_context();
    let ctx = CtxRef(off);
    if !ctx.is_null() {
        set_ctx_last_state_index(&mut core.alloc, ctx, 0);
        set_ctx_flags(&mut core.alloc, ctx, 0);
        set_ctx_suffix(&mut core.alloc, ctx, suffixcontext);
        set_state_successor(&mut core.alloc, suffixstate, ctx);
        if let Some(fs) = firststate {
            copy_state(&mut core.alloc, fs, ctx_one_state(ctx));
        }
    }
    ctx
}

// === decode/update ===========================================================

const EXP_ESCAPE: [i32; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];

fn get_mean(summ: u32, shift: u32, round: u32) -> u32 {
    (summ + (1 << (shift - round))) >> shift
}

/// `PPMdDecodeBinSymbol` (`Context.c:100`).
pub(crate) fn decode_bin_symbol<'a>(
    core: &mut PpmdCore<PpmdRangeCoder<'a>>,
    ctx: CtxRef,
    bs: &mut u16,
    freqlimit: i32,
    altnextbit: bool,
) {
    let rs = ctx_one_state(ctx);

    let bit = if altnextbit {
        core.coder.next_weighted_bit2(*bs as u32, TOT_BITS)
    } else {
        core.coder.next_weighted_bit(*bs as u32, 1u32 << TOT_BITS)
    };

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
    } else {
        core.prev_success = 0;
        core.found_state = StateRef::NULL;
        core.last_mask_index = 0;
        let sym = state_symbol(&core.alloc, rs);
        core.char_mask[sym as usize] = core.esc_count;

        let mean = get_mean(*bs as u32, PERIOD_BITS, 2);
        *bs = (*bs as u32).wrapping_sub(mean) as u16;
        core.init_esc = EXP_ESCAPE[(*bs >> 10) as usize];
    }
}

/// `PPMdDecodeSymbol1` (`Context.c:129`). Returns `-1` when a state was found
/// (via `model->FoundState`, mirroring the reference's overload), or the
/// escaped symbol on total escape.
pub(crate) fn decode_symbol1<'a>(
    core: &mut PpmdCore<PpmdRangeCoder<'a>>,
    ctx: CtxRef,
    greaterorequal: bool,
) -> i32 {
    core.scale = ctx_summ_freq(&core.alloc, ctx) as u32;

    let states = ctx_states(&core.alloc, ctx);
    let firstcount = state_freq(&core.alloc, states) as i32;
    let count = core.coder.current_count(core.scale) as i32;
    let adder = if greaterorequal { 1 } else { 0 };

    if count < firstcount {
        core.coder.remove_subrange(0, firstcount as u32);
        if 2 * firstcount + adder > core.scale as i32 {
            core.prev_success = 1;
            core.run_length += 1;
        } else {
            core.prev_success = 0;
        }

        core.found_state = states;
        set_state_freq(&mut core.alloc, states, (firstcount + 4) as u8);
        // SummFreq was cached into `core.scale` above and is unchanged since.
        let summ = core.scale as i32 + 4;
        set_ctx_summ_freq(&mut core.alloc, ctx, summ as u16);

        if firstcount + 4 > MAX_FREQ {
            rescale_context(core, ctx);
        }

        return -1;
    }

    let mut highcount = firstcount;
    core.prev_success = 0;

    let last_state_index = ctx_last_state_index(&core.alloc, ctx) as i32;
    for i in 1..=last_state_index {
        let si = state_at(states, i);
        let freq = state_freq(&core.alloc, si) as i32;
        highcount += freq;
        if highcount > count {
            core.coder
                .remove_subrange((highcount - freq) as u32, highcount as u32);
            update_context1(core, ctx, si);
            return -1;
        }
    }

    if core.found_state.is_null() {
        return -1;
    }
    let lastsym = state_symbol(&core.alloc, core.found_state);

    core.coder.remove_subrange(highcount as u32, core.scale);
    core.last_mask_index = last_state_index as u8;
    core.found_state = StateRef::NULL;

    for i in 0..=last_state_index {
        let si = state_at(states, i);
        let sym = state_symbol(&core.alloc, si);
        core.char_mask[sym as usize] = core.esc_count;
    }

    lastsym as i32
}

/// `UpdatePPMdContext1` (`Context.c:184`).
pub(crate) fn update_context1<C>(core: &mut PpmdCore<C>, ctx: CtxRef, state: StateRef) {
    let newfreq = state_freq(&core.alloc, state) + 4;
    set_state_freq(&mut core.alloc, state, newfreq);
    let summ = ctx_summ_freq(&core.alloc, ctx) as i32 + 4;
    set_ctx_summ_freq(&mut core.alloc, ctx, summ as u16);

    let prev = StateRef(state.0 - STATE_SIZE);
    // After the bump, `state`'s freq is `newfreq`; the swap moves it into `prev`.
    if newfreq > state_freq(&core.alloc, prev) {
        swap_states(&mut core.alloc, state, prev);
        core.found_state = prev;
        if newfreq as i32 > MAX_FREQ {
            rescale_context(core, ctx);
        }
    } else {
        core.found_state = state;
    }
}

/// `PPMdDecodeSymbol2` (`Context.c:203`).
pub(crate) fn decode_symbol2<'a>(
    core: &mut PpmdCore<PpmdRangeCoder<'a>>,
    ctx: CtxRef,
    see: &mut See2Context,
) {
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
    let count = core.coder.current_count(core.scale) as i32;

    if count < total {
        let mut i = 0usize;
        let mut highcount = state_freq(&core.alloc, ps[0]) as i32;
        while highcount <= count && i + 1 < n as usize {
            i += 1;
            highcount += state_freq(&core.alloc, ps[i]) as i32;
        }

        let freq_i = state_freq(&core.alloc, ps[i]) as i32;
        core.coder
            .remove_subrange((highcount - freq_i) as u32, highcount as u32);
        see.update();
        update_context2(core, ctx, ps[i]);
    } else {
        core.coder.remove_subrange(total as u32, core.scale);
        core.last_mask_index = ctx_last_state_index(&core.alloc, ctx);
        see.summ = see.summ.wrapping_add(core.scale as u16);

        for slot in ps.iter().take(n as usize) {
            let sym = state_symbol(&core.alloc, *slot);
            core.char_mask[sym as usize] = core.esc_count;
        }
    }
}

/// `UpdatePPMdContext2` (`Context.c:240`).
pub(crate) fn update_context2<C>(core: &mut PpmdCore<C>, ctx: CtxRef, state: StateRef) {
    core.found_state = state;
    let newfreq = state_freq(&core.alloc, state) + 4;
    set_state_freq(&mut core.alloc, state, newfreq);
    let summ = ctx_summ_freq(&core.alloc, ctx) as i32 + 4;
    set_ctx_summ_freq(&mut core.alloc, ctx, summ as u16);

    if newfreq as i32 > MAX_FREQ {
        rescale_context(core, ctx);
    }
    core.esc_count = core.esc_count.wrapping_add(1);
    core.run_length = core.init_rl;
}

/// `RescalePPMdContext` (`Context.c:250`): halve every state's frequency,
/// keep the list sorted by decreasing frequency (an insertion-sort pass fused
/// into the halving loop), then drop states whose frequency fell to zero —
/// possibly collapsing the context down to a single aliased state (see the
/// module doc).
pub(crate) fn rescale_context<C>(core: &mut PpmdCore<C>, ctx: CtxRef) {
    let states = ctx_states(&core.alloc, ctx);
    let n = ctx_last_state_index(&core.alloc, ctx) as i32 + 1;

    let fs = core.found_state;
    let fs_freq = state_freq(&core.alloc, fs);
    set_state_freq(&mut core.alloc, fs, fs_freq + 4);

    let mut escfreq = ctx_summ_freq(&core.alloc, ctx) as i32 + 4;
    let adder = if core.order_fall == 0 { 0 } else { 1 };
    let mut summfreq = 0i32;

    for i in 0..n {
        let si = state_at(states, i);
        let freq = state_freq(&core.alloc, si) as i32;
        escfreq -= freq;
        let newfreq = (freq + adder) >> 1;
        set_state_freq(&mut core.alloc, si, newfreq as u8);
        summfreq += newfreq;

        if i > 0 {
            let prev = state_at(states, i - 1);
            if newfreq > state_freq(&core.alloc, prev) as i32 {
                let (tsym, tsucc) = (
                    state_symbol(&core.alloc, si),
                    state_successor_raw(&core.alloc, si),
                );
                let tfreq = newfreq as u8;

                let mut j = i - 1;
                while j > 0
                    && tfreq as i32 > state_freq(&core.alloc, state_at(states, j - 1)) as i32
                {
                    j -= 1;
                }

                let n_bytes = ((i - j) as u32) * STATE_SIZE;
                let src_off = state_at(states, j).0;
                let dst_off = state_at(states, j + 1).0;
                core.alloc.copy_within(src_off, dst_off, n_bytes);

                let target = state_at(states, j);
                set_state_symbol(&mut core.alloc, target, tsym);
                set_state_freq(&mut core.alloc, target, tfreq);
                set_state_successor_raw(&mut core.alloc, target, tsucc);
            }
        }
    }

    // Drop states whose frequency has fallen to 0.
    if state_freq(&core.alloc, state_at(states, n - 1)) == 0 {
        let mut numzeros = 1i32;
        while numzeros < n && state_freq(&core.alloc, state_at(states, n - 1 - numzeros)) == 0 {
            numzeros += 1;
        }

        escfreq += numzeros;

        let new_last_state_index = ctx_last_state_index(&core.alloc, ctx) as i32 - numzeros;
        set_ctx_last_state_index(&mut core.alloc, ctx, new_last_state_index as u8);

        if new_last_state_index == 0 {
            let first = state_at(states, 0);
            let (tsym, tsucc) = (
                state_symbol(&core.alloc, first),
                state_successor_raw(&core.alloc, first),
            );
            let mut tfreq = state_freq(&core.alloc, first) as i32;
            loop {
                tfreq = (tfreq + 1) >> 1;
                escfreq >>= 1;
                if escfreq <= 1 {
                    break;
                }
            }

            core.alloc.free_units(states.0, (n + 1) >> 1);
            let one = ctx_one_state(ctx);
            set_state_symbol(&mut core.alloc, one, tsym);
            set_state_freq(&mut core.alloc, one, tfreq as u8);
            set_state_successor_raw(&mut core.alloc, one, tsucc);
            core.found_state = one;

            return;
        }

        let n0 = (n + 1) >> 1;
        let n1 = (new_last_state_index + 2) >> 1;
        if n0 != n1 {
            let new_states = core.alloc.shrink_units(states.0, n0, n1);
            set_ctx_states(&mut core.alloc, ctx, StateRef(new_states));
        }
    }

    let summ = summfreq + ((escfreq + 1) >> 1);
    set_ctx_summ_freq(&mut core.alloc, ctx, summ as u16);

    // The found state is the first one to breach the limit, thus it is the
    // largest and also first.
    core.found_state = ctx_states(&core.alloc, ctx);
}

/// `ClearPPMdModelMask` (`Context.c:324`).
pub(crate) fn clear_mask<C>(core: &mut PpmdCore<C>) {
    core.esc_count = 1;
    core.char_mask = [0u8; 256];
}
