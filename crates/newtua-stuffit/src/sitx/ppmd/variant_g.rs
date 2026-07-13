// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! PPMd model variant G (`PPMd/VariantG.h`/`.c`), used (with `brimstone=true`)
//! by StuffItX's Brimstone codec. The `brimstone` flag affects exactly three
//! things, all in [`restart_model`] and the range coder's `bottom`
//! (`.c:20-21,56-65`): the coder's underflow floor (`0x10000` vs `0x8000`),
//! the root context's `SummFreq` (385 vs 257), and the initial frequency of
//! symbols `<0x80` (2 vs 1). Everything else — the model update machinery —
//! is identical between Brimstone and plain variant G.

use super::alloc::BrimstoneAlloc;
use super::context::{
    clear_mask, copy_state, ctx_flags, ctx_last_state_index, ctx_one_state, ctx_states, ctx_suffix,
    ctx_summ_freq, decode_bin_symbol, decode_symbol1, decode_symbol2, new_context,
    new_context_as_child_of, number_of_states, set_ctx_flags, set_ctx_last_state_index,
    set_ctx_states, set_ctx_suffix, set_ctx_summ_freq, set_state_freq, set_state_successor,
    set_state_symbol, state_at, state_freq, state_successor, state_symbol, swap_states, CtxRef,
    PpmdCore, See2Context, StateRef, BIN_SCALE, MAX_FREQ, MAX_O, PERIOD_BITS,
};
use super::rangecoder::PpmdRangeCoder;

/// Generic over the range-coder backend `C`, for the same reason [`PpmdCore`]
/// is: [`restart_model`], [`update_model`] and [`make_root`] never touch the
/// coder, so the test-only symmetric encoder (`encoder_mirror.rs`)
/// instantiates this with `C = PpmdRangeEncoder` and reuses all three
/// unchanged instead of duplicating the model-update machinery.
pub(crate) struct PpmdModelVariantG<C> {
    pub(crate) core: PpmdCore<C>,
    pub(crate) min_context: CtxRef,
    pub(crate) med_context: CtxRef,
    pub(crate) max_context: CtxRef,
    pub(crate) max_order: i32,
    pub(crate) brimstone: bool,
    pub(crate) see2_cont: [[See2Context; 8]; 43],
    pub(crate) dummy_see2_cont: See2Context,
    pub(crate) ns2bs_indx: [u8; 256],
    pub(crate) ns2_indx: [u8; 256],
    pub(crate) bin_summ: [[u16; 16]; 128],
}

/// `StartPPMdModelVariantG` (`.c:16`). `alloc_size` is the Brimstone heap size
/// in bytes (already scaled by the caller, see `brimstone.rs`).
pub(crate) fn start(
    input: &[u8],
    alloc_size: u32,
    maxorder: i32,
    brimstone: bool,
) -> PpmdModelVariantG<PpmdRangeCoder<'_>> {
    let bottom = if brimstone { 0x10000 } else { 0x8000 };
    let coder = PpmdRangeCoder::new(input, true, bottom);
    let alloc = BrimstoneAlloc::new(alloc_size);

    let core = PpmdCore {
        coder,
        alloc,
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

/// The rest of `StartPPMdModelVariantG` after the coder/alloc are built —
/// generic over `C` so the test-only symmetric encoder (`encoder_mirror.rs`)
/// can build a `PpmdModelVariantG<PpmdRangeEncoder>` through the exact same
/// table setup and [`restart_model`] call instead of duplicating them.
pub(crate) fn new_model<C>(
    core: PpmdCore<C>,
    maxorder: i32,
    brimstone: bool,
) -> PpmdModelVariantG<C> {
    let mut ns2bs_indx = [0u8; 256];
    for (i, v) in ns2bs_indx.iter_mut().enumerate().take(6) {
        *v = (2 * i) as u8;
    }
    for v in ns2bs_indx.iter_mut().take(50).skip(6) {
        *v = 12;
    }
    for v in ns2bs_indx.iter_mut().skip(50) {
        *v = 14;
    }

    let mut ns2_indx = [0u8; 256];
    for (i, v) in ns2_indx.iter_mut().enumerate().take(4) {
        *v = i as u8;
    }
    for (i, v) in ns2_indx.iter_mut().enumerate().take(12).skip(4) {
        *v = (4 + ((i - 4) >> 1)) as u8;
    }
    for (i, v) in ns2_indx.iter_mut().enumerate().take(44).skip(12) {
        *v = (8 + ((i - 12) >> 2)) as u8;
    }
    for (i, v) in ns2_indx.iter_mut().enumerate().skip(44) {
        *v = (16 + ((i - 44) >> 3)) as u8;
    }

    let mut model = PpmdModelVariantG {
        core,
        min_context: CtxRef::NULL,
        med_context: CtxRef::NULL,
        max_context: CtxRef::NULL,
        max_order: maxorder,
        brimstone,
        see2_cont: [[See2Context::default(); 8]; 43],
        dummy_see2_cont: See2Context {
            shift: PERIOD_BITS as u8,
            ..See2Context::default()
        },
        ns2bs_indx,
        ns2_indx,
        bin_summ: [[0u16; 16]; 128],
    };

    restart_model(&mut model);
    model
}

/// `RestartModel` (`.c:45`).
pub(crate) fn restart_model<C>(model: &mut PpmdModelVariantG<C>) {
    model.core.alloc.init();

    model.core.char_mask = [0u8; 256];
    model.core.prev_success = 0;
    model.core.order_fall = 1;

    model.max_context = new_context(&mut model.core);
    set_ctx_last_state_index(&mut model.core.alloc, model.max_context, 255);
    let summ_freq: u16 = if model.brimstone { 385 } else { 257 };
    set_ctx_summ_freq(&mut model.core.alloc, model.max_context, summ_freq);

    let states_off = model.core.alloc.alloc_units(256 / 2);
    set_ctx_states(
        &mut model.core.alloc,
        model.max_context,
        StateRef(states_off),
    );

    let maxstates = ctx_states(&model.core.alloc, model.max_context);
    for i in 0..256i32 {
        let si = state_at(maxstates, i);
        set_state_symbol(&mut model.core.alloc, si, i as u8);
        let freq: u8 = if model.brimstone && i < 0x80 { 2 } else { 1 };
        set_state_freq(&mut model.core.alloc, si, freq);
        set_state_successor(&mut model.core.alloc, si, CtxRef::NULL);
    }

    let mut state = maxstates;
    let mut i = 1;
    loop {
        model.max_context =
            new_context_as_child_of(&mut model.core, model.max_context, state, None);
        if i == model.max_order {
            break;
        }
        state = ctx_one_state(model.max_context);
        set_state_symbol(&mut model.core.alloc, state, 0);
        set_state_freq(&mut model.core.alloc, state, 1);
        i += 1;
    }

    set_ctx_flags(&mut model.core.alloc, model.max_context, 1);

    model.med_context = ctx_suffix(&model.core.alloc, model.max_context);
    model.min_context = model.med_context;

    const INIT_BIN_ESC: [u16; 16] = [
        0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x5FFB, 0x5545, 0x63D1, 0x5D9D, 0x64A1, 0x5ABC, 0x6632,
        0x6051, 0x68F6, 0x549B, 0x6BCA, 0x3AB0,
    ];

    for (i, row) in model.bin_summ.iter_mut().enumerate() {
        for (k, cell) in row.iter_mut().enumerate() {
            *cell = (BIN_SCALE - (INIT_BIN_ESC[k] as i32) / (i as i32 + 2)) as u16;
        }
    }

    for (i, row) in model.see2_cont.iter_mut().enumerate() {
        for cell in row.iter_mut() {
            *cell = See2Context::make(4 * (i as i32) + 10, 3);
        }
    }
}

/// `NextPPMdVariantGByte` (`.c:103`).
pub(crate) fn next_byte<'a>(model: &mut PpmdModelVariantG<PpmdRangeCoder<'a>>) -> i32 {
    if model.min_context.is_null() {
        return -1;
    }

    if number_of_states(&model.core.alloc, model.min_context) != 1 {
        decode_symbol1_variant_g(model, model.min_context);
    } else {
        decode_bin_symbol_variant_g(model, model.min_context);
    }

    while model.core.found_state.is_null() {
        loop {
            model.core.order_fall += 1;
            model.min_context = ctx_suffix(&model.core.alloc, model.min_context);
            if model.min_context.is_null() {
                return -1;
            }
            if ctx_last_state_index(&model.core.alloc, model.min_context)
                != model.core.last_mask_index
            {
                break;
            }
        }
        decode_symbol2_variant_g(model, model.min_context);
    }

    let byte = state_symbol(&model.core.alloc, model.core.found_state);

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

    byte as i32
}

/// `UpdateModel` (`.c:140`).
pub(crate) fn update_model<C>(model: &mut PpmdModelVariantG<C>) {
    let fs_ref = model.core.found_state;
    let fs_symbol = state_symbol(&model.core.alloc, fs_ref);
    let fs_freq = state_freq(&model.core.alloc, fs_ref) as i32;
    let fs_successor = state_successor(&model.core.alloc, fs_ref);

    let mut state: Option<StateRef> = None;

    let min_suffix = ctx_suffix(&model.core.alloc, model.min_context);
    if fs_freq < MAX_FREQ / 4 && !min_suffix.is_null() {
        let context = min_suffix;
        if number_of_states(&model.core.alloc, context) != 1 {
            let mut st = ctx_states(&model.core.alloc, context);
            if state_symbol(&model.core.alloc, st) != fs_symbol {
                loop {
                    st = state_at(st, 1);
                    if state_symbol(&model.core.alloc, st) == fs_symbol {
                        break;
                    }
                }
                let prev = state_at(st, -1);
                if state_freq(&model.core.alloc, st) >= state_freq(&model.core.alloc, prev) {
                    swap_states(&mut model.core.alloc, st, prev);
                    st = prev;
                }
            }

            if (state_freq(&model.core.alloc, st) as i32) < 7 * MAX_FREQ / 8 {
                let f = state_freq(&model.core.alloc, st);
                set_state_freq(&mut model.core.alloc, st, f + 2);
                let summ = ctx_summ_freq(&model.core.alloc, context) as i32 + 2;
                set_ctx_summ_freq(&mut model.core.alloc, context, summ as u16);
            }
            state = Some(st);
        } else {
            let st = ctx_one_state(context);
            let f = state_freq(&model.core.alloc, st);
            if f < 32 {
                set_state_freq(&mut model.core.alloc, st, f + 1);
            }
            state = Some(st);
        }
    }

    let successor: CtxRef;
    let mut skip_count = 0i32;
    if model.core.order_fall == 0 {
        if !make_root(model, 2, None) {
            restart_model(model);
            model.core.esc_count = 0;
            return;
        }
        model.min_context = fs_successor;
        model.med_context = fs_successor;
        return;
    }
    model.core.order_fall -= 1;
    if model.core.order_fall == 0 {
        successor = fs_successor;
        skip_count = 1;
    } else {
        let s = new_context(&mut model.core);
        if s.is_null() {
            restart_model(model);
            model.core.esc_count = 0;
            return;
        }
        set_ctx_flags(&mut model.core.alloc, s, 1);
        successor = s;
    }

    if ctx_flags(&model.core.alloc, model.max_context) == 1 {
        let one = ctx_one_state(model.max_context);
        set_state_symbol(&mut model.core.alloc, one, fs_symbol);
        set_state_successor(&mut model.core.alloc, one, successor);
    }

    let minnum = number_of_states(&model.core.alloc, model.min_context);
    let s0 = ctx_summ_freq(&model.core.alloc, model.min_context) as i32 - minnum - (fs_freq - 1);

    let mut currcontext = model.med_context;
    while currcontext != model.min_context {
        let currnum = number_of_states(&model.core.alloc, currcontext);
        if currnum != 1 {
            if currnum & 1 == 0 {
                let states_off = ctx_states(&model.core.alloc, currcontext).0;
                let new_states = model.core.alloc.expand_units(states_off, currnum >> 1);
                if new_states == 0 {
                    restart_model(model);
                    model.core.esc_count = 0;
                    return;
                }
                set_ctx_states(&mut model.core.alloc, currcontext, StateRef(new_states));
            }
            let summ_freq = ctx_summ_freq(&model.core.alloc, currcontext) as i32;
            if 4 * currnum <= minnum && summ_freq <= 8 * currnum {
                set_ctx_summ_freq(&mut model.core.alloc, currcontext, (summ_freq + 2) as u16);
            }
            let summ_freq = ctx_summ_freq(&model.core.alloc, currcontext) as i32;
            if 2 * currnum < minnum {
                set_ctx_summ_freq(&mut model.core.alloc, currcontext, (summ_freq + 1) as u16);
            }
        } else {
            let new_off = model.core.alloc.alloc_units(1);
            if new_off == 0 {
                restart_model(model);
                model.core.esc_count = 0;
                return;
            }
            let new_states = StateRef(new_off);
            copy_state(
                &mut model.core.alloc,
                ctx_one_state(currcontext),
                new_states,
            );
            set_ctx_states(&mut model.core.alloc, currcontext, new_states);

            let f0 = state_freq(&model.core.alloc, new_states) as i32;
            let newf0 = if f0 < MAX_FREQ / 4 - 1 {
                f0 * 2
            } else {
                MAX_FREQ - 4
            };
            set_state_freq(&mut model.core.alloc, new_states, newf0 as u8);

            let summ = newf0 + model.core.init_esc + if minnum > 3 { 1 } else { 0 };
            set_ctx_summ_freq(&mut model.core.alloc, currcontext, summ as u16);
        }

        let summ_freq = ctx_summ_freq(&model.core.alloc, currcontext) as i32;
        let cf = 2 * fs_freq * (summ_freq + 6);
        let sf = s0 + summ_freq;
        let freq: i32;

        if cf < 6 * sf {
            freq = if cf >= 4 * sf {
                3
            } else if cf > sf {
                2
            } else {
                1
            };
            set_ctx_summ_freq(&mut model.core.alloc, currcontext, (summ_freq + 3) as u16);
        } else {
            freq = if cf >= 15 * sf {
                7
            } else if cf >= 12 * sf {
                6
            } else if cf >= 9 * sf {
                5
            } else {
                4
            };
            set_ctx_summ_freq(
                &mut model.core.alloc,
                currcontext,
                (summ_freq + freq) as u16,
            );
        }

        let currstates = ctx_states(&model.core.alloc, currcontext);
        let new_state = state_at(currstates, currnum);
        set_state_successor(&mut model.core.alloc, new_state, successor);
        set_state_symbol(&mut model.core.alloc, new_state, fs_symbol);
        set_state_freq(&mut model.core.alloc, new_state, freq as u8);
        set_ctx_last_state_index(&mut model.core.alloc, currcontext, currnum as u8);

        currcontext = ctx_suffix(&model.core.alloc, currcontext);
    }

    if !fs_successor.is_null() {
        let succ_flags = ctx_flags(&model.core.alloc, fs_successor);
        if succ_flags == 1 && !make_root(model, skip_count, state) {
            restart_model(model);
            model.core.esc_count = 0;
            return;
        }
        model.min_context = state_successor(&model.core.alloc, model.core.found_state);
    } else {
        set_state_successor(&mut model.core.alloc, model.core.found_state, successor);
        model.core.order_fall += 1;
    }

    model.med_context = model.min_context;
    model.max_context = successor;
}

/// `MakeRoot` (`.c:283`).
pub(crate) fn make_root<C>(
    model: &mut PpmdModelVariantG<C>,
    skip_count: i32,
    state: Option<StateRef>,
) -> bool {
    let mut context = model.min_context;
    let upbranch = state_successor(&model.core.alloc, model.core.found_state);
    // Fixed stack buffer: the chain never exceeds MAX_O entries (matching the
    // reference's `PPMdState *ps[MAX_O]`), so this avoids a heap allocation on
    // every decoded symbol.
    let mut statelist = [StateRef::NULL; MAX_O];
    let mut statecount = 0usize;

    let mut skip = false;

    if skip_count == 0 {
        statelist[statecount] = model.core.found_state;
        statecount += 1;
        if ctx_suffix(&model.core.alloc, context).is_null() {
            skip = true;
        }
    } else if skip_count == 2 {
        context = ctx_suffix(&model.core.alloc, context);
    }

    if !skip {
        if let Some(st) = state {
            context = ctx_suffix(&model.core.alloc, context);
            if state_successor(&model.core.alloc, st) != upbranch {
                context = state_successor(&model.core.alloc, st);
                skip = true;
            } else {
                statelist[statecount] = st;
                statecount += 1;
                if ctx_suffix(&model.core.alloc, context).is_null() {
                    skip = true;
                }
            }
        }
    }

    if !skip {
        let want = state_symbol(&model.core.alloc, model.core.found_state);
        loop {
            context = ctx_suffix(&model.core.alloc, context);
            let st = if number_of_states(&model.core.alloc, context) != 1 {
                let mut s = ctx_states(&model.core.alloc, context);
                while state_symbol(&model.core.alloc, s) != want {
                    s = state_at(s, 1);
                }
                s
            } else {
                ctx_one_state(context)
            };

            if state_successor(&model.core.alloc, st) != upbranch {
                context = state_successor(&model.core.alloc, st);
                break;
            }
            statelist[statecount] = st;
            statecount += 1;

            if ctx_suffix(&model.core.alloc, context).is_null() {
                break;
            }
        }
    }

    let upstate = ctx_one_state(upbranch);
    if number_of_states(&model.core.alloc, context) != 1 {
        let mut s = ctx_states(&model.core.alloc, context);
        let want = state_symbol(&model.core.alloc, upstate);
        while state_symbol(&model.core.alloc, s) != want {
            s = state_at(s, 1);
        }

        let cf = state_freq(&model.core.alloc, s) as i32 - 1;
        let s0 = ctx_summ_freq(&model.core.alloc, context) as i32
            - ctx_last_state_index(&model.core.alloc, context) as i32
            - 1
            - cf;

        let newfreq = if 2 * cf <= s0 {
            if 5 * cf > s0 {
                2
            } else {
                1
            }
        } else {
            1 + ((2 * cf + 3 * s0 - 1) / (2 * s0))
        };
        set_state_freq(&mut model.core.alloc, upstate, newfreq as u8);
    } else {
        let f = state_freq(&model.core.alloc, ctx_one_state(context));
        set_state_freq(&mut model.core.alloc, upstate, f);
    }

    for &st in statelist[..statecount].iter().rev() {
        let new_ctx = new_context_as_child_of(&mut model.core, context, st, Some(upstate));
        if new_ctx.is_null() {
            return false;
        }
        context = new_ctx;
    }

    if model.core.order_fall == 0 {
        set_ctx_last_state_index(&mut model.core.alloc, upbranch, 0);
        set_ctx_flags(&mut model.core.alloc, upbranch, 0);
        set_ctx_suffix(&mut model.core.alloc, upbranch, context);
    }

    true
}

/// `DecodeBinSymbolVariantG` (`.c:366`).
fn decode_bin_symbol_variant_g<'a>(model: &mut PpmdModelVariantG<PpmdRangeCoder<'a>>, ctx: CtxRef) {
    let rs = ctx_one_state(ctx);
    let freq = state_freq(&model.core.alloc, rs);
    let suffix = ctx_suffix(&model.core.alloc, ctx);
    let suffix_lsi = ctx_last_state_index(&model.core.alloc, suffix);
    let col = model.core.prev_success as usize + model.ns2bs_indx[suffix_lsi as usize] as usize;
    let row = freq as usize - 1;

    decode_bin_symbol(
        &mut model.core,
        ctx,
        &mut model.bin_summ[row][col],
        128,
        false,
    );
}

/// `DecodeSymbol1VariantG` (`.c:374`).
fn decode_symbol1_variant_g<'a>(model: &mut PpmdModelVariantG<PpmdRangeCoder<'a>>, ctx: CtxRef) {
    decode_symbol1(&mut model.core, ctx, false);
}

/// `DecodeSymbol2VariantG` (`.c:379`).
fn decode_symbol2_variant_g<'a>(model: &mut PpmdModelVariantG<PpmdRangeCoder<'a>>, ctx: CtxRef) {
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
        decode_symbol2(&mut model.core, ctx, &mut model.see2_cont[row][idx]);
    } else {
        model.core.scale = 1;
        decode_symbol2(&mut model.core, ctx, &mut model.dummy_see2_cont);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_and_restart_do_not_panic_and_seed_min_context() {
        let data = vec![0u8; 64];
        let model = start(&data, 1 << 16, 4, true);
        assert!(!model.min_context.is_null());
        assert!(!model.max_context.is_null());
        assert_eq!(model.min_context, model.med_context);
    }

    #[test]
    fn root_context_summ_freq_and_first_symbol_freqs_match_brimstone_flag() {
        let data = vec![0u8; 64];
        let model = start(&data, 1 << 16, 4, true);
        // Walk MinContext's suffix chain up to the order(-1) root (256 states).
        let mut ctx = model.min_context;
        loop {
            let suffix = ctx_suffix(&model.core.alloc, ctx);
            if suffix.is_null() {
                break;
            }
            ctx = suffix;
        }
        assert_eq!(ctx_summ_freq(&model.core.alloc, ctx), 385);
        let states = ctx_states(&model.core.alloc, ctx);
        assert_eq!(state_freq(&model.core.alloc, state_at(states, 0)), 2); // symbol 0 < 0x80
        assert_eq!(state_freq(&model.core.alloc, state_at(states, 0x80)), 1); // symbol 0x80 >= 0x80
    }

    #[test]
    fn plain_variant_g_root_uses_257_and_uniform_freq_one() {
        let data = vec![0u8; 64];
        let model = start(&data, 1 << 16, 4, false);
        let mut ctx = model.min_context;
        loop {
            let suffix = ctx_suffix(&model.core.alloc, ctx);
            if suffix.is_null() {
                break;
            }
            ctx = suffix;
        }
        assert_eq!(ctx_summ_freq(&model.core.alloc, ctx), 257);
        let states = ctx_states(&model.core.alloc, ctx);
        assert_eq!(state_freq(&model.core.alloc, state_at(states, 0)), 1);
    }

    #[test]
    fn next_byte_runs_to_completion_on_arbitrary_input_without_panicking() {
        // Not a conformance check (no known-good stream) — just exercises the
        // full decode/update loop across many bytes with varied input to
        // shake out panics (out-of-bounds offsets, index overflow, etc).
        let data: Vec<u8> = (0..4096u32)
            .map(|i| i.wrapping_mul(2654435761) as u8)
            .collect();
        let mut model = start(&data, 1 << 16, 4, true);
        let mut produced = 0;
        for _ in 0..2000 {
            let b = next_byte(&mut model);
            if b < 0 {
                break;
            }
            produced += 1;
        }
        assert!(produced > 0, "must decode at least one byte before EOF");
    }
}
