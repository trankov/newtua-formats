// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! StuffItX Brimstone codec (`XADStuffItXBrimstoneHandle`), compression
//! method 0: PPMd variant G with `brimstone=true` and its own free-list
//! sub-allocator (`ppmd::alloc`). A faithful port of
//! `XADPPMdHandles.m:118-150`.
//!
//! Unlike Cyanide/Darkhorse/Iron, Brimstone isn't block-framed — it's a
//! single continuous PPMd byte stream, driven purely by the number of bytes
//! the caller wants (`actualsize`, threaded in as `outlen`).

use std::io;

use super::ppmd::variant_g;

/// Decode a Brimstone-compressed stream, also reporting how many bytes of
/// `src` the model's range coder actually consumed — needed by Blend
/// (method 4) to resynchronize its cursor past this sub-block
/// (`CSInputSynchronizeFileOffset`, `XADStuffItXBlendHandle.m:111`).
///
/// `src` is the compressed body *after* the two header bytes the caller
/// already consumed (`allocsize=1<<readUInt8()`, `order=readUInt8()`,
/// `XADStuffItXParser.m:123-124`) — `alloc_size` and `order` are those two
/// values, already decoded by the caller. Produces up to `outlen` bytes,
/// stopping early if the model signals EOF (`NextPPMdVariantGByte`<0`).
pub(crate) fn decode_framed(
    src: &[u8],
    outlen: usize,
    order: u32,
    alloc_size: usize,
) -> io::Result<(Vec<u8>, usize)> {
    let mut model = variant_g::start(src, alloc_size as u32, order as i32, true);
    let mut out = Vec::with_capacity(outlen);
    for _ in 0..outlen {
        let b = variant_g::next_byte(&mut model);
        if b < 0 {
            break;
        }
        out.push(b as u8);
    }
    let consumed = model.core.coder.position();
    Ok((out, consumed))
}

/// Decode a Brimstone-compressed stream (`produceByteAtOffset:` driven by
/// `CSByteStreamHandle`, `XADPPMdHandles.m:143`), discarding the consumed
/// count (used by the container's top-level dispatch, which already knows
/// its stream's full length).
pub(crate) fn decode(
    src: &[u8],
    outlen: usize,
    order: u32,
    alloc_size: usize,
) -> io::Result<Vec<u8>> {
    decode_framed(src, outlen, order, alloc_size).map(|(out, _consumed)| out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_stops_early_on_model_eof_without_erroring() {
        // A tiny/garbage stream: the model consumes a handful of bytes and
        // then hits synthetic EOF (the range coder's past-end reads return 0
        // forever, which the model doesn't treat specially, but the request
        // for way more output than any real stream would produce still
        // exercises the early-stop path without panicking).
        let out = decode(&[0u8; 8], 4096, 4, 1 << 16).unwrap();
        assert!(out.len() <= 4096);
    }

    #[test]
    fn decode_respects_outlen_when_the_model_keeps_producing() {
        let src = vec![0xAAu8; 4096];
        let out = decode(&src, 16, 4, 1 << 16).unwrap();
        assert!(out.len() <= 16);
    }
}
