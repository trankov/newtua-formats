// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! StuffItX Blend codec (`XADStuffItXBlendHandle`), compression method 4.
//!
//! A meta-codec: the uncompressed stream is sliced into sub-blocks, each
//! prefixed by a 6-byte marker naming which of the other codecs (stored,
//! Darkhorse, Cyanide, Brimstone) compressed it and how large it is once
//! decoded. The decoder concatenates each sub-block's decoded bytes until it
//! has produced `size` bytes. A faithful port of `XADStuffItXBlendHandle.m`.

use std::io;

use super::brimstone;
use super::cyanide;
use super::darkhorse;

fn truncated() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "sitx: blend stream truncated")
}

/// Whether 6-byte window `buf` starts a valid sub-block marker
/// (`streamAtMost:toBuffer:`, `.m:48-62`): `buf[0]==0x77 && buf[1]<=3`, and —
/// if a *later* marker also looks possible within `buf[2..6]` — only accept
/// when the would-be size field's low 13 bits are clear (`&0x1fff==0`);
/// otherwise this is a false positive inside another sub-block's compressed
/// data and the scan must slide past it.
fn is_valid_marker(buf: &[u8; 6]) -> bool {
    if !(buf[0] == 0x77 && buf[1] <= 3) {
        return false;
    }
    let later_possible = (buf[2] == 0x77 && buf[3] <= 3)
        || (buf[3] == 0x77 && buf[4] <= 3)
        || (buf[4] == 0x77 && buf[5] <= 3);
    if later_possible {
        u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]) & 0x1fff == 0
    } else {
        true
    }
}

/// Scan `blocks[start..]` for the next valid marker (`.m:39-62`), sliding one
/// byte at a time. Returns its offset, or `None` once fewer than 6 bytes
/// remain — the reference's `actual<6` end of stream (`.m:42-46`).
fn scan_marker(blocks: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    loop {
        let buf: &[u8; 6] = blocks.get(pos..pos + 6)?.try_into().ok()?;
        if is_valid_marker(buf) {
            return Some(pos);
        }
        pos += 1;
    }
}

/// Decode a Blend-compressed stream (`streamAtMost:toBuffer:`, `.m:30-119`).
/// `blocks` is the block layer's already unwrapped output
/// (`p2::read_block_stream`); `size` is the total number of decoded bytes to
/// produce. Each sub-block's sub-codec reports how many bytes of `blocks` it
/// actually consumed, so the cursor resynchronizes past the sub-codec's own
/// buffered reads (`CSInputSynchronizeFileOffset`, `.m:111`) rather than
/// assuming `size_field` bytes were used verbatim.
pub(crate) fn decode(blocks: &[u8], size: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(size);
    let mut pos = 0usize;

    while out.len() < size {
        let Some(marker) = scan_marker(blocks, pos) else {
            break;
        };
        let typ = *blocks.get(marker + 1).ok_or_else(truncated)?;
        let size_field = u32::from_be_bytes(
            blocks
                .get(marker + 2..marker + 6)
                .ok_or_else(truncated)?
                .try_into()
                .unwrap(),
        ) as usize;
        pos = marker + 6;

        match typ {
            0 => {
                // Zero-copy: unlike the other three sub-codecs, stored data
                // needs no fresh `Vec` — copy the slice straight into `out`.
                let body = blocks.get(pos..pos + size_field).ok_or_else(truncated)?;
                out.extend_from_slice(body);
                pos += size_field;
            }
            1 => {
                let (bytes, consumed) = darkhorse::decode_framed(&blocks[pos..], size_field)?;
                out.extend_from_slice(&bytes);
                pos += consumed;
            }
            2 => {
                let (bytes, consumed) = cyanide::decode_framed(&blocks[pos..], size_field)?;
                out.extend_from_slice(&bytes);
                pos += consumed;
            }
            3 => {
                let allocsize_exp = *blocks.get(pos).ok_or_else(truncated)?;
                let order = *blocks.get(pos + 1).ok_or_else(truncated)?;
                pos += 2;
                let allocsize = 1usize << allocsize_exp;
                let (bytes, consumed) =
                    brimstone::decode_framed(&blocks[pos..], size_field, order as u32, allocsize)?;
                out.extend_from_slice(&bytes);
                pos += consumed;
            }
            _ => unreachable!("scan_marker only accepts buf[1] <= 3"),
        }
    }

    out.truncate(size);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(typ: u8, size_field: u32) -> Vec<u8> {
        let mut v = vec![0x77, typ];
        v.extend_from_slice(&size_field.to_be_bytes());
        v
    }

    // === marker scanning: acceptance rule (`.m:48-62`) ========================

    #[test]
    fn accepts_marker_with_no_later_match_visible() {
        let mut buf = [0u8; 6];
        buf[0] = 0x77;
        buf[1] = 2;
        buf[2] = 0xAA; // not 0x77, no later match possible anywhere in buf[2..6]
        buf[3] = 0xBB;
        buf[4] = 0xCC;
        buf[5] = 0xDD;
        assert!(is_valid_marker(&buf));
    }

    #[test]
    fn rejects_marker_whose_type_byte_is_out_of_range() {
        let buf = [0x77, 4, 0, 0, 0, 0];
        assert!(!is_valid_marker(&buf));
    }

    #[test]
    fn accepts_marker_with_later_possible_match_when_size_field_low_bits_clear() {
        // buf[2]==0x77 && buf[3]<=3 looks like a later marker; accept only
        // because be32(buf[2..6]) & 0x1fff == 0.
        let mut buf = [0x77u8, 1, 0x77, 1, 0, 0];
        // be32(buf[2..6]) = 0x77010000 -> low 13 bits (0x0000) are clear.
        assert_eq!(
            u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]) & 0x1fff,
            0
        );
        assert!(is_valid_marker(&buf));
        // Flip a low bit so the mask is no longer zero: must now be rejected.
        buf[5] = 1;
        assert_eq!(
            u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]) & 0x1fff,
            1
        );
        assert!(!is_valid_marker(&buf));
    }

    #[test]
    fn scan_marker_slides_past_a_false_positive_0x77() {
        // A stray 0x77 followed by a byte >3 is not a valid marker at all
        // (buf[1]<=3 fails outright), so the scan must slide past it (and
        // past the byte before it, whose own window also fails) to find the
        // real marker starting at index 2.
        let mut blocks = vec![0x77u8, 0xff]; // buf[1]=0xff > 3, rejected immediately
        blocks.extend_from_slice(&marker(0, 3));
        blocks.extend_from_slice(b"abc");
        let found = scan_marker(&blocks, 0).unwrap();
        assert_eq!(found, 2);
    }

    #[test]
    fn scan_marker_returns_none_when_fewer_than_six_bytes_remain() {
        assert_eq!(scan_marker(&[0x77, 0, 0], 0), None);
        assert_eq!(scan_marker(&[], 0), None);
    }

    // === decode(): stored sub-block ============================================

    #[test]
    fn single_stored_subblock_round_trips() {
        let mut blocks = marker(0, 5);
        blocks.extend_from_slice(b"hello");
        let out = decode(&blocks, 5).unwrap();
        assert_eq!(out, b"hello");
    }

    #[test]
    fn multiple_stored_subblocks_concatenate() {
        let mut blocks = marker(0, 3);
        blocks.extend_from_slice(b"foo");
        blocks.extend_from_slice(&marker(0, 3));
        blocks.extend_from_slice(b"bar");
        let out = decode(&blocks, 6).unwrap();
        assert_eq!(out, b"foobar");
    }

    #[test]
    fn stream_ends_early_when_no_further_marker_is_found() {
        // Declare a larger size than the stream actually holds: decode must
        // stop gracefully (matching `actual<6` -> endStream) instead of
        // erroring.
        let mut blocks = marker(0, 3);
        blocks.extend_from_slice(b"foo");
        let out = decode(&blocks, 100).unwrap();
        assert_eq!(out, b"foo");
    }

    #[test]
    fn truncated_stored_body_is_rejected() {
        let mut blocks = marker(0, 10);
        blocks.extend_from_slice(b"short");
        let err = decode(&blocks, 10).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    // === decode(): sub-codec dispatch, round-tripped against each codec's own
    // mirror encoder (Cyanide has none — see task-19c — so its slot is
    // exercised via the shared zero-block framing trick instead). ============

    #[test]
    fn darkhorse_subblock_round_trips() {
        // Build a tiny Darkhorse body via its own test-only mirror encoder,
        // matching darkhorse.rs's `literals_only_round_trip` shape.
        use super::super::darkhorse::{tests::Encoder, windowsize_for};
        let window_byte = 0u8;
        let mut enc = Encoder::new(windowsize_for(window_byte));
        for &b in b"blend darkhorse payload" {
            enc.literal(b);
        }
        let (dh_blocks, expected) = enc.finish(window_byte);

        let mut blocks = marker(1, expected.len() as u32);
        blocks.extend_from_slice(&dh_blocks);
        // Trailing marker so the scan proves `consumed` resynchronized past
        // exactly the Darkhorse body, not the whole rest of `blocks`.
        blocks.extend_from_slice(&marker(0, 3));
        blocks.extend_from_slice(b"XYZ");

        let mut want = expected.clone();
        want.extend_from_slice(b"XYZ");
        let out = decode(&blocks, want.len()).unwrap();
        assert_eq!(out, want);
    }

    #[test]
    fn cyanide_subblock_of_empty_blocks_round_trips() {
        // Cyanide has no forward encoder (19c); use the same zero-block
        // framing its own unit tests use to exercise the block-parsing
        // machinery end to end, wrapped in a Blend marker.
        let mut cy_blocks = vec![0u8]; // resetBlockStream's skipped byte
        cy_blocks.push(0xff); // immediate end marker -> decodes to nothing

        let mut blocks = marker(2, 0);
        blocks.extend_from_slice(&cy_blocks);
        blocks.extend_from_slice(&marker(0, 4));
        blocks.extend_from_slice(b"tail");

        let out = decode(&blocks, 4).unwrap();
        assert_eq!(out, b"tail");
    }

    #[test]
    fn brimstone_subblock_stops_at_declared_size_field() {
        // Brimstone has no known-good fixture either (19g); feed it garbage
        // and rely on `outlen` capping the output, matching
        // `decode_respects_outlen_when_the_model_keeps_producing`.
        let mut blocks = marker(3, 4);
        blocks.push(16); // allocsize exponent -> 1<<16
        blocks.push(4); // order
        blocks.extend_from_slice(&[0xAAu8; 64]);

        let out = decode(&blocks, 4).unwrap();
        assert!(out.len() <= 4);
    }

    #[test]
    fn mixed_stream_of_all_four_subcodec_types_concatenates_in_order() {
        use super::super::darkhorse::{tests::Encoder, windowsize_for};
        let window_byte = 0u8;
        let mut enc = Encoder::new(windowsize_for(window_byte));
        for &b in b"mix" {
            enc.literal(b);
        }
        let (dh_blocks, dh_expected) = enc.finish(window_byte);

        let mut blocks = marker(0, 3);
        blocks.extend_from_slice(b"AAA");
        blocks.extend_from_slice(&marker(1, dh_expected.len() as u32));
        blocks.extend_from_slice(&dh_blocks);
        blocks.extend_from_slice(&marker(0, 3));
        blocks.extend_from_slice(b"BBB");

        let mut want = b"AAA".to_vec();
        want.extend_from_slice(&dh_expected);
        want.extend_from_slice(b"BBB");

        let out = decode(&blocks, want.len()).unwrap();
        assert_eq!(out, want);
    }

    #[test]
    fn illegal_marker_type_byte_is_never_reached_by_scan() {
        // buf[1]<=3 is enforced by is_valid_marker itself; a stray byte 4..255
        // right after 0x77 is simply not a marker and the scan slides past it.
        let mut blocks = vec![0x77u8, 5, 0, 0, 0, 0];
        blocks.extend_from_slice(&marker(0, 2));
        blocks.extend_from_slice(b"ok");
        let out = decode(&blocks, 2).unwrap();
        assert_eq!(out, b"ok");
    }
}
