// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! StuffItX x86 branch preprocessor (`XADStuffItXX86Handle`).
//!
//! An inverse E8/E9 (near `call`/`jmp`) filter: the archive stores branch targets
//! as absolute addresses (which compress better), and this pass converts them
//! back to the relative offsets the original code held. It is a byte-for-byte
//! port of `-[XADStuffItXX86Handle produceByteAtOffset:]`, including the
//! `bitfield` aging heuristic that decides which E8/E9 bytes are real branch
//! opcodes and the multi-byte sign-extension unrolling loop.
//!
//! Positions (`pos`, `lasthit`) are in **output** coordinates. The transform is
//! length-preserving: a converted instruction consumes and emits one opcode byte
//! plus four address bytes, and an unconverted E8/E9 emits only its opcode (its
//! trailing bytes are read normally afterwards), so decoded length equals input
//! length.

/// `table[(bitfield>>1)&7]` gates conversion (`XADStuffItXX86Handle.m:58`).
const TABLE: [bool; 8] = [true, true, true, false, true, false, false, false];
/// `shifts[bitfield>>1]` picks the byte the unrolling loop inspects (`:72`).
const SHIFTS: [u32; 8] = [24, 16, 8, 8, 0, 0, 0, 0];

/// Decode the x86 preprocessor stream, producing at most `length` bytes (fewer
/// if `input` is exhausted first). `input` is the decompressor's output.
pub(crate) fn decode(input: &[u8], length: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(length.min(input.len()));
    let mut ip = 0usize; // input cursor
    let mut lasthit: i64 = -6;
    let mut bitfield: u32 = 0;
    let mut queue: [u8; 4] = [0; 4]; // converted address bytes awaiting output
    let mut qpos = 0usize;
    let mut qlen = 0usize;

    while out.len() < length {
        // Drain any queued (converted) address bytes first.
        if qpos < qlen {
            out.push(queue[qpos]);
            qpos += 1;
            continue;
        }
        let Some(&b) = input.get(ip) else {
            break; // input EOF
        };
        ip += 1;
        let pos = out.len() as i64; // output position of this byte

        if b == 0xe8 || b == 0xe9 {
            let dist = pos - lasthit;
            lasthit = pos;
            if dist > 5 {
                bitfield = 0;
            } else {
                for _ in 0..dist {
                    bitfield = (bitfield & 0x77) << 1;
                }
            }

            // Peek the four following bytes. Near EOF the reference's guard is
            // commented out; we simply leave the opcode (and its tail) as-is.
            if let Some(peek) = input.get(ip..ip + 4) {
                let buffer: [u8; 4] = peek.try_into().unwrap();
                if buffer[3] == 0x00 || buffer[3] == 0xff {
                    if TABLE[((bitfield >> 1) & 0x07) as usize] && (bitfield >> 1) <= 0x0f {
                        let mut absaddress = i32::from_le_bytes(buffer);
                        let mut reladdress;
                        loop {
                            reladdress = absaddress.wrapping_sub(pos as i32).wrapping_sub(6);
                            if bitfield == 0 {
                                break;
                            }
                            let shift = SHIFTS[(bitfield >> 1) as usize];
                            let something = (reladdress >> shift) & 0xff;
                            if something != 0 && something != 0xff {
                                break;
                            }
                            // `1 << (shift+8)` mirrors C `int` on x86: a shift of
                            // 32 wraps to 1 (unreachable here, shift <= 16).
                            let mask = 1i32.wrapping_shl(shift + 8).wrapping_sub(1);
                            absaddress = reladdress ^ mask;
                        }
                        reladdress &= 0x01ff_ffff; // 25-bit
                        if reladdress >= 0x0100_0000 {
                            reladdress |= 0xff00_0000u32 as i32; // sign-extend
                        }
                        queue = reladdress.to_le_bytes();
                        qpos = 0;
                        qlen = 4;
                        bitfield = 0;
                        ip += 4; // consume the peeked bytes
                    } else {
                        bitfield |= 0x11;
                    }
                } else {
                    bitfield |= 0x01;
                }
            }
        }

        out.push(b);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirror filter for the clean conversion path (`bitfield` stays 0 because
    /// every instruction converts): emit the opcode then `abs = rel + pos + 6`
    /// little-endian. `rel` must be a small non-negative 25-bit value so that the
    /// decoder recovers it unchanged (top byte 0x00, no sign extension).
    fn encode_clean(instrs: &[(u8, i32, &[u8])]) -> (Vec<u8>, Vec<u8>) {
        let mut filtered = Vec::new(); // the archive/on-disk form (decoder input)
        let mut original = Vec::new(); // the pre-filter form (expected output)
        for &(opcode, rel, filler) in instrs {
            let pos = filtered.len() as i32;
            let abs = rel.wrapping_add(pos).wrapping_add(6);
            filtered.push(opcode);
            filtered.extend_from_slice(&abs.to_le_bytes());
            original.push(opcode);
            original.extend_from_slice(&rel.to_le_bytes());
            filtered.extend_from_slice(filler);
            original.extend_from_slice(filler);
        }
        (filtered, original)
    }

    #[test]
    fn data_without_branches_is_identity() {
        let data: Vec<u8> = (0..200u32).map(|i| (i % 200) as u8).collect();
        // Ensure no E8/E9 bytes are present.
        let data: Vec<u8> = data
            .into_iter()
            .map(|b| if b == 0xe8 || b == 0xe9 { 0 } else { b })
            .collect();
        assert_eq!(decode(&data, data.len()), data);
    }

    #[test]
    fn clean_conversions_round_trip() {
        let filler: &[u8] = b"padding-no-branch-bytes-here";
        let (filtered, original) = encode_clean(&[
            (0xe8, 0x10, filler),
            (0xe9, 0x2000, filler),
            (0xe8, 0x123, filler),
        ]);
        assert_eq!(decode(&filtered, original.len()), original);
    }

    #[test]
    fn single_negative_address_sign_extends() {
        // A stored absolute whose top byte is 0xFF triggers the sign-extension
        // tail. With bitfield==0 the unrolling loop is skipped, so
        // rel = (abs - pos - 6) & 0x1ffffff, sign-extended at bit 24.
        let abs: i32 = 0xff00_0002u32 as i32; // top byte 0xFF -> buffer[3]==0xff
        let pos = 0i32;
        let mut input = vec![0xe8u8];
        input.extend_from_slice(&abs.to_le_bytes());
        let out = decode(&input, input.len());
        let mut expected_rel = abs.wrapping_sub(pos).wrapping_sub(6) & 0x01ff_ffff;
        if expected_rel >= 0x0100_0000 {
            expected_rel |= 0xff00_0000u32 as i32;
        }
        assert_eq!(out[0], 0xe8);
        assert_eq!(&out[1..5], &expected_rel.to_le_bytes());
    }

    #[test]
    fn middle_top_byte_is_not_converted() {
        // buffer[3] is neither 0x00 nor 0xFF: the opcode passes through and the
        // four "address" bytes are emitted verbatim as ordinary bytes.
        let mut input = vec![0xe8u8, 0x11, 0x22, 0x33, 0x44];
        input.extend_from_slice(b"tail");
        let out = decode(&input, input.len());
        assert_eq!(out, input);
    }

    #[test]
    fn branch_opcode_near_eof_is_left_as_is() {
        // Fewer than four bytes follow the E8: no conversion, opcode + tail kept.
        let input = vec![b'x', 0xe8, 0x01, 0x02];
        assert_eq!(decode(&input, input.len()), input);
    }

    #[test]
    fn stops_at_requested_length() {
        let input: Vec<u8> = (0..50).map(|_| b'z').collect();
        assert_eq!(decode(&input, 10).len(), 10);
    }
}
