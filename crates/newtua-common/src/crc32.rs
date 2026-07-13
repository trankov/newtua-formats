// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! CRC-32/IEEE (the "conditioned" variant used by zip and ALZip).
//!
//! Reflected polynomial `0xEDB88320`, initial value `0xFFFFFFFF`, final XOR
//! `0xFFFFFFFF`. ALZip stores this checksum over each member's *decompressed*
//! output; XADMaster verifies it with `IEEECRC32Handle … conditioned:YES`.

/// Compute the CRC-32/IEEE of `data`.
pub fn crc32_ieee(data: &[u8]) -> u32 {
    update(0, data)
}

/// One raw CRC-32 round over a single byte with the reflected `0xEDB88320`
/// polynomial — no pre/post conditioning. Equivalent to XADMaster's
/// `XADCRC(crc, byte, XADCRCTable_edb88320)`. It is the shared inner step of
/// [`update`] and of ZipCrypt's key schedule (which seeds its own constants).
pub fn crc32_step(crc: u32, byte: u8) -> u32 {
    let mut reg = crc ^ u32::from(byte);
    for _ in 0..8 {
        reg = if reg & 1 != 0 {
            (reg >> 1) ^ 0xEDB8_8320
        } else {
            reg >> 1
        };
    }
    reg
}

/// Continue a CRC-32/IEEE over more bytes, for streaming computation.
///
/// `crc` is the previously returned (conditioned) value, so chaining holds:
/// `update(crc32_ieee(a), b) == crc32_ieee([a, b].concat())`. Pass `0` to start.
pub fn update(crc: u32, data: &[u8]) -> u32 {
    let mut reg = !crc;
    for &byte in data {
        reg = crc32_step(reg, byte);
    }
    !reg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_value() {
        // Canonical CRC-32/IEEE check: "123456789" -> 0xCBF43926.
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn empty_is_zero() {
        assert_eq!(crc32_ieee(b""), 0);
    }

    #[test]
    fn known_sentence() {
        // Well-known CRC-32 of the pangram.
        assert_eq!(
            crc32_ieee(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }

    #[test]
    fn crc32_step_folds_into_ieee() {
        // Folding raw steps from the conditioned seed and inverting must match
        // the one-shot CRC — this ties the step to the existing `crc32_ieee`.
        let data = b"The quick brown fox jumps over the lazy dog";
        let mut reg = 0xFFFF_FFFFu32;
        for &b in data {
            reg = crc32_step(reg, b);
        }
        assert_eq!(!reg, crc32_ieee(data));
    }

    #[test]
    fn crc32_step_matches_table_formula() {
        // The raw step equals the table identity `(crc>>8) ^ T[(crc^b)&0xff]`.
        let table_step = |crc: u32, b: u8| -> u32 {
            let mut t = (crc ^ u32::from(b)) & 0xff;
            for _ in 0..8 {
                t = if t & 1 != 0 {
                    (t >> 1) ^ 0xEDB8_8320
                } else {
                    t >> 1
                };
            }
            (crc >> 8) ^ t
        };
        for &crc in &[0u32, 1, 0x1234_5678, 0xFFFF_FFFF, 878_082_192] {
            for b in [0u8, 1, 0x7f, 0xff, b'A'] {
                assert_eq!(
                    crc32_step(crc, b),
                    table_step(crc, b),
                    "crc={crc:#x} b={b:#x}"
                );
            }
        }
    }

    #[test]
    fn update_matches_oneshot() {
        let mid = update(0, b"12345");
        assert_eq!(update(mid, b"6789"), 0xCBF4_3926);
    }
}
