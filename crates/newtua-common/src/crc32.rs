//! CRC-32/IEEE (the "conditioned" variant used by zip and ALZip).
//!
//! Reflected polynomial `0xEDB88320`, initial value `0xFFFFFFFF`, final XOR
//! `0xFFFFFFFF`. ALZip stores this checksum over each member's *decompressed*
//! output; XADMaster verifies it with `IEEECRC32Handle … conditioned:YES`.

/// Compute the CRC-32/IEEE of `data`.
pub fn crc32_ieee(data: &[u8]) -> u32 {
    update(0, data)
}

/// Continue a CRC-32/IEEE over more bytes, for streaming computation.
///
/// `crc` is the previously returned (conditioned) value, so chaining holds:
/// `update(crc32_ieee(a), b) == crc32_ieee([a, b].concat())`. Pass `0` to start.
pub fn update(crc: u32, data: &[u8]) -> u32 {
    let mut reg = !crc;
    for &byte in data {
        reg ^= u32::from(byte);
        for _ in 0..8 {
            reg = if reg & 1 != 0 {
                (reg >> 1) ^ 0xEDB8_8320
            } else {
                reg >> 1
            };
        }
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
    fn update_matches_oneshot() {
        let mid = update(0, b"12345");
        assert_eq!(update(mid, b"6789"), 0xCBF4_3926);
    }
}
