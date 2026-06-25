//! CRC-16/ARC — reflected polynomial `0x8005` (`0xA001`), initial value 0, no
//! final XOR. Used by ARC, Zoo, and LZH to checksum decoded file contents.

/// Compute the CRC-16/ARC of `data`.
pub fn crc16_arc(data: &[u8]) -> u16 {
    update(0, data)
}

/// Continue a CRC-16/ARC over more bytes, for streaming computation.
pub fn update(mut crc: u16, data: &[u8]) -> u16 {
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xA001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_value() {
        // Canonical CRC-16/ARC check: "123456789" -> 0xBB3D.
        assert_eq!(crc16_arc(b"123456789"), 0xBB3D);
    }

    #[test]
    fn empty_is_zero() {
        assert_eq!(crc16_arc(b""), 0);
    }

    #[test]
    fn single_byte() {
        assert_eq!(crc16_arc(b"A"), 0x30C0);
    }

    #[test]
    fn update_matches_oneshot() {
        let mid = update(0, b"12345");
        assert_eq!(update(mid, b"6789"), 0xBB3D);
    }
}
