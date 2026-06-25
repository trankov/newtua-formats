//! CRC-16 variants used by the legacy formats.
//!
//! - CRC-16/ARC — reflected polynomial `0x8005` (`0xA001`), initial value 0, no
//!   final XOR. Used by ARC, Zoo, and LZH to checksum decoded file contents.
//! - CRC-16/CCITT (XMODEM) — polynomial `0x1021`, initial value 0, no
//!   reflection, no final XOR. Used by LBR for both its header checksum and the
//!   per-member content checksum. XADMaster computes this with a byte-swapped
//!   table and a final byte-swap (`XADUnReverseCRC16`); the net result is the
//!   plain MSB-first XMODEM CRC implemented directly here.

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

/// Compute the CRC-16/CCITT (XMODEM) of `data`.
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    update_ccitt(0, data)
}

/// Continue a CRC-16/CCITT (XMODEM) over more bytes, for streaming computation.
pub fn update_ccitt(mut crc: u16, data: &[u8]) -> u16 {
    for &byte in data {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
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

    #[test]
    fn ccitt_check_value() {
        // Canonical CRC-16/XMODEM check: "123456789" -> 0x31C3.
        assert_eq!(crc16_ccitt(b"123456789"), 0x31C3);
    }

    #[test]
    fn ccitt_empty_is_zero() {
        assert_eq!(crc16_ccitt(b""), 0);
    }

    #[test]
    fn ccitt_single_byte() {
        // CRC-16/XMODEM of one 'A' byte.
        assert_eq!(crc16_ccitt(b"A"), 0x58E5);
    }

    #[test]
    fn ccitt_update_matches_oneshot() {
        let mid = update_ccitt(0, b"12345");
        assert_eq!(update_ccitt(mid, b"6789"), 0x31C3);
    }
}
