//! Fixed-width little-endian integer reads from a byte source.
//!
//! Shared by the container parsers. These use `read_exact`, so a short read is
//! an `UnexpectedEof` error (a truncated header), not a silent partial value.
//! For signed 16-bit values, read with [`read_u16_le`] and cast (`as i16`).

use std::io::{self, Read};

/// Read one byte.
pub fn read_u8(r: &mut impl Read) -> io::Result<u8> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    Ok(b[0])
}

/// Read a little-endian `u16`.
pub fn read_u16_le(r: &mut impl Read) -> io::Result<u16> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_u8() {
        assert_eq!(read_u8(&mut &[0xABu8][..]).unwrap(), 0xAB);
    }

    #[test]
    fn reads_u16_le() {
        assert_eq!(read_u16_le(&mut &[0x34, 0x12][..]).unwrap(), 0x1234);
    }

    #[test]
    fn u16_le_casts_to_signed() {
        // 0xFFBE read as u16, reinterpreted as i16, is -66 (a Squeeze node link).
        assert_eq!(read_u16_le(&mut &[0xBE, 0xFF][..]).unwrap() as i16, -66);
    }

    #[test]
    fn short_read_is_eof_error() {
        assert!(read_u16_le(&mut &[0x01][..]).is_err());
    }
}
