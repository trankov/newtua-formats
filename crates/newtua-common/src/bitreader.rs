//! Bit readers.
//!
//! [`BitReaderLsb`] consumes bits from the least-significant end of each byte
//! first (formats whose bit-packed data is little-endian, e.g. Squeeze).
//! [`BitReaderMsb`] consumes them most-significant first (e.g. ARC Crunch).

use std::io::{self, Read};

/// Reads individual bits from an inner byte reader, least-significant bit first.
pub struct BitReaderLsb<R> {
    inner: R,
    byte: u8,
    nbits: u8,
}

impl<R: Read> BitReaderLsb<R> {
    /// Wrap `inner`, reading its bytes as an LSB-first bit stream.
    ///
    /// Bits are refilled one byte at a time; wrap an unbuffered source (e.g. a
    /// `File`) in a `BufReader` to avoid per-byte reads. Decoders reading from an
    /// in-memory buffer need no wrapping.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            byte: 0,
            nbits: 0,
        }
    }

    /// Read the next bit (LSB-first). Returns `None` at end of input.
    pub fn read_bit(&mut self) -> io::Result<Option<bool>> {
        if self.nbits == 0 {
            match crate::read_one_byte(&mut self.inner)? {
                Some(b) => {
                    self.byte = b;
                    self.nbits = 8;
                }
                None => return Ok(None),
            }
        }

        let bit = self.byte & 1 != 0;
        self.byte >>= 1;
        self.nbits -= 1;
        Ok(Some(bit))
    }

    /// Read the next `n`-bit code (`n` ≤ 32), least-significant bit first: the
    /// first bit read becomes bit 0 of the result. Returns `None` once fewer
    /// than `n` bits remain (a partial code at end of input is discarded).
    pub fn read_bits(&mut self, n: u8) -> io::Result<Option<u32>> {
        let mut acc = 0u32;
        for i in 0..n {
            match self.read_bit()? {
                Some(true) => acc |= 1 << i,
                Some(false) => {}
                None => return Ok(None),
            }
        }
        Ok(Some(acc))
    }
}

/// Reads fixed- or variable-width codes from an inner byte reader,
/// most-significant bit first (big-endian bit order).
pub struct BitReaderMsb<R> {
    inner: R,
    acc: u32,
    nbits: u8,
}

impl<R: Read> BitReaderMsb<R> {
    /// Wrap `inner`, reading its bytes as an MSB-first bit stream.
    ///
    /// As with [`BitReaderLsb`], bits are refilled one byte at a time; wrap an
    /// unbuffered source in a `BufReader` to avoid per-byte reads.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            acc: 0,
            nbits: 0,
        }
    }

    /// Read the next `n`-bit code (`n` ≤ 24), most-significant bit first.
    /// Returns `None` once fewer than `n` bits remain.
    pub fn read(&mut self, n: u8) -> io::Result<Option<u32>> {
        while self.nbits < n {
            match crate::read_one_byte(&mut self.inner)? {
                Some(b) => {
                    self.acc = (self.acc << 8) | u32::from(b);
                    self.nbits += 8;
                }
                None => return Ok(None),
            }
        }
        self.nbits -= n;
        let mask = (1u32 << n) - 1;
        Ok(Some((self.acc >> self.nbits) & mask))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn all_bits(input: &[u8]) -> Vec<bool> {
        let mut r = BitReaderLsb::new(Cursor::new(input.to_vec()));
        let mut bits = Vec::new();
        while let Some(b) = r.read_bit().unwrap() {
            bits.push(b);
        }
        bits
    }

    #[test]
    fn empty_input_has_no_bits() {
        assert_eq!(all_bits(&[]), Vec::<bool>::new());
    }

    #[test]
    fn reads_one_byte_lsb_first() {
        // 0xA5 = 1010_0101; LSB-first → 1,0,1,0,0,1,0,1
        let bits = all_bits(&[0xA5]);
        let expect = [true, false, true, false, false, true, false, true];
        assert_eq!(bits, expect);
    }

    #[test]
    fn crosses_byte_boundary() {
        // 0x01 → bit0 set only; 0x80 → bit7 set only.
        let bits = all_bits(&[0x01, 0x80]);
        let mut expect = vec![false; 16];
        expect[0] = true; // bit 0 of first byte
        expect[15] = true; // bit 7 of second byte
        assert_eq!(bits, expect);
    }

    #[test]
    fn eof_is_sticky() {
        let mut r = BitReaderLsb::new(Cursor::new(vec![0x00u8]));
        for _ in 0..8 {
            assert!(r.read_bit().unwrap().is_some());
        }
        assert!(r.read_bit().unwrap().is_none());
        assert!(r.read_bit().unwrap().is_none());
    }

    #[test]
    fn all_ones_byte_is_eight_true() {
        assert_eq!(all_bits(&[0xFF]), vec![true; 8]);
    }

    #[test]
    fn zero_byte_is_eight_false() {
        assert_eq!(all_bits(&[0x00]), vec![false; 8]);
    }

    /// A reader that returns `Interrupted` once before yielding each byte, to
    /// exercise the retry loop in [`BitReaderLsb::read_bit`].
    struct InterruptOnce {
        data: Vec<u8>,
        pos: usize,
        armed: bool,
    }

    impl Read for InterruptOnce {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.armed {
                self.armed = false;
                return Err(io::Error::new(io::ErrorKind::Interrupted, "test"));
            }
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            buf[0] = self.data[self.pos];
            self.pos += 1;
            Ok(1)
        }
    }

    #[test]
    fn retries_on_interrupted() {
        let reader = InterruptOnce {
            data: vec![0x01],
            pos: 0,
            armed: true,
        };
        let mut r = BitReaderLsb::new(reader);
        let mut bits = Vec::new();
        while let Some(b) = r.read_bit().unwrap() {
            bits.push(b);
        }
        let mut expect = vec![false; 8];
        expect[0] = true;
        assert_eq!(bits, expect);
    }

    #[test]
    fn lsb_read_bits_assembles_low_bit_first() {
        // 0xB1 = 1011_0001; LSB-first 4 bits = 0b0001 = 1, next 4 = 0b1011 = 0xB.
        let mut r = BitReaderLsb::new(Cursor::new(vec![0xB1]));
        assert_eq!(r.read_bits(4).unwrap(), Some(0x1));
        assert_eq!(r.read_bits(4).unwrap(), Some(0xB));
        assert_eq!(r.read_bits(4).unwrap(), None);
    }

    #[test]
    fn lsb_read_bits_crosses_byte_boundary() {
        // 0x34 0x12: 12 bits LSB-first → low byte first, then the low nibble of
        // the next byte as the high bits = 0x234.
        let mut r = BitReaderLsb::new(Cursor::new(vec![0x34, 0x12]));
        assert_eq!(r.read_bits(12).unwrap(), Some(0x234));
        assert_eq!(r.read_bits(4).unwrap(), Some(0x1));
    }

    #[test]
    fn lsb_read_bits_zero_width_is_zero() {
        let mut r = BitReaderLsb::new(Cursor::new(vec![0xFF]));
        assert_eq!(r.read_bits(0).unwrap(), Some(0));
    }

    #[test]
    fn lsb_read_bits_partial_at_eof_is_none() {
        // Only 8 bits available; asking for 12 must report end of input.
        let mut r = BitReaderLsb::new(Cursor::new(vec![0xAA]));
        assert_eq!(r.read_bits(12).unwrap(), None);
    }

    #[test]
    fn msb_reads_twelve_bit_codes() {
        // 0xAB 0xCD 0xEF → top 12 bits = 0xABC, next 12 = 0xDEF.
        let mut r = BitReaderMsb::new(Cursor::new(vec![0xAB, 0xCD, 0xEF]));
        assert_eq!(r.read(12).unwrap(), Some(0xABC));
        assert_eq!(r.read(12).unwrap(), Some(0xDEF));
        assert_eq!(r.read(12).unwrap(), None);
    }

    #[test]
    fn msb_reads_mixed_widths() {
        // 0xAB 0xCD → 4 bits = 0xA, 8 bits = 0xBC, 4 bits = 0xD.
        let mut r = BitReaderMsb::new(Cursor::new(vec![0xAB, 0xCD]));
        assert_eq!(r.read(4).unwrap(), Some(0xA));
        assert_eq!(r.read(8).unwrap(), Some(0xBC));
        assert_eq!(r.read(4).unwrap(), Some(0xD));
        assert_eq!(r.read(4).unwrap(), None);
    }

    #[test]
    fn msb_empty_input_is_none() {
        let mut r = BitReaderMsb::new(Cursor::new(Vec::new()));
        assert_eq!(r.read(12).unwrap(), None);
    }
}
