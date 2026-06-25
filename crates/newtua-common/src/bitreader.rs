//! LSB-first bit reader.
//!
//! Bits are consumed from the least-significant end of each byte first. Used by
//! formats whose bit-packed data is little-endian (e.g. Squeeze).

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
}
