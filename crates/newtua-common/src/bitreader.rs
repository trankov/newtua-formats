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

    /// Discard the remaining bits of the current byte so the next read starts on
    /// a byte boundary. A no-op when already aligned. Deflate's stored blocks use
    /// this before reading their byte-aligned length words (`CSInputSkipToByteBoundary`).
    pub fn align_to_byte(&mut self) {
        if self.nbits % 8 != 0 {
            self.nbits = 0;
        }
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

    /// Peek the next `n`-bit code (`n` ≤ 24), most-significant bit first,
    /// without consuming it — refills as needed but leaves the bits
    /// available for a later [`peek`](Self::peek) or [`consume`](Self::consume).
    /// Returns `None` once fewer than `n` bits remain. Formats whose codes
    /// are looked up in a table before the decoder knows how many bits the
    /// resolved code actually used (e.g. DMS HEAVY's canonical Huffman
    /// tables) peek the table's full index width, then
    /// [`consume`](Self::consume) only the resolved code's real length.
    pub fn peek(&mut self, n: u8) -> io::Result<Option<u32>> {
        while self.nbits < n {
            match crate::read_one_byte(&mut self.inner)? {
                Some(b) => {
                    self.acc = (self.acc << 8) | u32::from(b);
                    self.nbits += 8;
                }
                None => return Ok(None),
            }
        }
        let mask = (1u32 << n) - 1;
        Ok(Some((self.acc >> (self.nbits - n)) & mask))
    }

    /// Drop `n` bits already made available by a prior
    /// [`peek`](Self::peek) (which may have peeked more than `n`). The
    /// caller is responsible for having peeked at least `n` bits first.
    pub fn consume(&mut self, n: u8) {
        self.nbits -= n;
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
    fn align_to_byte_skips_partial_byte() {
        // Read 3 bits of 0xFF, align, then reads continue from the next byte.
        let mut r = BitReaderLsb::new(Cursor::new(vec![0xFF, 0x01]));
        for _ in 0..3 {
            assert_eq!(r.read_bit().unwrap(), Some(true));
        }
        r.align_to_byte();
        // 0x01: bit 0 set, rest clear.
        assert_eq!(r.read_bit().unwrap(), Some(true));
        for _ in 0..7 {
            assert_eq!(r.read_bit().unwrap(), Some(false));
        }
        assert_eq!(r.read_bit().unwrap(), None);
    }

    #[test]
    fn align_to_byte_when_already_aligned_is_noop() {
        // After consuming a whole byte we are aligned; align must not drop the
        // next byte.
        let mut r = BitReaderLsb::new(Cursor::new(vec![0xAA, 0x55]));
        assert_eq!(r.read_bits(8).unwrap(), Some(0xAA));
        r.align_to_byte();
        assert_eq!(r.read_bits(8).unwrap(), Some(0x55));
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

    #[test]
    fn peek_does_not_advance() {
        let mut r = BitReaderMsb::new(Cursor::new(vec![0xAB, 0xCD]));
        assert_eq!(r.peek(8).unwrap(), Some(0xAB));
        assert_eq!(
            r.peek(8).unwrap(),
            Some(0xAB),
            "a second peek sees the same bits"
        );
    }

    #[test]
    fn peek_then_consume_matches_read() {
        // peek(12) followed by consume(12) must see the same 12-bit codes,
        // in the same order, as two plain read(12) calls.
        let mut peeked = BitReaderMsb::new(Cursor::new(vec![0xAB, 0xCD, 0xEF]));
        let a = peeked.peek(12).unwrap().unwrap();
        peeked.consume(12);
        let b = peeked.peek(12).unwrap().unwrap();
        peeked.consume(12);

        let mut read = BitReaderMsb::new(Cursor::new(vec![0xAB, 0xCD, 0xEF]));
        assert_eq!(read.read(12).unwrap(), Some(a));
        assert_eq!(read.read(12).unwrap(), Some(b));
    }

    #[test]
    fn consume_less_than_peeked_leaves_the_remainder_available() {
        // 0xAB = 1010_1011. Peek all 8 bits, consume only the top 4
        // (0xA), then the next peek must see the low 4 bits (0xB) still
        // sitting at the front of the stream.
        let mut r = BitReaderMsb::new(Cursor::new(vec![0xAB, 0x00]));
        assert_eq!(r.peek(8).unwrap(), Some(0xAB));
        r.consume(4);
        assert_eq!(r.peek(4).unwrap(), Some(0xB));
    }

    #[test]
    fn peek_refills_across_a_byte_boundary() {
        let mut r = BitReaderMsb::new(Cursor::new(vec![0xAB, 0xCD]));
        r.peek(4).unwrap();
        r.consume(4); // burn the high nibble so the next peek needs a refill
        assert_eq!(r.peek(12).unwrap(), Some(0xBCD));
    }

    #[test]
    fn peek_past_eof_is_none() {
        let mut r = BitReaderMsb::new(Cursor::new(vec![0xFF]));
        assert_eq!(r.peek(16).unwrap(), None);
    }

    #[test]
    fn peek_zero_bits_is_zero_without_consuming_anything() {
        let mut r = BitReaderMsb::new(Cursor::new(vec![0xAB]));
        assert_eq!(r.peek(0).unwrap(), Some(0));
        assert_eq!(r.peek(8).unwrap(), Some(0xAB), "peek(0) must not consume");
    }
}
