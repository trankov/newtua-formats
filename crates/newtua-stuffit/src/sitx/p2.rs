// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Low-level StuffItX stream reading: an LSB-first bit reader over an in-memory
//! slice, the P2 variable-length integer, and the block-stream unwrapper.
//!
//! A faithful port of `CSHandle`'s bit methods, `StuffItXUtilities.m`, and
//! `XADStuffItXBlockHandle.m`. StuffItX packs its element headers as a bitstream
//! read least-significant-bit first, interleaved with raw byte reads; the parser
//! also needs to seek to arbitrary byte offsets (element data areas) and read the
//! current byte position, so the reader is kept local here rather than reusing
//! `newtua_common::BitReaderLsb`.

use std::io;

fn truncated() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "sitx: unexpected end of stream",
    )
}

/// An LSB-first bit reader over `&[u8]`, faithfully mirroring `CSHandle`'s
/// `readBitsLE:` / `flushReadBits` / raw-read / `offsetInFile` semantics.
///
/// `pos` is the byte position (`offsetInFile`): the next byte a raw read returns,
/// and the next byte the bit buffer refills from. When the bit buffer holds a
/// partially-consumed byte, `pos` already points **past** it — refilling reads a
/// byte and advances `pos`. `bitoffs` records `pos` at the moment the current
/// byte was loaded; a raw read or seek moves `pos` away from `bitoffs`, which the
/// next bit read detects and treats as a flush (matching the reference's
/// `if(offsetInFile != bitoffs) readbitsleft = 0`).
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    readbyte: u8,
    readbitsleft: u8,
    bitoffs: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            readbyte: 0,
            readbitsleft: 0,
            bitoffs: 0,
        }
    }

    /// Read `bits` bits (0..=32) least-significant-first, refilling the byte
    /// buffer from `pos` as needed. Port of `-[CSHandle readBitsLE:]`.
    pub(crate) fn bits_le(&mut self, bits: u32) -> io::Result<u32> {
        // A raw read or seek moved us off the buffered byte: drop it.
        if self.pos != self.bitoffs {
            self.readbitsleft = 0;
        }
        let mut res = 0u32;
        let mut done = 0u32;
        while done < bits {
            if self.readbitsleft == 0 {
                self.readbyte = *self.data.get(self.pos).ok_or_else(truncated)?;
                self.pos += 1;
                self.bitoffs = self.pos;
                self.readbitsleft = 8;
            }
            let mut num = bits - done;
            if num > u32::from(self.readbitsleft) {
                num = u32::from(self.readbitsleft);
            }
            let chunk = (u32::from(self.readbyte) >> (8 - self.readbitsleft)) & ((1u32 << num) - 1);
            res |= chunk << done;
            done += num;
            self.readbitsleft -= num as u8;
        }
        Ok(res)
    }

    /// Read a single bit.
    pub(crate) fn bit(&mut self) -> io::Result<u32> {
        self.bits_le(1)
    }

    /// Read one byte through the bit path (`readBitsLE:8`). On a byte boundary
    /// this yields the raw byte; used by the big-endian and `ReadSitxData` readers.
    pub(crate) fn byte(&mut self) -> io::Result<u8> {
        Ok(self.bits_le(8)? as u8)
    }

    /// The StuffItX P2 variable-length integer (`ReadSitxP2`, `StuffItXUtilities.m:3`).
    ///
    /// A unary prefix of `n-1` one-bits then a zero, followed by value bits read
    /// LSB-first until `n` ones have been seen (the last read bit is always the
    /// value's top set bit). The result is `value - 1`, so the minimum is 0.
    pub(crate) fn read_p2(&mut self) -> io::Result<u64> {
        let mut n = 1u32;
        while self.bit()? == 1 {
            n += 1;
        }
        let mut value = 0u64;
        let mut mask = 1u64;
        while n != 0 {
            if self.bit()? == 1 {
                n -= 1;
                value |= mask;
            }
            // `uint64_t` wraps in the reference: past 64 bits the mask becomes 0
            // and `value - 1` wraps, both harmless for well-formed values.
            mask = mask.wrapping_shl(1);
        }
        Ok(value.wrapping_sub(1))
    }

    /// Read a big-endian `u32` (`ReadSitxUInt32`): four bytes via the bit path.
    pub(crate) fn read_u32_be(&mut self) -> io::Result<u32> {
        let mut val = 0u32;
        for _ in 0..4 {
            val = (val << 8) | u32::from(self.byte()?);
        }
        Ok(val)
    }

    /// Read a big-endian `u64` (`ReadSitxUInt64`): eight bytes via the bit path.
    pub(crate) fn read_u64_be(&mut self) -> io::Result<u64> {
        let mut val = 0u64;
        for _ in 0..8 {
            val = (val << 8) | u64::from(self.byte()?);
        }
        Ok(val)
    }

    /// Read a big-endian `u32` from four **raw** bytes at the current position
    /// (`-[CSHandle readUInt32BE]`, `readAtMost:`), bypassing the bit buffer.
    /// Used for the block-tail CRC, which is byte-aligned, unlike the catalog's
    /// bit-path `ReadSitxUInt32`.
    pub(crate) fn read_raw_u32_be(&mut self) -> io::Result<u32> {
        let bytes: [u8; 4] = self.raw(4)?.try_into().unwrap();
        Ok(u32::from_be_bytes(bytes))
    }

    /// Read `n` bytes through the bit path (`ReadSitxData`).
    pub(crate) fn read_data(&mut self, n: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.byte()?);
        }
        Ok(out)
    }

    /// Read a length-prefixed string (`ReadSitxString`): a P2 length, then that
    /// many **raw** bytes, then a bit flush to the next byte boundary.
    pub(crate) fn read_string(&mut self) -> io::Result<Vec<u8>> {
        let len = self.read_p2()? as usize;
        let data = self.raw(len)?.to_vec();
        self.flush();
        Ok(data)
    }

    /// Read `n` raw bytes at the current byte position (`readDataOfLength:`),
    /// advancing `pos`. Independent of the bit buffer.
    pub(crate) fn raw(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(truncated)?;
        let slice = self.data.get(self.pos..end).ok_or_else(truncated)?;
        self.pos = end;
        Ok(slice)
    }

    /// Skip `n` raw bytes (`skipBytes:`).
    pub(crate) fn skip(&mut self, n: usize) -> io::Result<()> {
        self.raw(n).map(|_| ())
    }

    /// Discard the rest of the current byte's bits (`flushReadBits`).
    pub(crate) fn flush(&mut self) {
        self.readbitsleft = 0;
    }

    /// The current byte position (`offsetInFile`).
    pub(crate) fn offset(&self) -> usize {
        self.pos
    }

    /// Seek to a byte offset (`seekToFileOffset:`). The bit buffer is invalidated
    /// lazily on the next bit read (via the `pos != bitoffs` guard), exactly as in
    /// the reference; callers flush explicitly where the reference does.
    pub(crate) fn seek(&mut self, off: usize) {
        self.pos = off;
    }
}

/// Unwrap an element's block stream (`XADStuffItXBlockHandle`) into a single
/// byte vector. The body is a sequence `[size:P2][size raw bytes]…` terminated
/// by a zero-length block. The reader is first seeked to `dataoffset` and
/// flushed to a byte boundary, exactly as `HandleForElement` does before
/// constructing the block handle.
pub(crate) fn read_block_stream(r: &mut Reader, dataoffset: usize) -> io::Result<Vec<u8>> {
    r.seek(dataoffset);
    r.flush();
    let mut out = Vec::new();
    loop {
        let size = r.read_p2()? as usize;
        if size == 0 {
            break;
        }
        out.extend_from_slice(r.raw(size)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mirror P2 encoder: the inverse of [`Reader::read_p2`], emitting bits
    /// LSB-first. `value = result + 1`; the unary prefix is `popcount(value) - 1`
    /// ones then a zero; then `value`'s bits LSB-first up to its top set bit.
    fn encode_p2(bits: &mut Vec<bool>, result: u64) {
        let value = result + 1;
        let n = value.count_ones();
        for _ in 0..n - 1 {
            bits.push(true);
        }
        bits.push(false);
        let hb = 63 - value.leading_zeros();
        for i in 0..=hb {
            bits.push((value >> i) & 1 != 0);
        }
    }

    /// Pack a bit sequence LSB-first into bytes, the layout `Reader` reads.
    fn pack(bits: &[bool]) -> Vec<u8> {
        let mut out = vec![0u8; bits.len().div_ceil(8)];
        for (i, &b) in bits.iter().enumerate() {
            if b {
                out[i / 8] |= 1 << (i % 8);
            }
        }
        out
    }

    #[test]
    fn bits_le_reads_lsb_first_across_bytes() {
        // 0b1011_0010, 0b0000_0001 -> low bits first.
        let mut r = Reader::new(&[0b1011_0010, 0b0000_0001]);
        assert_eq!(r.bit().unwrap(), 0); // bit 0 of first byte
        assert_eq!(r.bit().unwrap(), 1); // bit 1
        assert_eq!(r.bits_le(3).unwrap(), 0b100); // bits 2,3,4 = 0,0,1 -> 0b100
        assert_eq!(r.bits_le(6).unwrap(), 0b00_1101); // bits 5,6,7 of b0 + 0,0,0 of b1... check
    }

    #[test]
    fn byte_on_boundary_returns_raw_byte() {
        let mut r = Reader::new(&[0xAB, 0xCD]);
        assert_eq!(r.byte().unwrap(), 0xAB);
        assert_eq!(r.byte().unwrap(), 0xCD);
    }

    #[test]
    fn u32_and_u64_are_big_endian() {
        let mut r = Reader::new(&[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(r.read_u32_be().unwrap(), 0x1234_5678);
        let mut r = Reader::new(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(r.read_u64_be().unwrap(), 0x0102_0304_0506_0708);
    }

    #[test]
    fn read_p2_round_trips_via_mirror_encoder() {
        for result in [0u64, 1, 2, 3, 7, 8, 15, 16, 127, 255, 1000, 65535, 1 << 20] {
            let mut bits = Vec::new();
            encode_p2(&mut bits, result);
            let bytes = pack(&bits);
            let mut r = Reader::new(&bytes);
            assert_eq!(r.read_p2().unwrap(), result, "result={result}");
        }
    }

    #[test]
    fn read_p2_zero_is_two_bits() {
        // result 0: value=1, prefix "0", value bit "1" -> bits 0,1 (LSB) = 0b10.
        let mut r = Reader::new(&[0b10]);
        assert_eq!(r.read_p2().unwrap(), 0);
    }

    #[test]
    fn read_p2_sequence_shares_the_bitstream() {
        let mut bits = Vec::new();
        for v in [5u64, 0, 42, 3] {
            encode_p2(&mut bits, v);
        }
        let bytes = pack(&bits);
        let mut r = Reader::new(&bytes);
        for v in [5u64, 0, 42, 3] {
            assert_eq!(r.read_p2().unwrap(), v);
        }
    }

    #[test]
    fn string_reads_length_then_raw_bytes_then_flushes() {
        // P2 length 3 (bits), then raw "abc". The length P2 leaves us mid-byte;
        // the raw bytes start at the next byte boundary (offsetInFile).
        let mut bits = Vec::new();
        encode_p2(&mut bits, 3);
        let mut bytes = pack(&bits);
        bytes.extend_from_slice(b"abc");
        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_string().unwrap(), b"abc");
    }

    #[test]
    fn offset_points_past_partially_read_byte() {
        let mut r = Reader::new(&[0xFF, 0xAA]);
        r.bit().unwrap(); // consume one bit of byte 0
        assert_eq!(r.offset(), 1); // offsetInFile already past byte 0
        let raw = r.raw(1).unwrap(); // raw read starts at byte 1
        assert_eq!(raw, &[0xAA]);
    }

    #[test]
    fn seek_and_flush_restart_on_a_byte_boundary() {
        let mut r = Reader::new(&[0b0000_0001, 0xAA, 0xBB]);
        r.bit().unwrap();
        r.seek(1);
        r.flush();
        assert_eq!(r.byte().unwrap(), 0xAA);
        assert_eq!(r.offset(), 2);
    }

    /// Mirror block-stream encoder: for each chunk emit a P2 size then the raw
    /// bytes, then a terminating zero-length P2. Bits are byte-aligned before the
    /// raw payload (P2 sizes here are chosen to leave the writer mid-byte, which
    /// the reader tolerates because raw reads start at `offsetInFile`).
    fn encode_block_stream(chunks: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in chunks {
            let mut bits = Vec::new();
            encode_p2(&mut bits, chunk.len() as u64);
            out.extend_from_slice(&pack(&bits));
            out.extend_from_slice(chunk);
        }
        let mut bits = Vec::new();
        encode_p2(&mut bits, 0); // terminator
        out.extend_from_slice(&pack(&bits));
        out
    }

    #[test]
    fn block_stream_concatenates_chunks_until_terminator() {
        let bytes = encode_block_stream(&[b"hello ", b"block ", b"stream"]);
        let mut r = Reader::new(&bytes);
        assert_eq!(read_block_stream(&mut r, 0).unwrap(), b"hello block stream");
    }

    #[test]
    fn empty_block_stream_is_empty() {
        let bytes = encode_block_stream(&[]);
        let mut r = Reader::new(&bytes);
        assert_eq!(read_block_stream(&mut r, 0).unwrap(), b"");
    }

    #[test]
    fn block_stream_respects_dataoffset() {
        let mut bytes = vec![0xDE, 0xAD]; // header bytes before the block stream
        bytes.extend_from_slice(&encode_block_stream(&[b"payload"]));
        let mut r = Reader::new(&bytes);
        assert_eq!(read_block_stream(&mut r, 2).unwrap(), b"payload");
    }

    #[test]
    fn reading_past_end_errors() {
        let mut r = Reader::new(&[0x01]);
        assert!(r.raw(2).is_err());
        let mut r = Reader::new(&[]);
        assert!(r.bit().is_err());
    }
}
