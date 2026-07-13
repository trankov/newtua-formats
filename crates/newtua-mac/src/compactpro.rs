// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Compact Pro (`.cpt`) — a classic Macintosh archive of files with two forks.
//!
//! A Compact Pro file is a flat 8-byte header pointing at a catalog near the end
//! of the file. The catalog is a CRC-protected, pre-order directory tree: each
//! node is a name plus either a child count (a directory) or 45 bytes of file
//! metadata. Every file carries up to two forks (resource then data), each of
//! which is emitted as its own entry — mirroring BinHex / MacBinary.
//!
//! Each fork is compressed with a two-stage pipeline, read outside-in:
//! `RLE( [LZH( raw )] )`. The outer RLE layer (control byte `0x81`) always runs
//! and decides how many bytes the fork produces; the inner LZH layer (an LZSS
//! sliding window with three per-block Huffman codes) runs only when the fork's
//! flag bit is set.
//!
//! Faithful port of XADMaster's `XADCompactProParser`,
//! `XADCompactProRLEHandle`, `XADCompactProLZHHandle` and the `XADLZSSHandle`
//! base loop.
//!
//! # Known limitations (out of scope)
//!
//! * Encryption (`flags & 1`) is not supported: reading such an entry returns
//!   [`io::ErrorKind::Unsupported`].
//! * Multi-volume archives are treated as a single stream; cross-volume forks
//!   are not stitched together.
//! * Filenames are kept as raw bytes (MacRoman); the full path from the root is
//!   joined with `/`. Decoding to Unicode is the caller's job, as for BinHex.
//! * Dates and Finder flags are parsed into entry fields only; they are not
//!   applied to any extracted file.

use std::io::{self, Read, Write};

use newtua_common::crc32::crc32_ieee;
use newtua_common::prefixcode::PrefixCode;

/// LZSS window size: 8192 bytes (a power of two, so positions mask cleanly).
const WINDOW_SIZE: usize = 8192;
/// `WINDOW_SIZE - 1`, used to wrap absolute positions into the ring.
const WINDOW_MASK: u64 = (WINDOW_SIZE as u64) - 1;
/// The block size the container always passes to the LZH decoder.
const DEFAULT_BLOCK_SIZE: usize = 0x1fff0;

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn unexpected_eof() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "compactpro: unexpected end of data",
    )
}

// === public types =============================================================

/// One catalog node: a directory, or one fork (resource or data) of a file.
pub struct CompactProEntry {
    name: Vec<u8>,
    is_directory: bool,
    is_resource_fork: bool,
    size: u32,
    file_type: [u8; 4],
    creator: [u8; 4],
    finder_flags: u16,
    creation_date: u32,
    modification_date: u32,
    /// Extraction parameters; `None` for directories.
    fork: Option<ForkInfo>,
}

/// How to extract one fork's bytes.
struct ForkInfo {
    /// Absolute offset of the compressed bytes within the archive.
    offset: usize,
    /// Compressed length in bytes.
    complen: usize,
    /// Whether the LZH layer is applied under the RLE layer.
    lzh: bool,
    /// Whether the file is encrypted (reading is then unsupported).
    encrypted: bool,
    /// CRC-32 to verify, present only when this file has a single fork. The
    /// stored value is a raw (un-inverted) accumulator, so the check is
    /// `crc32_ieee(decoded) == !stored`.
    crc: Option<u32>,
}

impl CompactProEntry {
    /// The full path from the archive root, raw bytes (MacRoman), joined with
    /// `/`. A file's two forks share the same path.
    pub fn name(&self) -> &[u8] {
        &self.name
    }
    /// The fork's uncompressed length in bytes (0 for directories).
    pub fn size(&self) -> u64 {
        u64::from(self.size)
    }
    /// Whether this entry is a directory (then it carries no fork).
    pub fn is_directory(&self) -> bool {
        self.is_directory
    }
    /// Whether this entry is the resource fork (`false` for data forks and
    /// directories).
    pub fn is_resource_fork(&self) -> bool {
        self.is_resource_fork
    }
    /// The Mac file type (OSType), four raw bytes.
    pub fn file_type(&self) -> [u8; 4] {
        self.file_type
    }
    /// The Mac creator code (OSType), four raw bytes.
    pub fn creator(&self) -> [u8; 4] {
        self.creator
    }
    /// The Finder flags.
    pub fn finder_flags(&self) -> u16 {
        self.finder_flags
    }
    /// Creation date, raw seconds since 1904-01-01 (the classic Mac epoch).
    pub fn creation_date(&self) -> u32 {
        self.creation_date
    }
    /// Last-modification date, raw seconds since 1904-01-01.
    pub fn modification_date(&self) -> u32 {
        self.modification_date
    }
}

/// A parsed Compact Pro archive: its raw bytes plus the flattened catalog.
pub struct CompactProArchive {
    data: Vec<u8>,
    entries: Vec<CompactProEntry>,
}

impl CompactProArchive {
    /// Whether `data` is a Compact Pro archive: a `1` marker byte and a catalog
    /// whose stored CRC matches the catalog metadata.
    pub fn recognize(data: &[u8]) -> bool {
        recognize(data)
    }

    /// Read and parse a Compact Pro archive from `r`.
    pub fn open<R: Read>(mut r: R) -> io::Result<Self> {
        let mut data = Vec::new();
        r.read_to_end(&mut data)?;
        let entries = parse_catalog(&data)?;
        Ok(Self { data, entries })
    }

    /// The flattened catalog: directories and fork entries in pre-order, each
    /// file's resource fork before its data fork.
    pub fn entries(&self) -> &[CompactProEntry] {
        &self.entries
    }

    /// Write entry `idx`'s decoded fork bytes to `out`. Directories write
    /// nothing. Encrypted entries return [`io::ErrorKind::Unsupported`].
    pub fn read_entry(&self, idx: usize, out: &mut dyn Write) -> io::Result<()> {
        let e = self
            .entries
            .get(idx)
            .ok_or_else(|| invalid("compactpro: entry index out of range"))?;
        let fork = match &e.fork {
            None => return Ok(()), // a directory: no data
            Some(f) => f,
        };
        if fork.encrypted {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "compactpro: encrypted entries are not supported",
            ));
        }
        let raw = self
            .data
            .get(fork.offset..fork.offset + fork.complen)
            .ok_or_else(|| invalid("compactpro: fork data past end of archive"))?;

        let length = e.size as usize;
        let decoded = if fork.lzh {
            let mut lzh = LzhDecoder::new(raw, DEFAULT_BLOCK_SIZE);
            rle_decode(|| lzh.next_byte(), length)?
        } else {
            let mut it = raw.iter().copied();
            rle_decode(|| Ok(it.next()), length)?
        };

        if let Some(stored) = fork.crc {
            if crc32_ieee(&decoded) != !stored {
                return Err(invalid("compactpro: fork CRC mismatch"));
            }
        }
        out.write_all(&decoded)
    }
}

// === recognition + catalog parsing ===========================================

/// Read a big-endian `u32` at `off`, or `None` if out of bounds.
fn u32_be(data: &[u8], off: usize) -> Option<u32> {
    let b = data.get(off..off + 4)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn recognize(data: &[u8]) -> bool {
    if data.len() < 8 || data[0] != 1 {
        return false;
    }
    let offset = match u32_be(data, 4) {
        Some(v) => v as usize,
        None => return false,
    };
    let expected = match u32_be(data, offset) {
        Some(v) => v,
        None => return false,
    };
    // The catalog metadata is a contiguous region right after the 4-byte stored
    // CRC. Scan it to find its end, then CRC the whole span at once.
    match catalog_region_end(data, offset + 4) {
        Some(end) => crc32_ieee(&data[offset + 4..end]) == !expected,
        None => false,
    }
}

/// Walk the flat catalog metadata starting at `start` (just past the stored
/// CRC) and return the offset one past its last byte, or `None` on overrun.
fn catalog_region_end(data: &[u8], start: usize) -> Option<usize> {
    let len = data.len();
    if start + 3 > len {
        return None;
    }
    let numentries = u16::from_be_bytes([data[start], data[start + 1]]) as usize;
    let commentsize = data[start + 2] as usize;
    let mut p = start + 3;
    p = p.checked_add(commentsize)?;
    if p > len {
        return None;
    }
    // The top-level count is the grand total of nodes; a flat scan that reads
    // name + (2 | 45) metadata bytes per node visits the whole pre-order tree.
    for _ in 0..numentries {
        if p >= len {
            return None;
        }
        let namelen = data[p];
        p += 1;
        p = p.checked_add((namelen & 0x7f) as usize)?;
        let metadatasize = if namelen & 0x80 != 0 { 2 } else { 45 };
        p = p.checked_add(metadatasize)?;
        if p > len {
            return None;
        }
    }
    Some(p)
}

/// A bounds-checked big-endian reader over the archive bytes.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8], pos: usize) -> Self {
        Self { data, pos }
    }
    fn u8(&mut self) -> io::Result<u8> {
        let b = *self.data.get(self.pos).ok_or_else(unexpected_eof)?;
        self.pos += 1;
        Ok(b)
    }
    fn u16(&mut self) -> io::Result<u16> {
        Ok(((self.u8()? as u16) << 8) | self.u8()? as u16)
    }
    fn u32(&mut self) -> io::Result<u32> {
        Ok(((self.u16()? as u32) << 16) | self.u16()? as u32)
    }
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(unexpected_eof)?;
        let s = self.data.get(self.pos..end).ok_or_else(unexpected_eof)?;
        self.pos = end;
        Ok(s)
    }
    fn array4(&mut self) -> io::Result<[u8; 4]> {
        let s = self.take(4)?;
        Ok([s[0], s[1], s[2], s[3]])
    }
}

fn parse_catalog(data: &[u8]) -> io::Result<Vec<CompactProEntry>> {
    if data.len() < 8 || data[0] != 1 {
        return Err(invalid("compactpro: not a Compact Pro archive"));
    }
    let offset = u32_be(data, 4).ok_or_else(unexpected_eof)? as usize;
    let mut r = Reader::new(data, offset);
    let _headcrc = r.u32()?;
    let numentries = r.u16()?;
    let commentlen = r.u8()?;
    r.take(commentlen as usize)?; // comment kept out of scope
    let mut entries = Vec::new();
    parse_dir(&mut r, &[], numentries as i64, &mut entries)?;
    Ok(entries)
}

/// Append a path component to `parent`, joining with `/` (root has no name).
fn join_path(parent: &[u8], name: &[u8]) -> Vec<u8> {
    if parent.is_empty() {
        name.to_vec()
    } else {
        let mut p = Vec::with_capacity(parent.len() + 1 + name.len());
        p.extend_from_slice(parent);
        p.push(b'/');
        p.extend_from_slice(name);
        p
    }
}

fn parse_dir(
    r: &mut Reader,
    parent: &[u8],
    count: i64,
    entries: &mut Vec<CompactProEntry>,
) -> io::Result<()> {
    let mut remaining = count;
    while remaining > 0 {
        let namelen = r.u8()?;
        let name = r.take((namelen & 0x7f) as usize)?.to_vec();
        let path = join_path(parent, &name);

        if namelen & 0x80 != 0 {
            let numdirentries = r.u16()?;
            entries.push(CompactProEntry {
                name: path.clone(),
                is_directory: true,
                is_resource_fork: false,
                size: 0,
                file_type: [0; 4],
                creator: [0; 4],
                finder_flags: 0,
                creation_date: 0,
                modification_date: 0,
                fork: None,
            });
            parse_dir(r, &path, numdirentries as i64, entries)?;
            remaining -= numdirentries as i64 + 1;
        } else {
            let _volume = r.u8()?;
            let fileoffs = r.u32()? as usize;
            let file_type = r.array4()?;
            let creator = r.array4()?;
            let creation_date = r.u32()?;
            let modification_date = r.u32()?;
            let finder_flags = r.u16()?;
            let crc = r.u32()?;
            let flags = r.u16()?;
            let resourcelength = r.u32()?;
            let datalength = r.u32()?;
            let resourcecomplen = r.u32()? as usize;
            let datacomplen = r.u32()? as usize;
            let encrypted = flags & 1 != 0;

            let mut push_fork = |is_resource: bool,
                                 size: u32,
                                 offset: usize,
                                 complen: usize,
                                 lzh: bool,
                                 crc: Option<u32>| {
                entries.push(CompactProEntry {
                    name: path.clone(),
                    is_directory: false,
                    is_resource_fork: is_resource,
                    size,
                    file_type,
                    creator,
                    finder_flags,
                    creation_date,
                    modification_date,
                    fork: Some(ForkInfo {
                        offset,
                        complen,
                        lzh,
                        encrypted,
                        crc,
                    }),
                });
            };

            if resourcelength != 0 {
                let single = if datalength != 0 { None } else { Some(crc) };
                push_fork(
                    true,
                    resourcelength,
                    fileoffs,
                    resourcecomplen,
                    flags & 2 != 0,
                    single,
                );
            }
            if datalength != 0 || resourcelength == 0 {
                let single = if resourcelength != 0 { None } else { Some(crc) };
                push_fork(
                    false,
                    datalength,
                    fileoffs + resourcecomplen,
                    datacomplen,
                    flags & 4 != 0,
                    single,
                );
            }
            remaining -= 1;
        }
    }
    Ok(())
}

// === RLE layer (outer) ========================================================

/// Decode exactly `length` bytes through the Compact Pro RLE layer, pulling
/// input bytes from `next` (which returns `Ok(None)` at end of input). Faithful
/// port of `XADCompactProRLEHandle`'s `produceByteAtOffset:`.
fn rle_decode(
    mut next: impl FnMut() -> io::Result<Option<u8>>,
    length: usize,
) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(length);
    let mut saved: u8 = 0;
    let mut repeat: i64 = 0;
    let mut halfescaped = false;

    let take = |next: &mut dyn FnMut() -> io::Result<Option<u8>>| -> io::Result<u8> {
        next()?.ok_or_else(unexpected_eof)
    };

    while out.len() < length {
        if repeat != 0 {
            repeat -= 1;
            out.push(saved);
            continue;
        }
        let byte = if halfescaped {
            halfescaped = false;
            0x81
        } else {
            take(&mut next)?
        };
        if byte == 0x81 {
            let b = take(&mut next)?;
            if b == 0x82 {
                let c = take(&mut next)?;
                if c != 0 {
                    repeat = c as i64 - 2;
                    out.push(saved);
                } else {
                    repeat = 1;
                    saved = 0x82;
                    out.push(0x81);
                }
            } else if b == 0x81 {
                halfescaped = true;
                saved = 0x81;
                out.push(0x81);
            } else {
                repeat = 1;
                saved = b;
                out.push(0x81);
            }
        } else {
            saved = byte;
            out.push(byte);
        }
    }
    Ok(out)
}

// === LZH layer (inner) ========================================================

/// A most-significant-bit-first cursor over an in-memory slice that also tracks
/// its byte offset and can re-align — the bookkeeping Compact Pro's per-block
/// padding quirk needs and the shared bit readers do not expose.
struct BitCursor<'a> {
    data: &'a [u8],
    /// Absolute bit position from the start of `data`.
    bitpos: usize,
}

impl<'a> BitCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, bitpos: 0 }
    }
    /// Next bit (MSB first), or `None` at end of input.
    fn read_bit(&mut self) -> io::Result<Option<bool>> {
        let byte = self.bitpos >> 3;
        if byte >= self.data.len() {
            return Ok(None);
        }
        let bit = (self.data[byte] >> (7 - (self.bitpos & 7))) & 1;
        self.bitpos += 1;
        Ok(Some(bit != 0))
    }
    /// Next `n`-bit value (MSB first), or `None` if fewer than `n` bits remain.
    fn read_bits(&mut self, n: u32) -> io::Result<Option<u32>> {
        let mut acc = 0u32;
        for _ in 0..n {
            match self.read_bit()? {
                Some(b) => acc = (acc << 1) | b as u32,
                None => return Ok(None),
            }
        }
        Ok(Some(acc))
    }
    /// Next whole byte (call only when byte-aligned), or `None` at end.
    fn read_byte(&mut self) -> io::Result<Option<u8>> {
        Ok(self.read_bits(8)?.map(|v| v as u8))
    }
    /// Discard any partial bits so the next read starts on a byte boundary.
    fn align_to_byte(&mut self) {
        if self.bitpos & 7 != 0 {
            self.bitpos = (self.bitpos & !7) + 8;
        }
    }
    /// Bytes consumed so far (meaningful at byte-aligned points).
    fn byte_offset(&self) -> usize {
        self.bitpos >> 3
    }
    /// Skip `n` whole bytes (call only when byte-aligned).
    fn skip_bytes(&mut self, n: usize) {
        self.bitpos += n * 8;
    }
}

/// One LZSS token.
enum Token {
    Literal(u8),
    Match { offset: usize, length: usize },
    End,
}

/// The LZH decoder: an LZSS sliding window fed by three per-block Huffman codes,
/// with the block-boundary byte-alignment quirk. Pulls output bytes on demand.
struct LzhDecoder<'a> {
    cursor: BitCursor<'a>,
    blocksize: usize,
    blockcount: usize,
    /// Byte offset of the current block's start (0 marks the first block).
    blockstart: usize,
    window: Vec<u8>,
    matchlength: i64,
    matchoffset: u64,
    pos: u64,
    literalcode: Option<PrefixCode>,
    lengthcode: Option<PrefixCode>,
    offsetcode: Option<PrefixCode>,
}

impl<'a> LzhDecoder<'a> {
    fn new(data: &'a [u8], blocksize: usize) -> Self {
        Self {
            cursor: BitCursor::new(data),
            blocksize,
            // Mirror -resetLZSSHandle: force a block parse on the first token.
            blockcount: blocksize,
            blockstart: 0,
            window: vec![0u8; WINDOW_SIZE],
            matchlength: 0,
            matchoffset: 0,
            pos: 0,
            literalcode: None,
            lengthcode: None,
            offsetcode: None,
        }
    }

    /// Read one code table: a byte count, then that many bytes of packed 4-bit
    /// code lengths. Port of `allocAndParseCodeOfSize:`.
    fn parse_code(&mut self, size: usize) -> io::Result<Option<PrefixCode>> {
        let numbytes = match self.cursor.read_byte()? {
            Some(b) => b as usize,
            None => return Ok(None),
        };
        if numbytes * 2 > size {
            return Err(invalid("compactpro: illegal LZH code table"));
        }
        // Only the first `2 * numbytes` symbols can carry a code; the rest of
        // the `size`-symbol alphabet stays at length 0 (absent), so they need no
        // storage. `size` bounds the table; it is not its length.
        let mut lengths = vec![0u32; numbytes * 2];
        for i in 0..numbytes {
            let val = match self.cursor.read_byte()? {
                Some(b) => b,
                None => return Ok(None),
            };
            lengths[2 * i] = u32::from(val >> 4);
            lengths[2 * i + 1] = u32::from(val & 0x0f);
        }
        Ok(Some(PrefixCode::try_from_lengths(&lengths, 15, true)?))
    }

    /// Decode one symbol from `code` via the cursor, MSB first.
    fn next_symbol(cursor: &mut BitCursor, code: &PrefixCode) -> io::Result<Option<i32>> {
        code.next_symbol_msb_with(|| cursor.read_bit())
    }

    /// Get the next literal or match token. Port of `nextLiteralOrOffset:`.
    fn next_token(&mut self) -> io::Result<Token> {
        if self.blockcount >= self.blocksize {
            if self.blockstart != 0 {
                // Don't let your bad implementations leak into your file
                // formats, people! Align, then skip 2 or 3 filler bytes by the
                // parity of the bytes consumed since the block start.
                self.cursor.align_to_byte();
                let off = self.cursor.byte_offset();
                if (off - self.blockstart) & 1 != 0 {
                    self.cursor.skip_bytes(3);
                } else {
                    self.cursor.skip_bytes(2);
                }
            }
            match self.parse_code(256)? {
                Some(c) => self.literalcode = Some(c),
                None => return Ok(Token::End),
            }
            match self.parse_code(64)? {
                Some(c) => self.lengthcode = Some(c),
                None => return Ok(Token::End),
            }
            match self.parse_code(128)? {
                Some(c) => self.offsetcode = Some(c),
                None => return Ok(Token::End),
            }
            self.blockcount = 0;
            self.blockstart = self.cursor.byte_offset();
        }

        match self.cursor.read_bit()? {
            None => Ok(Token::End),
            Some(true) => {
                self.blockcount += 2;
                let cursor = &mut self.cursor;
                let code = self.literalcode.as_ref().unwrap();
                match Self::next_symbol(cursor, code)? {
                    Some(v) => Ok(Token::Literal(v as u8)),
                    None => Ok(Token::End),
                }
            }
            Some(false) => {
                self.blockcount += 3;
                let length = {
                    let cursor = &mut self.cursor;
                    let code = self.lengthcode.as_ref().unwrap();
                    match Self::next_symbol(cursor, code)? {
                        Some(v) => v as usize,
                        None => return Ok(Token::End),
                    }
                };
                let offhi = {
                    let cursor = &mut self.cursor;
                    let code = self.offsetcode.as_ref().unwrap();
                    match Self::next_symbol(cursor, code)? {
                        Some(v) => v as usize,
                        None => return Ok(Token::End),
                    }
                };
                let offlo = match self.cursor.read_bits(6)? {
                    Some(v) => v as usize,
                    None => return Ok(Token::End),
                };
                Ok(Token::Match {
                    offset: (offhi << 6) | offlo,
                    length,
                })
            }
        }
    }

    /// Produce the next output byte, or `None` at end of stream. Port of
    /// `XADLZSSHandle`'s `produceByteAtOffset:`.
    fn next_byte(&mut self) -> io::Result<Option<u8>> {
        if self.matchlength == 0 {
            match self.next_token()? {
                Token::End => return Ok(None),
                Token::Literal(v) => {
                    self.window[(self.pos & WINDOW_MASK) as usize] = v;
                    self.pos += 1;
                    return Ok(Some(v));
                }
                Token::Match { offset, length } => {
                    self.matchlength = length as i64;
                    self.matchoffset = self.pos.wrapping_sub(offset as u64);
                }
            }
        }
        self.matchlength -= 1;
        let byte = self.window[(self.matchoffset & WINDOW_MASK) as usize];
        self.matchoffset += 1;
        self.window[(self.pos & WINDOW_MASK) as usize] = byte;
        self.pos += 1;
        Ok(Some(byte))
    }
}

// === tests ====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// A code table of two bytes with nibbles 1,1,1,0 declares three length-1
    /// codes: the Kraft sum exceeds 1, so canonical assignment would run off a
    /// leaf. `parse_code` must report invalid data rather than panic.
    #[test]
    fn oversubscribed_code_lengths_error_not_panic() {
        let corrupt = [0x02u8, 0x11, 0x10];
        let mut d = LzhDecoder::new(&corrupt[..], DEFAULT_BLOCK_SIZE);
        let err = d.parse_code(256).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    // --- a minimal MSB-first bit writer mirroring BitCursor ------------------

    struct BitW {
        out: Vec<u8>,
        acc: u8,
        n: u8,
    }
    impl BitW {
        fn new() -> Self {
            BitW {
                out: Vec::new(),
                acc: 0,
                n: 0,
            }
        }
        fn put_bit(&mut self, b: u32) {
            self.acc = (self.acc << 1) | (b as u8 & 1);
            self.n += 1;
            if self.n == 8 {
                self.out.push(self.acc);
                self.acc = 0;
                self.n = 0;
            }
        }
        fn put_bits(&mut self, val: u32, bits: u32) {
            for i in (0..bits).rev() {
                self.put_bit((val >> i) & 1);
            }
        }
        fn byte_len(&self) -> usize {
            self.out.len()
        }
        fn align(&mut self) {
            if self.n > 0 {
                self.acc <<= 8 - self.n;
                self.out.push(self.acc);
                self.acc = 0;
                self.n = 0;
            }
        }
        fn push_byte(&mut self, b: u8) {
            assert_eq!(self.n, 0, "push_byte while not byte-aligned");
            self.out.push(b);
        }
        fn finish(mut self) -> Vec<u8> {
            self.align();
            self.out
        }
    }

    // --- mirror LZH encoder ---------------------------------------------------

    #[derive(Clone)]
    enum Tok {
        Lit(u8),
        Match { offset: usize, length: usize },
    }

    fn cost(t: &Tok) -> usize {
        match t {
            Tok::Lit(_) => 2,
            Tok::Match { .. } => 3,
        }
    }

    /// Partition tokens into blocks exactly as the decoder does: a new block
    /// starts whenever `blockcount >= blocksize` before reading a token.
    fn partition(tokens: &[Tok], blocksize: usize) -> Vec<Vec<Tok>> {
        let mut blocks = Vec::new();
        let mut cur: Vec<Tok> = Vec::new();
        let mut bc = blocksize;
        for t in tokens {
            if bc >= blocksize {
                if !cur.is_empty() {
                    blocks.push(std::mem::take(&mut cur));
                }
                bc = 0;
            }
            cur.push(t.clone());
            bc += cost(t);
        }
        if !cur.is_empty() {
            blocks.push(cur);
        }
        blocks
    }

    /// Equal code length over a present set: `L = ceil(log2(k))`, at least 1.
    fn equal_length(k: usize) -> u32 {
        let mut l = 1u32;
        while (1usize << l) < k {
            l += 1;
        }
        l
    }

    /// Canonical (code, length) per present symbol, matching
    /// `PrefixCode::from_lengths(.., shortest_code_is_zeros = true)`.
    fn canonical(present: &BTreeSet<u32>) -> std::collections::BTreeMap<u32, (u32, u32)> {
        let mut map = std::collections::BTreeMap::new();
        if present.is_empty() {
            return map;
        }
        let l = equal_length(present.len());
        for (code, &s) in present.iter().enumerate() {
            map.insert(s, (code as u32, l));
        }
        map
    }

    /// Serialize one code table (byte count + packed 4-bit lengths).
    fn write_table(w: &mut BitW, present: &BTreeSet<u32>) {
        if present.is_empty() {
            w.put_bits(0, 8);
            return;
        }
        let max = *present.iter().max().unwrap() as usize;
        let numbytes = max / 2 + 1;
        let l = equal_length(present.len()) as u8;
        let mut lens = vec![0u8; numbytes * 2];
        for &s in present {
            lens[s as usize] = l;
        }
        w.put_bits(numbytes as u32, 8);
        for i in 0..numbytes {
            let val = (lens[2 * i] << 4) | lens[2 * i + 1];
            w.put_bits(u32::from(val), 8);
        }
    }

    fn emit_symbol(w: &mut BitW, codes: &std::collections::BTreeMap<u32, (u32, u32)>, sym: u32) {
        let (code, len) = codes[&sym];
        w.put_bits(code, len);
    }

    /// Encode `tokens` into a Compact Pro LZH stream with the given `blocksize`.
    fn encode_lzh(tokens: &[Tok], blocksize: usize) -> Vec<u8> {
        let blocks = partition(tokens, blocksize);
        let mut w = BitW::new();
        let mut blockstart = 0usize;
        for (bi, block) in blocks.iter().enumerate() {
            if bi > 0 {
                w.align();
                let off = w.byte_len();
                let skip = if (off - blockstart) & 1 != 0 { 3 } else { 2 };
                for _ in 0..skip {
                    w.push_byte(0);
                }
            }
            let mut lit = BTreeSet::new();
            let mut len = BTreeSet::new();
            let mut off = BTreeSet::new();
            for t in block {
                match t {
                    Tok::Lit(b) => {
                        lit.insert(u32::from(*b));
                    }
                    Tok::Match { offset, length } => {
                        len.insert(*length as u32);
                        off.insert((*offset >> 6) as u32);
                    }
                }
            }
            write_table(&mut w, &lit);
            write_table(&mut w, &len);
            write_table(&mut w, &off);
            blockstart = w.byte_len();

            let lit_codes = canonical(&lit);
            let len_codes = canonical(&len);
            let off_codes = canonical(&off);
            for t in block {
                match t {
                    Tok::Lit(b) => {
                        w.put_bit(1);
                        emit_symbol(&mut w, &lit_codes, u32::from(*b));
                    }
                    Tok::Match { offset, length } => {
                        w.put_bit(0);
                        emit_symbol(&mut w, &len_codes, *length as u32);
                        emit_symbol(&mut w, &off_codes, (*offset >> 6) as u32);
                        w.put_bits((*offset & 0x3f) as u32, 6);
                    }
                }
            }
        }
        w.finish()
    }

    /// Apply tokens through a window to get the decoder's expected output.
    fn simulate(tokens: &[Tok]) -> Vec<u8> {
        let mut out = Vec::new();
        for t in tokens {
            match t {
                Tok::Lit(b) => out.push(*b),
                Tok::Match { offset, length } => {
                    for _ in 0..*length {
                        out.push(out[out.len() - offset]);
                    }
                }
            }
        }
        out
    }

    fn lzh_decode_all(data: &[u8], blocksize: usize, want: usize) -> Vec<u8> {
        let mut d = LzhDecoder::new(data, blocksize);
        let mut out = Vec::new();
        while out.len() < want {
            match d.next_byte().unwrap() {
                Some(b) => out.push(b),
                None => break,
            }
        }
        out
    }

    // --- mirror container builder --------------------------------------------

    /// One fork for the container builder: the bytes stored in the archive plus
    /// the content they must decode to (used to compute the stored CRC).
    struct Fork {
        compressed: Vec<u8>,
        content: Vec<u8>,
    }

    /// An RLE-identity fork (content has no `0x81` bytes, so it is stored as-is).
    fn rle_fork(content: &[u8]) -> Fork {
        Fork {
            compressed: content.to_vec(),
            content: content.to_vec(),
        }
    }

    /// An LZH+RLE fork: encode `content` (no `0x81`) as a single LZH block.
    fn lzh_fork(content: &[u8]) -> Fork {
        let toks: Vec<Tok> = content.iter().map(|&b| Tok::Lit(b)).collect();
        Fork {
            compressed: encode_lzh(&toks, DEFAULT_BLOCK_SIZE),
            content: content.to_vec(),
        }
    }

    /// A file member for the container builder.
    struct File {
        name: &'static [u8],
        file_type: [u8; 4],
        creator: [u8; 4],
        flags: u16,
        resource: Option<Fork>,
        data: Option<Fork>,
    }

    /// CRC-32 stored as a raw (un-inverted) accumulator: `!crc32_ieee(x)`.
    fn raw_crc(x: &[u8]) -> u32 {
        !crc32_ieee(x)
    }

    fn build_archive(comment: &[u8], nodes: &[Node]) -> Vec<u8> {
        // Body holds the fork bytes; the catalog references them by offset.
        let mut body = Vec::new();
        let header_len = 8;
        // First lay out fork bytes after the 8-byte header.
        let mut placed: Vec<PlacedNode> = Vec::new();
        let mut cursor = header_len;
        flatten(nodes, &mut placed, &mut cursor, &mut body, header_len);

        // Build catalog metadata (everything after the stored CRC).
        let mut meta = Vec::new();
        let total = count_nodes(nodes);
        meta.extend_from_slice(&(total as u16).to_be_bytes());
        meta.push(comment.len() as u8);
        meta.extend_from_slice(comment);
        emit_nodes(nodes, &placed, &mut meta);

        let crc = raw_crc(&meta);
        let catalog_offset = header_len + body.len();

        let mut out = vec![0u8; 8];
        out[0] = 1; // marker
        out[1] = 0; // volume
        out[2..4].copy_from_slice(&[0, 0]); // xmagic
        out[4..8].copy_from_slice(&(catalog_offset as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(&crc.to_be_bytes());
        out.extend_from_slice(&meta);
        out
    }

    enum Node {
        Dir(&'static [u8], Vec<Node>),
        File(File),
    }

    struct PlacedNode {
        fileoffs: usize,
    }

    fn count_nodes(nodes: &[Node]) -> usize {
        let mut n = 0;
        for node in nodes {
            n += 1;
            if let Node::Dir(_, children) = node {
                n += count_nodes(children);
            }
        }
        n
    }

    fn flatten(
        nodes: &[Node],
        placed: &mut Vec<PlacedNode>,
        cursor: &mut usize,
        body: &mut Vec<u8>,
        _header_len: usize,
    ) {
        for node in nodes {
            match node {
                Node::Dir(_, children) => {
                    placed.push(PlacedNode { fileoffs: 0 });
                    flatten(children, placed, cursor, body, _header_len);
                }
                Node::File(f) => {
                    let fileoffs = *cursor;
                    if let Some(r) = &f.resource {
                        body.extend_from_slice(&r.compressed);
                        *cursor += r.compressed.len();
                    }
                    if let Some(d) = &f.data {
                        body.extend_from_slice(&d.compressed);
                        *cursor += d.compressed.len();
                    }
                    placed.push(PlacedNode { fileoffs });
                }
            }
        }
    }

    fn emit_nodes(nodes: &[Node], placed: &[PlacedNode], meta: &mut Vec<u8>) {
        let mut idx = 0;
        emit_nodes_rec(nodes, placed, &mut idx, meta);
    }

    fn emit_nodes_rec(nodes: &[Node], placed: &[PlacedNode], idx: &mut usize, meta: &mut Vec<u8>) {
        for node in nodes {
            match node {
                Node::Dir(name, children) => {
                    let _p = &placed[*idx];
                    *idx += 1;
                    meta.push(0x80 | (name.len() as u8));
                    meta.extend_from_slice(name);
                    meta.extend_from_slice(&(count_nodes(children) as u16).to_be_bytes());
                    emit_nodes_rec(children, placed, idx, meta);
                }
                Node::File(f) => {
                    let p = &placed[*idx];
                    *idx += 1;
                    meta.push(f.name.len() as u8);
                    meta.extend_from_slice(f.name);

                    let rcomp = f.resource.as_ref().map_or(0, |r| r.compressed.len()) as u32;
                    let dcomp = f.data.as_ref().map_or(0, |d| d.compressed.len()) as u32;
                    let rlen = f.resource.as_ref().map_or(0, |r| r.content.len()) as u32;
                    let dlen = f.data.as_ref().map_or(0, |d| d.content.len()) as u32;

                    // Compute the stored CRC: single fork -> that fork's content
                    // CRC; both forks -> a shared CRC (we store an arbitrary one,
                    // which the reader ignores).
                    let crc = self_crc(f);

                    meta.push(0); // volume
                    meta.extend_from_slice(&(p.fileoffs as u32).to_be_bytes());
                    meta.extend_from_slice(&f.file_type);
                    meta.extend_from_slice(&f.creator);
                    meta.extend_from_slice(&0u32.to_be_bytes()); // creation date
                    meta.extend_from_slice(&0u32.to_be_bytes()); // modification date
                    meta.extend_from_slice(&0u16.to_be_bytes()); // finder flags
                    meta.extend_from_slice(&crc.to_be_bytes());
                    meta.extend_from_slice(&f.flags.to_be_bytes());
                    meta.extend_from_slice(&rlen.to_be_bytes());
                    meta.extend_from_slice(&dlen.to_be_bytes());
                    meta.extend_from_slice(&rcomp.to_be_bytes());
                    meta.extend_from_slice(&dcomp.to_be_bytes());
                }
            }
        }
    }

    fn self_crc(f: &File) -> u32 {
        match (&f.resource, &f.data) {
            (Some(_), Some(_)) => 0, // shared CRC, ignored by the reader
            (Some(r), None) => raw_crc(&r.content),
            (None, Some(d)) => raw_crc(&d.content),
            // An empty file emits one empty data fork; CRC of "".
            (None, None) => raw_crc(b""),
        }
    }

    // --- RLE branch tests (direct, hand-crafted) -----------------------------

    fn rle(input: &[u8], length: usize) -> Vec<u8> {
        let mut it = input.iter().copied();
        rle_decode(|| Ok(it.next()), length).unwrap()
    }

    #[test]
    fn rle_passes_through_normal_bytes() {
        assert_eq!(rle(b"ABC", 3), b"ABC");
    }

    #[test]
    fn rle_run_repeat() {
        // 'A', then 0x81 0x82 5 -> total run length 5 of 'A'.
        assert_eq!(rle(&[b'A', 0x81, 0x82, 5], 5), b"AAAAA");
    }

    #[test]
    fn rle_run_count_zero_emits_81_then_82() {
        assert_eq!(rle(&[0x81, 0x82, 0], 2), &[0x81, 0x82]);
    }

    #[test]
    fn rle_half_escape() {
        // 0x81 0x81 -> emits 0x81 and re-enters; following 0x41 closes it.
        assert_eq!(rle(&[0x81, 0x81, 0x41], 2), &[0x81, 0x81]);
    }

    #[test]
    fn rle_escaped_literal_81_then_byte() {
        assert_eq!(rle(&[0x81, 0x41], 2), &[0x81, 0x41]);
    }

    // --- BitCursor mechanics (independent of the mirror encoder) --------------

    #[test]
    fn bitcursor_reads_msb_first() {
        let mut c = BitCursor::new(&[0b1011_0001]);
        assert_eq!(c.read_bits(4).unwrap(), Some(0b1011));
        assert_eq!(c.read_bits(4).unwrap(), Some(0b0001));
        assert_eq!(c.read_bit().unwrap(), None);
    }

    #[test]
    fn bitcursor_align_advances_to_next_boundary() {
        let mut c = BitCursor::new(&[0xFF, 0xAA, 0xBB]);
        c.read_bits(3).unwrap();
        assert_eq!(c.byte_offset(), 0);
        c.align_to_byte();
        assert_eq!(c.byte_offset(), 1);
        // Already aligned: align is a no-op.
        c.align_to_byte();
        assert_eq!(c.byte_offset(), 1);
        assert_eq!(c.read_byte().unwrap(), Some(0xAA));
    }

    #[test]
    fn bitcursor_skip_bytes() {
        let mut c = BitCursor::new(&[1, 2, 3, 4]);
        c.skip_bytes(2);
        assert_eq!(c.byte_offset(), 2);
        assert_eq!(c.read_byte().unwrap(), Some(3));
    }

    // --- LZH decode tests -----------------------------------------------------

    #[test]
    fn lzh_decodes_literals() {
        let toks = vec![Tok::Lit(b'h'), Tok::Lit(b'i'), Tok::Lit(b'!')];
        let want = simulate(&toks);
        let enc = encode_lzh(&toks, DEFAULT_BLOCK_SIZE);
        assert_eq!(lzh_decode_all(&enc, DEFAULT_BLOCK_SIZE, want.len()), want);
    }

    #[test]
    fn lzh_decodes_match_and_overlap() {
        // "abc" then copy 3 back (non-overlap), then an overlapping run of 'x'.
        let toks = vec![
            Tok::Lit(b'a'),
            Tok::Lit(b'b'),
            Tok::Lit(b'c'),
            Tok::Match {
                offset: 3,
                length: 3,
            },
            Tok::Lit(b'x'),
            Tok::Match {
                offset: 1,
                length: 4,
            },
        ];
        let want = simulate(&toks);
        let enc = encode_lzh(&toks, DEFAULT_BLOCK_SIZE);
        assert_eq!(lzh_decode_all(&enc, DEFAULT_BLOCK_SIZE, want.len()), want);
    }

    #[test]
    fn lzh_match_with_large_offset_uses_extra_bits() {
        // Build >64 bytes so an offset needs the high offset-symbol plus 6 low
        // bits (offset 100 -> hi = 1, lo = 36).
        let mut toks: Vec<Tok> = (0..100u32)
            .map(|i| Tok::Lit((i & 0x7f) as u8 + 1))
            .collect();
        toks.push(Tok::Match {
            offset: 100,
            length: 5,
        });
        let want = simulate(&toks);
        let enc = encode_lzh(&toks, DEFAULT_BLOCK_SIZE);
        assert_eq!(lzh_decode_all(&enc, DEFAULT_BLOCK_SIZE, want.len()), want);
    }

    #[test]
    fn lzh_single_symbol_table() {
        // A block whose literal alphabet is a single symbol (code length 1).
        let toks = vec![Tok::Lit(b'Z'), Tok::Lit(b'Z'), Tok::Lit(b'Z')];
        let want = simulate(&toks);
        let enc = encode_lzh(&toks, DEFAULT_BLOCK_SIZE);
        assert_eq!(lzh_decode_all(&enc, DEFAULT_BLOCK_SIZE, want.len()), want);
    }

    // --- block-boundary quirk (small blocksize) ------------------------------

    #[test]
    fn lzh_two_blocks_reload_tables() {
        // Block 1 uses 'a'/'b'; block 2 uses 'c'/'d' — proves per-block tables.
        let toks = vec![
            Tok::Lit(b'a'),
            Tok::Lit(b'b'),
            Tok::Lit(b'c'),
            Tok::Lit(b'd'),
        ];
        let want = simulate(&toks);
        // blocksize 4: each literal costs 2, so 2 literals per block -> 2 blocks.
        let enc = encode_lzh(&toks, 4);
        assert_eq!(lzh_decode_all(&enc, 4, want.len()), want);
    }

    #[test]
    fn lzh_block_boundary_both_parities() {
        // Drive several block transitions; the encoder and decoder must agree on
        // the 2-vs-3 filler-byte skip for whatever parity each boundary lands on.
        let toks: Vec<Tok> = (0..12u32).map(|i| Tok::Lit(b'A' + (i % 7) as u8)).collect();
        let want = simulate(&toks);
        for blocksize in [4usize, 5, 6, 7] {
            let enc = encode_lzh(&toks, blocksize);
            assert_eq!(
                lzh_decode_all(&enc, blocksize, want.len()),
                want,
                "blocksize {blocksize}"
            );
        }
    }

    // --- container / recognition tests ---------------------------------------

    #[test]
    fn recognizes_valid_archive_and_rejects_garbage() {
        let arc = build_archive(
            b"",
            &[Node::File(File {
                name: b"f",
                file_type: *b"TEXT",
                creator: *b"ttxt",
                flags: 0,
                resource: None,
                data: Some(rle_fork(b"hello")),
            })],
        );
        assert!(CompactProArchive::recognize(&arc));
        assert!(!CompactProArchive::recognize(b"not a cpt"));
        assert!(!CompactProArchive::recognize(&[1, 0, 0, 0, 0, 0, 0, 99]));
    }

    #[test]
    fn parses_flat_files_and_forks() {
        // One file with both forks: emits resource then data, same name.
        let arc = build_archive(
            b"",
            &[Node::File(File {
                name: b"both",
                file_type: *b"TEXT",
                creator: *b"ttxt",
                flags: 0,
                resource: Some(rle_fork(b"RES")),
                data: Some(rle_fork(b"DATA")),
            })],
        );
        let a = CompactProArchive::open(&arc[..]).unwrap();
        assert_eq!(a.entries().len(), 2);
        assert!(a.entries()[0].is_resource_fork());
        assert!(!a.entries()[1].is_resource_fork());
        assert_eq!(a.entries()[0].name(), b"both");
        assert_eq!(a.entries()[1].name(), b"both");
    }

    fn read(a: &CompactProArchive, idx: usize) -> Vec<u8> {
        let mut out = Vec::new();
        a.read_entry(idx, &mut out).unwrap();
        out
    }

    #[test]
    fn extracts_rle_only_fork() {
        let content = b"the quick brown fox"; // no 0x81 bytes -> RLE is identity
        let arc = build_archive(
            b"",
            &[Node::File(File {
                name: b"f",
                file_type: *b"TEXT",
                creator: *b"ttxt",
                flags: 0,
                resource: None,
                data: Some(rle_fork(content)),
            })],
        );
        let a = CompactProArchive::open(&arc[..]).unwrap();
        assert_eq!(read(&a, 0), content);
    }

    #[test]
    fn extracts_lzh_fork() {
        let content = b"abcabcabcabc"; // compressible, no 0x81
        let arc = build_archive(
            b"",
            &[Node::File(File {
                name: b"f",
                file_type: *b"TEXT",
                creator: *b"ttxt",
                flags: 4, // data fork uses LZH
                resource: None,
                data: Some(lzh_fork(content)),
            })],
        );
        let a = CompactProArchive::open(&arc[..]).unwrap();
        assert_eq!(read(&a, 0), content);
    }

    #[test]
    fn empty_file_yields_one_empty_data_fork() {
        let arc = build_archive(
            b"",
            &[Node::File(File {
                name: b"empty",
                file_type: *b"TEXT",
                creator: *b"ttxt",
                flags: 0,
                resource: None,
                data: None,
            })],
        );
        let a = CompactProArchive::open(&arc[..]).unwrap();
        assert_eq!(a.entries().len(), 1);
        assert!(!a.entries()[0].is_resource_fork());
        assert_eq!(a.entries()[0].size(), 0);
        assert_eq!(read(&a, 0), b"");
    }

    #[test]
    fn nested_directory_paths() {
        let arc = build_archive(
            b"",
            &[Node::Dir(
                b"dir",
                vec![Node::File(File {
                    name: b"inner",
                    file_type: *b"TEXT",
                    creator: *b"ttxt",
                    flags: 0,
                    resource: None,
                    data: Some(rle_fork(b"hi")),
                })],
            )],
        );
        let a = CompactProArchive::open(&arc[..]).unwrap();
        assert_eq!(a.entries().len(), 2);
        assert!(a.entries()[0].is_directory());
        assert_eq!(a.entries()[0].name(), b"dir");
        assert_eq!(a.entries()[1].name(), b"dir/inner");
        assert_eq!(read(&a, 1), b"hi");
    }

    #[test]
    fn encrypted_fork_is_unsupported() {
        let arc = build_archive(
            b"",
            &[Node::File(File {
                name: b"enc",
                file_type: *b"TEXT",
                creator: *b"ttxt",
                flags: 1, // encryption bit
                resource: None,
                data: Some(rle_fork(b"xxxx")),
            })],
        );
        let a = CompactProArchive::open(&arc[..]).unwrap();
        let mut out = Vec::new();
        let err = a.read_entry(0, &mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn read_entry_out_of_range_errors() {
        let arc = build_archive(
            b"",
            &[Node::File(File {
                name: b"f",
                file_type: *b"TEXT",
                creator: *b"ttxt",
                flags: 0,
                resource: None,
                data: Some(rle_fork(b"x")),
            })],
        );
        let a = CompactProArchive::open(&arc[..]).unwrap();
        let mut out = Vec::new();
        assert!(a.read_entry(9, &mut out).is_err());
    }

    #[test]
    fn single_fork_crc_is_verified() {
        let content = b"crc me";
        let arc = build_archive(
            b"",
            &[Node::File(File {
                name: b"f",
                file_type: *b"TEXT",
                creator: *b"ttxt",
                flags: 0,
                resource: None,
                data: Some(rle_fork(content)),
            })],
        );
        // The builder stored the correct single-fork CRC: reading succeeds.
        let a = CompactProArchive::open(&arc[..]).unwrap();
        assert_eq!(read(&a, 0), content);

        // Corrupt the stored CRC field -> read_entry must fail.
        let mut bad = arc.clone();
        patch_single_data_crc(&mut bad, raw_crc(content) ^ 0xffff_ffff);
        let a2 = CompactProArchive::open(&bad[..]).unwrap();
        let mut out = Vec::new();
        assert!(a2.read_entry(0, &mut out).is_err());
    }

    /// Locate the single file's 45-byte metadata block in `arc` and overwrite
    /// its CRC field, then restamp the catalog CRC. Assumes one flat file.
    fn patch_single_data_crc(arc: &mut [u8], new_crc: u32) {
        let offset = u32::from_be_bytes([arc[4], arc[5], arc[6], arc[7]]) as usize;
        // catalog: [crc u32][numentries u16][commentlen u8][comment..]
        let commentlen = arc[offset + 6] as usize;
        let mut p = offset + 7 + commentlen;
        // node: namelen u8 + name; file (high bit clear)
        let namelen = (arc[p] & 0x7f) as usize;
        p += 1 + namelen;
        // metadata: volume(1)+fileoffs(4)+type(4)+creator(4)+cdate(4)+mdate(4)
        //           +finderflags(2) = 23, then crc(4)
        let crc_at = p + 23;
        arc[crc_at..crc_at + 4].copy_from_slice(&new_crc.to_be_bytes());
        // restamp catalog CRC over metadata after the stored CRC.
        let end = catalog_region_end(arc, offset + 4).unwrap();
        let meta_crc = !crc32_ieee(&arc[offset + 4..end]);
        arc[offset..offset + 4].copy_from_slice(&meta_crc.to_be_bytes());
    }
}
