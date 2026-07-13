// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Amiga LZX archive container.
//!
//! Faithful port of XADMaster's `XADLZXParser.m` container logic. An LZX
//! archive is a 10-byte header followed by a chain of file records; each
//! record's fixed part is 31 bytes (little-endian), followed by a raw name and
//! an optional comment. Files are stored in "solid" groups: records with
//! `compsize == 0` accumulate into the next record that has a nonzero
//! `compsize`, which then owns the single compressed stream all of them share.
//!
//! This module covers the container, metadata (dates with the LZX year-patch
//! quirks, Amiga protection bits), solid grouping, method 0 (store), and
//! method 2 (the LZX codec itself: a Huffman-coded LZSS scheme with a 64 KiB
//! window, cut into blocks — see the "LZX codec" section below).

use std::borrow::Cow;
use std::io::{self, Cursor};

use newtua_common::bitreader::BitReaderLsb;
use newtua_common::crc32::crc32_ieee;
use newtua_common::lzss::LzssWindow;
use newtua_common::prefixcode::PrefixCode;

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn unsupported(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, msg.into())
}

/// A parsed Amiga LZX archive.
pub struct LzxArchive {
    data: Vec<u8>,
    entries: Vec<LzxEntry>,
}

/// The single compressed stream shared by every record in a solid group
/// (`XADLZXParser.m:125-130`).
#[derive(Clone, Copy)]
struct SolidStream {
    /// Offset of the compressed data in the archive, right after the closing
    /// record's name/comment.
    data_offset: usize,
    /// Length of the compressed data on disk.
    comp_size: u32,
    /// Total decompressed length of the whole solid group.
    total_size: u64,
    /// Compression method of the group, taken from the record that closed it.
    /// For members that merely accumulated into the group, this can differ from
    /// their own [`LzxEntry::method`] — decoding always keys off this one.
    method: u8,
}

/// One file record. Fields are the raw header values (`os`, `method`, `flags`,
/// `version`) plus the decoded date and, for Amiga sources, the decoded
/// protection bits.
pub struct LzxEntry {
    pub name: Vec<u8>,
    pub size: u64,
    pub os: u8,
    pub method: u8,
    pub flags: u16,
    pub version: u8,
    pub crc32: u32,
    pub comment: Option<Vec<u8>>,
    pub date: LzxDate,
    pub raw_date: u32,
    pub amiga_protection: Option<u32>,
    /// This file's byte range `[solid_offset, solid_offset + size)` within its
    /// solid group's decompressed stream (`XADSolidOffsetKey`).
    solid_offset: u64,
    /// The shared solid stream this entry's data lives in (several entries in
    /// the same group share identical `SolidStream` values).
    solid: SolidStream,
}

impl LzxEntry {
    /// Name of the archive's declared OS, or `None` if unrecognized
    /// (`XADLZXParser.m:93-101`).
    pub fn os_name(&self) -> Option<&'static str> {
        match self.os {
            0 => Some("MSDOS"),
            1 => Some("Windows"),
            2 => Some("OS/2"),
            10 => Some("Amiga"),
            20 => Some("Unix"),
            _ => None,
        }
    }

    /// Name of the record's own compression method, or `None` if unrecognized
    /// (`XADLZXParser.m:85-90`).
    pub fn method_name(&self) -> Option<&'static str> {
        match self.method {
            0 => Some("None"),
            2 => Some("LZX"),
            _ => None,
        }
    }
}

/// A file record's decoded modification date, with the LZX year-patch quirks
/// already applied (see [`LzxDate::from_raw`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LzxDate {
    pub year: i32,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
}

impl LzxDate {
    /// Unpack the bitfields of a raw LZX date/time word and apply the two
    /// year patches different LZX versions have accumulated
    /// (`XADLZXParser.m:54-67`): the original LZX shifts years `>= 2028` down
    /// by 28, and Dr.Titus's patch shifts years `< 1978` up by 64. Years in
    /// between are already correct.
    fn from_raw(date: u32) -> Self {
        let day = (date >> 27) & 31;
        let month = ((date >> 23) & 15) + 1;
        let mut year = (((date >> 17) & 63) + 1970) as i32;
        let hour = (date >> 12) & 31;
        let minute = (date >> 6) & 63;
        let second = date & 63;

        if year >= 2028 {
            year += 2000 - 2028;
        } else if year < 1978 {
            year += 2034 - 1970;
        }

        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }
    }
}

/// Read a little-endian `u8`/`u16`/`u32` at `*pos`, advancing it, and skip raw
/// bytes. Each is bounds-checked against `data` so a truncated record yields a
/// clean error instead of a panic.
fn rd_u8(data: &[u8], pos: &mut usize) -> io::Result<u8> {
    let b = *data
        .get(*pos)
        .ok_or_else(|| invalid("lzx: truncated record"))?;
    *pos += 1;
    Ok(b)
}

fn rd_u16(data: &[u8], pos: &mut usize) -> io::Result<u16> {
    let s = data
        .get(*pos..*pos + 2)
        .ok_or_else(|| invalid("lzx: truncated record"))?;
    *pos += 2;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn rd_u32(data: &[u8], pos: &mut usize) -> io::Result<u32> {
    let s = data
        .get(*pos..*pos + 4)
        .ok_or_else(|| invalid("lzx: truncated record"))?;
    *pos += 4;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn skip(data: &[u8], pos: &mut usize, n: usize) -> io::Result<()> {
    if *pos + n > data.len() {
        return Err(invalid("lzx: truncated record"));
    }
    *pos += n;
    Ok(())
}

fn rd_bytes(data: &[u8], pos: &mut usize, n: usize) -> io::Result<Vec<u8>> {
    let s = data
        .get(*pos..*pos + n)
        .ok_or_else(|| invalid("lzx: truncated record"))?;
    *pos += n;
    Ok(s.to_vec())
}

/// Amiga protection bits decoded from a record's `attributes` field, only
/// meaningful for `os == 10` (Amiga). The four RWED bits are stored inverted
/// (a clear bit in `attributes` means the permission bit is set); ASHP are
/// stored the right way round (`XADLZXParser.m:104-117`).
fn amiga_protection_bits(attributes: u16) -> u32 {
    let mut prot = 0u32;
    if attributes & 0x01 == 0 {
        prot |= 0x08; // Read
    }
    if attributes & 0x02 == 0 {
        prot |= 0x04; // Write
    }
    if attributes & 0x04 == 0 {
        prot |= 0x01; // Delete
    }
    if attributes & 0x08 == 0 {
        prot |= 0x02; // Execute
    }
    if attributes & 0x10 != 0 {
        prot |= 0x10; // Archive
    }
    if attributes & 0x20 != 0 {
        prot |= 0x80; // Hold
    }
    if attributes & 0x40 != 0 {
        prot |= 0x40; // Script
    }
    if attributes & 0x80 != 0 {
        prot |= 0x20; // Pure
    }
    prot
}

impl LzxArchive {
    /// Structural format check: at least 10 bytes and the `"LZX"` signature.
    pub fn recognize(data: &[u8]) -> bool {
        data.len() >= 10 && &data[0..3] == b"LZX"
    }

    pub fn open(data: &[u8]) -> io::Result<Self> {
        if !Self::recognize(data) {
            return Err(invalid("lzx: not an LZX archive"));
        }
        let entries = parse_entries(data)?;
        Ok(Self {
            data: data.to_vec(),
            entries,
        })
    }

    pub fn entries(&self) -> &[LzxEntry] {
        &self.entries
    }

    /// Decompress one entry's data (method 0/store, or method 2/LZX).
    pub fn read_entry(&self, entry: &LzxEntry) -> io::Result<Vec<u8>> {
        // Materialize the whole decompressed solid stream, then cut this
        // entry's file out of it. Store borrows the on-disk bytes directly;
        // method 2 (LZX) decodes into an owned buffer; the slice + CRC step
        // below is shared across both.
        let stream: Cow<[u8]> = match entry.solid.method {
            0 => {
                // Store carries no compression, so the on-disk span and the
                // decompressed solid stream must be the same length.
                if entry.solid.comp_size as u64 != entry.solid.total_size {
                    return Err(invalid("lzx: store record size mismatch"));
                }
                let end = entry.solid.data_offset + entry.solid.total_size as usize;
                let bytes = self
                    .data
                    .get(entry.solid.data_offset..end)
                    .ok_or_else(|| invalid("lzx: solid stream out of range"))?;
                Cow::Borrowed(bytes)
            }
            2 => {
                let end = entry.solid.data_offset + entry.solid.comp_size as usize;
                let compressed = self
                    .data
                    .get(entry.solid.data_offset..end)
                    .ok_or_else(|| invalid("lzx: solid stream out of range"))?;
                Cow::Owned(lzx_decompress(compressed, entry.solid.total_size as usize)?)
            }
            other => return Err(unsupported(format!("LZX: unsupported method {other}"))),
        };

        let start = entry.solid_offset as usize;
        let slice = stream
            .get(start..start + entry.size as usize)
            .ok_or_else(|| invalid("lzx: entry range out of solid stream"))?;

        if crc32_ieee(slice) != entry.crc32 {
            return Err(invalid("lzx: CRC-32 mismatch"));
        }
        Ok(slice.to_vec())
    }
}

/// Pending record accumulated in the current solid group, before its solid
/// stream is known (assigned once the group closes).
struct PendingEntry {
    name: Vec<u8>,
    size: u64,
    os: u8,
    method: u8,
    flags: u16,
    version: u8,
    crc32: u32,
    comment: Option<Vec<u8>>,
    date: LzxDate,
    raw_date: u32,
    amiga_protection: Option<u32>,
    solid_offset: u64,
}

fn parse_entries(data: &[u8]) -> io::Result<Vec<LzxEntry>> {
    let mut pos = 10; // skipBytes:10 (XADLZXParser.m:24)
    let mut entries = Vec::new();
    let mut solid_files: Vec<PendingEntry> = Vec::new();
    let mut solid_size: u64 = 0;

    // Only this first field's short read is a clean end-of-archive; every
    // other short read below it is a truncated (invalid) record
    // (XADLZXParser.m:32-34: only `attributes` is wrapped in @try/@catch).
    while let Ok(attributes) = rd_u16(data, &mut pos) {
        let filesize = rd_u32(data, &mut pos)?;
        let compsize = rd_u32(data, &mut pos)?;
        let os = rd_u8(data, &mut pos)?;
        let method = rd_u8(data, &mut pos)?;
        let flags = rd_u16(data, &mut pos)?;
        let commentlen = rd_u8(data, &mut pos)?;
        let version = rd_u8(data, &mut pos)?;
        skip(data, &mut pos, 2)?;
        let date = rd_u32(data, &mut pos)?;
        let datacrc = rd_u32(data, &mut pos)?;
        skip(data, &mut pos, 4)?; // headercrc, read and ignored by the parser
        let namelen = rd_u8(data, &mut pos)?;

        let name = rd_bytes(data, &mut pos, namelen as usize)?;
        let comment = if commentlen > 0 {
            Some(rd_bytes(data, &mut pos, commentlen as usize)?)
        } else {
            None
        };

        let dataoffs = pos;

        let amiga_protection = (os == 10).then(|| amiga_protection_bits(attributes));

        let solid_offset = solid_size;
        solid_files.push(PendingEntry {
            name,
            size: filesize as u64,
            os,
            method,
            flags,
            version,
            crc32: datacrc,
            comment,
            date: LzxDate::from_raw(date),
            raw_date: date,
            amiga_protection,
            solid_offset,
        });
        solid_size += filesize as u64;

        if compsize != 0 {
            let solid = SolidStream {
                data_offset: dataoffs,
                comp_size: compsize,
                total_size: solid_size,
                method,
            };
            for pending in solid_files.drain(..) {
                entries.push(LzxEntry {
                    name: pending.name,
                    size: pending.size,
                    os: pending.os,
                    method: pending.method,
                    flags: pending.flags,
                    version: pending.version,
                    crc32: pending.crc32,
                    comment: pending.comment,
                    date: pending.date,
                    raw_date: pending.raw_date,
                    amiga_protection: pending.amiga_protection,
                    solid_offset: pending.solid_offset,
                    solid,
                });
            }
            solid_size = 0;
        }

        pos = dataoffs + compsize as usize;
    }

    Ok(entries)
}

// --- LZX codec (method 2) ---
//
// Faithful port of XADMaster's `XADLZXHandle.m`: an LZSS scheme with a 64 KiB
// window, whose literals and match parameters are Huffman-coded and whose
// stream is cut into blocks. See `task-16b-lzx-codec.md` for the full
// breakdown this port follows.

/// The compressed input is fed to the bit reader as 16-bit words with their
/// two bytes swapped (`XADLZXSwapHandle`, `XADLZXHandle.m:172-189`). A trailing
/// odd byte (only possible on a malformed stream — valid LZX input is an even
/// number of bytes) is left as-is; the decoder simply won't reach it.
fn swap_pairs(input: &[u8]) -> Vec<u8> {
    let mut out = input.to_vec();
    for pair in out.chunks_exact_mut(2) {
        pair.swap(0, 1);
    }
    out
}

/// Number of additional raw bits following a match's offset/length class,
/// indexed by that class (`XADLZXHandle.m:32-36`).
const ADDITIONAL_BITS_TABLE: [u32; 32] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14,
];

/// Base value for a match's offset/length class, before its additional raw
/// bits are added (`XADLZXHandle.m:37-41`).
const BASE_TABLE: [u32; 32] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152,
];

type LzxBits = BitReaderLsb<Cursor<Vec<u8>>>;

/// Read `n` (≤ 32) bits, LSB-first, or a truncated-stream error instead of the
/// primitive's own `None` at end of input.
fn need_bits(bits: &mut LzxBits, n: u8) -> io::Result<u32> {
    bits.read_bits(n)?
        .ok_or_else(|| invalid("lzx: bit stream ended"))
}

/// Decode one symbol from `code`, or a truncated-stream error at end of input.
fn need_symbol(code: &PrefixCode, bits: &mut LzxBits) -> io::Result<i32> {
    code.next_symbol_le(bits)?
        .ok_or_else(|| invalid("lzx: bit stream ended"))
}

/// Decode `count` delta-coded lengths into `lengths[start..start+count]`
/// (`readDeltaLengths`, `XADLZXHandle.m:114-166`). Each delta is taken
/// relative to the *previous* value already in `lengths` at that slot — for
/// the main code this is what makes lengths persist across blocks. `altmode`
/// (`fix`) shifts both the bit width and constant offset of the two run-length
/// escape branches (17/18/19).
fn read_delta_lengths(
    bits: &mut LzxBits,
    lengths: &mut [u32],
    start: usize,
    count: usize,
    altmode: bool,
) -> io::Result<()> {
    let fix: u32 = u32::from(altmode);

    let mut prelengths = [0u32; 20];
    for p in prelengths.iter_mut() {
        *p = need_bits(bits, 4)?;
    }
    let precode = PrefixCode::try_from_lengths(&prelengths, 15, true)?;

    let mut i = 0usize;
    while i < count {
        let val = need_symbol(&precode, bits)?;
        let (n, length): (u32, u32) = match val {
            0..=16 => {
                let old = *lengths
                    .get(start + i)
                    .ok_or_else(|| invalid("lzx: delta length index out of range"))?;
                (1, (old + 17 - val as u32) % 17)
            }
            17 => (need_bits(bits, 4)? + 4 - fix, 0),
            18 => (need_bits(bits, (5 + fix) as u8)? + 20 - fix, 0),
            19 => {
                let n = need_bits(bits, 1)? + 4 - fix;
                let newval = need_symbol(&precode, bits)?;
                let old = *lengths
                    .get(start + i)
                    .ok_or_else(|| invalid("lzx: delta length index out of range"))?;
                (n, (old + 17 - newval as u32) % 17)
            }
            _ => return Err(invalid("lzx: bad pre-code symbol")),
        };

        for j in 0..n as usize {
            let slot = lengths
                .get_mut(start + i + j)
                .ok_or_else(|| invalid("lzx: delta length index out of range"))?;
            *slot = length;
        }
        i += n as usize;
    }
    Ok(())
}

/// State established by one block header: the type, the two Huffman codes it
/// installs, and the output position (in bytes) where the block ends.
struct BlockHeader {
    blocktype: u32,
    /// Only present for block type 3 (`XADLZXHandle.m:96-101`).
    offsetcode: Option<PrefixCode>,
    maincode: PrefixCode,
    blockend: u64,
}

/// Read one block header (`readBlockHeaderAtPosition`, `XADLZXHandle.m:78-112`).
/// `mainlengths` is the decoder's persistent length table: `read_delta_lengths`
/// updates it in place, carrying values across blocks as the format requires.
fn read_block_header(
    bits: &mut LzxBits,
    mainlengths: &mut [u32; 768],
    pos: u64,
) -> io::Result<BlockHeader> {
    let blocktype = need_bits(bits, 3)?;
    if blocktype == 0 || blocktype > 3 {
        return Err(invalid("lzx: illegal LZX block type"));
    }
    if blocktype == 1 {
        return Err(unsupported("lzx: LZX block type 1 unsupported"));
    }

    let offsetcode = if blocktype == 3 {
        let mut codelengths = [0u32; 8];
        for c in codelengths.iter_mut() {
            *c = need_bits(bits, 3)?;
        }
        Some(PrefixCode::try_from_lengths(&codelengths, 7, true)?)
    } else {
        None
    };

    let b0 = need_bits(bits, 8)?;
    let b1 = need_bits(bits, 8)?;
    let b2 = need_bits(bits, 8)?;
    let blocksize = (b0 << 16) | (b1 << 8) | b2;
    let blockend = pos + u64::from(blocksize);

    // Both halves of the 768-entry main code (256 literals + 512 match
    // classes) are delta-coded against whatever `mainlengths` already held —
    // carried over from the previous block, or all-zero at stream start.
    read_delta_lengths(bits, mainlengths, 0, 256, false)?;
    read_delta_lengths(bits, mainlengths, 256, 512, true)?;
    let maincode = PrefixCode::try_from_lengths(mainlengths, 16, true)?;

    Ok(BlockHeader {
        blocktype,
        offsetcode,
        maincode,
        blockend,
    })
}

/// Decompress one LZX (method 2) solid stream to exactly `out_len` bytes
/// (`XADLZXHandle.m:23-76`; the surrounding `XADLZSSHandle` loop that stops at
/// a caller-given length, since LZX carries no end-of-stream symbol).
fn lzx_decompress(input: &[u8], out_len: usize) -> io::Result<Vec<u8>> {
    let mut bits: LzxBits = BitReaderLsb::new(Cursor::new(swap_pairs(input)));
    let mut window = LzssWindow::new(65536);
    let mut out = Vec::with_capacity(out_len);

    // LZX carries no end-of-stream symbol: the caller-supplied `out_len` bounds
    // the loop. With no output wanted, no block header is read at all — matching
    // the reference handle, which is simply never asked to produce a byte.
    if out_len == 0 {
        return Ok(out);
    }

    // `mainlengths` and `lastoffs` are the only state carried across blocks; the
    // current block's header (its Huffman codes, type, and end position) is
    // re-read whenever output reaches `blockend`.
    let mut mainlengths = [0u32; 768];
    let mut lastoffs: i32 = 1;
    let mut header = read_block_header(&mut bits, &mut mainlengths, 0)?;

    while out.len() < out_len {
        let pos = out.len() as u64;
        if pos >= header.blockend {
            header = read_block_header(&mut bits, &mut mainlengths, pos)?;
        }

        let symbol = need_symbol(&header.maincode, &mut bits)?;

        if symbol < 256 {
            window.emit_literal(symbol as u8, &mut out);
            continue;
        }

        let offsclass = (symbol as u32) & 31;
        let offsbits = ADDITIONAL_BITS_TABLE[offsclass as usize];
        let mut offs = BASE_TABLE[offsclass as usize] as i32;

        if offs == 0 {
            offs = lastoffs; // repeat the previous match's distance
        } else if header.blocktype == 3 && offsbits >= 3 {
            offs += (need_bits(&mut bits, (offsbits - 3) as u8)? as i32) << 3;
            let oc = header
                .offsetcode
                .as_ref()
                .ok_or_else(|| invalid("lzx: missing offset code for block type 3"))?;
            offs += need_symbol(oc, &mut bits)?;
        } else {
            offs += need_bits(&mut bits, offsbits as u8)? as i32;
        }
        lastoffs = offs;

        let lenclass = ((symbol as u32 - 256) >> 5) & 15;
        let lenbits = ADDITIONAL_BITS_TABLE[lenclass as usize];
        let len = BASE_TABLE[lenclass as usize] + 3 + need_bits(&mut bits, lenbits as u8)?;

        // The final match of the stream may run past `out_len`; XADMaster's
        // handle is simply never asked for more bytes than that, so clip here
        // instead of over-producing.
        let remaining = out_len - out.len();
        window.emit_match(offs as usize, (len as usize).min(remaining), &mut out);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One record's fields for the mirror encoder below. Every field defaults
    /// to zero / empty, so each test spells out only what it cares about
    /// (`Record { filesize: 4, name: b"a", ..Default::default() }`).
    #[derive(Default)]
    pub(super) struct Record<'a> {
        pub(super) attributes: u16,
        pub(super) filesize: u32,
        pub(super) compsize: u32,
        pub(super) os: u8,
        pub(super) method: u8,
        pub(super) flags: u16,
        pub(super) version: u8,
        pub(super) date: u32,
        pub(super) datacrc: u32,
        pub(super) name: &'a [u8],
        pub(super) comment: Option<&'a [u8]>,
    }

    /// Appends one 31-byte fixed record header plus name/comment (test-only
    /// mirror encoder for the container this module parses).
    pub(super) fn push_record(buf: &mut Vec<u8>, rec: Record) {
        buf.extend_from_slice(&rec.attributes.to_le_bytes());
        buf.extend_from_slice(&rec.filesize.to_le_bytes());
        buf.extend_from_slice(&rec.compsize.to_le_bytes());
        buf.push(rec.os);
        buf.push(rec.method);
        buf.extend_from_slice(&rec.flags.to_le_bytes());
        buf.push(rec.comment.map_or(0, |c| c.len() as u8));
        buf.push(rec.version);
        buf.extend_from_slice(&[0, 0]); // skipped bytes
        buf.extend_from_slice(&rec.date.to_le_bytes());
        buf.extend_from_slice(&rec.datacrc.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // headercrc, ignored by the parser
        buf.push(rec.name.len() as u8);
        buf.extend_from_slice(rec.name);
        if let Some(c) = rec.comment {
            buf.extend_from_slice(c);
        }
    }

    pub(super) fn archive_header() -> Vec<u8> {
        b"LZX".iter().copied().chain([0u8; 7]).collect()
    }

    #[test]
    fn recognizes_lzx_magic() {
        assert!(LzxArchive::open(b"LZX\0\0\0\0\0\0\0").is_ok());
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(LzxArchive::open(b"ZZZ\0\0\0\0\0\0\0").is_err());
    }

    #[test]
    fn rejects_too_short() {
        assert!(LzxArchive::open(b"LZX").is_err());
    }

    #[test]
    fn parses_single_store_record() {
        let payload = b"hello world";
        let crc = crc32_ieee(payload);

        let mut buf = archive_header();
        push_record(
            &mut buf,
            Record {
                attributes: 0xFFFF,
                filesize: payload.len() as u32,
                compsize: payload.len() as u32,
                flags: 0x1234,
                version: 5,
                datacrc: crc,
                name: b"hello.txt",
                ..Default::default()
            },
        );
        buf.extend_from_slice(payload);

        let archive = LzxArchive::open(&buf).unwrap();
        let entries = archive.entries();
        assert_eq!(entries.len(), 1);

        let e = &entries[0];
        assert_eq!(e.name, b"hello.txt");
        assert_eq!(e.size, payload.len() as u64);
        assert_eq!(e.os, 0);
        assert_eq!(e.method, 0);
        assert_eq!(e.flags, 0x1234);
        assert_eq!(e.version, 5);
        assert_eq!(e.crc32, crc);
        assert_eq!(e.comment, None);
        assert_eq!(e.amiga_protection, None);

        assert_eq!(archive.read_entry(e).unwrap(), payload);
    }

    #[test]
    fn os_and_method_names_map_known_codes() {
        let mut buf = archive_header();
        push_record(
            &mut buf,
            Record {
                filesize: 1,
                compsize: 1,
                os: 10,    // Amiga
                method: 2, // LZX
                datacrc: crc32_ieee(b"x"),
                name: b"a",
                ..Default::default()
            },
        );
        buf.extend_from_slice(b"x");

        let archive = LzxArchive::open(&buf).unwrap();
        let e = &archive.entries()[0];
        assert_eq!(e.os_name(), Some("Amiga"));
        assert_eq!(e.method_name(), Some("LZX"));
    }

    #[test]
    fn os_and_method_names_are_none_for_unknown_codes() {
        let mut buf = archive_header();
        push_record(
            &mut buf,
            Record {
                filesize: 1,
                compsize: 1,
                os: 200,   // unrecognized OS
                method: 7, // unrecognized method
                datacrc: crc32_ieee(b"x"),
                name: b"a",
                ..Default::default()
            },
        );
        buf.extend_from_slice(b"x");

        let archive = LzxArchive::open(&buf).unwrap();
        let e = &archive.entries()[0];
        assert_eq!(e.os_name(), None);
        assert_eq!(e.method_name(), None);
    }

    fn pack_date(
        year_field: u32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
    ) -> u32 {
        (day << 27)
            | ((month - 1) << 23)
            | (year_field << 17)
            | (hour << 12)
            | (minute << 6)
            | second
    }

    #[test]
    fn date_decodes_fields() {
        // year_field 20 -> raw year 1990, no patch branch applies.
        let date = pack_date(20, 3, 15, 9, 41, 22);
        let d = LzxDate::from_raw(date);
        assert_eq!(
            d,
            LzxDate {
                year: 1990,
                month: 3,
                day: 15,
                hour: 9,
                minute: 41,
                second: 22
            }
        );
    }

    #[test]
    fn date_applies_high_year_patch() {
        // year_field 60 -> raw year 2030, patched to 2030 + (2000-2028) = 2002.
        let date = pack_date(60, 1, 1, 0, 0, 0);
        assert_eq!(LzxDate::from_raw(date).year, 2002);
    }

    #[test]
    fn date_applies_low_year_patch() {
        // year_field 5 -> raw year 1975, patched to 1975 + (2034-1970) = 2039.
        let date = pack_date(5, 1, 1, 0, 0, 0);
        assert_eq!(LzxDate::from_raw(date).year, 2039);
    }

    #[test]
    fn date_leaves_ordinary_years_untouched() {
        // year_field 30 -> raw year 2000, in the untouched 2000..2027 range.
        let date = pack_date(30, 1, 1, 0, 0, 0);
        assert_eq!(LzxDate::from_raw(date).year, 2000);
    }

    #[test]
    fn amiga_protection_all_clear_grants_rwed() {
        // Every RWED bit clear -> all four permissions granted (inverted sense).
        assert_eq!(amiga_protection_bits(0x00), 0x0F);
    }

    #[test]
    fn amiga_protection_all_set_grants_ashp_only() {
        // RWED bits set -> no permissions; ASHP bits set -> all four flags.
        assert_eq!(amiga_protection_bits(0xFF), 0xF0);
    }

    #[test]
    fn amiga_protection_low_nibble_set_denies_rwed() {
        assert_eq!(amiga_protection_bits(0x0F), 0x00);
    }

    #[test]
    fn amiga_protection_round_trip_all_bits() {
        assert_eq!(amiga_protection_bits(0xF0), 0xFF);
    }

    #[test]
    fn amiga_os_record_gets_protection_bits() {
        let payload = b"amiga file";
        let crc = crc32_ieee(payload);

        let mut buf = archive_header();
        push_record(
            &mut buf,
            // attributes default 0: all RWED bits clear -> full permissions
            Record {
                filesize: payload.len() as u32,
                compsize: payload.len() as u32,
                os: 10, // Amiga
                datacrc: crc,
                name: b"a",
                ..Default::default()
            },
        );
        buf.extend_from_slice(payload);

        let archive = LzxArchive::open(&buf).unwrap();
        assert_eq!(archive.entries()[0].amiga_protection, Some(0x0F));
    }

    #[test]
    fn non_amiga_os_record_has_no_protection_bits() {
        let payload = b"dos file";
        let crc = crc32_ieee(payload);

        let mut buf = archive_header();
        push_record(
            &mut buf,
            // os default 0 = MSDOS: no Amiga protection bits
            Record {
                filesize: payload.len() as u32,
                compsize: payload.len() as u32,
                datacrc: crc,
                name: b"a",
                ..Default::default()
            },
        );
        buf.extend_from_slice(payload);

        let archive = LzxArchive::open(&buf).unwrap();
        assert_eq!(archive.entries()[0].amiga_protection, None);
    }

    #[test]
    fn solid_group_shares_one_stream() {
        let a: &[u8] = b"aaaa";
        let b: &[u8] = b"bbbb";
        let c: &[u8] = b"cccc";
        let solid_data = [a, b, c].concat();

        let mut buf = archive_header();
        // First two records accumulate (compsize == 0): no data bytes of their
        // own follow, they just chain straight into the next header.
        push_record(
            &mut buf,
            Record {
                filesize: 4,
                datacrc: crc32_ieee(a),
                name: b"a",
                ..Default::default()
            },
        );
        push_record(
            &mut buf,
            Record {
                filesize: 4,
                datacrc: crc32_ieee(b),
                name: b"b",
                ..Default::default()
            },
        );
        // The closing record's compsize covers the whole group's solid data.
        push_record(
            &mut buf,
            Record {
                filesize: 4,
                compsize: solid_data.len() as u32,
                datacrc: crc32_ieee(c),
                name: b"c",
                ..Default::default()
            },
        );
        buf.extend_from_slice(&solid_data);

        let archive = LzxArchive::open(&buf).unwrap();
        let entries = archive.entries();
        assert_eq!(entries.len(), 3);

        assert_eq!(entries[0].name, b"a");
        assert_eq!(entries[1].name, b"b");
        assert_eq!(entries[2].name, b"c");

        assert_eq!(archive.read_entry(&entries[0]).unwrap(), a);
        assert_eq!(archive.read_entry(&entries[1]).unwrap(), b);
        assert_eq!(archive.read_entry(&entries[2]).unwrap(), c);
    }

    #[test]
    fn solid_group_followed_by_independent_record() {
        // After a closing record, the *next* record starts a fresh group, even
        // if it also has compsize == 0 pending accumulation of its own.
        let a: &[u8] = b"aa";
        let b: &[u8] = b"bb";

        let mut buf = archive_header();
        push_record(
            &mut buf,
            Record {
                filesize: 2,
                compsize: 2,
                datacrc: crc32_ieee(a),
                name: b"a",
                ..Default::default()
            },
        );
        buf.extend_from_slice(a);
        push_record(
            &mut buf,
            Record {
                filesize: 2,
                compsize: 2,
                datacrc: crc32_ieee(b),
                name: b"b",
                ..Default::default()
            },
        );
        buf.extend_from_slice(b);

        let archive = LzxArchive::open(&buf).unwrap();
        let entries = archive.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(archive.read_entry(&entries[0]).unwrap(), a);
        assert_eq!(archive.read_entry(&entries[1]).unwrap(), b);
    }

    #[test]
    fn empty_archive_has_no_entries() {
        let archive = LzxArchive::open(&archive_header()).unwrap();
        assert!(archive.entries().is_empty());
    }

    #[test]
    fn truncated_mid_header_ends_cleanly_without_entries() {
        // Only one byte of the next record's `attributes` field is present.
        let mut buf = archive_header();
        buf.push(0xAB);
        let archive = LzxArchive::open(&buf).unwrap();
        assert!(archive.entries().is_empty());
    }

    #[test]
    fn truncated_mid_header_after_some_records_ends_that_group() {
        let payload = b"ok";
        let mut buf = archive_header();
        push_record(
            &mut buf,
            Record {
                filesize: 2,
                compsize: 2,
                datacrc: crc32_ieee(payload),
                name: b"ok",
                ..Default::default()
            },
        );
        buf.extend_from_slice(payload);
        buf.push(0xAB); // a lone byte of the next (never completed) record

        let archive = LzxArchive::open(&buf).unwrap();
        assert_eq!(archive.entries().len(), 1);
        assert_eq!(archive.read_entry(&archive.entries()[0]).unwrap(), payload);
    }

    #[test]
    fn namelen_past_end_of_file_is_an_error() {
        let mut buf = archive_header();
        push_record(
            &mut buf,
            Record {
                name: b"toolongname",
                ..Default::default()
            },
        );
        // Truncate right after the fixed part, before the name bytes.
        buf.truncate(buf.len() - "toolongname".len());
        assert!(LzxArchive::open(&buf).is_err());
    }

    #[test]
    fn commentlen_past_end_of_file_is_an_error() {
        let mut buf = archive_header();
        push_record(
            &mut buf,
            Record {
                name: b"a",
                comment: Some(b"a comment"),
                ..Default::default()
            },
        );
        // Truncate right after the name, before the comment bytes.
        buf.truncate(buf.len() - "a comment".len());
        assert!(LzxArchive::open(&buf).is_err());
    }

    #[test]
    fn unknown_method_errors_on_read() {
        let payload = b"data";
        let mut buf = archive_header();
        push_record(
            &mut buf,
            Record {
                filesize: 4,
                compsize: 4,
                method: 99, // unrecognized method
                datacrc: crc32_ieee(payload),
                name: b"a",
                ..Default::default()
            },
        );
        buf.extend_from_slice(payload);

        let archive = LzxArchive::open(&buf).unwrap();
        assert_eq!(archive.entries()[0].method, 99);
        assert!(archive.read_entry(&archive.entries()[0]).is_err());
    }

    #[test]
    fn method_2_garbage_stream_errors_without_panicking() {
        // `b"data"` is not a valid LZX bitstream; decoding it must fail
        // cleanly (a real LZX round trip is exercised in `codec_tests`).
        let mut buf = archive_header();
        push_record(
            &mut buf,
            Record {
                filesize: 4,
                compsize: 4,
                method: 2,
                name: b"a",
                ..Default::default()
            },
        );
        buf.extend_from_slice(b"data");

        let archive = LzxArchive::open(&buf).unwrap();
        assert!(archive.read_entry(&archive.entries()[0]).is_err());
    }

    #[test]
    fn corrupted_crc_is_rejected() {
        let payload = b"hello";
        let mut buf = archive_header();
        push_record(
            &mut buf,
            Record {
                filesize: payload.len() as u32,
                compsize: payload.len() as u32,
                datacrc: crc32_ieee(payload) ^ 1, // corrupt the stored CRC
                name: b"a",
                ..Default::default()
            },
        );
        buf.extend_from_slice(payload);

        let archive = LzxArchive::open(&buf).unwrap();
        assert!(archive.read_entry(&archive.entries()[0]).is_err());
    }

    #[test]
    fn swap_pairs_exchanges_each_16_bit_word() {
        assert_eq!(
            swap_pairs(&[0x01, 0x02, 0x03, 0x04]),
            vec![0x02, 0x01, 0x04, 0x03]
        );
    }

    #[test]
    fn swap_pairs_leaves_a_trailing_odd_byte() {
        assert_eq!(swap_pairs(&[0x01, 0x02, 0x03]), vec![0x02, 0x01, 0x03]);
    }
}

/// Tests for the LZX codec itself (method 2): block headers, delta-length
/// decoding, the main decode loop, and a mirror encoder used as the oracle
/// (there is no system LZX compressor to synthesize fixtures with).
#[cfg(test)]
mod codec_tests {
    use super::tests::{archive_header, push_record, Record};
    use super::*;
    use newtua_testutil::BitWriter;
    use std::io::Cursor;

    fn reader(bytes: &[u8]) -> LzxBits {
        BitReaderLsb::new(Cursor::new(bytes.to_vec()))
    }

    #[test]
    fn read_delta_lengths_applies_simple_value_deltas() {
        // A precode where symbol 14 has the single 1-bit codeword `0`: every
        // stream bit "0" decodes to val=14, giving delta length
        // (0 + 17 - 14) % 17 = 3 for each of the 4 target lengths (mainlengths
        // start all zero, as on the first block of a stream).
        let mut w = BitWriter::default();
        for i in 0..20u32 {
            w.bits(if i == 14 { 1 } else { 0 }, 4);
        }
        for _ in 0..4 {
            w.bits(0, 1); // codeword "0" -> pre-code symbol 14
        }
        let bytes = w.finish();

        let mut bits = reader(&bytes);
        let mut lengths = [0u32; 768];
        read_delta_lengths(&mut bits, &mut lengths, 0, 4, false).unwrap();
        assert_eq!(&lengths[0..4], &[3, 3, 3, 3]);
        assert_eq!(&lengths[4..8], &[0, 0, 0, 0]); // untouched
    }

    #[test]
    fn read_delta_lengths_deltas_are_relative_to_the_previous_block() {
        // Same precode as above (bit "0" -> pre-code val 14, delta -3 mod 17).
        // Starting from a nonzero previous length shows the delta is applied
        // relative to it, not to an absolute value.
        let mut w = BitWriter::default();
        for i in 0..20u32 {
            w.bits(if i == 14 { 1 } else { 0 }, 4);
        }
        w.bits(0, 1);
        let bytes = w.finish();

        let mut bits = reader(&bytes);
        let mut lengths = [0u32; 768];
        lengths[0] = 5; // carried over from a previous block
        read_delta_lengths(&mut bits, &mut lengths, 0, 1, false).unwrap();
        // (5 + 17 - 14) % 17 = 8
        assert_eq!(lengths[0], 8);
    }

    #[test]
    fn read_delta_lengths_truncated_stream_errors() {
        // Only the 20 pre-lengths, no symbols to actually fill `count` values.
        let mut w = BitWriter::default();
        for _ in 0..20u32 {
            w.bits(0, 4); // every pre-length 0 -> empty precode (no leaves)
        }
        let bytes = w.finish();

        let mut bits = reader(&bytes);
        let mut lengths = [0u32; 768];
        assert!(read_delta_lengths(&mut bits, &mut lengths, 0, 4, false).is_err());
    }

    // --- Mirror encoder: the oracle for the codec above ---
    //
    // There is no system LZX compressor, so fixtures are synthesized by
    // inverting the decoder: canonical code assignment mirrors
    // `PrefixCode::from_lengths`, and the offset/length class lookup mirrors
    // `BASE_TABLE`/`ADDITIONAL_BITS_TABLE`. Round-tripping through our own
    // `lzx_decompress` (and, in the oracle test, through `unar`) is the proof.

    /// Canonical (code, length) per symbol index, mirroring
    /// `PrefixCode::from_lengths(..., shortest_code_is_zeros = true)`. A
    /// length of 0 (absent) gets `(0, 0)`, never encoded.
    fn canonical_codes(lengths: &[u32], max_length: u32) -> Vec<(u32, u32)> {
        let mut codes = vec![(0u32, 0u32); lengths.len()];
        let mut code = 0u32;
        for length in 1..=max_length {
            for (i, &len) in lengths.iter().enumerate() {
                if len == length {
                    codes[i] = (code, length);
                    code += 1;
                }
            }
            code <<= 1;
        }
        codes
    }

    /// Write one symbol's canonical code, most-significant-bit first — the
    /// order that lands correctly in a tree `next_symbol_le` will walk
    /// top-down bit-by-bit.
    fn encode_symbol(w: &mut BitWriter, codes: &[(u32, u32)], symbol: usize) {
        let (code, length) = codes[symbol];
        for bitpos in (0..length).rev() {
            w.bits((code >> bitpos) & 1, 1);
        }
    }

    /// The smallest uniform code length that fits `n` distinct symbols
    /// (`n = 0` is treated as 1, so a code is always well-formed).
    fn uniform_length_for(n: usize) -> u32 {
        let mut length = 1u32;
        while (1usize << length) < n.max(1) {
            length += 1;
        }
        length
    }

    /// The offset/length class whose range contains `value` (the inverse of
    /// `BASE_TABLE`/`ADDITIONAL_BITS_TABLE`: the table is contiguous and
    /// increasing, so the highest class whose base does not exceed `value` is
    /// the right one).
    fn class_for(value: u32) -> usize {
        let mut class = 0;
        for (c, &base) in BASE_TABLE.iter().enumerate() {
            if base <= value {
                class = c;
            } else {
                break;
            }
        }
        class
    }

    fn match_symbol(offsclass: usize, lenclass: usize) -> usize {
        256 + (lenclass << 5) + offsclass
    }

    /// One decoded unit the mirror encoder writes: a literal byte, or a match
    /// (`repeat = true` reuses the decoder's `lastoffs`, so `distance` is
    /// unused — and must equal whatever the previous non-repeat match's
    /// distance was, or the round-trip won't reproduce the intended text).
    enum Op {
        Literal(u8),
        Match {
            repeat: bool,
            distance: u32,
            length: u32,
        },
    }

    fn op_main_symbol(op: &Op) -> usize {
        match op {
            Op::Literal(b) => *b as usize,
            Op::Match {
                repeat,
                distance,
                length,
            } => {
                let offsclass = if *repeat { 0 } else { class_for(*distance) };
                let lenclass = class_for(*length - 3);
                match_symbol(offsclass, lenclass)
            }
        }
    }

    /// Builds a method-2 LZX solid stream one block at a time, mirroring
    /// `XADLZXHandle.m`'s block/stream layout exactly (see the header comment
    /// on the codec above).
    struct LzxTestEncoder {
        w: BitWriter,
        /// Persistent main-code lengths, carried across blocks exactly as the
        /// decoder's `mainlengths` is.
        mainlengths: [u32; 768],
    }

    impl LzxTestEncoder {
        fn new() -> Self {
            Self {
                w: BitWriter::default(),
                mainlengths: [0u32; 768],
            }
        }

        /// Delta-encode `target[start..start+count]` against `mainlengths`
        /// (inverse of `read_delta_lengths`), using only the plain
        /// value-delta branch (`val <= 16`) — the run-length escapes are a
        /// pure size optimization the encoder doesn't need. The pre-code
        /// itself is a fixed flat 5-bit code over all 20 pre-symbols, wide
        /// enough for any delta value (0..=16).
        fn encode_delta_lengths(&mut self, target: &[u32; 768], start: usize, count: usize) {
            let prelengths = [5u32; 20];
            for &p in &prelengths {
                self.w.bits(p, 4);
            }
            let precode = canonical_codes(&prelengths, 15);

            for i in 0..count {
                let old = self.mainlengths[start + i];
                let want = target[start + i];
                let val = (old + 17 - want) % 17;
                encode_symbol(&mut self.w, &precode, val as usize);
            }
        }

        /// Write one block: header, main-code lengths (delta-coded against
        /// the running state), and the symbol stream. `offsetcode_lengths` is
        /// `Some` only for block type 3.
        fn write_block(
            &mut self,
            blocktype: u32,
            offsetcode_lengths: Option<[u32; 8]>,
            ops: &[Op],
            block_output_len: u32,
        ) {
            self.w.bits(blocktype, 3);

            let offsetcode_codes = offsetcode_lengths.map(|lens| {
                for l in lens {
                    self.w.bits(l, 3);
                }
                canonical_codes(&lens, 7)
            });

            self.w.bits((block_output_len >> 16) & 0xFF, 8);
            self.w.bits((block_output_len >> 8) & 0xFF, 8);
            self.w.bits(block_output_len & 0xFF, 8);

            let mut used: Vec<usize> = ops.iter().map(op_main_symbol).collect();
            used.sort_unstable();
            used.dedup();
            let length = uniform_length_for(used.len());
            let mut target = [0u32; 768];
            for &s in &used {
                target[s] = length;
            }

            self.encode_delta_lengths(&target, 0, 256);
            self.encode_delta_lengths(&target, 256, 512);
            self.mainlengths = target;

            let codes = canonical_codes(&target, 16);
            for op in ops {
                match op {
                    Op::Literal(b) => encode_symbol(&mut self.w, &codes, *b as usize),
                    Op::Match {
                        repeat,
                        distance,
                        length,
                    } => {
                        let offsclass = if *repeat { 0 } else { class_for(*distance) };
                        let lenclass = class_for(*length - 3);
                        encode_symbol(&mut self.w, &codes, match_symbol(offsclass, lenclass));

                        if !*repeat {
                            let bits = ADDITIONAL_BITS_TABLE[offsclass];
                            let extra = *distance - BASE_TABLE[offsclass];
                            if blocktype == 3 && bits >= 3 {
                                self.w.bits(extra >> 3, bits - 3);
                                let oc = offsetcode_codes
                                    .as_ref()
                                    .expect("block type 3 carries an offset code");
                                encode_symbol(&mut self.w, oc, (extra & 7) as usize);
                            } else {
                                self.w.bits(extra, bits);
                            }
                        }

                        let lenbits = ADDITIONAL_BITS_TABLE[lenclass];
                        self.w.bits(*length - 3 - BASE_TABLE[lenclass], lenbits);
                    }
                }
            }
        }

        /// Flush to bytes and apply the same byte-pair swap the decoder
        /// undoes, padding to an even length first (real LZX streams are
        /// whole 16-bit words).
        fn finish(self) -> Vec<u8> {
            let mut bytes = self.w.finish();
            if bytes.len() % 2 != 0 {
                bytes.push(0);
            }
            swap_pairs(&bytes)
        }
    }

    #[test]
    fn literal_only_round_trips() {
        let data = b"Hello, LZX!";
        let mut enc = LzxTestEncoder::new();
        let ops: Vec<Op> = data.iter().map(|&b| Op::Literal(b)).collect();
        enc.write_block(2, None, &ops, data.len() as u32);
        let compressed = enc.finish();

        assert_eq!(lzx_decompress(&compressed, data.len()).unwrap(), data);
    }

    #[test]
    fn literal_then_match_round_trips() {
        // "abc" + a distance-3 length-3 match -> "abcabc". offsclass 3 (base 3,
        // 0 extra bits) and lenclass 0 (base 0, 0 extra bits): both classes
        // consume no additional bits, the simplest nontrivial match.
        let ops = vec![
            Op::Literal(b'a'),
            Op::Literal(b'b'),
            Op::Literal(b'c'),
            Op::Match {
                repeat: false,
                distance: 3,
                length: 3,
            },
        ];
        let mut enc = LzxTestEncoder::new();
        enc.write_block(2, None, &ops, 6);
        let compressed = enc.finish();

        assert_eq!(lzx_decompress(&compressed, 6).unwrap(), b"abcabc");
    }

    #[test]
    fn repeat_offset_class_reuses_lastoffs() {
        // "abc" + a distance-3 match + a *repeat* match (offsclass 0), both
        // length 3 -> "abcabcabc". The repeat op carries no distance of its
        // own; the decoder must reuse the previous match's distance (3).
        let ops = vec![
            Op::Literal(b'a'),
            Op::Literal(b'b'),
            Op::Literal(b'c'),
            Op::Match {
                repeat: false,
                distance: 3,
                length: 3,
            },
            Op::Match {
                repeat: true,
                distance: 0,
                length: 3,
            },
        ];
        let mut enc = LzxTestEncoder::new();
        enc.write_block(2, None, &ops, 9);
        let compressed = enc.finish();

        assert_eq!(lzx_decompress(&compressed, 9).unwrap(), b"abcabcabc");
    }

    #[test]
    fn block_type_3_offset_code_round_trips() {
        // 21 distinct literals, then a distance-21 length-5 match. Distance 21
        // falls in offsclass 8 (base 16, 3 extra bits) — the `offsbits >= 3`
        // case that only decodes correctly when block type 3 is in play and
        // an offset code is present to supply the low 3 bits.
        let prefix = b"0123456789ABCDEFGHIJK"; // 21 bytes
        assert_eq!(prefix.len(), 21);

        let mut ops: Vec<Op> = prefix.iter().map(|&b| Op::Literal(b)).collect();
        ops.push(Op::Match {
            repeat: false,
            distance: 21,
            length: 5,
        });

        let offsetcode_lengths = [3u32; 8]; // uniform length-3 code over all 8 symbols
        let mut enc = LzxTestEncoder::new();
        enc.write_block(3, Some(offsetcode_lengths), &ops, 26);
        let compressed = enc.finish();

        let mut expected = prefix.to_vec();
        expected.extend_from_slice(&prefix[0..5]);
        assert_eq!(lzx_decompress(&compressed, 26).unwrap(), expected);
    }

    #[test]
    fn mainlengths_carry_across_blocks() {
        // Block 1 uses only symbol 'A'; block 2 uses only symbol 'B'. Since
        // `mainlengths` persists, block 2's delta-lengths must both retire
        // 'A' (length -> 0) and introduce 'B' (length -> 1) relative to
        // exactly what block 1 left behind — a bug in the carry-over would
        // desync the decoder and corrupt (or error out) the second block.
        let mut enc = LzxTestEncoder::new();
        let a_ops: Vec<Op> = (0..5).map(|_| Op::Literal(b'A')).collect();
        let b_ops: Vec<Op> = (0..5).map(|_| Op::Literal(b'B')).collect();
        enc.write_block(2, None, &a_ops, 5);
        enc.write_block(2, None, &b_ops, 5);
        let compressed = enc.finish();

        assert_eq!(lzx_decompress(&compressed, 10).unwrap(), b"AAAAABBBBB");
    }

    #[test]
    fn output_past_64kib_window_wraps_correctly() {
        // A 100-byte literal prefix, then enough distance-100 matches to
        // repeat that cycle past the 64 KiB window size — proving the window
        // wraparound (already unit-tested in `lzss.rs` in isolation) holds up
        // end to end through the block/Huffman decode loop.
        let prefix: Vec<u8> = (0..100u32).map(|i| i as u8).collect();
        let match_len = 150u32;
        let match_count = 466; // 100 + 466*150 = 70_000
        let total = prefix.len() as u32 + match_count * match_len;

        let mut ops: Vec<Op> = prefix.iter().map(|&b| Op::Literal(b)).collect();
        for _ in 0..match_count {
            ops.push(Op::Match {
                repeat: false,
                distance: 100,
                length: match_len,
            });
        }

        let mut enc = LzxTestEncoder::new();
        enc.write_block(2, None, &ops, total);
        let compressed = enc.finish();

        let expected: Vec<u8> = prefix
            .iter()
            .copied()
            .cycle()
            .take(total as usize)
            .collect();
        assert_eq!(
            lzx_decompress(&compressed, total as usize).unwrap(),
            expected
        );
    }

    #[test]
    fn clips_the_final_match_to_out_len() {
        // A distance-3 length-6 match after "abc" would naturally produce
        // "abcabcabc" (9 bytes), but the block declares (and the container
        // asks for) only 7 — the last match must stop 2 bytes early rather
        // than over-produce.
        let ops = vec![
            Op::Literal(b'a'),
            Op::Literal(b'b'),
            Op::Literal(b'c'),
            Op::Match {
                repeat: false,
                distance: 3,
                length: 6,
            },
        ];
        let mut enc = LzxTestEncoder::new();
        enc.write_block(2, None, &ops, 7);
        let compressed = enc.finish();

        assert_eq!(lzx_decompress(&compressed, 7).unwrap(), b"abcabca");
    }

    #[test]
    fn block_type_0_is_illegal() {
        let mut w = BitWriter::default();
        w.bits(0, 3); // blocktype 0
        assert!(lzx_decompress(&w.finish(), 1).is_err());
    }

    #[test]
    fn block_type_1_is_unsupported() {
        let mut w = BitWriter::default();
        w.bits(1, 3); // blocktype 1
        assert!(lzx_decompress(&w.finish(), 1).is_err());
    }

    #[test]
    fn block_type_above_3_is_illegal() {
        let mut w = BitWriter::default();
        w.bits(4, 3); // blocktype 4: out of range
        assert!(lzx_decompress(&w.finish(), 1).is_err());
    }

    #[test]
    fn truncated_stream_errors_without_panicking() {
        // A block type and nothing else: every subsequent read runs dry.
        let mut w = BitWriter::default();
        w.bits(2, 3);
        assert!(lzx_decompress(&w.finish(), 100).is_err());
    }

    #[test]
    fn empty_input_errors_without_panicking() {
        assert!(lzx_decompress(&[], 10).is_err());
    }

    #[test]
    fn method_2_entry_decodes_through_read_entry() {
        let payload = b"Hello, LZX container!";
        let mut enc = LzxTestEncoder::new();
        let ops: Vec<Op> = payload.iter().map(|&b| Op::Literal(b)).collect();
        enc.write_block(2, None, &ops, payload.len() as u32);
        let compressed = enc.finish();

        let mut buf = archive_header();
        push_record(
            &mut buf,
            Record {
                filesize: payload.len() as u32,
                compsize: compressed.len() as u32,
                method: 2,
                datacrc: crc32_ieee(payload),
                name: b"a",
                ..Default::default()
            },
        );
        buf.extend_from_slice(&compressed);

        let archive = LzxArchive::open(&buf).unwrap();
        let entries = archive.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(archive.read_entry(&entries[0]).unwrap(), payload);
    }

    #[test]
    fn method_2_solid_group_decodes_each_member() {
        let a: &[u8] = b"AAAA file one";
        let b: &[u8] = b"BBBB file two, a bit longer";

        let mut ops: Vec<Op> = a.iter().map(|&byte| Op::Literal(byte)).collect();
        ops.extend(b.iter().map(|&byte| Op::Literal(byte)));
        let total = (a.len() + b.len()) as u32;

        let mut enc = LzxTestEncoder::new();
        enc.write_block(2, None, &ops, total);
        let compressed = enc.finish();

        let mut buf = archive_header();
        push_record(
            &mut buf,
            Record {
                filesize: a.len() as u32,
                datacrc: crc32_ieee(a),
                name: b"a",
                ..Default::default()
            },
        );
        push_record(
            &mut buf,
            Record {
                filesize: b.len() as u32,
                compsize: compressed.len() as u32,
                method: 2,
                datacrc: crc32_ieee(b),
                name: b"b",
                ..Default::default()
            },
        );
        buf.extend_from_slice(&compressed);

        let archive = LzxArchive::open(&buf).unwrap();
        let entries = archive.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(archive.read_entry(&entries[0]).unwrap(), a);
        assert_eq!(archive.read_entry(&entries[1]).unwrap(), b);
    }

    #[test]
    fn method_2_corrupted_crc_is_rejected() {
        let payload = b"data";
        let mut enc = LzxTestEncoder::new();
        let ops: Vec<Op> = payload.iter().map(|&b| Op::Literal(b)).collect();
        enc.write_block(2, None, &ops, payload.len() as u32);
        let compressed = enc.finish();

        let mut buf = archive_header();
        push_record(
            &mut buf,
            Record {
                filesize: payload.len() as u32,
                compsize: compressed.len() as u32,
                method: 2,
                datacrc: crc32_ieee(payload) ^ 1, // corrupt
                name: b"a",
                ..Default::default()
            },
        );
        buf.extend_from_slice(&compressed);

        let archive = LzxArchive::open(&buf).unwrap();
        assert!(archive.read_entry(&archive.entries()[0]).is_err());
    }
}
