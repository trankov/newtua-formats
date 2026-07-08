//! ALZip (`.alz`) — a flat multi-file container from the Korean ALZip tool.
//!
//! After an 8-byte file header (`A L Z 0x01 … 0x00`) comes a stream of records.
//! A local record starts with `B L Z 0x01`; the central-directory (`C L Z 0x01`)
//! and comment (`E L Z 0x01`) signatures mark the end of the member stream.
//!
//! Each local record carries a name length, MS-DOS attributes (`0x10` =
//! directory), an MS-DOS timestamp, and flags. The flags' low bit means
//! "encrypted"; the high nibble (`flags >> 4`) is the *byte width* used for the
//! compressed/uncompressed sizes (1/2/4/8). When that width is non-zero a size
//! block follows: method byte, a skipped byte, the IEEE CRC-32 of the
//! decompressed data, then the compressed and uncompressed sizes.
//!
//! Supported compression methods: 0 stored, 1 bzip2, 2 raw deflate, and 3
//! obfuscated deflate (the same deflate stream, but with the code-length
//! meta-table read in a size-derived order). Encrypted members and multi-volume
//! sets are reported as [`io::ErrorKind::Unsupported`].

#![forbid(unsafe_code)]

use std::io::{self, Read, Write};

use bzip2_rs::DecoderReader as Bzip2Reader;
use newtua_common::crc32::crc32_ieee;
use newtua_common::deflate;

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn unsupported(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, msg.into())
}

/// The deflate meta-table order for method 3, derived from `param` (the
/// uncompressed size modulo 16). A faithful port of `CalculateSillyTable`
/// (`XADALZipParser.m`), including its quirks: the swap index wraps modulo 18
/// (not 19), and a swap onto the same slot is skipped.
fn silly_meta_order(param: usize) -> [u8; 19] {
    let mut table = [0u8; 19];
    for (i, v) in table.iter_mut().enumerate() {
        *v = i as u8;
    }
    for i in 0..19 {
        let mut swapindex = (i % 6) * 3 + param;
        if swapindex > 18 {
            swapindex %= 18;
        }
        if swapindex != i {
            table.swap(i, swapindex);
        }
    }
    table
}

/// One member of an ALZip archive.
pub struct AlzEntry {
    name: Vec<u8>,
    is_dir: bool,
    is_encrypted: bool,
    method: u8,
    crc32: u32,
    size: u64,
    data_offset: usize,
    compsize: usize,
}

impl AlzEntry {
    /// Raw name bytes (path separators preserved); charset decoding is the
    /// caller's job.
    pub fn name(&self) -> &[u8] {
        &self.name
    }
    /// Whether this entry is a directory (MS-DOS attribute `0x10`, no data).
    pub fn is_dir(&self) -> bool {
        self.is_dir
    }
    /// Whether this entry's data is encrypted (not supported for extraction).
    pub fn is_encrypted(&self) -> bool {
        self.is_encrypted
    }
    /// The ALZip compression method (0 stored, 1 bzip2, 2 deflate, 3 obfuscated).
    pub fn method(&self) -> u8 {
        self.method
    }
    /// Uncompressed size in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }
}

/// A parsed ALZip archive.
pub struct AlzArchive {
    data: Vec<u8>,
    entries: Vec<AlzEntry>,
}

impl AlzArchive {
    /// Whether `data` starts with a valid ALZip file header.
    pub fn recognize(data: &[u8]) -> bool {
        data.len() >= 8 && &data[0..4] == b"ALZ\x01" && data[7] == 0
    }

    /// Read the whole archive from `r` and parse every member record.
    pub fn open<R: Read>(mut r: R) -> io::Result<Self> {
        let mut data = Vec::new();
        r.read_to_end(&mut data)?;
        if !Self::recognize(&data) {
            return Err(invalid("alz: not an ALZip archive"));
        }
        let entries = parse(&data)?;
        Ok(Self { data, entries })
    }

    /// The members, in archive order.
    pub fn entries(&self) -> &[AlzEntry] {
        &self.entries
    }

    /// Decode member `idx` and write it to `out`, verifying its CRC-32.
    ///
    /// Stored (0), bzip2 (1), and raw deflate (2) members are decoded. Obfuscated
    /// deflate (3), encrypted members, and data that runs past the end of a
    /// single volume surface as errors.
    pub fn read_entry(&self, idx: usize, out: &mut dyn Write) -> io::Result<()> {
        let e = self
            .entries
            .get(idx)
            .ok_or_else(|| invalid("alz: index out of range"))?;
        if e.is_dir {
            return Err(invalid("alz: entry is a directory"));
        }
        if e.is_encrypted {
            return Err(unsupported("alz: encrypted members are not supported"));
        }

        let comp = &self.data[e.data_offset..e.data_offset + e.compsize];
        let size = usize::try_from(e.size).map_err(|_| invalid("alz: size too large"))?;

        let decoded = match e.method {
            0 => comp.to_vec(),
            1 => read_n(Bzip2Reader::new(comp), size)?,
            // Method 2 is plain deflate; method 3 is the same stream with a
            // size-obfuscated meta-table order (`CalculateSillyTable`).
            2 => deflate::inflate(comp, size, &deflate::ZIP_ORDER)?,
            3 => deflate::inflate(comp, size, &silly_meta_order(size % 16))?,
            other => return Err(unsupported(format!("alz: unsupported method {other}"))),
        };

        if crc32_ieee(&decoded) != e.crc32 {
            return Err(invalid("alz: CRC-32 mismatch"));
        }
        out.write_all(&decoded)
    }
}

/// Read exactly `n` bytes from `r` (the known uncompressed size).
fn read_n(mut r: impl Read, n: usize) -> io::Result<Vec<u8>> {
    let mut out = vec![0u8; n];
    r.read_exact(&mut out)?;
    Ok(out)
}

fn rd_u8(d: &[u8], p: &mut usize) -> io::Result<u8> {
    let b = *d.get(*p).ok_or_else(|| invalid("alz: truncated record"))?;
    *p += 1;
    Ok(b)
}

fn rd_u16(d: &[u8], p: &mut usize) -> io::Result<u16> {
    let b = d
        .get(*p..*p + 2)
        .ok_or_else(|| invalid("alz: truncated record"))?;
    *p += 2;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn rd_u32(d: &[u8], p: &mut usize) -> io::Result<u32> {
    let b = d
        .get(*p..*p + 4)
        .ok_or_else(|| invalid("alz: truncated record"))?;
    *p += 4;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a 1/2/4/8-byte little-endian number, selected by `sizebytes`.
fn parse_number(d: &[u8], p: &mut usize, sizebytes: u8) -> io::Result<u64> {
    let n = match sizebytes {
        1 | 2 | 4 | 8 => sizebytes as usize,
        _ => return Err(invalid("alz: illegal size width")),
    };
    let b = d
        .get(*p..*p + n)
        .ok_or_else(|| invalid("alz: truncated size field"))?;
    *p += n;
    let mut v = 0u64;
    for (i, &byte) in b.iter().enumerate() {
        v |= u64::from(byte) << (8 * i);
    }
    Ok(v)
}

fn parse(data: &[u8]) -> io::Result<Vec<AlzEntry>> {
    let mut entries = Vec::new();
    let mut pos = 8; // past the file header (validated by `recognize`)

    loop {
        let sig = match data.get(pos..pos + 4) {
            Some(s) => s,
            // A clean end-of-data is fine; anything shorter than a signature is
            // a truncated record.
            None if pos == data.len() => break,
            None => return Err(invalid("alz: truncated record signature")),
        };
        pos += 4;

        match sig {
            b"BLZ\x01" => {}
            // Central directory / comment block: the member stream is over.
            b"CLZ\x01" | b"ELZ\x01" => break,
            _ => return Err(invalid("alz: unknown record signature")),
        }

        let namelen = rd_u16(data, &mut pos)? as usize;
        let attrs = rd_u8(data, &mut pos)?;
        let _dostime = rd_u32(data, &mut pos)?;
        let flags = rd_u8(data, &mut pos)?;
        let _ = rd_u8(data, &mut pos)?; // one skipped byte

        let is_dir = attrs & 0x10 != 0;
        let is_encrypted = flags & 0x01 != 0;
        let sizebytes = flags >> 4;

        let (method, crc32, compsize, size) = if sizebytes != 0 {
            let method = rd_u8(data, &mut pos)?;
            let _ = rd_u8(data, &mut pos)?; // one skipped byte
            let crc32 = rd_u32(data, &mut pos)?;
            let compsize = parse_number(data, &mut pos, sizebytes)?;
            let size = parse_number(data, &mut pos, sizebytes)?;
            (method, crc32, compsize, size)
        } else {
            // No size block (typically a directory): no method and no data.
            (0, 0, 0, 0)
        };

        let name = data
            .get(pos..pos + namelen)
            .ok_or_else(|| invalid("alz: truncated name"))?
            .to_vec();
        pos += namelen;

        let data_offset = pos;
        let compsize =
            usize::try_from(compsize).map_err(|_| invalid("alz: compressed size too large"))?;
        let end = data_offset
            .checked_add(compsize)
            .filter(|&e| e <= data.len())
            .ok_or_else(|| invalid("alz: member data past end of file"))?;

        entries.push(AlzEntry {
            name,
            is_dir,
            is_encrypted,
            method,
            crc32,
            size,
            data_offset,
            compsize,
        });
        pos = end;
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: [u8; 8] = [b'A', b'L', b'Z', 0x01, 0, 0, 0, 0];

    fn push_number(out: &mut Vec<u8>, value: u64, sizebytes: u8) {
        out.extend_from_slice(&value.to_le_bytes()[..sizebytes as usize]);
    }

    /// Build an unencrypted local file record with an explicit size width.
    fn file_record(
        name: &[u8],
        method: u8,
        crc: u32,
        comp: &[u8],
        size: u64,
        sizebytes: u8,
    ) -> Vec<u8> {
        // flags: size width in the high nibble, encryption bit clear.
        record_with_flags(name, sizebytes << 4, method, crc, comp, size)
    }

    /// Build a directory record (attrs `0x10`, no size block, no data).
    fn dir_record(name: &[u8]) -> Vec<u8> {
        let mut r = vec![b'B', b'L', b'Z', 0x01];
        r.extend_from_slice(&(name.len() as u16).to_le_bytes());
        r.push(0x10); // attrs: directory
        r.extend_from_slice(&0u32.to_le_bytes()); // dostime
        r.push(0x00); // flags: sizebytes == 0
        r.push(0x00); // skipped byte
        r.extend_from_slice(name);
        r
    }

    fn archive(records: &[Vec<u8>]) -> Vec<u8> {
        let mut a = HEADER.to_vec();
        for rec in records {
            a.extend_from_slice(rec);
        }
        a.extend_from_slice(b"CLZ\x01"); // central directory ends the member stream
        a
    }

    #[test]
    fn recognizes_valid_header() {
        assert!(AlzArchive::recognize(&HEADER));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bad = HEADER;
        bad[1] = b'X';
        assert!(!AlzArchive::recognize(&bad));
        // byte[7] must be zero, too.
        let mut bad7 = HEADER;
        bad7[7] = 1;
        assert!(!AlzArchive::recognize(&bad7));
        assert!(AlzArchive::open(&bad[..]).is_err());
    }

    #[test]
    fn parses_two_members_and_fields() {
        let a = archive(&[
            file_record(b"a.txt", 0, 0x1234, b"A", 1, 4),
            file_record(b"sub/b.bin", 2, 0xDEAD_BEEF, b"\x01\x02\x03", 9, 4),
        ]);
        let arc = AlzArchive::open(&a[..]).unwrap();
        let e = arc.entries();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].name(), b"a.txt");
        assert_eq!(e[0].method(), 0);
        assert_eq!(e[0].size(), 1);
        assert!(!e[0].is_dir());
        assert_eq!(e[1].name(), b"sub/b.bin");
        assert_eq!(e[1].method(), 2);
        assert_eq!(e[1].size(), 9);
    }

    #[test]
    fn parses_directory_entry() {
        let a = archive(&[dir_record(b"folder"), file_record(b"f", 0, 0, b"x", 1, 4)]);
        let arc = AlzArchive::open(&a[..]).unwrap();
        let e = arc.entries();
        assert_eq!(e.len(), 2);
        assert!(e[0].is_dir());
        assert_eq!(e[0].name(), b"folder");
        assert_eq!(e[0].size(), 0);
        assert!(!e[1].is_dir());
    }

    #[test]
    fn handles_size_widths_1_2_4() {
        for sizebytes in [1u8, 2, 4] {
            let a = archive(&[file_record(b"w", 0, 0, b"hi", 2, sizebytes)]);
            let arc = AlzArchive::open(&a[..]).unwrap();
            assert_eq!(arc.entries()[0].size(), 2, "sizebytes={sizebytes}");
        }
    }

    #[test]
    fn unknown_signature_errors() {
        let mut a = HEADER.to_vec();
        a.extend_from_slice(b"XYZ\x01"); // not BLZ/CLZ/ELZ
        assert!(AlzArchive::open(&a[..]).is_err());
    }

    #[test]
    fn truncated_record_errors() {
        let mut a = HEADER.to_vec();
        a.extend_from_slice(b"BLZ\x01\x05"); // claims a name length, then stops
        assert!(AlzArchive::open(&a[..]).is_err());
    }

    // ---- cycle 3: decoding -------------------------------------------------

    use newtua_common::crc32::crc32_ieee;

    fn deflate(content: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        flate2::read::DeflateEncoder::new(content, flate2::Compression::best())
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    fn bzip2(content: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        bzip2::read::BzEncoder::new(content, bzip2::Compression::new(9))
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    /// Build a record with explicit flags (so we can set the encryption bit).
    fn record_with_flags(
        name: &[u8],
        flags: u8,
        method: u8,
        crc: u32,
        comp: &[u8],
        size: u64,
    ) -> Vec<u8> {
        let sizebytes = flags >> 4;
        let mut r = vec![b'B', b'L', b'Z', 0x01];
        r.extend_from_slice(&(name.len() as u16).to_le_bytes());
        r.push(0x00);
        r.extend_from_slice(&0u32.to_le_bytes());
        r.push(flags);
        r.push(0x00);
        r.push(method);
        r.push(0x00);
        r.extend_from_slice(&crc.to_le_bytes());
        push_number(&mut r, comp.len() as u64, sizebytes);
        push_number(&mut r, size, sizebytes);
        r.extend_from_slice(name);
        r.extend_from_slice(comp);
        r
    }

    fn read(arc: &AlzArchive, idx: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        arc.read_entry(idx, &mut out)?;
        Ok(out)
    }

    #[test]
    fn decodes_stored() {
        let content = b"Hello ALZip stored member";
        let a = archive(&[file_record(
            b"s.txt",
            0,
            crc32_ieee(content),
            content,
            content.len() as u64,
            4,
        )]);
        let arc = AlzArchive::open(&a[..]).unwrap();
        assert_eq!(read(&arc, 0).unwrap(), content);
    }

    #[test]
    fn decodes_deflate() {
        let content = b"deflate deflate deflate raw stream no zlib wrapper deflate".repeat(3);
        let comp = deflate(&content);
        let a = archive(&[file_record(
            b"d.bin",
            2,
            crc32_ieee(&content),
            &comp,
            content.len() as u64,
            4,
        )]);
        let arc = AlzArchive::open(&a[..]).unwrap();
        assert_eq!(read(&arc, 0).unwrap(), content);
    }

    #[test]
    fn decodes_bzip2() {
        let content = b"bzip2 bzip2 bzip2 BZh block-sorting compression here".repeat(4);
        let comp = bzip2(&content);
        let a = archive(&[file_record(
            b"b.bin",
            1,
            crc32_ieee(&content),
            &comp,
            content.len() as u64,
            4,
        )]);
        let arc = AlzArchive::open(&a[..]).unwrap();
        assert_eq!(read(&arc, 0).unwrap(), content);
    }

    #[test]
    fn crc_mismatch_errors() {
        let content = b"payload with a deliberately wrong checksum";
        let a = archive(&[file_record(
            b"x",
            0,
            0xDEAD_BEEF,
            content,
            content.len() as u64,
            4,
        )]);
        let arc = AlzArchive::open(&a[..]).unwrap();
        assert!(read(&arc, 0).is_err());
    }

    #[test]
    fn truncated_compressed_data_errors() {
        let content = b"some content to deflate then truncate".repeat(5);
        let mut comp = deflate(&content);
        comp.truncate(comp.len() / 2); // chop the stream
        let a = archive(&[file_record(
            b"t",
            2,
            crc32_ieee(&content),
            &comp,
            content.len() as u64,
            4,
        )]);
        let arc = AlzArchive::open(&a[..]).unwrap();
        assert!(read(&arc, 0).is_err());
    }

    /// Build a method-3 (obfuscated deflate) fixture: the deflate stream is
    /// written in the size-derived meta order the decoder must reconstruct.
    fn method_3_comp(content: &[u8]) -> Vec<u8> {
        newtua_common::deflate::deflate_dynamic(content, &silly_meta_order(content.len() % 16))
    }

    #[test]
    fn decodes_method_3() {
        let content = b"obfuscated deflate, method 3, over and over. ".repeat(4);
        let comp = method_3_comp(&content);
        let a = archive(&[file_record(
            b"m3.bin",
            3,
            crc32_ieee(&content),
            &comp,
            content.len() as u64,
            4,
        )]);
        let arc = AlzArchive::open(&a[..]).unwrap();
        assert_eq!(read(&arc, 0).unwrap(), content);
    }

    #[test]
    fn decodes_method_3_various_sizes() {
        // The meta order depends on size % 16, so cover a spread of residues.
        for extra in 0..16usize {
            let content: Vec<u8> = (0..extra).map(|i| b'A' + (i % 20) as u8).collect();
            let comp = method_3_comp(&content);
            let a = archive(&[file_record(
                b"s",
                3,
                crc32_ieee(&content),
                &comp,
                content.len() as u64,
                4,
            )]);
            let arc = AlzArchive::open(&a[..]).unwrap();
            assert_eq!(
                read(&arc, 0).unwrap(),
                content,
                "len % 16 == {}",
                extra % 16
            );
        }
    }

    #[test]
    fn method_3_crc_mismatch_errors() {
        let content = b"method 3 payload with a wrong checksum".to_vec();
        let comp = method_3_comp(&content);
        let a = archive(&[file_record(
            b"bad",
            3,
            0xDEAD_BEEF,
            &comp,
            content.len() as u64,
            4,
        )]);
        let arc = AlzArchive::open(&a[..]).unwrap();
        assert!(read(&arc, 0).is_err());
    }

    #[test]
    fn encrypted_is_unsupported() {
        // flags: sizebytes=4 (0x40) | encrypted (0x01).
        let a = archive(&[record_with_flags(b"e", 0x41, 0, 0, b"data", 4)]);
        let arc = AlzArchive::open(&a[..]).unwrap();
        assert!(arc.entries()[0].is_encrypted());
        let err = read(&arc, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn reading_directory_errors() {
        let a = archive(&[dir_record(b"folder")]);
        let arc = AlzArchive::open(&a[..]).unwrap();
        assert!(read(&arc, 0).is_err());
    }

    #[test]
    fn member_data_past_end_errors() {
        // compsize claims 99 bytes but only 1 is present.
        let mut rec = file_record(b"x", 0, 0, b"X", 1, 4);
        // Overwrite the compsize field (after the 4-byte CRC) with 99.
        // Record layout: BLZ(4) namelen(2) attrs(1) dostime(4) flags(1) skip(1)
        // method(1) skip(1) crc(4) compsize(4) ...
        let off = 4 + 2 + 1 + 4 + 1 + 1 + 1 + 1 + 4;
        rec[off..off + 4].copy_from_slice(&99u32.to_le_bytes());
        let mut a = HEADER.to_vec();
        a.extend_from_slice(&rec);
        assert!(AlzArchive::open(&a[..]).is_err());
    }
}
