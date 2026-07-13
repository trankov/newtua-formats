// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! LBR (`.lbr`) — the CP/M library container.
//!
//! An LBR has no compression of its own: it is a flat directory of members,
//! each either stored verbatim or itself a Squeezed / Crunched file. The image
//! is a sequence of 128-byte sectors. The first sectors hold the directory: a
//! run of 32-byte records, the first of which describes the directory itself.
//! Each later record names a member and points at its data by sector index and
//! length. Names are CP/M 8.3, space-padded.
//!
//! Faithful port of XADMaster's `XADLBRParser.m`.

use std::io::{self, Read, Write};

use newtua_common::crc16::{crc16_ccitt, update_ccitt};

use crate::crunch_cpm::CrunchArchive;
use crate::squeeze::SqueezeFile;

const SECTOR: usize = 128;
const RECORD: usize = 32;

/// How a member's bytes are stored.
enum Member {
    /// Verbatim bytes, checked against the directory's CP/M CRC-16.
    Stored { crc16: u16 },
    /// An embedded Squeeze (`.SQ`) stream; decoded via [`SqueezeFile`].
    Squeezed,
    /// An embedded standalone Crunch stream. Recognized and listed, but its
    /// decoder is a separate roadmap item (CP/M Crunch / CrLZH); the ARC-era
    /// `crunch` module is a different algorithm and cannot decode it.
    Crunched,
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn u16_le(d: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([d[at], d[at + 1]])
}

/// One member of an LBR archive.
pub struct LbrEntry {
    name: Vec<u8>,
    offset: usize,
    size: usize,
    member: Member,
    creation_date: u16,
    modification_date: u16,
    creation_time: u16,
    modification_time: u16,
}

impl LbrEntry {
    /// The member's 8.3 name as raw bytes (charset decoding is the caller's job).
    pub fn name(&self) -> &[u8] {
        &self.name
    }
    /// The member's on-disk size in bytes: the stored file length, or for a
    /// compressed member the length of its embedded stream.
    pub fn size(&self) -> u64 {
        self.size as u64
    }
    /// Raw CP/M creation date word (days since 1978-01-01), 0 if unset.
    pub fn creation_date(&self) -> u16 {
        self.creation_date
    }
    /// Raw CP/M last-modification date word, 0 if unset.
    pub fn modification_date(&self) -> u16 {
        self.modification_date
    }
    /// Raw CP/M creation time word.
    pub fn creation_time(&self) -> u16 {
        self.creation_time
    }
    /// Raw CP/M last-modification time word.
    pub fn modification_time(&self) -> u16 {
        self.modification_time
    }
}

/// A parsed LBR archive.
pub struct LbrArchive {
    data: Vec<u8>,
    entries: Vec<LbrEntry>,
}

impl LbrArchive {
    /// Structural format check, mirroring `XADLBRParser`'s recognizer: a blank
    /// header record, a non-zero sector count, and (when present) a matching
    /// directory CRC.
    pub fn recognize(data: &[u8]) -> bool {
        if data.len() < SECTOR {
            return false;
        }
        if data[0] != 0 {
            return false;
        }
        if data[1..12].iter().any(|&b| b != b' ') {
            return false;
        }
        if data[12] != 0 || data[13] != 0 {
            return false;
        }
        if data[26..32].iter().any(|&b| b != 0) {
            return false;
        }

        let sectors = u16_le(data, 14) as usize;
        if sectors == 0 {
            return false;
        }

        // Verify the directory CRC when one is stored and the directory is fully
        // present. The CRC covers the directory with its own CRC field zeroed.
        let correct = u16_le(data, 16);
        let size = sectors * SECTOR;
        if correct != 0 && size <= data.len() {
            let mut crc = crc16_ccitt(&data[0..16]);
            crc = update_ccitt(crc, &[0, 0]);
            crc = update_ccitt(crc, &data[18..size]);
            if crc != correct {
                return false;
            }
        }

        true
    }

    /// Parse the directory of an LBR from `r`.
    pub fn open<R: Read>(mut r: R) -> io::Result<Self> {
        let mut data = Vec::new();
        r.read_to_end(&mut data)?;
        let entries = parse(&data)?;
        Ok(Self { data, entries })
    }

    /// The active members, in directory order.
    pub fn entries(&self) -> &[LbrEntry] {
        &self.entries
    }

    /// Decode member `idx` and write it to `out`.
    ///
    /// Stored members are copied verbatim and their CP/M CRC-16 is verified;
    /// Squeezed members are decoded (and verify their own internal checksum);
    /// Crunched members are decoded as embedded standalone Crunch files.
    pub fn read_entry(&self, idx: usize, out: &mut dyn Write) -> io::Result<()> {
        let e = self
            .entries
            .get(idx)
            .ok_or_else(|| invalid("lbr: index out of range"))?;
        let body = self
            .data
            .get(e.offset..e.offset + e.size)
            .ok_or_else(|| invalid("lbr: member data past end of file"))?;
        match e.member {
            Member::Stored { crc16 } => {
                if crc16_ccitt(body) != crc16 {
                    return Err(invalid("lbr: CRC mismatch"));
                }
                out.write_all(body)
            }
            Member::Squeezed => {
                let decoded = SqueezeFile::open(body)?.decode()?;
                out.write_all(&decoded)
            }
            Member::Crunched => {
                // The member body is a complete standalone Crunch (CP/M LZW or
                // CrLZH) file; decode it through the crunch_cpm container.
                CrunchArchive::open(body)?.read_entry(0, out)
            }
        }
    }
}

/// Read a NUL-terminated name starting at `start`, bounded by `data`.
fn read_cstr(data: &[u8], start: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for &b in &data[start.min(data.len())..] {
        if b == 0 {
            break;
        }
        out.push(b);
    }
    out
}

/// Build a member's 8.3 name, trimming trailing spaces from each half.
fn member_name(name: &[u8], ext: &[u8]) -> Vec<u8> {
    let mut nlen = name.len();
    while nlen > 1 && name[nlen - 1] == b' ' {
        nlen -= 1;
    }
    let mut elen = ext.len();
    while elen > 1 && ext[elen - 1] == b' ' {
        elen -= 1;
    }
    let mut out = name[..nlen].to_vec();
    out.push(b'.');
    out.extend_from_slice(&ext[..elen]);
    out
}

fn parse(data: &[u8]) -> io::Result<Vec<LbrEntry>> {
    if data.len() < SECTOR {
        return Err(invalid("lbr: truncated header"));
    }
    let numsectors = u16_le(data, 14) as usize;
    if numsectors == 0 {
        return Err(invalid("lbr: zero directory sectors"));
    }
    let numentries = numsectors * 4 - 1;

    let mut entries = Vec::new();
    for i in 0..numentries {
        let off = (i + 1) * RECORD;
        let rec = data
            .get(off..off + RECORD)
            .ok_or_else(|| invalid("lbr: truncated directory"))?;

        if rec[0] != 0 {
            continue; // deleted or unused slot
        }

        let index = u16_le(rec, 12) as usize;
        let length = u16_le(rec, 14) as usize;
        let crc16 = u16_le(rec, 16);
        let padding = rec[26] as usize;

        let offset = index * SECTOR;
        let size = (length * SECTOR).saturating_sub(padding);

        // The 2nd character of the extension flags Squeeze ('q') or Crunch
        // ('z'), but the embedded magic must agree — otherwise it is a plain
        // stored member whose name happens to fit the pattern.
        let ext = &rec[9..12];
        let magic = data.get(offset..offset + 2);
        let (member, name) = match (ext[1], magic) {
            (b'q' | b'Q', Some([0x76, 0xff])) => (Member::Squeezed, read_cstr(data, offset + 4)),
            (b'z' | b'Z', Some([0x76, 0xfe | 0xfd])) => {
                (Member::Crunched, read_cstr(data, offset + 2))
            }
            _ => (Member::Stored { crc16 }, member_name(&rec[1..9], ext)),
        };

        entries.push(LbrEntry {
            name,
            offset,
            size,
            member,
            creation_date: u16_le(rec, 18),
            modification_date: u16_le(rec, 20),
            creation_time: u16_le(rec, 22),
            modification_time: u16_le(rec, 24),
        });
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A member to place in a test LBR: 8.3 name halves, a status byte, and the
    /// raw bytes stored for it.
    struct M {
        name: [u8; 8],
        ext: [u8; 3],
        status: u8,
        content: Vec<u8>,
    }

    fn m(name: &str, ext: &str, content: &[u8]) -> M {
        let mut n = [b' '; 8];
        let mut e = [b' '; 3];
        n[..name.len()].copy_from_slice(name.as_bytes());
        e[..ext.len()].copy_from_slice(ext.as_bytes());
        M {
            name: n,
            ext: e,
            status: 0,
            content: content.to_vec(),
        }
    }

    /// Build a 32-byte directory record.
    #[allow(clippy::too_many_arguments)]
    fn record(
        status: u8,
        name: [u8; 8],
        ext: [u8; 3],
        index: u16,
        length: u16,
        crc: u16,
        padding: u8,
    ) -> [u8; 32] {
        let mut r = [0u8; 32];
        r[0] = status;
        r[1..9].copy_from_slice(&name);
        r[9..12].copy_from_slice(&ext);
        r[12..14].copy_from_slice(&index.to_le_bytes());
        r[14..16].copy_from_slice(&length.to_le_bytes());
        r[16..18].copy_from_slice(&crc.to_le_bytes());
        r[26] = padding;
        r
    }

    /// Assemble a valid LBR image from `members`, computing sector layout, the
    /// per-member CCITT CRC, and the directory CRC in the header record.
    fn build_lbr(members: &[M]) -> Vec<u8> {
        let records = members.len() + 1; // + header record
        let numsectors = records.div_ceil(4).max(1) as u16;

        // Lay member data out in sectors immediately after the directory.
        let mut dir = vec![0xffu8; numsectors as usize * 128];
        let mut data: Vec<u8> = Vec::new();
        let mut sector = numsectors;

        // Header record (record 0): describes the directory itself.
        dir[0..32].copy_from_slice(&record(
            0, [b' '; 8], [b' '; 3], 0, numsectors,
            0, // CRC filled in after the directory is complete
            0,
        ));

        for (i, mem) in members.iter().enumerate() {
            let clen = mem.content.len();
            let length = clen.div_ceil(128).max(1) as u16;
            let padding = (length as usize * 128 - clen) as u8;
            let crc = newtua_common::crc16::crc16_ccitt(&mem.content);

            let off = (i + 1) * 32;
            dir[off..off + 32].copy_from_slice(&record(
                mem.status, mem.name, mem.ext, sector, length, crc, padding,
            ));

            data.extend_from_slice(&mem.content);
            data.resize(data.len() + padding as usize, 0);
            sector += length;
        }

        // Directory CRC: over the whole directory with the CRC field zeroed.
        let crc = newtua_common::crc16::crc16_ccitt(&dir);
        dir[16..18].copy_from_slice(&crc.to_le_bytes());

        dir.extend_from_slice(&data);
        dir
    }

    fn read(arc: &LbrArchive, idx: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        arc.read_entry(idx, &mut out)?;
        Ok(out)
    }

    #[test]
    fn recognizes_valid_header() {
        let lbr = build_lbr(&[m("HELLO", "TXT", b"Hello, LBR!")]);
        assert!(LbrArchive::recognize(&lbr));
    }

    #[test]
    fn rejects_short_data() {
        assert!(!LbrArchive::recognize(&[0u8; 64]));
    }

    #[test]
    fn rejects_nonzero_first_byte() {
        let mut lbr = build_lbr(&[m("A", "TXT", b"x")]);
        lbr[0] = 1;
        assert!(!LbrArchive::recognize(&lbr));
    }

    #[test]
    fn rejects_bad_header_name() {
        let mut lbr = build_lbr(&[m("A", "TXT", b"x")]);
        lbr[3] = b'X'; // header name must be all spaces
        assert!(!LbrArchive::recognize(&lbr));
    }

    #[test]
    fn rejects_zero_sectors() {
        let mut lbr = build_lbr(&[m("A", "TXT", b"x")]);
        lbr[14] = 0;
        lbr[15] = 0;
        assert!(!LbrArchive::recognize(&lbr));
    }

    #[test]
    fn rejects_bad_directory_crc() {
        let mut lbr = build_lbr(&[m("A", "TXT", b"x")]);
        lbr[16] ^= 0xff; // corrupt the stored directory CRC
        assert!(!LbrArchive::recognize(&lbr));
    }

    #[test]
    fn lists_and_names_members() {
        let lbr = build_lbr(&[
            m("HELLO", "TXT", b"Hello, LBR!"),
            m("DATA", "BIN", b"\x00\x01\x02"),
        ]);
        let arc = LbrArchive::open(&lbr[..]).unwrap();
        let e = arc.entries();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].name(), b"HELLO.TXT");
        assert_eq!(e[1].name(), b"DATA.BIN");
    }

    #[test]
    fn extracts_stored_member() {
        let content = b"The quick brown fox jumps over the lazy dog.";
        let lbr = build_lbr(&[m("FOX", "TXT", content)]);
        let arc = LbrArchive::open(&lbr[..]).unwrap();
        assert_eq!(read(&arc, 0).unwrap(), content);
    }

    #[test]
    fn respects_padding_across_sectors() {
        // 200 bytes spans two sectors (256) with 56 bytes of padding.
        let content: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
        let lbr = build_lbr(&[m("BIG", "DAT", &content)]);
        let arc = LbrArchive::open(&lbr[..]).unwrap();
        assert_eq!(read(&arc, 0).unwrap(), content);
    }

    #[test]
    fn skips_inactive_entries() {
        let mut deleted = m("OLD", "TXT", b"gone");
        deleted.status = 0xff;
        let lbr = build_lbr(&[deleted, m("KEEP", "TXT", b"here")]);
        let arc = LbrArchive::open(&lbr[..]).unwrap();
        let e = arc.entries();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].name(), b"KEEP.TXT");
        assert_eq!(read(&arc, 0).unwrap(), b"here");
    }

    #[test]
    fn empty_directory_has_no_members() {
        let lbr = build_lbr(&[]);
        let arc = LbrArchive::open(&lbr[..]).unwrap();
        assert_eq!(arc.entries().len(), 0);
    }

    #[test]
    fn exposes_raw_cpm_date_words() {
        let mut lbr = build_lbr(&[m("DATED", "TXT", b"x")]);
        // Entry record 1 begins at offset 32; its date/time words are at 18..26.
        let base = 32 + 18;
        lbr[base..base + 2].copy_from_slice(&0x1234u16.to_le_bytes());
        lbr[base + 2..base + 4].copy_from_slice(&0x5678u16.to_le_bytes());
        lbr[base + 4..base + 6].copy_from_slice(&0x0abcu16.to_le_bytes());
        lbr[base + 6..base + 8].copy_from_slice(&0x0defu16.to_le_bytes());

        let arc = LbrArchive::open(&lbr[..]).unwrap();
        let e = &arc.entries()[0];
        assert_eq!(e.size(), 1);
        assert_eq!(e.creation_date(), 0x1234);
        assert_eq!(e.modification_date(), 0x5678);
        assert_eq!(e.creation_time(), 0x0abc);
        assert_eq!(e.modification_time(), 0x0def);
    }

    // A complete embedded `.SQ` decoding to "A" with internal name "a"
    // (the single-symbol stream from the squeeze module's own tests).
    const SQ_A: &[u8] = &[
        0x76, 0xFF, // magic
        0x41, 0x00, // checksum (sum of "A")
        0x61, 0x00, // internal name "a\0"
        0x01, 0x00, 0xBE, 0xFF, 0xFF, 0xFE, 0x02, // squeeze stream
    ];

    #[test]
    fn squeezed_member_uses_internal_name_and_decodes() {
        // Extension's 2nd char 'Q' marks Squeeze; the magic confirms it.
        let lbr = build_lbr(&[m("ANYTHING", "AQT", SQ_A)]);
        let arc = LbrArchive::open(&lbr[..]).unwrap();
        let e = arc.entries();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].name(), b"a"); // internal squeeze name, not "ANYTHING.AQT"
        assert_eq!(read(&arc, 0).unwrap(), b"A");
    }

    #[test]
    fn squeeze_pattern_without_magic_is_stored() {
        // Looks squeezed by extension, but the bytes are not a `.SQ` stream:
        // it must fall back to a stored member with its 8.3 name.
        let lbr = build_lbr(&[m("PLAIN", "AQT", b"not really squeezed")]);
        let arc = LbrArchive::open(&lbr[..]).unwrap();
        assert_eq!(arc.entries()[0].name(), b"PLAIN.AQT");
        assert_eq!(read(&arc, 0).unwrap(), b"not really squeezed");
    }

    #[test]
    fn crunched_member_uses_internal_name_and_decodes() {
        // A complete standalone Crunch (LZW, type 0xfe) file with internal name
        // "foo": magic, type, name, NUL, version1/version2 (0x20 → new variant),
        // errordetection 1 (no checksum), reserved, then the hand-built LZW body
        // that decodes to "AB" (see crunch_cpm.rs tests).
        let crunch: &[u8] = &[
            0x76, 0xfe, b'f', b'o', b'o', 0x00, 0x20, 0x20, 0x01, 0x00, // header
            0x20, 0x90, 0xA0, 0x00, // LZW body → "AB"
        ];
        let lbr = build_lbr(&[m("FOO", "AZT", crunch)]);
        let arc = LbrArchive::open(&lbr[..]).unwrap();
        assert_eq!(arc.entries()[0].name(), b"foo"); // internal crunch name
        assert_eq!(read(&arc, 0).unwrap(), b"AB");
    }

    #[test]
    fn per_member_crc_mismatch_errors() {
        let content = b"checksummed payload";
        let lbr = build_lbr(&[m("CRC", "TXT", content)]);
        let mut arc = LbrArchive::open(&lbr[..]).unwrap();
        // Corrupt the first stored data byte (directory is 1 sector = 128 bytes).
        arc.data[128] ^= 0xff;
        assert!(read(&arc, 0).is_err());
    }
}
