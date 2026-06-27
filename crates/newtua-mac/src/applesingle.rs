//! AppleSingle and AppleDouble — fork containers with an entry table.
//!
//! Both formats share one structure: a header (magic + version + 16-byte
//! filler), a count of entries, then that many 12-byte descriptors (`id`,
//! `offset`, `length`). Sections we care about are the data fork (id 1), the
//! resource fork (id 2), the real name (id 3), the dates (id 8) and the Finder
//! info (id 9). AppleSingle usually carries both forks; AppleDouble carries the
//! resource fork (and Finder info) only. They differ only in their magic.
//!
//! Byte-swapped little-endian variants exist; the magic identifies them and the
//! rest of the file is then read little-endian. One quirk faithfully preserved
//! from XADMaster: the date section (id 8) is *always* big-endian, regardless of
//! that flag.
//!
//! Faithful port of XADMaster's `XADAppleSingleParser.m`.
//!
//! # Known limitations (out of scope)
//!
//! - The extended-attributes block (`com.apple.*`, an `ATTR` blob that may
//!   follow the 32-byte Finder info in id 9, or the AppleDouble attributes) is
//!   not parsed.
//! - The comment section (id 4) is ignored.
//! - Names are kept as raw bytes (MacRoman); decoding to Unicode is the caller's
//!   job, as for BinHex.

use std::io::{self, Read, Write};

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Which of the two sister formats a file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppleFormat {
    /// AppleSingle: data + resource fork in one file.
    Single,
    /// AppleDouble: the side file, usually resource fork + Finder info only.
    Double,
}

/// One fork (data or resource) inside an AppleSingle / AppleDouble file.
pub struct AppleSingleEntry {
    name: Vec<u8>,
    size: u32,
    is_resource_fork: bool,
    file_type: [u8; 4],
    creator: [u8; 4],
    finder_flags: u16,
    creation_date: Option<u32>,
    modification_date: Option<u32>,
    backup_date: Option<u32>,
    access_date: Option<u32>,
    /// Offset of this fork's bytes within the file.
    offset: usize,
}

impl AppleSingleEntry {
    /// The file's name as raw bytes (from section id 3, or empty if absent).
    pub fn name(&self) -> &[u8] {
        &self.name
    }
    /// This fork's length in bytes.
    pub fn size(&self) -> u64 {
        u64::from(self.size)
    }
    /// Whether this entry is the resource fork (`false` for the data fork).
    pub fn is_resource_fork(&self) -> bool {
        self.is_resource_fork
    }
    /// The Mac file type (OSType) from the Finder info, or zeros if absent.
    pub fn file_type(&self) -> [u8; 4] {
        self.file_type
    }
    /// The Mac creator code (OSType) from the Finder info, or zeros if absent.
    pub fn creator(&self) -> [u8; 4] {
        self.creator
    }
    /// The Finder flags, or zero if there is no Finder info section.
    pub fn finder_flags(&self) -> u16 {
        self.finder_flags
    }
    /// Creation date, raw seconds since 2000-01-01, if a date section exists.
    pub fn creation_date(&self) -> Option<u32> {
        self.creation_date
    }
    /// Last-modification date, raw seconds since 2000-01-01.
    pub fn modification_date(&self) -> Option<u32> {
        self.modification_date
    }
    /// Backup date, raw seconds since 2000-01-01.
    pub fn backup_date(&self) -> Option<u32> {
        self.backup_date
    }
    /// Last-access date, raw seconds since 2000-01-01.
    pub fn access_date(&self) -> Option<u32> {
        self.access_date
    }
}

/// A parsed AppleSingle or AppleDouble file.
pub struct AppleSingleArchive {
    data: Vec<u8>,
    entries: Vec<AppleSingleEntry>,
    format: AppleFormat,
}

impl AppleSingleArchive {
    /// Whether `data` is an AppleSingle or AppleDouble file (any endianness).
    pub fn recognize(data: &[u8]) -> bool {
        if data.len() < 8 {
            return false;
        }
        let magic = u32::from_be_bytes(data[0..4].try_into().unwrap());
        if !matches!(magic, 0x0005_1600 | 0x0005_1607 | 0x0016_0500 | 0x0716_0500) {
            return false;
        }
        let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
        matches!(version, 0x0002_0000 | 0x0000_0200)
    }

    /// Read and parse an AppleSingle / AppleDouble file from `r`.
    pub fn open<R: Read>(mut r: R) -> io::Result<Self> {
        let mut data = Vec::new();
        r.read_to_end(&mut data)?;

        if data.len() < 8 {
            return Err(invalid("applesingle: file too short"));
        }
        let magic = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let (format, be) = match magic {
            0x0005_1600 => (AppleFormat::Single, true),
            0x0005_1607 => (AppleFormat::Double, true),
            0x0016_0500 => (AppleFormat::Single, false),
            0x0716_0500 => (AppleFormat::Double, false),
            _ => return Err(invalid("applesingle: bad magic")),
        };
        let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
        if !matches!(version, 0x0002_0000 | 0x0000_0200) {
            return Err(invalid("applesingle: bad version"));
        }

        // Header is magic(4) + version(4) + filler(16); the entry count follows
        // at offset 24, then `num` 12-byte descriptors.
        let num =
            rd16(&data, 24, be).ok_or_else(|| invalid("applesingle: truncated header"))? as usize;

        let mut dataoffs = 0u32;
        let mut datalen = 0u32;
        let mut rsrcoffs = 0u32;
        let mut rsrclen = 0u32;

        let mut name: Vec<u8> = Vec::new();
        let mut file_type = [0u8; 4];
        let mut creator = [0u8; 4];
        let mut finder_flags = 0u16;
        let mut creation_date = None;
        let mut modification_date = None;
        let mut backup_date = None;
        let mut access_date = None;

        for i in 0..num {
            let d = 26 + i * 12;
            let entryid =
                rd32(&data, d, be).ok_or_else(|| invalid("applesingle: truncated table"))?;
            let entryoffs =
                rd32(&data, d + 4, be).ok_or_else(|| invalid("applesingle: truncated table"))?;
            let entrylen =
                rd32(&data, d + 8, be).ok_or_else(|| invalid("applesingle: truncated table"))?;

            let off = entryoffs as usize;
            let len = entrylen as usize;
            let section = |end: usize| -> io::Result<&[u8]> {
                data.get(off..off + end)
                    .ok_or_else(|| invalid("applesingle: section past end of file"))
            };

            match entryid {
                1 => {
                    dataoffs = entryoffs;
                    datalen = entrylen;
                }
                2 => {
                    rsrcoffs = entryoffs;
                    rsrclen = entrylen;
                }
                3 => {
                    name = section(len)?.to_vec();
                }
                8 => {
                    // Faithful to XADMaster: these fields are always big-endian,
                    // even when the rest of the file is little-endian.
                    let dt = section(len)?;
                    if len >= 4 {
                        creation_date = Some(u32::from_be_bytes(dt[0..4].try_into().unwrap()));
                    }
                    if len >= 8 {
                        modification_date = Some(u32::from_be_bytes(dt[4..8].try_into().unwrap()));
                    }
                    if len >= 12 {
                        backup_date = Some(u32::from_be_bytes(dt[8..12].try_into().unwrap()));
                    }
                    if len >= 16 {
                        access_date = Some(u32::from_be_bytes(dt[12..16].try_into().unwrap()));
                    }
                }
                9 => {
                    // The Finder info struct: type/creator/flags are big-endian.
                    let want = len.min(32);
                    let fi = section(want)?;
                    if want >= 4 {
                        file_type.copy_from_slice(&fi[0..4]);
                    }
                    if want >= 8 {
                        creator.copy_from_slice(&fi[4..8]);
                    }
                    if want >= 10 {
                        finder_flags = u16::from_be_bytes(fi[8..10].try_into().unwrap());
                    }
                }
                _ => {}
            }
        }

        let make = |size: u32, is_resource_fork: bool, offset: usize| AppleSingleEntry {
            name: name.clone(),
            size,
            is_resource_fork,
            file_type,
            creator,
            finder_flags,
            creation_date,
            modification_date,
            backup_date,
            access_date,
            offset,
        };

        // Faithful to XADMaster: a fork is emitted only when its offset is
        // non-zero. Data fork first, then resource fork.
        let mut entries = Vec::new();
        if dataoffs != 0 {
            entries.push(make(datalen, false, dataoffs as usize));
        }
        if rsrcoffs != 0 {
            entries.push(make(rsrclen, true, rsrcoffs as usize));
        }

        Ok(Self {
            data,
            entries,
            format,
        })
    }

    /// The forks, in order: data fork first (if any), then the resource fork.
    pub fn entries(&self) -> &[AppleSingleEntry] {
        &self.entries
    }

    /// Whether this is an AppleSingle or an AppleDouble file.
    pub fn format(&self) -> AppleFormat {
        self.format
    }

    /// Write fork `idx`'s raw bytes to `out`.
    pub fn read_entry(&self, idx: usize, out: &mut dyn Write) -> io::Result<()> {
        let e = self
            .entries
            .get(idx)
            .ok_or_else(|| invalid("applesingle: entry index out of range"))?;
        let end = e.offset + e.size as usize;
        let fork = self
            .data
            .get(e.offset..end)
            .ok_or_else(|| invalid("applesingle: fork data past end of file"))?;
        out.write_all(fork)
    }
}

/// Read a big- or little-endian `u16` at `off`, or `None` if out of bounds.
fn rd16(data: &[u8], off: usize, be: bool) -> Option<u16> {
    let b = data.get(off..off + 2)?;
    let arr = [b[0], b[1]];
    Some(if be {
        u16::from_be_bytes(arr)
    } else {
        u16::from_le_bytes(arr)
    })
}

/// Read a big- or little-endian `u32` at `off`, or `None` if out of bounds.
fn rd32(data: &[u8], off: usize, be: bool) -> Option<u32> {
    let b = data.get(off..off + 4)?;
    let arr = [b[0], b[1], b[2], b[3]];
    Some(if be {
        u32::from_be_bytes(arr)
    } else {
        u32::from_le_bytes(arr)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const AS_BE: u32 = 0x0005_1600;
    const AD_BE: u32 = 0x0005_1607;
    const AS_LE: u32 = 0x0016_0500;
    const VER_BE: u32 = 0x0002_0000;
    const VER_LE: u32 = 0x0000_0200;

    fn w16(v: u16, be: bool) -> [u8; 2] {
        if be {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    }
    fn w32(v: u32, be: bool) -> [u8; 4] {
        if be {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    }

    /// Build a 32-byte Finder info blob: type/creator/flags are always BE.
    fn finder_info(ftype: &[u8; 4], creator: &[u8; 4], flags: u16) -> Vec<u8> {
        let mut v = vec![0u8; 32];
        v[0..4].copy_from_slice(ftype);
        v[4..8].copy_from_slice(creator);
        v[8..10].copy_from_slice(&flags.to_be_bytes());
        v
    }

    /// Build a dates blob: four u32, always big-endian (the XADMaster quirk).
    fn dates(creation: u32, modification: u32, backup: u32, access: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&creation.to_be_bytes());
        v.extend_from_slice(&modification.to_be_bytes());
        v.extend_from_slice(&backup.to_be_bytes());
        v.extend_from_slice(&access.to_be_bytes());
        v
    }

    /// Assemble a file from a list of `(id, section bytes)`. Descriptors are laid
    /// out in order, section bodies packed right after the descriptor table.
    fn build(magic: u32, version: u32, be: bool, sections: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let n = sections.len();
        let table = 24 + 2 + 12 * n;
        let mut out = vec![0u8; table];
        out[0..4].copy_from_slice(&magic.to_be_bytes());
        out[4..8].copy_from_slice(&version.to_be_bytes());
        out[24..26].copy_from_slice(&w16(n as u16, be));

        let mut off = table;
        let mut body = Vec::new();
        for (i, (id, sec)) in sections.iter().enumerate() {
            let d = 26 + i * 12;
            out[d..d + 4].copy_from_slice(&w32(*id, be));
            out[d + 4..d + 8].copy_from_slice(&w32(off as u32, be));
            out[d + 8..d + 12].copy_from_slice(&w32(sec.len() as u32, be));
            body.extend_from_slice(sec);
            off += sec.len();
        }
        out.extend_from_slice(&body);
        out
    }

    fn read_fork(arc: &AppleSingleArchive, idx: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        arc.read_entry(idx, &mut out)?;
        Ok(out)
    }

    #[test]
    fn recognizes_applesingle_be() {
        let f = build(AS_BE, VER_BE, true, &[(1, b"data".to_vec())]);
        assert!(AppleSingleArchive::recognize(&f));
    }

    #[test]
    fn recognizes_appledouble_be() {
        let f = build(AD_BE, VER_BE, true, &[(2, b"rsrc".to_vec())]);
        assert!(AppleSingleArchive::recognize(&f));
    }

    #[test]
    fn recognizes_little_endian_variant() {
        let f = build(AS_LE, VER_LE, false, &[(1, b"data".to_vec())]);
        assert!(AppleSingleArchive::recognize(&f));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut f = build(AS_BE, VER_BE, true, &[(1, b"x".to_vec())]);
        f[0] = 0xFF;
        assert!(!AppleSingleArchive::recognize(&f));
    }

    #[test]
    fn rejects_bad_version() {
        let f = build(AS_BE, 0x0003_0000, true, &[(1, b"x".to_vec())]);
        assert!(!AppleSingleArchive::recognize(&f));
    }

    #[test]
    fn rejects_too_short() {
        assert!(!AppleSingleArchive::recognize(b"\x00\x05\x16"));
    }

    #[test]
    fn reports_format() {
        let single =
            AppleSingleArchive::open(&build(AS_BE, VER_BE, true, &[(1, b"d".to_vec())])[..])
                .unwrap();
        assert_eq!(single.format(), AppleFormat::Single);
        let double =
            AppleSingleArchive::open(&build(AD_BE, VER_BE, true, &[(2, b"r".to_vec())])[..])
                .unwrap();
        assert_eq!(double.format(), AppleFormat::Double);
    }

    #[test]
    fn extracts_both_forks() {
        let f = build(
            AS_BE,
            VER_BE,
            true,
            &[
                (1, b"the data fork".to_vec()),
                (2, b"the rsrc fork".to_vec()),
            ],
        );
        let arc = AppleSingleArchive::open(&f[..]).unwrap();
        assert_eq!(arc.entries().len(), 2);
        assert!(!arc.entries()[0].is_resource_fork());
        assert!(arc.entries()[1].is_resource_fork());
        assert_eq!(read_fork(&arc, 0).unwrap(), b"the data fork");
        assert_eq!(read_fork(&arc, 1).unwrap(), b"the rsrc fork");
    }

    #[test]
    fn appledouble_has_only_resource_fork() {
        let f = build(
            AD_BE,
            VER_BE,
            true,
            &[
                (2, b"rsrc only".to_vec()),
                (9, finder_info(b"TEXT", b"ttxt", 0)),
            ],
        );
        let arc = AppleSingleArchive::open(&f[..]).unwrap();
        assert_eq!(arc.entries().len(), 1);
        assert!(arc.entries()[0].is_resource_fork());
        assert_eq!(read_fork(&arc, 0).unwrap(), b"rsrc only");
    }

    #[test]
    fn reads_name_from_section_3() {
        let f = build(
            AS_BE,
            VER_BE,
            true,
            &[(3, b"realname.txt".to_vec()), (1, b"d".to_vec())],
        );
        let arc = AppleSingleArchive::open(&f[..]).unwrap();
        assert_eq!(arc.entries()[0].name(), b"realname.txt");
    }

    #[test]
    fn reads_finder_info() {
        let f = build(
            AS_BE,
            VER_BE,
            true,
            &[
                (1, b"d".to_vec()),
                (9, finder_info(b"PDF ", b"prvw", 0x2080)),
            ],
        );
        let arc = AppleSingleArchive::open(&f[..]).unwrap();
        let e = &arc.entries()[0];
        assert_eq!(&e.file_type(), b"PDF ");
        assert_eq!(&e.creator(), b"prvw");
        assert_eq!(e.finder_flags(), 0x2080);
    }

    #[test]
    fn parses_dates() {
        let f = build(
            AS_BE,
            VER_BE,
            true,
            &[
                (1, b"d".to_vec()),
                (8, dates(0x1111, 0x2222, 0x3333, 0x4444)),
            ],
        );
        let arc = AppleSingleArchive::open(&f[..]).unwrap();
        let e = &arc.entries()[0];
        assert_eq!(e.creation_date(), Some(0x1111));
        assert_eq!(e.modification_date(), Some(0x2222));
        assert_eq!(e.backup_date(), Some(0x3333));
        assert_eq!(e.access_date(), Some(0x4444));
    }

    #[test]
    fn dates_are_always_big_endian_even_in_le_file() {
        // The whole file is little-endian, but the dates blob is BE — faithful
        // to XADMaster, which reads id-8 fields with readUInt32BE regardless.
        let f = build(
            AS_LE,
            VER_LE,
            false,
            &[(1, b"d".to_vec()), (8, dates(0x1234_5678, 0, 0, 0))],
        );
        let arc = AppleSingleArchive::open(&f[..]).unwrap();
        assert_eq!(arc.entries()[0].creation_date(), Some(0x1234_5678));
    }

    #[test]
    fn little_endian_forks_parse_like_big_endian() {
        let f = build(
            AS_LE,
            VER_LE,
            false,
            &[(1, b"data-LE".to_vec()), (2, b"rsrc-LE".to_vec())],
        );
        let arc = AppleSingleArchive::open(&f[..]).unwrap();
        assert_eq!(read_fork(&arc, 0).unwrap(), b"data-LE");
        assert_eq!(read_fork(&arc, 1).unwrap(), b"rsrc-LE");
    }

    #[test]
    fn ignores_unknown_section_ids() {
        let f = build(
            AS_BE,
            VER_BE,
            true,
            &[
                (4, b"a comment".to_vec()),
                (1, b"d".to_vec()),
                (99, b"junk".to_vec()),
            ],
        );
        let arc = AppleSingleArchive::open(&f[..]).unwrap();
        assert_eq!(arc.entries().len(), 1);
        assert_eq!(read_fork(&arc, 0).unwrap(), b"d");
    }

    #[test]
    fn data_fork_at_offset_zero_is_not_emitted() {
        // XADMaster only emits a fork when its recorded offset is non-zero.
        // Forge a descriptor for id 1 with offset 0.
        let mut f = build(AS_BE, VER_BE, true, &[(1, b"ignored".to_vec())]);
        // Descriptor offset field is at 26+4 .. 26+8.
        f[30..34].copy_from_slice(&0u32.to_be_bytes());
        let arc = AppleSingleArchive::open(&f[..]).unwrap();
        assert_eq!(arc.entries().len(), 0);
    }

    #[test]
    fn open_rejects_non_apple_file() {
        let bytes = [0u8; 64];
        assert!(AppleSingleArchive::open(&bytes[..]).is_err());
    }

    #[test]
    fn read_entry_out_of_range_errors() {
        let f = build(AS_BE, VER_BE, true, &[(1, b"d".to_vec())]);
        let arc = AppleSingleArchive::open(&f[..]).unwrap();
        assert!(read_fork(&arc, 9).is_err());
    }

    #[test]
    fn open_rejects_fork_past_end() {
        let mut f = build(AS_BE, VER_BE, true, &[(1, b"short".to_vec())]);
        // Inflate the recorded data-fork length far past the file end.
        f[34..38].copy_from_slice(&9999u32.to_be_bytes());
        let arc = AppleSingleArchive::open(&f[..]).unwrap();
        let mut out = Vec::new();
        assert!(arc.read_entry(0, &mut out).is_err());
    }
}
