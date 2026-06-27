//! MacBinary I / II / III — a 128-byte header carrying one Mac file's two forks.
//!
//! A MacBinary file is a flat container: a fixed 128-byte header, then the data
//! fork and the resource fork, each padded up to a 128-byte block boundary
//! (with an optional secondary header in between, length in the main header).
//! There is no compression — the forks are stored verbatim.
//!
//! Faithful port of XADMaster's `+macBinaryVersionForHeader:` (recognition and
//! version detection) and `-parseMacBinaryWithDictionary:` (field layout and
//! fork offsets), both in `XADMacArchiveParser.m`.
//!
//! # Known limitations (out of scope)
//!
//! Filenames are kept as raw bytes (MacRoman); decoding them to Unicode is the
//! caller's job, as for BinHex.

use std::io::{self, Read, Write};

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// One fork (data or resource) of the single Mac file inside a MacBinary file.
pub struct MacBinaryEntry {
    name: Vec<u8>,
    size: u32,
    is_resource_fork: bool,
    file_type: [u8; 4],
    creator: [u8; 4],
    finder_flags: u16,
    creation_date: u32,
    modification_date: u32,
    /// Offset of this fork's bytes within the file.
    offset: usize,
}

impl MacBinaryEntry {
    /// The file's name as raw bytes (MacRoman). Both forks carry the same name.
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

/// A parsed MacBinary file: one Mac file's header plus its two forks.
pub struct MacBinaryArchive {
    data: Vec<u8>,
    entries: Vec<MacBinaryEntry>,
    version: u8,
}

impl MacBinaryArchive {
    /// Whether `data` is a MacBinary file (version I, II or III).
    pub fn recognize(data: &[u8]) -> bool {
        version_for_header(data) > 0
    }

    /// Read and parse a MacBinary file from `r`.
    pub fn open<R: Read>(mut r: R) -> io::Result<Self> {
        let mut data = Vec::new();
        r.read_to_end(&mut data)?;

        let version = version_for_header(&data);
        if version == 0 {
            return Err(invalid("macbinary: not a MacBinary file"));
        }

        let b = &data;
        let namelen = b[1] as usize;
        let name = b[2..2 + namelen].to_vec();
        let file_type: [u8; 4] = b[65..69].try_into().unwrap();
        let creator: [u8; 4] = b[69..73].try_into().unwrap();
        let finder_flags = (u16::from(b[73]) << 8) | u16::from(b[101]);
        let creation_date = u32::from_be_bytes(b[91..95].try_into().unwrap());
        let modification_date = u32::from_be_bytes(b[95..99].try_into().unwrap());

        let datasize = u32::from_be_bytes(b[83..87].try_into().unwrap());
        let rsrcsize = u32::from_be_bytes(b[87..91].try_into().unwrap());
        let extsize = u16::from_be_bytes(b[120..122].try_into().unwrap());

        let data_offset = 128 + block_size(u32::from(extsize));
        let rsrc_offset = data_offset + block_size(datasize);

        let make = |size: u32, is_resource_fork: bool, offset: usize| MacBinaryEntry {
            name: name.clone(),
            size,
            is_resource_fork,
            file_type,
            creator,
            finder_flags,
            creation_date,
            modification_date,
            offset,
        };

        // Port of the entry rules (XADMacArchiveParser.m:385-408). The quirk:
        // an empty file (both forks zero) still yields one empty data fork.
        let mut entries = Vec::new();
        if datasize != 0 || rsrcsize == 0 {
            entries.push(make(datasize, false, data_offset));
        }
        if rsrcsize != 0 {
            entries.push(make(rsrcsize, true, rsrc_offset));
        }

        Ok(Self {
            data,
            entries,
            version,
        })
    }

    /// The forks, in order: data fork first, then the resource fork if present.
    pub fn entries(&self) -> &[MacBinaryEntry] {
        &self.entries
    }

    /// The detected MacBinary version (1, 2 or 3).
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Write fork `idx`'s raw bytes to `out`.
    pub fn read_entry(&self, idx: usize, out: &mut dyn Write) -> io::Result<()> {
        let e = self
            .entries
            .get(idx)
            .ok_or_else(|| invalid("macbinary: entry index out of range"))?;
        let end = e.offset + e.size as usize;
        let fork = self
            .data
            .get(e.offset..end)
            .ok_or_else(|| invalid("macbinary: fork data past end of file"))?;
        out.write_all(fork)
    }
}

/// Round a length up to the next 128-byte block boundary. Port of the
/// `BlockSize` macro; done in `u64` so the `+127` cannot overflow.
fn block_size(x: u32) -> usize {
    ((u64::from(x) + 127) & !127) as usize
}

/// Compute the MacBinary version of a header: 1, 2 or 3, or 0 if not MacBinary.
/// Port of `+macBinaryVersionForHeader:`.
fn version_for_header(data: &[u8]) -> u8 {
    if data.len() < 128 {
        return 0;
    }
    let b = data;

    // Zero-fill bytes.
    if b[0] != 0 || b[74] != 0 || b[82] != 0 {
        return 0;
    }
    if b[108..=115].iter().any(|&x| x != 0) {
        return 0;
    }

    // A valid name: length 1..=63 with no embedded NUL.
    let namelen = b[1];
    if namelen == 0 || namelen > 63 {
        return 0;
    }
    if b[2..2 + namelen as usize].contains(&0) {
        return 0;
    }

    // A valid header CRC marks MacBinary II / III. XADMaster computes a
    // byte-swapped table CRC then byte-swaps the stored value; the two swaps
    // cancel, leaving the plain CRC-16/CCITT (XMODEM) of bytes[0..124].
    let stored = u16::from_be_bytes([b[124], b[125]]);
    if newtua_common::crc16::crc16_ccitt(&b[0..124]) == stored {
        if &b[102..106] == b"mBIN" {
            return 3;
        }
        return 2;
    }

    // Heuristics for accepting a version I file (no CRC).
    if b[99..=125].iter().any(|&x| x != 0) {
        return 0;
    }
    if u32::from_be_bytes([b[83], b[84], b[85], b[86]]) > 0x7fff_ffff {
        return 0; // data fork size
    }
    if u32::from_be_bytes([b[87], b[88], b[89], b[90]]) > 0x7fff_ffff {
        return 0; // resource fork size
    }
    if u32::from_be_bytes([b[91], b[92], b[93], b[94]]) == 0 {
        return 0; // creation date
    }
    if u32::from_be_bytes([b[95], b[96], b[97], b[98]]) == 0 {
        return 0; // last-modified date
    }

    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use newtua_common::crc16::crc16_ccitt;

    /// Build a 128-byte MacBinary header. `set_crc` writes the correct CCITT
    /// header CRC (making it a v2/v3 header); `v3` adds the `mBIN` signature.
    #[allow(clippy::too_many_arguments)]
    fn header(
        name: &[u8],
        ftype: &[u8; 4],
        creator: &[u8; 4],
        flags: u16,
        datalen: u32,
        rsrclen: u32,
        creation: u32,
        modification: u32,
        v3: bool,
        set_crc: bool,
    ) -> Vec<u8> {
        let mut h = vec![0u8; 128];
        h[0] = 0;
        h[1] = name.len() as u8;
        h[2..2 + name.len()].copy_from_slice(name);
        h[65..69].copy_from_slice(ftype);
        h[69..73].copy_from_slice(creator);
        h[73] = (flags >> 8) as u8;
        h[101] = (flags & 0xff) as u8;
        h[83..87].copy_from_slice(&datalen.to_be_bytes());
        h[87..91].copy_from_slice(&rsrclen.to_be_bytes());
        h[91..95].copy_from_slice(&creation.to_be_bytes());
        h[95..99].copy_from_slice(&modification.to_be_bytes());
        // extsize at 120..122 stays 0.
        if v3 {
            h[102..106].copy_from_slice(b"mBIN");
        }
        if set_crc {
            let crc = crc16_ccitt(&h[0..124]);
            h[124..126].copy_from_slice(&crc.to_be_bytes());
        }
        h
    }

    /// Assemble a full MacBinary file: header + padded data fork + padded
    /// resource fork (no secondary header, extsize = 0).
    fn file(h: &[u8], data: &[u8], resource: &[u8]) -> Vec<u8> {
        let mut f = h.to_vec();
        f.extend_from_slice(data);
        f.resize(128 + block_size(data.len() as u32), 0);
        f.extend_from_slice(resource);
        f.resize(
            128 + block_size(data.len() as u32) + block_size(resource.len() as u32),
            0,
        );
        f
    }

    fn read_fork(arc: &MacBinaryArchive, idx: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        arc.read_entry(idx, &mut out)?;
        Ok(out)
    }

    #[test]
    fn recognizes_macbinary_ii() {
        let h = header(b"file", b"TEXT", b"ttxt", 0, 5, 0, 1, 1, false, true);
        assert!(MacBinaryArchive::recognize(&h));
    }

    #[test]
    fn recognizes_macbinary_iii() {
        let h = header(b"file", b"TEXT", b"ttxt", 0, 5, 0, 1, 1, true, true);
        assert!(MacBinaryArchive::recognize(&h));
    }

    #[test]
    fn recognizes_macbinary_i_heuristic() {
        // No CRC; v1 needs bytes[99..=125] all zero and non-zero dates, so
        // finder flags low byte (byte 101) must be 0 too.
        let h = header(b"file", b"TEXT", b"ttxt", 0, 5, 0, 100, 200, false, false);
        assert!(MacBinaryArchive::recognize(&h));
    }

    #[test]
    fn version_reports_each_variant() {
        assert_eq!(
            version_for_header(&header(b"f", b"TEXT", b"ttxt", 0, 1, 0, 1, 1, true, true)),
            3
        );
        assert_eq!(
            version_for_header(&header(b"f", b"TEXT", b"ttxt", 0, 1, 0, 1, 1, false, true)),
            2
        );
        assert_eq!(
            version_for_header(&header(b"f", b"TEXT", b"ttxt", 0, 1, 0, 9, 9, false, false)),
            1
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(!MacBinaryArchive::recognize(
            b"not a macbinary header at all....."
        ));
    }

    #[test]
    fn rejects_truncated_header() {
        let h = header(b"file", b"TEXT", b"ttxt", 0, 5, 0, 1, 1, false, true);
        assert!(!MacBinaryArchive::recognize(&h[..100]));
    }

    #[test]
    fn rejects_nonzero_fill_byte() {
        let mut h = header(b"file", b"TEXT", b"ttxt", 0, 5, 0, 1, 1, false, true);
        h[74] = 1; // must be zero
        assert!(!MacBinaryArchive::recognize(&h));
    }

    #[test]
    fn rejects_zero_namelen() {
        let h = header(b"", b"TEXT", b"ttxt", 0, 5, 0, 1, 1, false, true);
        assert!(!MacBinaryArchive::recognize(&h));
    }

    #[test]
    fn rejects_nul_inside_name() {
        let mut h = header(b"file", b"TEXT", b"ttxt", 0, 5, 0, 1, 1, false, true);
        h[3] = 0; // a NUL inside the name region
        let crc = crc16_ccitt(&h[0..124]);
        h[124..126].copy_from_slice(&crc.to_be_bytes());
        assert!(!MacBinaryArchive::recognize(&h));
    }

    #[test]
    fn parses_metadata_and_dates() {
        let h = header(
            b"doc", b"PDF ", b"prvw", 0x2080, 1, 0, 0x1234, 0x5678, true, true,
        );
        let f = file(&h, b"x", b"");
        let arc = MacBinaryArchive::open(&f[..]).unwrap();
        let e = &arc.entries()[0];
        assert_eq!(e.name(), b"doc");
        assert_eq!(&e.file_type(), b"PDF ");
        assert_eq!(&e.creator(), b"prvw");
        assert_eq!(e.finder_flags(), 0x2080);
        assert_eq!(e.creation_date(), 0x1234);
        assert_eq!(e.modification_date(), 0x5678);
        assert_eq!(arc.version(), 3);
    }

    #[test]
    fn lists_only_data_fork_when_no_resource() {
        let h = header(b"file", b"TEXT", b"ttxt", 0, 5, 0, 1, 1, false, true);
        let f = file(&h, b"hello", b"");
        let arc = MacBinaryArchive::open(&f[..]).unwrap();
        assert_eq!(arc.entries().len(), 1);
        assert!(!arc.entries()[0].is_resource_fork());
        assert_eq!(arc.entries()[0].size(), 5);
    }

    #[test]
    fn empty_file_yields_one_empty_data_fork() {
        // datasize == 0 and rsrcsize == 0: the quirk is one empty data fork.
        let h = header(b"file", b"TEXT", b"ttxt", 0, 0, 0, 1, 1, false, true);
        let f = file(&h, b"", b"");
        let arc = MacBinaryArchive::open(&f[..]).unwrap();
        assert_eq!(arc.entries().len(), 1);
        assert!(!arc.entries()[0].is_resource_fork());
        assert_eq!(arc.entries()[0].size(), 0);
    }

    #[test]
    fn only_resource_fork_when_data_empty_but_resource_present() {
        let h = header(b"file", b"TEXT", b"ttxt", 0, 0, 4, 1, 1, false, true);
        let f = file(&h, b"", b"RES!");
        let arc = MacBinaryArchive::open(&f[..]).unwrap();
        assert_eq!(arc.entries().len(), 1);
        assert!(arc.entries()[0].is_resource_fork());
        assert_eq!(arc.entries()[0].size(), 4);
    }

    #[test]
    fn lists_both_forks_when_present() {
        let h = header(b"file", b"TEXT", b"ttxt", 0, 5, 4, 1, 1, false, true);
        let f = file(&h, b"hello", b"RES!");
        let arc = MacBinaryArchive::open(&f[..]).unwrap();
        assert_eq!(arc.entries().len(), 2);
        assert!(!arc.entries()[0].is_resource_fork());
        assert!(arc.entries()[1].is_resource_fork());
    }

    #[test]
    fn extracts_both_forks_at_block_offsets() {
        let data = b"hello world, this is the data fork";
        let resource = b"resource fork bytes";
        let h = header(
            b"file",
            b"TEXT",
            b"ttxt",
            0,
            data.len() as u32,
            resource.len() as u32,
            1,
            1,
            false,
            true,
        );
        let f = file(&h, data, resource);
        let arc = MacBinaryArchive::open(&f[..]).unwrap();
        assert_eq!(read_fork(&arc, 0).unwrap(), data);
        assert_eq!(read_fork(&arc, 1).unwrap(), resource);
    }

    #[test]
    fn data_fork_offset_accounts_for_secondary_header() {
        // extsize at 120..122; data fork moves to 128 + block_size(extsize).
        let data = b"DATA";
        let mut h = header(
            b"file",
            b"TEXT",
            b"ttxt",
            0,
            data.len() as u32,
            0,
            1,
            1,
            false,
            true,
        );
        let extsize: u16 = 10;
        h[120..122].copy_from_slice(&extsize.to_be_bytes());
        // Re-stamp the CRC after editing the header.
        let crc = crc16_ccitt(&h[0..124]);
        h[124..126].copy_from_slice(&crc.to_be_bytes());
        let mut f = h.clone();
        f.resize(128 + block_size(extsize as u32), 0); // secondary header block
        f.extend_from_slice(data);
        let arc = MacBinaryArchive::open(&f[..]).unwrap();
        assert_eq!(read_fork(&arc, 0).unwrap(), data);
    }

    #[test]
    fn read_entry_out_of_range_errors() {
        let h = header(b"file", b"TEXT", b"ttxt", 0, 5, 0, 1, 1, false, true);
        let f = file(&h, b"hello", b"");
        let arc = MacBinaryArchive::open(&f[..]).unwrap();
        assert!(read_fork(&arc, 9).is_err());
    }

    #[test]
    fn open_rejects_non_macbinary() {
        let bytes = [1u8; 200];
        assert!(MacBinaryArchive::open(&bytes[..]).is_err());
    }

    #[test]
    fn open_rejects_fork_past_end() {
        // A header claiming a 1000-byte data fork but a file that stops short.
        let h = header(b"file", b"TEXT", b"ttxt", 0, 1000, 0, 1, 1, false, true);
        let mut f = h.clone();
        f.extend_from_slice(b"only a few bytes");
        let arc = MacBinaryArchive::open(&f[..]).unwrap();
        let mut out = Vec::new();
        assert!(arc.read_entry(0, &mut out).is_err());
    }
}
