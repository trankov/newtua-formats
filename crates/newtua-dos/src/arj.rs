//! ARJ (`.arj`) — Robert Jung's MS-DOS archiver.
//!
//! An ARJ archive is a main header followed by a flat sequence of local
//! headers, each immediately preceding its member's data and terminated by a
//! local header whose size is zero. Every header is `0x60 0xea`, a 16-bit
//! size, that many header bytes, then a 32-bit CRC of the header. The main
//! header's CRC is what recognition keys on. Members are stored verbatim or
//! compressed with one of the LZH-static methods (1/2/3); decoded contents are
//! checked against a per-entry CRC-32/IEEE.
//!
//! Faithful port of XADMaster's `XADARJParser.m`. The LZH-static codec is the
//! shared [`crate::lzh_static::LzhStaticReader`], here with a 15-bit window.

use std::io::{self, Read, Write};

use newtua_common::crc32::crc32_ieee;

use crate::lzh_static::LzhStaticReader;

/// Sliding-window size exponent for ARJ's LZH-static members.
const WINDOW_BITS: u32 = 15;

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn unsupported(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, msg.into())
}

/// One member of an ARJ archive.
pub struct ArjEntry {
    /// Path as raw bytes (charset decoding and separator normalisation are the
    /// caller's job), exactly as stored in the local header.
    name: Vec<u8>,
    method: u8,
    crc32: u32,
    size: usize,
    dataoffset: usize,
    datalen: usize,
    is_dir: bool,
    is_encrypted: bool,
}

impl ArjEntry {
    /// The member's path as raw bytes.
    pub fn name(&self) -> &[u8] {
        &self.name
    }
    /// The member's decompressed size in bytes.
    pub fn size(&self) -> u64 {
        self.size as u64
    }
    /// Whether the entry is a directory (file type 3).
    pub fn is_dir(&self) -> bool {
        self.is_dir
    }
    /// Whether the entry is encrypted (header flag `0x01`).
    pub fn is_encrypted(&self) -> bool {
        self.is_encrypted
    }
    /// The compression method: 0 stored, 1/2/3 LZH-static, 4 fastest.
    pub fn method(&self) -> u8 {
        self.method
    }
}

/// A parsed ARJ archive.
pub struct ArjArchive {
    data: Vec<u8>,
    entries: Vec<ArjEntry>,
}

impl ArjArchive {
    /// Structural format check: scan for a main header whose stored CRC-32
    /// matches the header bytes.
    pub fn recognize(data: &[u8]) -> bool {
        data.len() >= 40 && find_header(data, 0).is_some()
    }

    /// Read and parse an ARJ archive from `r`.
    pub fn open<R: Read>(mut r: R) -> io::Result<Self> {
        let mut data = Vec::new();
        r.read_to_end(&mut data)?;
        let entries = parse(&data)?;
        Ok(Self { data, entries })
    }

    /// The members, in archive order.
    pub fn entries(&self) -> &[ArjEntry] {
        &self.entries
    }

    /// Decode member `idx` and write it to `out`. Stored members are copied;
    /// methods 1/2/3 are decoded with LZH-static (15-bit window). Directories
    /// produce no output; encrypted and other methods are `Unsupported`. The
    /// decoded bytes are verified against the entry's CRC-32/IEEE.
    pub fn read_entry(&self, idx: usize, out: &mut dyn Write) -> io::Result<()> {
        let e = self
            .entries
            .get(idx)
            .ok_or_else(|| invalid("arj: index out of range"))?;

        if e.is_dir {
            return Ok(()); // directories carry no data and no checksum
        }
        if e.is_encrypted {
            return Err(unsupported("arj: encryption not supported"));
        }

        let comp = self
            .data
            .get(e.dataoffset..e.dataoffset + e.datalen)
            .ok_or_else(|| invalid("arj: member data past end of file"))?;

        let decoded = match e.method {
            0 => comp
                .get(..e.size)
                .ok_or_else(|| invalid("arj: stored member shorter than its size"))?
                .to_vec(),
            1..=3 => {
                let mut buf = vec![0u8; e.size];
                LzhStaticReader::new(comp, WINDOW_BITS).read_exact(&mut buf)?;
                buf
            }
            4 => return Err(unsupported("arj: method 4 (Fastest) — task 8b")),
            other => return Err(unsupported(format!("arj: unsupported method {other}"))),
        };

        if crc32_ieee(&decoded) != e.crc32 {
            return Err(invalid("arj: CRC-32 mismatch"));
        }
        out.write_all(&decoded)
    }
}

/// Scan `data` from `start` for the first header marker (`0x60 0xea`) whose
/// 16-bit size is in range and whose trailing stored CRC-32 matches the header
/// bytes. Returns the marker offset and the header size.
fn find_header(data: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut i = start;
    while i + 4 <= data.len() {
        if data[i] == 0x60 && data[i + 1] == 0xea {
            let size = u16::from_le_bytes([data[i + 2], data[i + 3]]) as usize;
            if (32..=2600).contains(&size) && i + 4 + size + 4 <= data.len() {
                let header = &data[i + 4..i + 4 + size];
                let stored =
                    u32::from_le_bytes(data[i + 4 + size..i + 8 + size].try_into().unwrap());
                if crc32_ieee(header) == stored {
                    return Some((i, size));
                }
            }
        }
        i += 1;
    }
    None
}

/// Read a little-endian `u8`/`u16`/`u32` at `*pos`, advancing it. Each is
/// bounds-checked against `data` so a truncated archive yields a clean error.
fn rd_u8(data: &[u8], pos: &mut usize) -> io::Result<u8> {
    let b = *data
        .get(*pos)
        .ok_or_else(|| invalid("arj: truncated header"))?;
    *pos += 1;
    Ok(b)
}

fn rd_u16(data: &[u8], pos: &mut usize) -> io::Result<u16> {
    let s = data
        .get(*pos..*pos + 2)
        .ok_or_else(|| invalid("arj: truncated header"))?;
    *pos += 2;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn rd_u32(data: &[u8], pos: &mut usize) -> io::Result<u32> {
    let s = data
        .get(*pos..*pos + 4)
        .ok_or_else(|| invalid("arj: truncated header"))?;
    *pos += 4;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Read a NUL-terminated byte string at `*pos`, consuming the terminator.
fn read_cstring(data: &[u8], pos: &mut usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let b = rd_u8(data, pos)?;
        if b == 0 {
            return Ok(out);
        }
        out.push(b);
    }
}

/// Walk the main header and then the flat list of local headers, collecting
/// entries until the zero-size terminating local header.
fn parse(data: &[u8]) -> io::Result<Vec<ArjEntry>> {
    let (m, headersize) =
        find_header(data, 0).ok_or_else(|| invalid("arj: no valid main header"))?;

    // Main header: only the file type matters to us (it must be 2).
    let header = &data[m + 4..m + 4 + headersize];
    if header[6] != 2 {
        return Err(invalid("arj: main header is not file type 2"));
    }

    // Step past the main header's marker, body and CRC, then its (possibly
    // empty) extended-header block.
    let mut cur = m + 4 + headersize + 4;
    let extlen = rd_u16(data, &mut cur)? as usize;
    if extlen != 0 {
        cur += extlen + 4;
    }

    let mut entries = Vec::new();
    loop {
        if rd_u8(data, &mut cur)? != 0x60 || rd_u8(data, &mut cur)? != 0xea {
            return Err(invalid("arj: bad local header marker"));
        }
        let headersize = rd_u16(data, &mut cur)? as usize;
        if headersize == 0 {
            break; // end of archive
        }
        if !(32..=2600).contains(&headersize) {
            return Err(invalid("arj: local header size out of range"));
        }

        // Fixed 28-byte basic part.
        let p = cur;
        let firstsize = rd_u8(data, &mut cur)? as usize;
        let _version = rd_u8(data, &mut cur)?;
        let _minversion = rd_u8(data, &mut cur)?;
        let _os = rd_u8(data, &mut cur)?;
        let flags = rd_u8(data, &mut cur)?;
        let method = rd_u8(data, &mut cur)?;
        let filetype = rd_u8(data, &mut cur)?;
        let _passwordmod = rd_u8(data, &mut cur)?;
        let _modification = rd_u32(data, &mut cur)?;
        let compsize = rd_u32(data, &mut cur)? as usize;
        let size = rd_u32(data, &mut cur)? as usize;
        let crc = rd_u32(data, &mut cur)?;
        let _filespecoffs = rd_u16(data, &mut cur)?;
        let _accessmode = rd_u16(data, &mut cur)?;
        if firstsize < 28 {
            return Err(invalid("arj: local header firstsize too small"));
        }
        cur = p + firstsize; // skip any extra basic-header bytes

        let name = read_cstring(data, &mut cur)?;
        let _comment = read_cstring(data, &mut cur)?;
        let _headcrc = rd_u32(data, &mut cur)?;
        let extlen = rd_u16(data, &mut cur)? as usize;
        if extlen != 0 {
            cur += extlen + 4;
        }

        let dataoffset = cur;
        if dataoffset + compsize > data.len() {
            return Err(invalid("arj: member data past end of file"));
        }

        entries.push(ArjEntry {
            name,
            method,
            crc32: crc,
            size,
            dataoffset,
            datalen: compsize,
            is_dir: filetype == 3,
            is_encrypted: flags & 0x01 != 0,
        });

        cur = dataoffset + compsize;
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One local member to place in a test archive.
    struct M {
        name: &'static [u8],
        flags: u8,
        method: u8,
        filetype: u8,
        passwordmod: u8,
        size: u32,
        crc: u32,
        data: Vec<u8>,
    }

    impl M {
        /// A stored file member with content `c`.
        fn stored(name: &'static [u8], c: &[u8]) -> Self {
            M {
                name,
                flags: 0,
                method: 0,
                filetype: 0,
                passwordmod: 0,
                size: c.len() as u32,
                crc: crc32_ieee(c),
                data: c.to_vec(),
            }
        }
    }

    /// Wrap a header region as `0x60 0xea <size> <header> <crc32(header)>`.
    fn block(header: &[u8]) -> Vec<u8> {
        let mut b = vec![0x60, 0xea];
        b.extend_from_slice(&(header.len() as u16).to_le_bytes());
        b.extend_from_slice(header);
        b.extend_from_slice(&crc32_ieee(header).to_le_bytes());
        b
    }

    /// Build the main header region: 28 fixed bytes, then a NUL-terminated
    /// archive name and comment. `name` keeps it at/above the 32-byte minimum.
    fn main_header(os: u8, filetype: u8, name: &[u8]) -> Vec<u8> {
        let mut h = vec![0u8; 28];
        h[0] = 28; // firstsize
        h[3] = os;
        h[6] = filetype;
        h.extend_from_slice(name);
        h.push(0); // name terminator
        h.push(0); // empty comment terminator
        h
    }

    /// Build a local header region for member `m`: 28 fixed bytes, then a
    /// NUL-terminated filename and (empty) comment.
    fn local_header(m: &M) -> Vec<u8> {
        let mut h = vec![0u8; 28];
        h[0] = 28; // firstsize
        h[3] = 2; // os = Unix
        h[4] = m.flags;
        h[5] = m.method;
        h[6] = m.filetype;
        h[7] = m.passwordmod;
        h[12..16].copy_from_slice(&(m.data.len() as u32).to_le_bytes()); // compsize
        h[16..20].copy_from_slice(&m.size.to_le_bytes());
        h[20..24].copy_from_slice(&m.crc.to_le_bytes());
        h.extend_from_slice(m.name);
        h.push(0); // filename terminator
        h.push(0); // empty comment terminator
        h
    }

    /// Assemble a complete ARJ image: main header, its (empty) extended-header
    /// terminator, each member's local header + data, then the zero-size local
    /// header that ends the archive.
    fn build_arj(members: &[M]) -> Vec<u8> {
        let mut out = block(&main_header(2, 2, b"archive"));
        out.extend_from_slice(&[0, 0]); // main header: extlen = 0
        for m in members {
            out.extend_from_slice(&block(&local_header(m)));
            out.extend_from_slice(&[0, 0]); // local header: extlen = 0
            out.extend_from_slice(&m.data);
        }
        // Terminating local header: marker then a zero size.
        out.extend_from_slice(&[0x60, 0xea, 0, 0]);
        out
    }

    #[test]
    fn recognizes_valid_archive() {
        let arj = build_arj(&[M::stored(b"A.TXT", b"hi there")]);
        assert!(ArjArchive::recognize(&arj));
    }

    #[test]
    fn rejects_short_data() {
        assert!(!ArjArchive::recognize(&[0u8; 20]));
    }

    #[test]
    fn rejects_without_marker() {
        assert!(!ArjArchive::recognize(&[0x11u8; 64]));
    }

    #[test]
    fn recognizes_with_leading_garbage() {
        let mut arj = vec![0x00, 0x61, 0xff, 0x12, 0x34]; // innocuous prefix
        arj.extend_from_slice(&build_arj(&[M::stored(b"A.TXT", b"hi")]));
        assert!(ArjArchive::recognize(&arj));
    }

    #[test]
    fn lists_members() {
        let arj = build_arj(&[
            M::stored(b"HELLO.TXT", b"Hello, ARJ!"),
            M::stored(b"DATA.BIN", b"\x00\x01\x02\x03"),
        ]);
        let arc = ArjArchive::open(&arj[..]).unwrap();
        let e = arc.entries();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].name(), b"HELLO.TXT");
        assert_eq!(e[0].size(), 11);
        assert_eq!(e[1].name(), b"DATA.BIN");
        assert_eq!(e[1].size(), 4);
    }

    #[test]
    fn stops_at_zero_size_local_header() {
        let arj = build_arj(&[M::stored(b"ONE.TXT", b"only")]);
        let arc = ArjArchive::open(&arj[..]).unwrap();
        assert_eq!(arc.entries().len(), 1);
    }

    #[test]
    fn flags_directory_entry() {
        let mut m = M::stored(b"subdir", b"");
        m.filetype = 3;
        let arj = build_arj(&[m]);
        let arc = ArjArchive::open(&arj[..]).unwrap();
        assert!(arc.entries()[0].is_dir());
    }

    #[test]
    fn flags_encrypted_entry() {
        let mut m = M::stored(b"SECRET.TXT", b"ciphertext");
        m.flags = 0x01;
        let arj = build_arj(&[m]);
        let arc = ArjArchive::open(&arj[..]).unwrap();
        assert!(arc.entries()[0].is_encrypted());
    }

    #[test]
    fn rejects_main_header_wrong_filetype() {
        // A structurally valid archive whose main header claims a file type
        // other than 2 is not a main header at all.
        let mut out = block(&main_header(2, 5, b"archive"));
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&[0x60, 0xea, 0, 0]);
        assert!(ArjArchive::open(&out[..]).is_err());
    }

    #[test]
    fn rejects_on_bad_header_crc() {
        // A lone main header block (40 bytes, the only marker in the data): a
        // corrupted header byte no longer matches the stored CRC, so there is
        // nothing left for recognition to validate.
        let mut blk = block(&main_header(2, 2, b"archive"));
        assert!(ArjArchive::recognize(&blk));
        blk[6] ^= 0xff; // reserved header byte, CRC now wrong
        assert!(!ArjArchive::recognize(&blk));
    }

    // --- read_entry --------------------------------------------------------

    /// Build a compressed member around a raw `stream`, decoding to `decoded`.
    fn compressed(name: &'static [u8], method: u8, decoded: &[u8], stream: Vec<u8>) -> M {
        M {
            name,
            flags: 0,
            method,
            filetype: 0,
            passwordmod: 0,
            size: decoded.len() as u32,
            crc: crc32_ieee(decoded),
            data: stream,
        }
    }

    fn read(arc: &ArjArchive, idx: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        arc.read_entry(idx, &mut out)?;
        Ok(out)
    }

    /// Minimal MSB-first bit writer, matching `BitReaderMsb`'s bit order, used
    /// to hand-assemble LZH-static streams for the decoder tests.
    struct BitW {
        out: Vec<u8>,
        acc: u32,
        n: u32,
    }

    impl BitW {
        fn new() -> Self {
            BitW {
                out: Vec::new(),
                acc: 0,
                n: 0,
            }
        }
        fn put(&mut self, val: u32, bits: u32) {
            for i in (0..bits).rev() {
                self.acc = (self.acc << 1) | ((val >> i) & 1);
                self.n += 1;
                if self.n == 8 {
                    self.out.push(self.acc as u8);
                    self.acc = 0;
                    self.n = 0;
                }
            }
        }
        fn finish(mut self) -> Vec<u8> {
            if self.n > 0 {
                self.out.push((self.acc << (8 - self.n)) as u8);
            }
            self.out
        }
    }

    /// A one-block LZH-static stream of `count` literals, all the single symbol
    /// `byte`. Window 15 means the distance code's fields are 5 bits wide.
    fn lzh_repeat(byte: u8, count: u16) -> Vec<u8> {
        let mut w = BitW::new();
        w.put(count as u32, 16); // block size = token count
        w.put(0, 5); // metacode: num = 0 (single symbol)
        w.put(0, 5); // metacode value
        w.put(0, 9); // literal code: num = 0 (single symbol)
        w.put(byte as u32, 9); // literal value
        w.put(0, 5); // distance code: num = 0 (single symbol)
        w.put(0, 5); // distance value (unused)
        w.finish()
    }

    /// A one-block LZH-static stream of `tokens` matches, each length 3 at
    /// offset 1 over a zero-initialised window: decodes to `3*tokens` zeros.
    fn lzh_match_zeros(tokens: u16) -> Vec<u8> {
        let mut w = BitW::new();
        w.put(tokens as u32, 16);
        w.put(0, 5); // metacode single symbol
        w.put(0, 5);
        w.put(0, 9); // literal single symbol...
        w.put(0x100, 9); // ...the length-3 match symbol
        w.put(0, 5); // distance single symbol = 0 -> offset 1
        w.put(0, 5);
        w.finish()
    }

    #[test]
    fn extracts_stored_member() {
        let content = b"The quick brown fox jumps over the lazy dog.";
        let arj = build_arj(&[M::stored(b"FOX.TXT", content)]);
        let arc = ArjArchive::open(&arj[..]).unwrap();
        assert_eq!(read(&arc, 0).unwrap(), content);
    }

    #[test]
    fn crc_mismatch_is_error() {
        let mut m = M::stored(b"C.TXT", b"checksummed");
        m.crc ^= 0xdead_beef; // stored CRC no longer matches the data
        let arj = build_arj(&[m]);
        let arc = ArjArchive::open(&arj[..]).unwrap();
        assert!(read(&arc, 0).is_err());
    }

    #[test]
    fn directory_extracts_empty() {
        let mut m = M::stored(b"subdir", b"");
        m.filetype = 3;
        let arj = build_arj(&[m]);
        let arc = ArjArchive::open(&arj[..]).unwrap();
        assert_eq!(read(&arc, 0).unwrap(), b"");
    }

    #[test]
    fn encrypted_is_unsupported() {
        let mut m = M::stored(b"S.TXT", b"secret");
        m.flags = 0x01;
        let arj = build_arj(&[m]);
        let arc = ArjArchive::open(&arj[..]).unwrap();
        assert_eq!(
            read(&arc, 0).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn method_4_is_unsupported() {
        let mut m = M::stored(b"F.TXT", b"fastest");
        m.method = 4;
        let arj = build_arj(&[m]);
        let arc = ArjArchive::open(&arj[..]).unwrap();
        assert_eq!(
            read(&arc, 0).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn unknown_method_is_unsupported() {
        let mut m = M::stored(b"X.TXT", b"data");
        m.method = 9;
        let arj = build_arj(&[m]);
        let arc = ArjArchive::open(&arj[..]).unwrap();
        assert_eq!(
            read(&arc, 0).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn extracts_lzh_repeated_literal() {
        let decoded = vec![b'Z'; 50];
        let m = compressed(b"R.BIN", 1, &decoded, lzh_repeat(b'Z', 50));
        let arj = build_arj(&[m]);
        let arc = ArjArchive::open(&arj[..]).unwrap();
        assert_eq!(read(&arc, 0).unwrap(), decoded);
    }

    #[test]
    fn extracts_lzh_offset_one_matches() {
        let decoded = vec![0u8; 30]; // 10 matches * length 3
        let m = compressed(b"M.BIN", 2, &decoded, lzh_match_zeros(10));
        let arj = build_arj(&[m]);
        let arc = ArjArchive::open(&arj[..]).unwrap();
        assert_eq!(read(&arc, 0).unwrap(), decoded);
    }
}
