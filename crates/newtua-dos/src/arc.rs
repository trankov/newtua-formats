//! ARC (SEA ARC / PKARC) — a flat-or-nested multi-file container.
//!
//! Each member is `0x1A`, a method byte, a 13-byte name, then sizes, an MS-DOS
//! date/time, a CRC-16, and (except the oldest method) the uncompressed size,
//! followed by the member data. Method `0x00` ends the archive; `0x1E` opens a
//! subdirectory and `0x1F`/`0x80` close one.
//!
//! Supported methods so far: 1/2 stored, 3 packed (RLE90), 4 squeezed
//! (Huffman + RLE90), 5/6/7 crunched (hash LZW, ±RLE90), 8 crunched-LZW
//! (compress + RLE90), 9 squashed (compress), 0xa crushed (adaptive LZW +
//! RLE90), 0xb distilled (LZSS + Huffman), 0x7f compressed (compress).

use std::io::{self, Read, Write};

use newtua_common::compress::CompressReader;
use newtua_common::crc16::crc16_arc;
use newtua_common::rle90::Rle90Reader;

use crate::crunch::{CrunchHash, CrunchReader};
use crate::crush::CrushReader;
use crate::distill::decode as decode_distill;
use crate::squeeze::SqueezeReader;

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn rd_u16(d: &[u8], p: &mut usize) -> io::Result<u16> {
    let b = d
        .get(*p..*p + 2)
        .ok_or_else(|| invalid("arc: truncated header"))?;
    *p += 2;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn rd_u32(d: &[u8], p: &mut usize) -> io::Result<u32> {
    let b = d
        .get(*p..*p + 4)
        .ok_or_else(|| invalid("arc: truncated header"))?;
    *p += 4;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// One member of an ARC archive.
pub struct ArcEntry {
    name: Vec<u8>,
    is_dir: bool,
    method: u8,
    uncompressed_size: u32,
    compressed_size: u32,
    data_offset: usize,
    crc16: u16,
}

impl ArcEntry {
    /// Raw path bytes (`/`-joined for nested members); charset decoding is the
    /// caller's job.
    pub fn name(&self) -> &[u8] {
        &self.name
    }
    /// Whether this entry is a directory marker (no data).
    pub fn is_dir(&self) -> bool {
        self.is_dir
    }
    /// The ARC compression method (low 7 bits).
    pub fn method(&self) -> u8 {
        self.method
    }
    /// Uncompressed size in bytes.
    pub fn size(&self) -> u32 {
        self.uncompressed_size
    }
}

/// A parsed ARC archive.
pub struct ArcArchive {
    data: Vec<u8>,
    entries: Vec<ArcEntry>,
}

impl ArcArchive {
    /// Parse all member headers from `r`.
    pub fn open<R: Read>(mut r: R) -> io::Result<Self> {
        let mut data = Vec::new();
        r.read_to_end(&mut data)?;
        let entries = parse(&data)?;
        Ok(Self { data, entries })
    }

    /// The members, in archive order.
    pub fn entries(&self) -> &[ArcEntry] {
        &self.entries
    }

    /// Decode member `idx` and write it to `out`, verifying its CRC-16.
    pub fn read_entry(&self, idx: usize, out: &mut dyn Write) -> io::Result<()> {
        let e = self
            .entries
            .get(idx)
            .ok_or_else(|| invalid("arc: index out of range"))?;
        if e.is_dir {
            return Err(invalid("arc: entry is a directory"));
        }
        let comp = &self.data[e.data_offset..e.data_offset + e.compressed_size as usize];
        let decoded = decode_method(e.method, comp, e.uncompressed_size as usize)?;
        if crc16_arc(&decoded) != e.crc16 {
            return Err(invalid("arc: CRC mismatch"));
        }
        out.write_all(&decoded)
    }
}

fn trim_name(raw: &[u8]) -> Vec<u8> {
    let mut len = 0;
    while len < 12 && raw[len] != 0 {
        len += 1;
    }
    if len > 1 && (raw[len - 1] == b' ' || raw[len - 1] == b'.') {
        len -= 1;
    }
    raw[..len].to_vec()
}

fn join(stack: &[Vec<u8>], name: &[u8]) -> Vec<u8> {
    if stack.is_empty() {
        return name.to_vec();
    }
    let mut out = Vec::new();
    for part in stack {
        out.extend_from_slice(part);
        out.push(b'/');
    }
    out.extend_from_slice(name);
    out
}

fn parse(data: &[u8]) -> io::Result<Vec<ArcEntry>> {
    let mut entries = Vec::new();
    let mut pos = 0usize;
    let mut dirs: Vec<Vec<u8>> = Vec::new();

    loop {
        // Skip up to 64 bytes of junk to find the next 0x1A header marker.
        let start = pos;
        while data.get(pos).is_some_and(|&b| b != 0x1A) {
            pos += 1;
            if pos - start >= 64 {
                return Err(invalid("arc: no header marker"));
            }
        }
        if pos >= data.len() {
            break; // end of file
        }
        pos += 1; // consume the 0x1A

        let method = match data.get(pos) {
            Some(&m) => m,
            None => break,
        };
        pos += 1;

        if method == 0x00 {
            break; // end of archive
        }
        if method == 0x1F || method == 0x80 {
            dirs.pop(); // close a subdirectory
            continue;
        }

        let raw_name = data
            .get(pos..pos + 13)
            .ok_or_else(|| invalid("arc: truncated name"))?;
        let name = trim_name(raw_name);
        pos += 13;

        let compressed_size = rd_u32(data, &mut pos)?;
        let _date = rd_u16(data, &mut pos)?;
        let _time = rd_u16(data, &mut pos)?;
        let crc16 = rd_u16(data, &mut pos)?;
        let uncompressed_size = if method == 1 {
            compressed_size
        } else {
            rd_u32(data, &mut pos)?
        };
        if method & 0x80 != 0 {
            pos += 12; // Archimedes load/exec/attrs, unused
        }

        let data_offset = pos;
        let is_dir = method == 0x1E;
        let end = if is_dir {
            data_offset
        } else {
            data_offset
                .checked_add(compressed_size as usize)
                .filter(|&e| e <= data.len())
                .ok_or_else(|| invalid("arc: member data past end of file"))?
        };

        entries.push(ArcEntry {
            name: join(&dirs, &name),
            is_dir,
            method: method & 0x7F,
            uncompressed_size: if is_dir { 0 } else { uncompressed_size },
            compressed_size: if is_dir { 0 } else { compressed_size },
            data_offset,
            crc16,
        });
        if is_dir {
            dirs.push(name);
        }
        pos = end;
    }

    Ok(entries)
}

fn read_n(mut r: impl Read, n: usize) -> io::Result<Vec<u8>> {
    let mut out = vec![0u8; n];
    r.read_exact(&mut out)?;
    Ok(out)
}

fn decode_method(method: u8, comp: &[u8], uncompressed_size: usize) -> io::Result<Vec<u8>> {
    match method {
        // Stored.
        1 | 2 => Ok(comp.to_vec()),
        // Packed: RLE90.
        3 => read_n(Rle90Reader::new(comp), uncompressed_size),
        // Squeezed: Huffman, then RLE90.
        4 => {
            let huffman = SqueezeReader::new(comp)?;
            read_n(Rle90Reader::new(huffman), uncompressed_size)
        }
        // Crunched (no packing): 12-bit hash LZW, no RLE90.
        5 => read_n(
            CrunchReader::new(comp, CrunchHash::Quadratic),
            uncompressed_size,
        ),
        // Crunched: 12-bit hash LZW (quadratic hash), then RLE90.
        6 => read_n(
            Rle90Reader::new(CrunchReader::new(comp, CrunchHash::Quadratic)),
            uncompressed_size,
        ),
        // Crunched (fast): 12-bit hash LZW (multiplicative hash), then RLE90.
        7 => read_n(
            Rle90Reader::new(CrunchReader::new(comp, CrunchHash::Multiplicative)),
            uncompressed_size,
        ),
        // Crunched (LZW): a leading 0x0c byte, then 12-bit compress, then RLE90.
        8 => {
            let body = comp
                .split_first()
                .filter(|(&b, _)| b == 0x0c)
                .map(|(_, rest)| rest)
                .ok_or_else(|| invalid("arc: bad crunched-LZW header byte"))?;
            let lzw = CompressReader::new(body, 12, true);
            read_n(Rle90Reader::new(lzw), uncompressed_size)
        }
        // Squashed: 13-bit compress, no RLE90.
        9 => read_n(CompressReader::new(comp, 13, true), uncompressed_size),
        // Crushed: adaptive LZW, then RLE90.
        0x0a => read_n(Rle90Reader::new(CrushReader::new(comp)), uncompressed_size),
        // Distilled: LZSS with a header-supplied Huffman code, no RLE90.
        // `decode` is authoritative on length, so it returns the bytes directly
        // (like the stored methods) rather than going through `read_n`.
        0x0b => decode_distill(comp),
        // Compressed: a leading flags byte gives the max code width.
        0x7f => {
            let (&flags, body) = comp
                .split_first()
                .ok_or_else(|| invalid("arc: missing compress flags byte"))?;
            let lzw = CompressReader::new(body, flags & 0x1f, true);
            read_n(lzw, uncompressed_size)
        }
        other => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("arc: unsupported method {other}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhex::hex;

    /// Build a stored (method 2) member.
    fn stored(name: &[u8], content: &[u8]) -> Vec<u8> {
        member(0x02, name, content, content)
    }

    /// Build a member with an explicit method, payload, and the uncompressed
    /// content (used for the CRC).
    fn member(method: u8, name: &[u8], payload: &[u8], content: &[u8]) -> Vec<u8> {
        let mut e = vec![0x1A, method];
        let mut nm = [0u8; 13];
        nm[..name.len()].copy_from_slice(name);
        e.extend_from_slice(&nm);
        e.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // compsize
        e.extend_from_slice(&[0, 0, 0, 0]); // date, time
        e.extend_from_slice(&crc16_arc(content).to_le_bytes()); // crc16
        e.extend_from_slice(&(content.len() as u32).to_le_bytes()); // uncompsize
        e.extend_from_slice(payload);
        e
    }

    fn archive(members: &[Vec<u8>]) -> Vec<u8> {
        let mut a = Vec::new();
        for m in members {
            a.extend_from_slice(m);
        }
        a.extend_from_slice(&[0x1A, 0x00]); // end marker
        a
    }

    fn read(arc: &ArcArchive, idx: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        arc.read_entry(idx, &mut out)?;
        Ok(out)
    }

    #[test]
    fn parses_two_members() {
        let a = archive(&[stored(b"a", b"A"), stored(b"bb.txt", b"BB")]);
        let arc = ArcArchive::open(&a[..]).unwrap();
        let e = arc.entries();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].name(), b"a");
        assert_eq!(e[1].name(), b"bb.txt");
        assert_eq!(e[1].size(), 2);
    }

    #[test]
    fn decodes_stored() {
        let a = archive(&[stored(b"a", b"Hello ARC")]);
        let arc = ArcArchive::open(&a[..]).unwrap();
        assert_eq!(read(&arc, 0).unwrap(), b"Hello ARC");
    }

    #[test]
    fn decodes_packed_rle90() {
        // Method 3 over data with no 0x90 and no runs → RLE90 is identity.
        let content = b"abcdef";
        let a = archive(&[member(0x03, b"p", content, content)]);
        let arc = ArcArchive::open(&a[..]).unwrap();
        assert_eq!(read(&arc, 0).unwrap(), content);
    }

    #[test]
    fn decodes_squeezed() {
        // Method 4: a squeeze stream decoding to "A" (then identity RLE90).
        let squeeze_stream = [0x01, 0x00, 0xBE, 0xFF, 0xFF, 0xFE, 0x02];
        let a = archive(&[member(0x04, b"s", &squeeze_stream, b"A")]);
        let arc = ArcArchive::open(&a[..]).unwrap();
        assert_eq!(read(&arc, 0).unwrap(), b"A");
    }

    #[test]
    fn nested_directory_path() {
        let dir = {
            let mut e = vec![0x1A, 0x1E];
            let mut nm = [0u8; 13];
            nm[..3].copy_from_slice(b"sub");
            e.extend_from_slice(&nm);
            e.extend_from_slice(&0u32.to_le_bytes());
            e.extend_from_slice(&[0, 0, 0, 0]);
            e.extend_from_slice(&0u16.to_le_bytes());
            e.extend_from_slice(&0u32.to_le_bytes());
            e
        };
        let pop = vec![0x1A, 0x1F];
        let a = archive(&[dir, stored(b"inner", b"x"), pop, stored(b"outer", b"y")]);
        let arc = ArcArchive::open(&a[..]).unwrap();
        let e = arc.entries();
        assert_eq!(e[0].name(), b"sub");
        assert!(e[0].is_dir());
        assert_eq!(e[1].name(), b"sub/inner");
        assert_eq!(e[2].name(), b"outer");
    }

    #[test]
    fn crc_mismatch_errors() {
        let mut a = archive(&[stored(b"a", b"A")]);
        // Corrupt the stored byte (last data byte before the end marker).
        let data_byte = a.len() - 3;
        a[data_byte] ^= 0xFF;
        let arc = ArcArchive::open(&a[..]).unwrap();
        assert!(read(&arc, 0).is_err());
    }

    #[test]
    fn decodes_squashed() {
        // Method 9: Unix compress (maxbits 13, block mode), no RLE90 layer.
        let content = b"squash squash squash squash!";
        let stream = hex(b"73e2d40933070d8880030b1e1448d020c2862100");
        let a = archive(&[member(0x09, b"s", &stream, content)]);
        let arc = ArcArchive::open(&a[..]).unwrap();
        assert_eq!(read(&arc, 0).unwrap(), content);
    }

    #[test]
    fn decodes_crunched_lzw() {
        // Method 8: a leading 0x0c, then compress (maxbits 12), then RLE90.
        let content = b"crunch lzw crunch lzw crunch";
        let stream = hex(b"0c63e4d47133060d08367aee800838b0e0c1840b05124403");
        let a = archive(&[member(0x08, b"c", &stream, content)]);
        let arc = ArcArchive::open(&a[..]).unwrap();
        assert_eq!(read(&arc, 0).unwrap(), content);
    }

    #[test]
    fn decodes_compressed_7f() {
        // Method 0x7f: a leading flags byte (0x0c → 12-bit), then compress.
        let content = b"compressed method 7f: foofoofoo barbarbar foofoofoo";
        let stream = hex(b"0c63deb48123a7cc9c3965c8806853860e9a370a6f98d101c2cc9b3716315e0421268c9c8e1f3d56bc983123");
        let a = archive(&[member(0x7f, b"cmp", &stream, content)]);
        let arc = ArcArchive::open(&a[..]).unwrap();
        assert_eq!(read(&arc, 0).unwrap(), content);
    }

    #[test]
    fn unsupported_method_errors() {
        // 0x0c is not a real ARC method; it must surface as an error.
        let a = archive(&[member(0x0c, b"c", b"....", b"....")]);
        let arc = ArcArchive::open(&a[..]).unwrap();
        assert!(read(&arc, 0).is_err());
    }
}
