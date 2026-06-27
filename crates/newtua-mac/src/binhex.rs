//! BinHex 4.0 (`.hqx`) — the classic Macintosh ASCII transport encoding.
//!
//! A BinHex file is an ASCII envelope around the two forks (data + resource) of
//! one Mac file. Decoding runs three layers, in order:
//!
//! 1. **ASCII / hqx (6-bit).** After a `:` marker the payload is text in a
//!    64-symbol alphabet; each symbol is its index in that alphabet. Bytes not
//!    in the alphabet (newlines, spaces, tabs) are silently skipped; a closing
//!    `:` ends the stream.
//! 2. **6→8 unpacking.** Base64-style: four 6-bit codes make three bytes.
//! 3. **RLE90.** On top of the unpacked bytes, the shared [`Rle90Reader`].
//!
//! The fully decoded byte stream is a header followed by the two forks, each
//! protected by a CRC-16/CCITT (XMODEM). Faithful port of XADMaster's
//! `XADBinHexParser.m` (both the parser and the `XADBinHexHandle` codec).

use std::io::{self, Read, Write};

use newtua_common::crc16::crc16_ccitt;
use newtua_common::rle90::Rle90Reader;

/// The 64-symbol hqx alphabet, copied byte-for-byte from XADMaster's `GetBits`.
/// It deliberately omits some characters (the digit `7`, the letters `O`, `W`,
/// `g`, `n`, `o`); a symbol's value is its index here.
const ALPHABET: &[u8] = b"!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr";

/// Reverse map: alphabet byte -> its 6-bit code, `0xFF` for bytes not in the
/// alphabet. Const-built from [`ALPHABET`], so [`HqxReader::get_bits`] is an
/// O(1) table lookup rather than a linear scan of all 64 symbols per code.
const REV: [u8; 256] = {
    let mut table = [0xFFu8; 256];
    let mut i = 0;
    while i < ALPHABET.len() {
        table[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
};

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// The 6→8 hqx decoder: a [`Read`] over the ASCII payload that yields the
/// unpacked (pre-RLE90) bytes. It maps alphabet characters to 6-bit codes,
/// skips anything else, and ends at the closing `:`.
struct HqxReader<'a> {
    data: &'a [u8],
    pos: usize,
    /// Output-byte position within the three-byte unpack cycle (0, 1, 2).
    phase: u8,
    prev_bits: u8,
    eof: bool,
}

impl<'a> HqxReader<'a> {
    /// Start decoding at `start`, the byte just after the opening `:` marker.
    fn new(data: &'a [u8], start: usize) -> Self {
        Self {
            data,
            pos: start,
            phase: 0,
            prev_bits: 0,
            eof: false,
        }
    }

    /// Next 6-bit code, skipping non-alphabet bytes. `None` at the closing `:`
    /// or when the input runs out (XADMaster's `GetBits` / `CSByteStreamEOF`).
    fn get_bits(&mut self) -> Option<u8> {
        loop {
            let byte = *self.data.get(self.pos)?;
            self.pos += 1;
            if byte == b':' {
                return None;
            }
            let code = REV[byte as usize];
            if code != 0xFF {
                return Some(code);
            }
        }
    }

    /// Next unpacked byte, or `None` at end of stream. The three-byte cycle is a
    /// direct port of `DecodeByte`; any `get_bits` EOF ends the stream, matching
    /// XADMaster's `CSByteStreamEOF` longjmp out of the codec.
    fn decode_byte(&mut self) -> Option<u8> {
        let phase = self.phase;
        self.phase = if phase == 2 { 0 } else { phase + 1 };
        match phase {
            0 => {
                let b1 = self.get_bits()?;
                let b2 = self.get_bits()?;
                self.prev_bits = b2;
                Some((b1 << 2) | (b2 >> 4))
            }
            1 => {
                let b1 = self.prev_bits;
                let b2 = self.get_bits()?;
                self.prev_bits = b2;
                Some((b1 << 4) | (b2 >> 2))
            }
            _ => {
                let b1 = self.prev_bits;
                let b2 = self.get_bits()?;
                Some((b1 << 6) | b2)
            }
        }
    }
}

impl Read for HqxReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut n = 0;
        while n < out.len() {
            if self.eof {
                break;
            }
            match self.decode_byte() {
                Some(b) => {
                    out[n] = b;
                    n += 1;
                }
                // Latch EOF: once the closing ':' (or the end of input) is hit,
                // every later read must keep returning 0, never resuming the
                // decode past it.
                None => self.eof = true,
            }
        }
        Ok(n)
    }
}

/// One fork (data or resource) of the single Mac file inside a BinHex archive.
/// Both forks share the same name; the data fork is always present, the
/// resource fork only when its length is non-zero.
pub struct BinHexEntry {
    name: Vec<u8>,
    size: u32,
    is_resource_fork: bool,
    file_type: [u8; 4],
    creator: [u8; 4],
    finder_flags: u16,
    /// Offset of this fork's bytes within the decoded stream.
    offset: usize,
}

impl BinHexEntry {
    /// The file's name as raw bytes (MacRoman; charset decoding is the caller's
    /// job). Both forks carry the same name.
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
}

/// A parsed BinHex 4.0 archive: one Mac file's header plus its two forks,
/// decoded out of the ASCII envelope.
pub struct BinHexArchive {
    decoded: Vec<u8>,
    entries: Vec<BinHexEntry>,
}

impl BinHexArchive {
    /// Structural format check: find the envelope marker, the `:` data start,
    /// then decode the header and verify its CRC. Port of XADMaster's
    /// `recognizeFileWithHandle:`.
    pub fn recognize(data: &[u8]) -> bool {
        let Some(start) = find_data_start(data) else {
            return false;
        };
        let mut r = Rle90Reader::new(HqxReader::new(data, start));

        let mut namelen = [0u8; 1];
        if r.read_exact(&mut namelen).is_err() {
            return false;
        }
        let namelen = namelen[0] as usize;
        if !(1..=63).contains(&namelen) {
            return false;
        }

        // Decode the rest of the header (name + 19 fixed bytes + 2 CRC bytes)
        // into one buffer alongside the namelen byte, then check its CRC.
        let mut header = vec![0u8; namelen + 22];
        header[0] = namelen as u8;
        if r.read_exact(&mut header[1..]).is_err() {
            return false;
        }
        header_crc_ok(&header)
    }

    /// Read and parse a BinHex archive from `r`.
    pub fn open<R: Read>(mut r: R) -> io::Result<Self> {
        let mut raw = Vec::new();
        r.read_to_end(&mut raw)?;
        let start =
            find_data_start(&raw).ok_or_else(|| invalid("binhex: no BinHex data marker"))?;

        // Run the three-layer pipeline (hqx 6->8, then RLE90) into one buffer;
        // the forks are then sliced out by absolute offset, matching the
        // reference's random-access reads.
        let mut decoded = Vec::new();
        Rle90Reader::new(HqxReader::new(&raw, start)).read_to_end(&mut decoded)?;

        let entries = parse(&decoded)?;
        Ok(Self { decoded, entries })
    }

    /// The forks, in order: data fork first, then the resource fork if present.
    pub fn entries(&self) -> &[BinHexEntry] {
        &self.entries
    }

    /// Decode fork `idx` and write it to `out`, verifying its CRC-16/CCITT.
    pub fn read_entry(&self, idx: usize, out: &mut dyn Write) -> io::Result<()> {
        let e = self
            .entries
            .get(idx)
            .ok_or_else(|| invalid("binhex: entry index out of range"))?;

        let end = e.offset + e.size as usize;
        let fork = self
            .decoded
            .get(e.offset..end)
            .ok_or_else(|| invalid("binhex: fork data past end of stream"))?;
        let crc = self
            .decoded
            .get(end..end + 2)
            .ok_or_else(|| invalid("binhex: missing fork CRC"))?;
        let stored = u16::from_be_bytes([crc[0], crc[1]]);
        if crc16_ccitt(fork) != stored {
            return Err(invalid("binhex: fork CRC mismatch"));
        }

        out.write_all(fork)
    }
}

/// Locate the start of the encoded payload: the byte just after the `:` that
/// follows the envelope marker line. Port of `recognizeFileWithHandle:`'s
/// marker scan. `None` if the marker, its line break, or the `:` is missing.
fn find_data_start(data: &[u8]) -> Option<usize> {
    const MARKER: &[u8] = b"(This file must be converted with BinHex";

    let mut offs = data.windows(MARKER.len()).position(|w| w == MARKER)? + MARKER.len();
    while offs < data.len() && data[offs] != b'\n' && data[offs] != b'\r' {
        offs += 1;
    }
    if offs >= data.len() {
        return None;
    }
    while offs < data.len() && matches!(data[offs], b'\n' | b'\r' | b'\t' | b' ') {
        offs += 1;
    }
    if offs >= data.len() || data[offs] != b':' {
        return None;
    }
    Some(offs + 1)
}

/// Verify the header CRC. `buf` starts at the namelen byte; the CRC covers the
/// first `20 + namelen` bytes and is stored big-endian in the two bytes that
/// follow. Returns `false` if those CRC bytes are missing or the CRC disagrees.
fn header_crc_ok(buf: &[u8]) -> bool {
    let region = 20 + buf[0] as usize;
    match buf.get(region..region + 2) {
        Some(crc) => crc16_ccitt(&buf[..region]) == u16::from_be_bytes([crc[0], crc[1]]),
        None => false,
    }
}

/// Parse the decoded stream into fork entries, verifying the header CRC.
fn parse(buf: &[u8]) -> io::Result<Vec<BinHexEntry>> {
    let namelen = *buf.first().ok_or_else(|| invalid("binhex: empty header"))? as usize;
    if namelen > 63 {
        return Err(invalid("binhex: name length exceeds 63"));
    }

    let field = |off: usize, len: usize| -> io::Result<&[u8]> {
        buf.get(off..off + len)
            .ok_or_else(|| invalid("binhex: truncated header"))
    };

    let name = field(1, namelen)?.to_vec();
    let file_type: [u8; 4] = field(2 + namelen, 4)?.try_into().unwrap();
    let creator: [u8; 4] = field(6 + namelen, 4)?.try_into().unwrap();
    let finder_flags = u16::from_be_bytes(field(10 + namelen, 2)?.try_into().unwrap());
    let datalen = u32::from_be_bytes(field(12 + namelen, 4)?.try_into().unwrap());
    let resourcelen = u32::from_be_bytes(field(16 + namelen, 4)?.try_into().unwrap());

    if !header_crc_ok(buf) {
        return Err(invalid("binhex: header CRC mismatch"));
    }

    // Data fork always present; resource fork only when non-empty.
    let mut entries = vec![BinHexEntry {
        name: name.clone(),
        size: datalen,
        is_resource_fork: false,
        file_type,
        creator,
        finder_flags,
        offset: 22 + namelen,
    }];
    if resourcelen > 0 {
        entries.push(BinHexEntry {
            name,
            size: resourcelen,
            is_resource_fork: true,
            file_type,
            creator,
            finder_flags,
            offset: 24 + namelen + datalen as usize,
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_from(data: &[u8], start: usize) -> Vec<u8> {
        let mut out = Vec::new();
        Rle90Reader::new(HqxReader::new(data, start))
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    /// Mirror of `DecodeByte`: pack `data` into 6-bit codes and render them as
    /// alphabet characters (the inverse of [`HqxReader`]). The caller appends
    /// the closing `:`.
    fn hqx_encode(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let sym = |v: u8| ALPHABET[v as usize];
        for chunk in data.chunks(3) {
            let b0 = chunk[0];
            out.push(sym(b0 >> 2));
            match (chunk.get(1), chunk.get(2)) {
                (Some(&b1), Some(&b2)) => {
                    out.push(sym(((b0 & 3) << 4) | (b1 >> 4)));
                    out.push(sym(((b1 & 0xF) << 2) | (b2 >> 6)));
                    out.push(sym(b2 & 0x3F));
                }
                (Some(&b1), None) => {
                    out.push(sym(((b0 & 3) << 4) | (b1 >> 4)));
                    out.push(sym((b1 & 0xF) << 2));
                }
                (None, _) => {
                    out.push(sym((b0 & 3) << 4));
                }
            }
        }
        out
    }

    /// hqx-encode `data`, append the closing `:`, and run the full pipeline.
    fn roundtrip(data: &[u8]) -> Vec<u8> {
        let mut enc = hqx_encode(data);
        enc.push(b':');
        decode_from(&enc, 0)
    }

    #[test]
    fn alphabet_has_64_symbols() {
        assert_eq!(ALPHABET.len(), 64);
    }

    #[test]
    fn decodes_four_codes_into_three_bytes() {
        // Codes "#$% are alphabet indices 1,2,3,4. By DecodeByte:
        //   byte0 = (1<<2)|(2>>4) = 4
        //   byte1 = (2<<4)|(3>>2) = 32
        //   byte2 = (3<<6)|4      = 196
        // None is 0x90, so RLE90 passes them through unchanged.
        assert_eq!(decode_from(b"\"#$%:", 0), vec![4, 32, 196]);
    }

    #[test]
    fn skips_non_alphabet_bytes_between_codes() {
        // Newlines, tabs and spaces are not in the alphabet, so GetBits skips
        // them; the decoded bytes are unchanged.
        assert_eq!(decode_from(b"\"\n#\t$ %:", 0), vec![4, 32, 196]);
    }

    #[test]
    fn stops_at_closing_colon() {
        // After two codes -> one byte, the next GetBits hits ':' and ends the
        // stream, so only the first byte is produced.
        assert_eq!(decode_from(b"\"#:$%", 0), vec![4]);
    }

    #[test]
    fn rle90_run_expands_repeated_byte() {
        // Unpacked bytes [0x41, 0x90, 0x04] are an RLE90 run: 'A' four times.
        assert_eq!(roundtrip(&[0x41, 0x90, 0x04]), vec![0x41; 4]);
    }

    #[test]
    fn rle90_escaped_marker_is_literal_0x90() {
        assert_eq!(roundtrip(&[0x90, 0x00]), vec![0x90]);
    }

    #[test]
    fn rle90_run_after_escaped_marker_repeats_0x90() {
        assert_eq!(roundtrip(&[0x90, 0x00, 0x90, 0x03]), vec![0x90; 3]);
    }

    // --- container fixtures ---------------------------------------------------

    /// Mirror RLE90 encoder: produces a stream the shared `Rle90Reader` decodes
    /// back to `data`. Runs of >=2 identical bytes become `b 0x90 count`; a
    /// literal `0x90` becomes `0x90 0x00`.
    fn rle90_encode(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let b = data[i];
            let mut run = 1;
            while i + run < data.len() && data[i + run] == b && run < 255 {
                run += 1;
            }
            if b == 0x90 {
                out.extend_from_slice(&[0x90, 0x00]);
            } else {
                out.push(b);
            }
            if run >= 2 {
                out.extend_from_slice(&[0x90, run as u8]);
            }
            i += run;
        }
        out
    }

    /// Assemble the fully decoded stream (header + CRC + data fork + CRC +
    /// resource fork + CRC) for a single Mac file.
    fn mac_stream(
        name: &[u8],
        ftype: &[u8; 4],
        creator: &[u8; 4],
        flags: u16,
        data: &[u8],
        resource: &[u8],
    ) -> Vec<u8> {
        assert!(name.len() <= 63);
        let mut header = Vec::new();
        header.push(name.len() as u8);
        header.extend_from_slice(name);
        header.push(0); // version
        header.extend_from_slice(ftype);
        header.extend_from_slice(creator);
        header.extend_from_slice(&flags.to_be_bytes());
        header.extend_from_slice(&(data.len() as u32).to_be_bytes());
        header.extend_from_slice(&(resource.len() as u32).to_be_bytes());

        let mut stream = header.clone();
        stream.extend_from_slice(&crc16_ccitt(&header).to_be_bytes());
        stream.extend_from_slice(data);
        stream.extend_from_slice(&crc16_ccitt(data).to_be_bytes());
        stream.extend_from_slice(resource);
        stream.extend_from_slice(&crc16_ccitt(resource).to_be_bytes());
        stream
    }

    /// Wrap a decoded stream in the ASCII envelope: RLE90- then hqx-encode it,
    /// prefix the marker line, and bracket the payload with `:`.
    fn wrap_stream(stream: &[u8]) -> Vec<u8> {
        let hqx = hqx_encode(&rle90_encode(stream));
        let mut out = Vec::new();
        out.extend_from_slice(b"(This file must be converted with BinHex 4.0)\r\n:");
        out.extend_from_slice(&hqx);
        out.push(b':');
        out
    }

    fn build_hqx(
        name: &[u8],
        ftype: &[u8; 4],
        creator: &[u8; 4],
        flags: u16,
        data: &[u8],
        resource: &[u8],
    ) -> Vec<u8> {
        wrap_stream(&mac_stream(name, ftype, creator, flags, data, resource))
    }

    fn read_fork(arc: &BinHexArchive, idx: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        arc.read_entry(idx, &mut out)?;
        Ok(out)
    }

    #[test]
    fn recognizes_valid_archive() {
        let hqx = build_hqx(b"file", b"TEXT", b"ttxt", 0, b"hello", b"");
        assert!(BinHexArchive::recognize(&hqx));
    }

    #[test]
    fn rejects_data_without_marker() {
        assert!(!BinHexArchive::recognize(
            b"just some random bytes, no marker"
        ));
    }

    #[test]
    fn rejects_marker_without_data_colon() {
        let mut data = Vec::new();
        data.extend_from_slice(b"(This file must be converted with BinHex 4.0)\r\nno colon here");
        assert!(!BinHexArchive::recognize(&data));
    }

    #[test]
    fn rejects_zero_namelen() {
        // namelen 0 is outside recognise's 1..=63 range.
        let hqx = build_hqx(b"", b"TEXT", b"ttxt", 0, b"x", b"");
        assert!(!BinHexArchive::recognize(&hqx));
    }

    #[test]
    fn rejects_bad_header_crc() {
        let mut stream = mac_stream(b"file", b"TEXT", b"ttxt", 0, b"hello", b"");
        // Header CRC lives at offset 20 + namelen; corrupt its first byte.
        let crc_off = 20 + 4;
        stream[crc_off] ^= 0xFF;
        let hqx = wrap_stream(&stream);
        assert!(!BinHexArchive::recognize(&hqx));
    }

    #[test]
    fn lists_only_data_fork_when_no_resource() {
        let hqx = build_hqx(b"file", b"TEXT", b"ttxt", 0, b"hello", b"");
        let arc = BinHexArchive::open(&hqx[..]).unwrap();
        assert_eq!(arc.entries().len(), 1);
        assert!(!arc.entries()[0].is_resource_fork());
        assert_eq!(arc.entries()[0].name(), b"file");
        assert_eq!(arc.entries()[0].size(), 5);
    }

    #[test]
    fn lists_both_forks_when_resource_present() {
        let hqx = build_hqx(b"file", b"TEXT", b"ttxt", 0, b"hello", b"RES!");
        let arc = BinHexArchive::open(&hqx[..]).unwrap();
        assert_eq!(arc.entries().len(), 2);
        assert!(!arc.entries()[0].is_resource_fork());
        assert!(arc.entries()[1].is_resource_fork());
        assert_eq!(arc.entries()[1].size(), 4);
    }

    #[test]
    fn extracts_data_fork() {
        let hqx = build_hqx(b"file", b"TEXT", b"ttxt", 0, b"hello world", b"RES!");
        let arc = BinHexArchive::open(&hqx[..]).unwrap();
        assert_eq!(read_fork(&arc, 0).unwrap(), b"hello world");
    }

    #[test]
    fn extracts_resource_fork() {
        let hqx = build_hqx(
            b"file",
            b"TEXT",
            b"ttxt",
            0,
            b"hello world",
            b"resource data",
        );
        let arc = BinHexArchive::open(&hqx[..]).unwrap();
        assert_eq!(read_fork(&arc, 1).unwrap(), b"resource data");
    }

    #[test]
    fn parses_metadata() {
        let hqx = build_hqx(b"doc", b"PDF ", b"prvw", 0x2080, b"x", b"");
        let arc = BinHexArchive::open(&hqx[..]).unwrap();
        let e = &arc.entries()[0];
        assert_eq!(&e.file_type(), b"PDF ");
        assert_eq!(&e.creator(), b"prvw");
        assert_eq!(e.finder_flags(), 0x2080);
    }

    #[test]
    fn data_fork_crc_mismatch_errors() {
        let mut stream = mac_stream(b"file", b"TEXT", b"ttxt", 0, b"hello", b"");
        // Data fork CRC sits at offset 22 + namelen + datalen.
        let crc_off = 22 + 4 + 5;
        stream[crc_off] ^= 0xFF;
        let hqx = wrap_stream(&stream);
        let arc = BinHexArchive::open(&hqx[..]).unwrap();
        assert!(read_fork(&arc, 0).is_err());
    }

    #[test]
    fn open_rejects_bad_header_crc() {
        let mut stream = mac_stream(b"file", b"TEXT", b"ttxt", 0, b"hello", b"");
        stream[20 + 4] ^= 0xFF;
        let hqx = wrap_stream(&stream);
        assert!(BinHexArchive::open(&hqx[..]).is_err());
    }
}
