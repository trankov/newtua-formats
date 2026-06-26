//! Zoo (`.zoo`) — the cross-platform Zoo archiver container.
//!
//! A Zoo archive is a header followed by a singly-linked list of directory
//! entries; each entry points at its own data and at the next entry. There is
//! no central directory — parsing walks the `nextdirentry` chain until an entry
//! with a zero link terminates it. Members are stored verbatim or compressed
//! with one of two methods: LZW (method 1) or LZH-static (method 2). Decoded
//! contents are checked against a per-entry CRC-16/ARC.
//!
//! This module covers the container, stored members, and method 2 (LZH-static).
//! Method 1 (Zoo's LZW) is a separate roadmap item and is reported as
//! `Unsupported`.
//!
//! Faithful port of XADMaster's `XADZooParser.m` and `XADLZHStaticHandle.m`.

use std::io::{self, Read, Write};

use newtua_common::bitreader::BitReaderMsb;
use newtua_common::crc16::crc16_arc;
use newtua_common::lzss::LzssWindow;
use newtua_common::prefixcode::PrefixCode;

/// Magic at file offset 0x14 and at the start of every directory entry.
const MAGIC: u32 = 0xfdc4a7dc;
/// Sliding-window size exponent used by every Zoo LZH-static member.
const WINDOW_BITS: u32 = 13;

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn unsupported(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, msg.into())
}

/// Read a little-endian `u8`/`u16`/`u32` at `*pos`, advancing it. Each is
/// bounds-checked against `data` so a truncated archive yields a clean error.
fn rd_u8(data: &[u8], pos: &mut usize) -> io::Result<u8> {
    let b = *data
        .get(*pos)
        .ok_or_else(|| invalid("zoo: truncated entry"))?;
    *pos += 1;
    Ok(b)
}

fn rd_u16(data: &[u8], pos: &mut usize) -> io::Result<u16> {
    let s = data
        .get(*pos..*pos + 2)
        .ok_or_else(|| invalid("zoo: truncated entry"))?;
    *pos += 2;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn rd_u32(data: &[u8], pos: &mut usize) -> io::Result<u32> {
    let s = data
        .get(*pos..*pos + 4)
        .ok_or_else(|| invalid("zoo: truncated entry"))?;
    *pos += 4;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// One member of a Zoo archive.
pub struct ZooEntry {
    /// Full path as raw bytes (charset decoding is the caller's job): the long
    /// name when present, otherwise the short 8.3 name, prefixed by the stored
    /// directory and suffixed with `;<generation>` exactly as `XADZooParser`.
    name: Vec<u8>,
    method: u8,
    crc16: u16,
    uncompsize: usize,
    compsize: usize,
    dataoffset: usize,
    is_deleted: bool,
}

impl ZooEntry {
    /// The member's path as raw bytes.
    pub fn name(&self) -> &[u8] {
        &self.name
    }
    /// The member's decompressed size in bytes.
    pub fn size(&self) -> u64 {
        self.uncompsize as u64
    }
    /// Zoo stores no directory entries — directories appear only as path
    /// prefixes — so this is always `false`. Provided for API parity.
    pub fn is_dir(&self) -> bool {
        false
    }
    /// Whether the entry is flagged deleted in the directory.
    pub fn is_deleted(&self) -> bool {
        self.is_deleted
    }
    /// The compression method: 0 stored, 1 LZW, 2 LZH-static.
    pub fn method(&self) -> u8 {
        self.method
    }
}

/// A parsed Zoo archive.
pub struct ZooArchive {
    data: Vec<u8>,
    entries: Vec<ZooEntry>,
}

impl ZooArchive {
    /// Structural format check: long enough for the header and the archive
    /// magic at offset 0x14.
    pub fn recognize(data: &[u8]) -> bool {
        data.len() >= 0x22 && data[0x14..0x18] == MAGIC.to_le_bytes()
    }

    /// Read and parse a Zoo archive from `r`.
    pub fn open<R: Read>(mut r: R) -> io::Result<Self> {
        let mut data = Vec::new();
        r.read_to_end(&mut data)?;
        if !Self::recognize(&data) {
            return Err(invalid("zoo: not a Zoo archive"));
        }
        let entries = parse(&data)?;
        Ok(Self { data, entries })
    }

    /// The members, in directory order.
    pub fn entries(&self) -> &[ZooEntry] {
        &self.entries
    }

    /// Decode member `idx` and write it to `out`. Stored members are copied;
    /// method 2 is decoded with LZH-static; method 1 (LZW) is `Unsupported`.
    /// The decoded bytes are verified against the entry's CRC-16/ARC.
    pub fn read_entry(&self, idx: usize, out: &mut dyn Write) -> io::Result<()> {
        let e = self
            .entries
            .get(idx)
            .ok_or_else(|| invalid("zoo: index out of range"))?;
        let comp = self
            .data
            .get(e.dataoffset..e.dataoffset + e.compsize)
            .ok_or_else(|| invalid("zoo: member data past end of file"))?;

        let decoded = match e.method {
            0 => comp
                .get(..e.uncompsize)
                .ok_or_else(|| invalid("zoo: stored member shorter than its size"))?
                .to_vec(),
            2 => {
                let mut buf = vec![0u8; e.uncompsize];
                LzhStaticReader::new(comp, WINDOW_BITS).read_exact(&mut buf)?;
                buf
            }
            1 => return Err(unsupported("zoo: LZW (method 1) is not supported")),
            other => return Err(unsupported(format!("zoo: unsupported method {other}"))),
        };

        if crc16_arc(&decoded) != e.crc16 {
            return Err(invalid("zoo: CRC-16 mismatch"));
        }
        out.write_all(&decoded)
    }
}

/// Read a name field of `len` bytes at `*pos`, stripping a single trailing NUL
/// if present (Zoo writes the terminator inconsistently).
fn read_name(data: &[u8], pos: &mut usize, len: usize) -> io::Result<Vec<u8>> {
    let s = data
        .get(*pos..*pos + len)
        .ok_or_else(|| invalid("zoo: truncated name"))?;
    *pos += len;
    let end = if s.last() == Some(&0) { len - 1 } else { len };
    Ok(s[..end].to_vec())
}

/// Walk the directory chain from `firstoffset` and collect entries.
fn parse(data: &[u8]) -> io::Result<Vec<ZooEntry>> {
    let mut start = 0x18usize;
    let firstoffset = rd_u32(data, &mut start)? as usize;

    let mut entries = Vec::new();
    let mut pos = firstoffset;
    loop {
        let magic = rd_u32(data, &mut pos)?;
        if magic != MAGIC {
            return Err(invalid("zoo: bad directory entry magic"));
        }

        let typ = rd_u8(data, &mut pos)?;
        let method = rd_u8(data, &mut pos)?;
        let nextdirentry = rd_u32(data, &mut pos)? as usize;
        let dataoffset = rd_u32(data, &mut pos)? as usize;
        let _date = rd_u16(data, &mut pos)?;
        let _time = rd_u16(data, &mut pos)?;
        let crc16 = rd_u16(data, &mut pos)?;
        let uncompsize = rd_u32(data, &mut pos)? as usize;
        let compsize = rd_u32(data, &mut pos)? as usize;
        let _creatorversion = rd_u8(data, &mut pos)?;
        let _minversion = rd_u8(data, &mut pos)?;
        let deleted = rd_u8(data, &mut pos)?;
        let _structure = rd_u8(data, &mut pos)?;
        let _commentoffset = rd_u32(data, &mut pos)?;
        let _commentlength = rd_u16(data, &mut pos)?;

        if nextdirentry == 0 {
            break;
        }

        // Short 8.3 name: 13 bytes, truncated at the first NUL (max 12).
        let shortbuf = data
            .get(pos..pos + 13)
            .ok_or_else(|| invalid("zoo: truncated short name"))?;
        pos += 13;
        let shortlen = shortbuf.iter().take(12).position(|&b| b == 0).unwrap_or(12);
        let shortname = shortbuf[..shortlen].to_vec();

        let mut longname: Option<Vec<u8>> = None;
        let mut dirname: Option<Vec<u8>> = None;
        let mut generation = 0u8;

        if typ == 2 {
            let varlength = rd_u16(data, &mut pos)? as usize;
            let _tzoffs = rd_u8(data, &mut pos)?;
            let _crcent = rd_u16(data, &mut pos)?;

            let longnamelength = if varlength >= 1 {
                rd_u8(data, &mut pos)? as usize
            } else {
                0
            };
            let dirlength = if varlength >= 2 {
                rd_u8(data, &mut pos)? as usize
            } else {
                0
            };

            if longnamelength != 0 && varlength >= 2 + longnamelength {
                longname = Some(read_name(data, &mut pos, longnamelength)?);
            }
            if dirlength != 0 && varlength >= 2 + longnamelength + dirlength {
                dirname = Some(read_name(data, &mut pos, dirlength)?);
            }

            let total = 2 + longnamelength + dirlength;
            if varlength > total + 2 {
                let _system = rd_u16(data, &mut pos)?;
            }
            if varlength > total + 5 {
                let _perm = rd_u16(data, &mut pos)?;
                let _perm_hi = rd_u8(data, &mut pos)?;
            }
            if varlength > total + 6 {
                generation = rd_u8(data, &mut pos)?;
            }
            if varlength > total + 8 {
                let _extraversion = rd_u16(data, &mut pos)?;
            }
        }

        let name = build_name(
            &shortname,
            longname.as_deref(),
            dirname.as_deref(),
            generation,
        );

        entries.push(ZooEntry {
            name,
            method,
            crc16,
            uncompsize,
            compsize,
            dataoffset,
            is_deleted: deleted != 0,
        });

        pos = nextdirentry;
    }

    Ok(entries)
}

/// Assemble an entry's path: `dir/` prefix (if any), then the long name or the
/// short name, then `;<generation>` (if non-zero), matching `XADZooParser`.
fn build_name(
    short: &[u8],
    longname: Option<&[u8]>,
    dir: Option<&[u8]>,
    generation: u8,
) -> Vec<u8> {
    if longname.is_none() && dir.is_none() && generation == 0 {
        return short.to_vec();
    }
    let mut name = Vec::new();
    if let Some(d) = dir {
        name.extend_from_slice(d);
        name.push(b'/');
    }
    name.extend_from_slice(longname.unwrap_or(short));
    if generation != 0 {
        name.extend_from_slice(format!(";{generation}").as_bytes());
    }
    name
}

/// LZH-static decoder (Zoo method 2): an LZSS sliding window driven by two
/// per-block prefix codes — one for literals and match lengths, one for match
/// distances. Stops once the caller has drained `uncompsize` bytes.
///
/// Faithful port of `XADLZHStaticHandle`.
struct LzhStaticReader<R> {
    bits: BitReaderMsb<R>,
    window: LzssWindow,
    window_bits: u32,
    buffer: Vec<u8>,
    buffer_pos: usize,
    finished: bool,
}

impl<R: Read> LzhStaticReader<R> {
    fn new(inner: R, window_bits: u32) -> Self {
        Self {
            bits: BitReaderMsb::new(inner),
            window: LzssWindow::new(1 << window_bits),
            window_bits,
            buffer: Vec::new(),
            buffer_pos: 0,
            finished: false,
        }
    }

    /// Read an `n`-bit field, treating a short read as a truncated stream.
    fn rb(&mut self, n: u8, msg: &'static str) -> io::Result<u32> {
        self.bits.read(n)?.ok_or_else(|| invalid(msg))
    }

    /// Decode one whole block into `buffer`: its block size, the two prefix
    /// codes, then that many literal/match tokens. Returns `false` at end of
    /// input (no more blocks).
    fn decode_block(&mut self) -> io::Result<bool> {
        let blocksize = match self.bits.read(16)? {
            Some(n) => n,
            None => return Ok(false),
        };
        let literalcode = self.parse_literal_code()?;
        let width = if self.window_bits < 15 { 4 } else { 5 };
        let distancecode = self.parse_code_of_width(width, -1)?;

        for _ in 0..blocksize {
            let lit = literalcode
                .next_symbol_msb(&mut self.bits)?
                .ok_or_else(|| invalid("zoo: truncated LZH stream"))?;
            if lit < 0x100 {
                self.window.emit_literal(lit as u8, &mut self.buffer);
            } else {
                let length = (lit - 0x100 + 3) as usize;
                let bit = distancecode
                    .next_symbol_msb(&mut self.bits)?
                    .ok_or_else(|| invalid("zoo: truncated LZH stream"))?;
                let offset = match bit {
                    0 => 1,
                    1 => 2,
                    b => {
                        (1usize << (b - 1))
                            + self.rb((b - 1) as u8, "zoo: truncated LZH stream")? as usize
                            + 1
                    }
                };
                self.window.emit_match(offset, length, &mut self.buffer);
            }
        }
        Ok(true)
    }

    /// `allocAndParseCodeOfWidth:specialIndex:` — read a prefix code whose
    /// symbol count and per-symbol lengths are serialised `bits`-wide.
    fn parse_code_of_width(&mut self, bits: u8, special_index: i32) -> io::Result<PrefixCode> {
        let num = self.rb(bits, "zoo: truncated LZH code")? as i32;
        if num == 0 {
            let val = self.rb(bits, "zoo: truncated LZH code")?;
            return Ok(PrefixCode::single_symbol(val as i32));
        }

        let mut lengths = vec![0u32; num as usize];
        let mut n = 0i32;
        while n < num {
            let mut len = self.rb(3, "zoo: truncated LZH code")?;
            if len == 7 {
                while self.rb(1, "zoo: truncated LZH code")? != 0 {
                    len += 1;
                }
            }
            lengths[n as usize] = len;
            n += 1;

            if n == special_index {
                let zeroes = self.rb(2, "zoo: truncated LZH code")?;
                for _ in 0..zeroes {
                    if n >= num {
                        return Err(invalid("zoo: LZH code length overflow"));
                    }
                    lengths[n as usize] = 0;
                    n += 1;
                }
            }
        }
        Ok(PrefixCode::from_lengths(&lengths, 16, true))
    }

    /// `allocAndParseLiteralCode` — the literal/length code, whose own lengths
    /// are run-length coded through a 5-bit-wide meta code.
    fn parse_literal_code(&mut self) -> io::Result<PrefixCode> {
        let metacode = self.parse_code_of_width(5, 3)?;

        let num = self.rb(9, "zoo: truncated LZH literal code")? as i32;
        if num == 0 {
            let val = self.rb(9, "zoo: truncated LZH literal code")?;
            return Ok(PrefixCode::single_symbol(val as i32));
        }

        let mut lengths = vec![0u32; num as usize];
        let mut n = 0i32;
        while n < num {
            let c = metacode
                .next_symbol_msb(&mut self.bits)?
                .ok_or_else(|| invalid("zoo: truncated LZH literal code"))?;
            if c <= 2 {
                let zeros = match c {
                    0 => 1,
                    1 => self.rb(4, "zoo: truncated LZH literal code")? + 3,
                    _ => self.rb(9, "zoo: truncated LZH literal code")? + 20,
                };
                if n + zeros as i32 > num {
                    return Err(invalid("zoo: LZH literal length overflow"));
                }
                for _ in 0..zeros {
                    lengths[n as usize] = 0;
                    n += 1;
                }
            } else {
                lengths[n as usize] = (c - 2) as u32;
                n += 1;
            }
        }
        Ok(PrefixCode::from_lengths(&lengths, 16, true))
    }
}

impl<R: Read> Read for LzhStaticReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.buffer_pos >= self.buffer.len() && !self.finished {
            self.buffer.clear();
            self.buffer_pos = 0;
            if !self.decode_block()? {
                self.finished = true;
            }
        }
        let avail = self.buffer.len() - self.buffer_pos;
        let n = avail.min(out.len());
        out[..n].copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + n]);
        self.buffer_pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAGIC_BYTES: [u8; 4] = [0xdc, 0xa7, 0xc4, 0xfd];

    /// One member to place in a test archive.
    struct E {
        typ: u8,
        method: u8,
        crc16: u16,
        uncompsize: u32,
        short: &'static str,
        longname: Option<&'static [u8]>,
        dir: Option<&'static [u8]>,
        generation: u8,
        deleted: bool,
        data: Vec<u8>,
    }

    impl E {
        /// A stored member with content `c`.
        fn stored(typ: u8, short: &'static str, c: &[u8]) -> Self {
            E {
                typ,
                method: 0,
                crc16: crc16_arc(c),
                uncompsize: c.len() as u32,
                short,
                longname: None,
                dir: None,
                generation: 0,
                deleted: false,
                data: c.to_vec(),
            }
        }
    }

    /// Build a 38-byte fixed entry header plus name/var fields.
    fn build_record(e: &E) -> Vec<u8> {
        let mut r = vec![0u8; 38];
        r[0..4].copy_from_slice(&MAGIC_BYTES);
        r[4] = e.typ;
        r[5] = e.method;
        // 6..10 nextdirentry, 10..14 dataoffset: patched by build_zoo.
        r[18..20].copy_from_slice(&e.crc16.to_le_bytes());
        r[20..24].copy_from_slice(&e.uncompsize.to_le_bytes());
        r[24..28].copy_from_slice(&(e.data.len() as u32).to_le_bytes());
        r[30] = e.deleted as u8;

        let mut short = [0u8; 13];
        let sb = e.short.as_bytes();
        short[..sb.len()].copy_from_slice(sb);
        r.extend_from_slice(&short);

        if e.typ == 2 {
            let lnl = e.longname.map(|l| l.len()).unwrap_or(0);
            let dl = e.dir.map(|d| d.len()).unwrap_or(0);
            let total = 2 + lnl + dl;

            let mut content = vec![lnl as u8, dl as u8];
            if let Some(l) = e.longname {
                content.extend_from_slice(l);
            }
            if let Some(d) = e.dir {
                content.extend_from_slice(d);
            }
            let varlength = if e.generation > 0 {
                content.extend_from_slice(&[0, 0]); // system
                content.extend_from_slice(&[0, 0, 0]); // permissions
                content.push(e.generation); // generation
                (total + 7) as u16
            } else {
                total as u16
            };

            r.extend_from_slice(&varlength.to_le_bytes());
            r.push(0); // tzoffs
            r.extend_from_slice(&[0, 0]); // crcent
            r.extend_from_slice(&content);
        }
        r
    }

    /// Assemble a valid Zoo image from `entries`, wiring the directory chain and
    /// the data offsets.
    fn build_zoo(entries: &[E]) -> Vec<u8> {
        const HLEN: usize = 0x22;
        let mut recs: Vec<Vec<u8>> = entries.iter().map(build_record).collect();

        let mut offs = Vec::new();
        let mut off = HLEN;
        for r in &recs {
            offs.push(off);
            off += r.len();
        }
        let term_off = off;
        let data_start = term_off + 38;

        let mut data_offs = Vec::new();
        let mut doff = data_start;
        for e in entries {
            data_offs.push(doff);
            doff += e.data.len();
        }

        for (i, r) in recs.iter_mut().enumerate() {
            let next = if i + 1 < entries.len() {
                offs[i + 1]
            } else {
                term_off
            };
            r[6..10].copy_from_slice(&(next as u32).to_le_bytes());
            r[10..14].copy_from_slice(&(data_offs[i] as u32).to_le_bytes());
        }

        let mut out = vec![0u8; HLEN];
        out[0x14..0x18].copy_from_slice(&MAGIC_BYTES);
        out[0x18..0x1c].copy_from_slice(&(HLEN as u32).to_le_bytes());
        for r in &recs {
            out.extend_from_slice(r);
        }
        // Terminator entry: valid magic, zero next link.
        let mut term = vec![0u8; 38];
        term[0..4].copy_from_slice(&MAGIC_BYTES);
        out.extend_from_slice(&term);
        for e in entries {
            out.extend_from_slice(&e.data);
        }
        out
    }

    fn read(arc: &ZooArchive, idx: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        arc.read_entry(idx, &mut out)?;
        Ok(out)
    }

    #[test]
    fn recognizes_valid_magic() {
        let zoo = build_zoo(&[E::stored(0, "A.TXT", b"hi")]);
        assert!(ZooArchive::recognize(&zoo));
    }

    #[test]
    fn rejects_short_data() {
        assert!(!ZooArchive::recognize(&[0u8; 16]));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut zoo = build_zoo(&[E::stored(0, "A.TXT", b"hi")]);
        zoo[0x14] ^= 0xff;
        assert!(!ZooArchive::recognize(&zoo));
    }

    #[test]
    fn lists_short_named_members() {
        let zoo = build_zoo(&[
            E::stored(0, "HELLO.TXT", b"Hello, Zoo!"),
            E::stored(0, "DATA.BIN", b"\x00\x01\x02"),
        ]);
        let arc = ZooArchive::open(&zoo[..]).unwrap();
        let e = arc.entries();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].name(), b"HELLO.TXT");
        assert_eq!(e[1].name(), b"DATA.BIN");
        assert_eq!(e[0].size(), 11);
    }

    #[test]
    fn stops_at_zero_next_link() {
        // A single real entry; the chain terminates at the zero-link header.
        let zoo = build_zoo(&[E::stored(0, "ONE.TXT", b"only")]);
        let arc = ZooArchive::open(&zoo[..]).unwrap();
        assert_eq!(arc.entries().len(), 1);
    }

    #[test]
    fn extracts_stored_member() {
        let content = b"The quick brown fox jumps over the lazy dog.";
        let zoo = build_zoo(&[E::stored(0, "FOX.TXT", content)]);
        let arc = ZooArchive::open(&zoo[..]).unwrap();
        assert_eq!(read(&arc, 0).unwrap(), content);
    }

    #[test]
    fn type2_long_name_overrides_short() {
        let mut e = E::stored(2, "SHORT.TXT", b"data");
        e.longname = Some(b"a-much-longer-name.txt");
        let zoo = build_zoo(&[e]);
        let arc = ZooArchive::open(&zoo[..]).unwrap();
        assert_eq!(arc.entries()[0].name(), b"a-much-longer-name.txt");
    }

    #[test]
    fn type2_directory_prefixes_name() {
        let mut e = E::stored(2, "F.TXT", b"data");
        e.longname = Some(b"file.txt");
        e.dir = Some(b"sub/folder");
        let zoo = build_zoo(&[e]);
        let arc = ZooArchive::open(&zoo[..]).unwrap();
        assert_eq!(arc.entries()[0].name(), b"sub/folder/file.txt");
    }

    #[test]
    fn type2_generation_is_appended() {
        let mut e = E::stored(2, "GEN.TXT", b"data");
        e.generation = 7;
        let zoo = build_zoo(&[e]);
        let arc = ZooArchive::open(&zoo[..]).unwrap();
        assert_eq!(arc.entries()[0].name(), b"GEN.TXT;7");
    }

    #[test]
    fn crc_mismatch_is_error() {
        let content = b"checksummed";
        let zoo = build_zoo(&[E::stored(0, "C.TXT", content)]);
        let mut arc = ZooArchive::open(&zoo[..]).unwrap();
        let off = arc.entries()[0].dataoffset;
        arc.data[off] ^= 0xff;
        assert!(read(&arc, 0).is_err());
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
    /// `byte` (every code is the zero-length single-symbol form).
    fn lzh_repeat(byte: u8, count: u16) -> Vec<u8> {
        let mut w = BitW::new();
        w.put(count as u32, 16); // block size = token count
        w.put(0, 5); // metacode: num=0 (single symbol)
        w.put(0, 5); // metacode value
        w.put(0, 9); // literal code: num=0 (single symbol)
        w.put(byte as u32, 9); // literal value
        w.put(0, 4); // distance code: num=0 (single symbol)
        w.put(0, 4); // distance value (unused)
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
        w.put(0, 4); // distance single symbol = 0 -> offset 1
        w.put(0, 4);
        w.finish()
    }

    #[test]
    fn lzh_decodes_repeated_literal() {
        let expected = vec![b'Z'; 50];
        let stream = lzh_repeat(b'Z', 50);
        let mut e = E::stored(0, "R.BIN", &expected);
        e.method = 2;
        e.data = stream;
        let zoo = build_zoo(&[e]);
        let arc = ZooArchive::open(&zoo[..]).unwrap();
        assert_eq!(read(&arc, 0).unwrap(), expected);
    }

    #[test]
    fn lzh_decodes_offset_one_matches() {
        let expected = vec![0u8; 30]; // 10 matches * length 3
        let stream = lzh_match_zeros(10);
        let mut e = E::stored(0, "M.BIN", &expected);
        e.method = 2;
        e.data = stream;
        let zoo = build_zoo(&[e]);
        let arc = ZooArchive::open(&zoo[..]).unwrap();
        assert_eq!(read(&arc, 0).unwrap(), expected);
    }

    #[test]
    fn lzw_method_is_unsupported() {
        let mut e = E::stored(0, "L.BIN", b"whatever");
        e.method = 1;
        let zoo = build_zoo(&[e]);
        let arc = ZooArchive::open(&zoo[..]).unwrap();
        let err = read(&arc, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn bad_entry_magic_is_error() {
        let mut zoo = build_zoo(&[E::stored(0, "A.TXT", b"hi")]);
        // First directory entry begins at firstoffset 0x22; clobber its magic.
        zoo[0x22] ^= 0xff;
        assert!(ZooArchive::open(&zoo[..]).is_err());
    }
}
