//! PackIt (`.pit`) — an early flat Macintosh archive: a stream of records, one
//! per file (up to two forks each), terminated by a `PEnd` marker.
//!
//! Each record starts with a four-byte signature that selects how it is stored:
//!
//! | Signature | Compression     | Encryption            |
//! |-----------|-----------------|-----------------------|
//! | `PMag`    | none            | none                  |
//! | `PMa4`    | StuffIt-Huffman | none                  |
//! | `PMa5`    | StuffIt-Huffman | XOR (key from PC-1)   |
//! | `PMa6`    | StuffIt-Huffman | DES (ECB)             |
//! | `PEnd`    | —               | end of archive        |
//!
//! For the compressed records the 94-byte file header, both forks and the
//! trailing CRC all live *inside* the compressed (and, if present, encrypted)
//! stream — so even the file name cannot be read without first decrypting and
//! decompressing. The read pipeline is therefore outside-in:
//! `Huffman( [DES|XOR( raw )] )`.
//!
//! Faithful port of XADMaster's `XADPackItParser`, `XADPackItXORHandle`,
//! `XADPackItDESHandle` and `XADStuffItHuffmanHandle`.
//!
//! # Known limitations (out of scope)
//!
//! * Filenames and passwords are handled as raw bytes (MacRoman); decoding to
//!   Unicode is the caller's job, as for BinHex / MacBinary.
//! * Dates and Finder flags are parsed into entry fields only; they are not
//!   applied to any extracted file.
//! * PackIt has no directories and no multi-volume archives.

use std::io::{self, Read, Write};

use newtua_common::crc16::crc16_ccitt;

use newtua_common::stuffit_huffman::StuffItHuffman;

use crate::des;

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn unexpected_eof() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "packit: unexpected end of data",
    )
}

/// The fixed header size at the front of every record's (decoded) stream.
const HEADER_SIZE: usize = 94;

// === public types =============================================================

/// One fork (data or resource) of one file in a PackIt archive.
pub struct PackItEntry {
    name: Vec<u8>,
    size: u32,
    is_resource_fork: bool,
    is_encrypted: bool,
    file_type: [u8; 4],
    creator: [u8; 4],
    finder_flags: u16,
    creation_date: u32,
    modification_date: u32,
    /// The already-decoded fork bytes (decompressed and decrypted at parse time).
    bytes: Vec<u8>,
}

impl PackItEntry {
    /// The file's name as raw bytes (MacRoman). Both forks share the same name.
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
    /// Whether the record this fork came from was encrypted (`PMa5`/`PMa6`).
    pub fn is_encrypted(&self) -> bool {
        self.is_encrypted
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

/// A parsed PackIt archive: the flattened list of fork entries.
pub struct PackItArchive {
    entries: Vec<PackItEntry>,
}

impl PackItArchive {
    /// Whether `data` begins with a PackIt record signature
    /// (`PMag`/`PMa4`/`PMa5`/`PMa6`).
    pub fn recognize(data: &[u8]) -> bool {
        data.len() >= 4 && &data[0..3] == b"PMa" && matches!(data[3], b'g' | b'4' | b'5' | b'6')
    }

    /// Read and parse a PackIt archive containing no encrypted records. An
    /// encrypted (`PMa5`/`PMa6`) record makes this fail with
    /// [`io::ErrorKind::InvalidInput`]; use [`open_with_password`](Self::open_with_password).
    pub fn open<R: Read>(r: R) -> io::Result<Self> {
        Self::parse(r, None)
    }

    /// Read and parse a PackIt archive, decrypting `PMa5`/`PMa6` records with
    /// `password` (raw MacRoman bytes; only the first 8 are used). Unencrypted
    /// records ignore the password.
    pub fn open_with_password<R: Read>(r: R, password: &[u8]) -> io::Result<Self> {
        Self::parse(r, Some(password))
    }

    fn parse<R: Read>(mut r: R, password: Option<&[u8]>) -> io::Result<Self> {
        let mut data = Vec::new();
        r.read_to_end(&mut data)?;
        let entries = parse_records(&data, password)?;
        Ok(Self { entries })
    }

    /// The forks in archive order: each file's data fork (if emitted) before its
    /// resource fork.
    pub fn entries(&self) -> &[PackItEntry] {
        &self.entries
    }

    /// Write entry `idx`'s decoded fork bytes to `out`.
    pub fn read_entry(&self, idx: usize, out: &mut dyn Write) -> io::Result<()> {
        let e = self
            .entries
            .get(idx)
            .ok_or_else(|| invalid("packit: entry index out of range"))?;
        out.write_all(&e.bytes)
    }
}

// === record parsing ===========================================================

/// Which cipher (if any) wraps a record's compressed stream.
#[derive(Clone, Copy, PartialEq)]
enum Crypto {
    None,
    Xor,
    Des,
}

/// The parsed 94-byte file header.
struct Header {
    name: Vec<u8>,
    file_type: [u8; 4],
    creator: [u8; 4],
    finder_flags: u16,
    datasize: u32,
    rsrcsize: u32,
    modification: u32,
    creation: u32,
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Parse a 94-byte header. `h` must be at least `HEADER_SIZE` bytes.
fn parse_header(h: &[u8]) -> Header {
    let namelen = (h[0] as usize).min(63);
    Header {
        name: h[1..1 + namelen].to_vec(),
        file_type: h[64..68].try_into().unwrap(),
        creator: h[68..72].try_into().unwrap(),
        finder_flags: be16(&h[72..74]),
        // bytes 74..76 skipped
        datasize: be32(&h[76..80]),
        rsrcsize: be32(&h[80..84]),
        modification: be32(&h[84..88]),
        creation: be32(&h[88..92]),
        // headcrc u16 at 92..94 ignored
    }
}

/// One decoded record: its header, the two fork byte ranges, and where the next
/// record begins.
struct Record {
    header: Header,
    data_fork: Vec<u8>,
    rsrc_fork: Vec<u8>,
    end: usize,
}

fn parse_records(data: &[u8], password: Option<&[u8]>) -> io::Result<Vec<PackItEntry>> {
    let mut entries = Vec::new();
    let mut pos = 0usize;
    while pos + 4 <= data.len() {
        let magic = &data[pos..pos + 4];
        if magic == b"PEnd" {
            break;
        }
        let (comp, crypto) = match magic {
            b"PMag" => (false, Crypto::None),
            b"PMa4" => (true, Crypto::None),
            b"PMa5" => (true, Crypto::Xor),
            b"PMa6" => (true, Crypto::Des),
            _ => return Err(invalid("packit: unknown record signature")),
        };
        let encrypted = crypto != Crypto::None;
        if encrypted && password.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PackIt: password required for encrypted record",
            ));
        }

        let start = pos + 4;
        let rec = decode_record(data, start, comp, crypto, password)?;

        let h = &rec.header;
        let make = |is_resource_fork: bool, size: u32, bytes: Vec<u8>| PackItEntry {
            name: h.name.clone(),
            size,
            is_resource_fork,
            is_encrypted: encrypted,
            file_type: h.file_type,
            creator: h.creator,
            finder_flags: h.finder_flags,
            creation_date: h.creation,
            modification_date: h.modification,
            bytes,
        };
        // The quirk (as in Compact Pro): an empty file still yields one empty
        // data fork. The reference emits the data fork before the resource fork.
        if h.datasize != 0 || h.rsrcsize == 0 {
            entries.push(make(false, h.datasize, rec.data_fork));
        }
        if h.rsrcsize != 0 {
            entries.push(make(true, h.rsrcsize, rec.rsrc_fork));
        }

        pos = rec.end;
    }
    Ok(entries)
}

fn split_forks(mut forks: Vec<u8>, datasize: usize) -> (Vec<u8>, Vec<u8>) {
    let rsrc_fork = forks.split_off(datasize);
    (forks, rsrc_fork)
}

fn decode_record(
    data: &[u8],
    start: usize,
    comp: bool,
    crypto: Crypto,
    password: Option<&[u8]>,
) -> io::Result<Record> {
    if !comp {
        // PMag: header, forks and CRC are stored verbatim.
        let header_bytes = data
            .get(start..start + HEADER_SIZE)
            .ok_or_else(unexpected_eof)?;
        let header = parse_header(header_bytes);
        let datasize = header.datasize as usize;
        let forks_len = datasize + header.rsrcsize as usize;
        let forks_start = start + HEADER_SIZE;
        let forks = data
            .get(forks_start..forks_start + forks_len)
            .ok_or_else(unexpected_eof)?;
        let crc_at = forks_start + forks_len;
        let stored = be16(data.get(crc_at..crc_at + 2).ok_or_else(unexpected_eof)?);
        if crc16_ccitt(forks) != stored {
            return Err(invalid("packit: fork CRC mismatch"));
        }
        let (data_fork, rsrc_fork) = split_forks(forks.to_vec(), datasize);
        Ok(Record {
            header,
            data_fork,
            rsrc_fork,
            end: start + HEADER_SIZE + forks_len + 2,
        })
    } else {
        // PMa4/5/6: decrypt (if needed), then Huffman-decode the whole stream.
        let region = data.get(start..).ok_or_else(unexpected_eof)?;
        let src = match crypto {
            Crypto::None => region.to_vec(),
            Crypto::Xor => xor_decrypt(region, password.unwrap()),
            Crypto::Des => des_decrypt(region, password.unwrap()),
        };

        let mut huff = StuffItHuffman::new(&src)?;
        let header_bytes = huff.read_exact(HEADER_SIZE)?;
        let header = parse_header(&header_bytes);
        let datasize = header.datasize as usize;
        let forks_len = datasize + header.rsrcsize as usize;
        let forks = huff.read_exact(forks_len)?;
        let crc_bytes = huff.read_exact(2)?;
        let stored = be16(&crc_bytes);
        if crc16_ccitt(&forks) != stored {
            return Err(invalid("packit: fork CRC mismatch"));
        }

        // The next record begins after the bytes the Huffman reader consumed
        // from its source. For the ciphers the source is the decrypted stream,
        // which runs byte-for-byte with the file but in whole 8-byte blocks, so
        // round up to the next block.
        let consumed = huff.consumed_bytes();
        let end = match crypto {
            Crypto::None => start + consumed,
            _ => start + ((consumed + 7) & !7),
        };

        let (data_fork, rsrc_fork) = split_forks(forks, datasize);
        Ok(Record {
            header,
            data_fork,
            rsrc_fork,
            end,
        })
    }
}

// === ciphers (under the Huffman layer) ========================================

/// PC-1, the first DES key-permutation table, used to derive the XOR key from
/// the password (56 one-based bit indices).
#[rustfmt::skip]
const KEYTR1: [usize; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6,
    61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
];

/// Derive PackIt's 8-byte XOR key from the password via PC-1. Port of
/// `XADPackItXORHandle`'s key setup (only the first seven bytes are used in the
/// gamma).
fn xor_key(password: &[u8]) -> [u8; 8] {
    let mut passbuf = [0u8; 8];
    let n = password.len().min(8);
    passbuf[..n].copy_from_slice(&password[..n]);

    let mut key = [0u8; 8];
    for (i, &kt) in KEYTR1.iter().enumerate() {
        let bitindex = kt - 1;
        let bit = ((u32::from(passbuf[bitindex / 8]) << (bitindex % 8)) & 0x80) >> (i % 8);
        key[i / 8] |= bit as u8;
    }
    key
}

/// Decrypt a `PMa5` region: XOR each byte with `key[pos % 7]`. XOR is its own
/// inverse, so this also encrypts.
fn xor_decrypt(region: &[u8], password: &[u8]) -> Vec<u8> {
    let key = xor_key(password);
    region
        .iter()
        .enumerate()
        .map(|(j, &b)| b ^ key[j % 7])
        .collect()
}

/// Decrypt a `PMa6` region: DES-ECB decrypt every 8-byte block (the reference
/// calls `DES_encrypt(block, decrypt=1)`). A short final block is zero-padded.
fn des_decrypt(region: &[u8], password: &[u8]) -> Vec<u8> {
    let mut key = [0u8; 8];
    let n = password.len().min(8);
    key[..n].copy_from_slice(&password[..n]);
    let ks = des::set_key(&key);

    let mut out = Vec::with_capacity(region.len().div_ceil(8) * 8);
    for chunk in region.chunks(8) {
        let mut block = [0u8; 8];
        block[..chunk.len()].copy_from_slice(chunk);
        des::encrypt_block(&mut block, true, &ks);
        out.extend_from_slice(&block);
    }
    out
}

// === tests ====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // --- mirror StuffIt-Huffman encoder (balanced tree) ----------------------

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
        fn finish(mut self) -> Vec<u8> {
            if self.n > 0 {
                self.acc <<= 8 - self.n;
                self.out.push(self.acc);
            }
            self.out
        }
    }

    fn write_tree(w: &mut BitW, symbols: &[u8]) {
        if symbols.len() == 1 {
            w.put_bit(1);
            w.put_bits(u32::from(symbols[0]), 8);
            return;
        }
        let mid = symbols.len() / 2;
        w.put_bit(0);
        write_tree(w, &symbols[..mid]);
        write_tree(w, &symbols[mid..]);
    }

    fn walk_codes(symbols: &[u8], prefix: u32, len: u32, codes: &mut HashMap<u8, (u32, u32)>) {
        if symbols.len() == 1 {
            codes.insert(symbols[0], (prefix, len));
            return;
        }
        let mid = symbols.len() / 2;
        walk_codes(&symbols[..mid], prefix << 1, len + 1, codes);
        walk_codes(&symbols[mid..], (prefix << 1) | 1, len + 1, codes);
    }

    /// Compress `stream` into a StuffIt-Huffman byte stream.
    fn huffman_encode(stream: &[u8]) -> Vec<u8> {
        let mut symbols: Vec<u8> = stream.to_vec();
        symbols.sort_unstable();
        symbols.dedup();
        let mut w = BitW::new();
        write_tree(&mut w, &symbols);
        let mut codes = HashMap::new();
        walk_codes(&symbols, 0, 0, &mut codes);
        for &b in stream {
            let (c, l) = codes[&b];
            w.put_bits(c, l);
        }
        w.finish()
    }

    // --- mirror cipher encoders ----------------------------------------------

    fn pad8(mut v: Vec<u8>) -> Vec<u8> {
        while v.len() % 8 != 0 {
            v.push(0);
        }
        v
    }

    fn xor_encrypt(stream: &[u8], password: &[u8]) -> Vec<u8> {
        // XOR is symmetric; pad to a block so the decoder's rounding matches.
        xor_decrypt(&pad8(stream.to_vec()), password)
    }

    fn des_encrypt(stream: &[u8], password: &[u8]) -> Vec<u8> {
        let mut key = [0u8; 8];
        let n = password.len().min(8);
        key[..n].copy_from_slice(&password[..n]);
        let ks = des::set_key(&key);
        let padded = pad8(stream.to_vec());
        let mut out = Vec::with_capacity(padded.len());
        for chunk in padded.chunks_exact(8) {
            let mut block: [u8; 8] = chunk.try_into().unwrap();
            des::encrypt_block(&mut block, false, &ks);
            out.extend_from_slice(&block);
        }
        out
    }

    // --- mirror container builder --------------------------------------------

    struct File {
        name: &'static [u8],
        file_type: [u8; 4],
        creator: [u8; 4],
        finder_flags: u16,
        creation: u32,
        modification: u32,
        data: Vec<u8>,
        rsrc: Vec<u8>,
    }

    impl File {
        fn plain(name: &'static [u8], data: &[u8], rsrc: &[u8]) -> Self {
            File {
                name,
                file_type: *b"TEXT",
                creator: *b"ttxt",
                finder_flags: 0,
                creation: 0,
                modification: 0,
                data: data.to_vec(),
                rsrc: rsrc.to_vec(),
            }
        }
    }

    /// Build a record's 94-byte header.
    fn build_header(f: &File) -> Vec<u8> {
        let mut h = vec![0u8; HEADER_SIZE];
        let namelen = f.name.len().min(63);
        h[0] = namelen as u8;
        h[1..1 + namelen].copy_from_slice(&f.name[..namelen]);
        h[64..68].copy_from_slice(&f.file_type);
        h[68..72].copy_from_slice(&f.creator);
        h[72..74].copy_from_slice(&f.finder_flags.to_be_bytes());
        h[76..80].copy_from_slice(&(f.data.len() as u32).to_be_bytes());
        h[80..84].copy_from_slice(&(f.rsrc.len() as u32).to_be_bytes());
        h[84..88].copy_from_slice(&f.modification.to_be_bytes());
        h[88..92].copy_from_slice(&f.creation.to_be_bytes());
        // headcrc 92..94 left zero (ignored on read)
        h
    }

    /// The decoded stream a compressed record carries: header + forks + CRC.
    fn build_stream(f: &File) -> Vec<u8> {
        let mut s = build_header(f);
        s.extend_from_slice(&f.data);
        s.extend_from_slice(&f.rsrc);
        let mut forks = f.data.clone();
        forks.extend_from_slice(&f.rsrc);
        s.extend_from_slice(&crc16_ccitt(&forks).to_be_bytes());
        s
    }

    fn record_pmag(f: &File) -> Vec<u8> {
        let mut r = b"PMag".to_vec();
        r.extend_from_slice(&build_stream(f));
        r
    }

    fn record_pma4(f: &File) -> Vec<u8> {
        let mut r = b"PMa4".to_vec();
        r.extend_from_slice(&huffman_encode(&build_stream(f)));
        r
    }

    fn record_pma5(f: &File, password: &[u8]) -> Vec<u8> {
        let mut r = b"PMa5".to_vec();
        r.extend_from_slice(&xor_encrypt(&huffman_encode(&build_stream(f)), password));
        r
    }

    fn record_pma6(f: &File, password: &[u8]) -> Vec<u8> {
        let mut r = b"PMa6".to_vec();
        r.extend_from_slice(&des_encrypt(&huffman_encode(&build_stream(f)), password));
        r
    }

    fn archive(records: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for r in records {
            out.extend_from_slice(r);
        }
        out.extend_from_slice(b"PEnd");
        out
    }

    fn read(a: &PackItArchive, idx: usize) -> Vec<u8> {
        let mut out = Vec::new();
        a.read_entry(idx, &mut out).unwrap();
        out
    }

    // --- recognition ----------------------------------------------------------

    #[test]
    fn recognizes_all_signatures() {
        for sig in [b"PMag", b"PMa4", b"PMa5", b"PMa6"] {
            assert!(PackItArchive::recognize(sig));
        }
    }

    #[test]
    fn rejects_garbage_and_short_input() {
        assert!(!PackItArchive::recognize(b"PMaz"));
        assert!(!PackItArchive::recognize(b"junk"));
        assert!(!PackItArchive::recognize(b"PM"));
        assert!(!PackItArchive::recognize(b""));
    }

    // --- PMag (uncompressed) --------------------------------------------------

    #[test]
    fn pmag_both_forks() {
        let f = File::plain(b"file", b"DATA-fork", b"RSRC-fork");
        let arc = archive(&[record_pmag(&f)]);
        let a = PackItArchive::open(&arc[..]).unwrap();
        assert_eq!(a.entries().len(), 2);
        assert!(!a.entries()[0].is_resource_fork());
        assert!(a.entries()[1].is_resource_fork());
        assert_eq!(a.entries()[0].name(), b"file");
        assert_eq!(read(&a, 0), b"DATA-fork");
        assert_eq!(read(&a, 1), b"RSRC-fork");
    }

    #[test]
    fn pmag_parses_metadata() {
        let mut f = File::plain(b"doc", b"x", b"");
        f.file_type = *b"PDF ";
        f.creator = *b"prvw";
        f.finder_flags = 0x2080;
        f.creation = 0x1111_2222;
        f.modification = 0x3333_4444;
        let arc = archive(&[record_pmag(&f)]);
        let a = PackItArchive::open(&arc[..]).unwrap();
        let e = &a.entries()[0];
        assert_eq!(e.name(), b"doc");
        assert_eq!(&e.file_type(), b"PDF ");
        assert_eq!(&e.creator(), b"prvw");
        assert_eq!(e.finder_flags(), 0x2080);
        assert_eq!(e.creation_date(), 0x1111_2222);
        assert_eq!(e.modification_date(), 0x3333_4444);
        assert!(!e.is_encrypted());
    }

    #[test]
    fn pmag_empty_file_yields_one_empty_data_fork() {
        let f = File::plain(b"empty", b"", b"");
        let arc = archive(&[record_pmag(&f)]);
        let a = PackItArchive::open(&arc[..]).unwrap();
        assert_eq!(a.entries().len(), 1);
        assert!(!a.entries()[0].is_resource_fork());
        assert_eq!(a.entries()[0].size(), 0);
        assert_eq!(read(&a, 0), b"");
    }

    #[test]
    fn pmag_resource_only() {
        let f = File::plain(b"r", b"", b"only-resource");
        let arc = archive(&[record_pmag(&f)]);
        let a = PackItArchive::open(&arc[..]).unwrap();
        assert_eq!(a.entries().len(), 1);
        assert!(a.entries()[0].is_resource_fork());
        assert_eq!(read(&a, 0), b"only-resource");
    }

    #[test]
    fn pmag_crc_mismatch_is_error() {
        let f = File::plain(b"file", b"hello", b"");
        let mut arc = archive(&[record_pmag(&f)]);
        // Corrupt the stored CRC (the last 2 bytes before PEnd).
        let crc_at = 4 + HEADER_SIZE + 5; // sig + header + datasize
        arc[crc_at] ^= 0xff;
        assert!(PackItArchive::open(&arc[..]).is_err());
    }

    // --- PMa4 (Huffman, no encryption) ----------------------------------------

    #[test]
    fn pma4_round_trips() {
        let f = File::plain(b"comp", b"aaaa bbbb cccc aaaa bbbb", b"res res res");
        let arc = archive(&[record_pma4(&f)]);
        let a = PackItArchive::open(&arc[..]).unwrap();
        assert_eq!(read(&a, 0), f.data.as_slice());
        assert_eq!(read(&a, 1), f.rsrc.as_slice());
        assert!(!a.entries()[0].is_encrypted());
    }

    // --- PMa5 (XOR) -----------------------------------------------------------

    #[test]
    fn pma5_round_trips_with_password() {
        let pw = b"secret";
        let f = File::plain(b"xorfile", b"the data fork content here", b"resfork");
        let arc = archive(&[record_pma5(&f, pw)]);
        let a = PackItArchive::open_with_password(&arc[..], pw).unwrap();
        assert_eq!(read(&a, 0), f.data.as_slice());
        assert_eq!(read(&a, 1), f.rsrc.as_slice());
        assert!(a.entries()[0].is_encrypted());
    }

    #[test]
    fn pma5_without_password_is_invalid_input() {
        let arc = archive(&[record_pma5(&File::plain(b"x", b"data", b""), b"pw")]);
        let res = PackItArchive::open(&arc[..]);
        assert!(matches!(res, Err(e) if e.kind() == io::ErrorKind::InvalidInput));
    }

    // --- PMa6 (DES) -----------------------------------------------------------

    #[test]
    fn pma6_round_trips_with_password() {
        let pw = b"8charkey";
        let f = File::plain(b"desfile", b"DES-encrypted data fork payload", b"rfork");
        let arc = archive(&[record_pma6(&f, pw)]);
        let a = PackItArchive::open_with_password(&arc[..], pw).unwrap();
        assert_eq!(read(&a, 0), f.data.as_slice());
        assert_eq!(read(&a, 1), f.rsrc.as_slice());
        assert!(a.entries()[0].is_encrypted());
    }

    #[test]
    fn pma6_without_password_is_invalid_input() {
        let arc = archive(&[record_pma6(&File::plain(b"x", b"data", b""), b"pw")]);
        let res = PackItArchive::open(&arc[..]);
        assert!(matches!(res, Err(e) if e.kind() == io::ErrorKind::InvalidInput));
    }

    // --- record boundaries (multiple records back to back) --------------------

    #[test]
    fn three_pmag_records_in_sequence() {
        let arc = archive(&[
            record_pmag(&File::plain(b"one", b"first", b"")),
            record_pmag(&File::plain(b"two", b"second", b"RES")),
            record_pmag(&File::plain(b"three", b"third", b"")),
        ]);
        let a = PackItArchive::open(&arc[..]).unwrap();
        // one(data) + two(data,rsrc) + three(data) = 4 entries.
        assert_eq!(a.entries().len(), 4);
        assert_eq!(a.entries()[0].name(), b"one");
        assert_eq!(read(&a, 0), b"first");
        assert_eq!(a.entries()[1].name(), b"two");
        assert_eq!(read(&a, 1), b"second");
        assert_eq!(read(&a, 2), b"RES");
        assert_eq!(a.entries()[3].name(), b"three");
        assert_eq!(read(&a, 3), b"third");
    }

    #[test]
    fn encrypted_records_boundary_rounds_to_eight() {
        // Two DES records back to back: finding the second proves the round-up
        // to an 8-byte block boundary is correct.
        let pw = b"key12345";
        let arc = archive(&[
            record_pma6(&File::plain(b"first", b"first payload", b""), pw),
            record_pma6(&File::plain(b"second", b"second payload here", b"sres"), pw),
        ]);
        let a = PackItArchive::open_with_password(&arc[..], pw).unwrap();
        assert_eq!(a.entries().len(), 3);
        assert_eq!(a.entries()[0].name(), b"first");
        assert_eq!(read(&a, 0), b"first payload");
        assert_eq!(a.entries()[1].name(), b"second");
        assert_eq!(read(&a, 1), b"second payload here");
        assert_eq!(read(&a, 2), b"sres");
    }

    #[test]
    fn mixed_records_in_sequence() {
        let pw = b"pw";
        let arc = archive(&[
            record_pmag(&File::plain(b"plain", b"plain data", b"")),
            record_pma4(&File::plain(b"huff", b"huffman huffman data", b"")),
            record_pma5(&File::plain(b"xor", b"xored content", b""), pw),
        ]);
        let a = PackItArchive::open_with_password(&arc[..], pw).unwrap();
        assert_eq!(a.entries().len(), 3);
        assert_eq!(read(&a, 0), b"plain data");
        assert_eq!(read(&a, 1), b"huffman huffman data");
        assert_eq!(read(&a, 2), b"xored content");
    }

    // --- XOR key derivation (independent of the oracle) -----------------------

    #[test]
    fn xor_key_single_high_bit_password() {
        // passbuf[0] = 0x80 sets only NBS key bit 1, which PC-1 maps to key[0]
        // bit 0 -> key = [1,0,0,0,0,0,0,0].
        let key = xor_key(&[0x80]);
        assert_eq!(key, [1, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn xor_key_password_letter_a() {
        // 'A' = 0x41. Bit 2 (0x40) is key bit 2 -> key[1] bit 0; bit 8 (0x01) is
        // a PC-1 parity bit and is dropped -> key = [0,1,0,0,0,0,0,0].
        let key = xor_key(b"A");
        assert_eq!(key, [0, 1, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn xor_gamma_uses_key_mod_seven() {
        // With key[0] = 1 (others 0) the gamma toggles byte 0 and byte 7 (7 % 7
        // == 0) but leaves byte 1 untouched.
        let out = xor_decrypt(&[0x10, 0x10, 0, 0, 0, 0, 0, 0x10], &[0x80]);
        assert_eq!(out[0], 0x11);
        assert_eq!(out[1], 0x10);
        assert_eq!(out[7], 0x11);
    }

    // --- read_entry bounds ----------------------------------------------------

    #[test]
    fn read_entry_out_of_range_errors() {
        let arc = archive(&[record_pmag(&File::plain(b"f", b"x", b""))]);
        let a = PackItArchive::open(&arc[..]).unwrap();
        let mut out = Vec::new();
        assert!(a.read_entry(9, &mut out).is_err());
    }
}
