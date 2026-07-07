//! Classic StuffIt (`.sit`) — a flat Macintosh archive of files with two forks.
//!
//! The archive is a 22-byte header (`SIT!` signature plus a total-size field)
//! followed by a linear sequence of fixed 112-byte entry headers. Folders are
//! delimited by start/end marker records (the marker lives in the compression
//! method byte); files carry up to two forks (resource then data), each emitted
//! as its own entry — as in Compact Pro and BinHex.
//!
//! Each fork header names a compression method (low nibble) and an encryption
//! bit (`0x80`). This crate currently decodes methods **0 (store), 1 (RLE90),
//! 2 (Unix `compress` / LZW), 3 (StuffIt-Huffman), 5 (LZAH / dynamic LZH), 13
//! (LZ + Huffman), and 15 (Arsenic)** — the first four reuse the shared
//! primitives in [`newtua_common`]; methods 5, 13 and 15 live in their own
//! `stuffit5` / `stuffit13` / `stuffit15` modules. The header CRC and each
//! fork's content CRC are verified with CRC-16/ARC.
//!
//! Faithful port of XADMaster's `XADStuffItParser`.
//!
//! # Known limitations (out of scope)
//!
//! * Compression methods 6/8/14 are not implemented yet; reading such a fork
//!   returns [`io::ErrorKind::Unsupported`].
//! * Encryption (method bit `0x80`) is not supported. Classic StuffIt encrypts
//!   with a modified DES whose key is derived from the password *and* a `'MKey'`
//!   resource that lives in the **resource fork of the `.sit` file itself** — not
//!   in the archive bytes — so a pure byte-stream parser cannot reach it.
//!   Reading an encrypted fork returns [`io::ErrorKind::Unsupported`].
//! * The archive comment (a `'SitC'` resource) lives in that same file resource
//!   fork and is likewise out of scope.
//! * Filenames are kept as raw bytes (MacRoman); the full path from the root is
//!   joined with `/`. Decoding to Unicode is the caller's job, as for BinHex.
//! * Dates and Finder flags are parsed into entry fields only; they are not
//!   applied to any extracted file.
//! * ST-installer archive variants are recognised by XADMaster but not handled
//!   here.

use std::io::{self, Read, Write};

use newtua_common::crc16::crc16_arc;

use crate::methods;

/// Size of one entry header.
const FILE_HEADER_SIZE: usize = 112;
/// Records start right after the 22-byte archive header.
const ARCHIVE_HEADER_SIZE: usize = 22;

/// Marker that an entry begins a folder (in the method byte, after masking).
const START_FOLDER: u8 = 0x20;
/// Marker that an entry ends a folder.
const END_FOLDER: u8 = 0x21;
/// Method bit: the entry's fork is password-protected.
const ENCRYPTED_FLAG: u8 = 0x80;
/// Method bit: a folder contains encrypted items.
const FOLDER_CONTAINS_ENCRYPTED: u8 = 0x10;
/// Folder-marker mask: strip the encryption and folder-encrypted bits.
const FOLDER_MASK: u8 = !(ENCRYPTED_FLAG | FOLDER_CONTAINS_ENCRYPTED);

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn unexpected_eof() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "stuffit: unexpected end of data",
    )
}

// === public types =============================================================

/// How to extract one fork's bytes.
struct ForkInfo {
    /// Absolute offset of the compressed bytes within the archive.
    offset: usize,
    /// Compressed length in bytes.
    complen: usize,
    /// Compression method byte (low nibble selects the codec; `0x80` = encrypted).
    method: u8,
    /// Stored CRC-16/ARC of the decoded fork.
    crc: u16,
}

/// One catalog node: a directory, or one fork (resource or data) of a file.
pub struct StuffItEntry {
    name: Vec<u8>,
    is_directory: bool,
    is_resource_fork: bool,
    is_encrypted: bool,
    size: u32,
    file_type: [u8; 4],
    creator: [u8; 4],
    finder_flags: u16,
    creation_date: u32,
    modification_date: u32,
    /// Extraction parameters; `None` for directories.
    fork: Option<ForkInfo>,
}

impl StuffItEntry {
    /// The full path from the archive root, raw bytes (MacRoman), joined with
    /// `/`. A file's two forks share the same path.
    pub fn name(&self) -> &[u8] {
        &self.name
    }
    /// The fork's uncompressed length in bytes (0 for directories).
    pub fn size(&self) -> u64 {
        u64::from(self.size)
    }
    /// Whether this entry is a directory (then it carries no fork).
    pub fn is_directory(&self) -> bool {
        self.is_directory
    }
    /// Whether this entry is the resource fork (`false` for data forks and
    /// directories).
    pub fn is_resource_fork(&self) -> bool {
        self.is_resource_fork
    }
    /// Whether this entry is encrypted (a fork with the `0x80` method bit, or a
    /// folder marked as containing encrypted items).
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

/// A parsed classic StuffIt archive: its raw bytes plus the flattened catalog.
pub struct StuffItArchive {
    data: Vec<u8>,
    entries: Vec<StuffItEntry>,
}

impl StuffItArchive {
    /// Whether `data` looks like a classic StuffIt archive (`SIT!` at offset 0
    /// and `rLau` at offset 10).
    pub fn recognize(data: &[u8]) -> bool {
        recognize(data)
    }

    /// Read and parse a classic StuffIt archive from `r`.
    pub fn open<R: Read>(mut r: R) -> io::Result<Self> {
        let mut data = Vec::new();
        r.read_to_end(&mut data)?;
        let entries = parse(&data)?;
        Ok(Self { data, entries })
    }

    /// The flattened catalog: directories and fork entries in archive order,
    /// each file's resource fork before its data fork.
    pub fn entries(&self) -> &[StuffItEntry] {
        &self.entries
    }

    /// Write entry `idx`'s decoded fork bytes to `out`. Directories write
    /// nothing. Encrypted or unsupported-method forks return
    /// [`io::ErrorKind::Unsupported`].
    pub fn read_entry(&self, idx: usize, out: &mut dyn Write) -> io::Result<()> {
        let e = self
            .entries
            .get(idx)
            .ok_or_else(|| invalid("stuffit: entry index out of range"))?;
        let fork = match &e.fork {
            None => return Ok(()), // a directory: no data
            Some(f) => f,
        };
        if e.is_encrypted {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "stuffit: encrypted entries are not supported",
            ));
        }
        let raw = self
            .data
            .get(fork.offset..fork.offset + fork.complen)
            .ok_or_else(|| invalid("stuffit: fork data past end of archive"))?;
        let size = e.size as usize;

        let decoded = methods::decode_fork(fork.method, raw, size)?;
        methods::verify_content_crc(fork.method, &decoded, fork.crc)?;
        out.write_all(&decoded)
    }
}

// === parsing ==================================================================

/// Big-endian `u32` at `off`, or `None` if out of bounds.
fn u32_be(data: &[u8], off: usize) -> Option<u32> {
    let b = data.get(off..off + 4)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn recognize(data: &[u8]) -> bool {
    // A classic StuffIt archive is `SIT!` at offset 0 and `rLau` at offset 10.
    // (ST-installer variants exist; they are out of scope for now.)
    data.len() >= 14 && &data[0..4] == b"SIT!" && &data[10..14] == b"rLau"
}

/// Join the folder stack and a leaf name with `/` (root has no prefix).
fn join_path(dirs: &[Vec<u8>], name: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    for d in dirs {
        p.extend_from_slice(d);
        p.push(b'/');
    }
    p.extend_from_slice(name);
    p
}

fn parse(data: &[u8]) -> io::Result<Vec<StuffItEntry>> {
    if !recognize(data) {
        return Err(invalid("stuffit: not a classic StuffIt archive"));
    }
    // `totalsize` (offset 6) bounds the entry loop; the 12 bytes after it are
    // skipped, so records start at offset 22.
    let totalsize = u32_be(data, 6).ok_or_else(unexpected_eof)? as usize;
    let mut pos = ARCHIVE_HEADER_SIZE;
    let mut entries = Vec::new();
    let mut dirstack: Vec<Vec<u8>> = Vec::new();

    while pos + FILE_HEADER_SIZE <= totalsize {
        let header = data
            .get(pos..pos + FILE_HEADER_SIZE)
            .ok_or_else(unexpected_eof)?;
        let stored_crc = u16::from_be_bytes([header[110], header[111]]);
        if crc16_arc(&header[0..110]) != stored_crc {
            return Err(invalid("stuffit: bad entry header checksum"));
        }

        let resourcemethod = header[0];
        let datamethod = header[1];
        let mut namelen = header[2] as usize;
        if namelen > 31 {
            namelen = 31;
        }
        let name = &header[3..3 + namelen];

        let file_type = [header[66], header[67], header[68], header[69]];
        let creator = [header[70], header[71], header[72], header[73]];
        let finder_flags = u16::from_be_bytes([header[74], header[75]]);
        let creation_date = u32::from_be_bytes([header[76], header[77], header[78], header[79]]);
        let modification_date =
            u32::from_be_bytes([header[80], header[81], header[82], header[83]]);
        let rsrclength = u32::from_be_bytes([header[84], header[85], header[86], header[87]]);
        let datalength = u32::from_be_bytes([header[88], header[89], header[90], header[91]]);
        let rsrccomplen =
            u32::from_be_bytes([header[92], header[93], header[94], header[95]]) as usize;
        let datacomplen =
            u32::from_be_bytes([header[96], header[97], header[98], header[99]]) as usize;
        let rsrccrc = u16::from_be_bytes([header[100], header[101]]);
        let datacrc = u16::from_be_bytes([header[102], header[103]]);

        let start = pos + FILE_HEADER_SIZE;

        let is_start = (datamethod & FOLDER_MASK) == START_FOLDER
            || (resourcemethod & FOLDER_MASK) == START_FOLDER;
        let is_end = (datamethod & FOLDER_MASK) == END_FOLDER
            || (resourcemethod & FOLDER_MASK) == END_FOLDER;

        if is_start {
            let path = join_path(&dirstack, name);
            let contains_encrypted = (datamethod & FOLDER_CONTAINS_ENCRYPTED != 0)
                || (resourcemethod & FOLDER_CONTAINS_ENCRYPTED != 0);
            entries.push(StuffItEntry {
                name: path,
                is_directory: true,
                is_resource_fork: false,
                is_encrypted: contains_encrypted,
                size: 0,
                file_type,
                creator,
                finder_flags,
                creation_date,
                modification_date,
                fork: None,
            });
            dirstack.push(name.to_vec());
            pos = start;
        } else if is_end {
            dirstack.pop();
            pos = start;
        } else {
            let path = join_path(&dirstack, name);

            if rsrclength != 0 {
                entries.push(StuffItEntry {
                    name: path.clone(),
                    is_directory: false,
                    is_resource_fork: true,
                    is_encrypted: resourcemethod & ENCRYPTED_FLAG != 0,
                    size: rsrclength,
                    file_type,
                    creator,
                    finder_flags,
                    creation_date,
                    modification_date,
                    fork: Some(ForkInfo {
                        offset: start,
                        complen: rsrccomplen,
                        method: resourcemethod,
                        crc: rsrccrc,
                    }),
                });
            }
            if datalength != 0 || rsrclength == 0 {
                entries.push(StuffItEntry {
                    name: path,
                    is_directory: false,
                    is_resource_fork: false,
                    is_encrypted: datamethod & ENCRYPTED_FLAG != 0,
                    size: datalength,
                    file_type,
                    creator,
                    finder_flags,
                    creation_date,
                    modification_date,
                    fork: Some(ForkInfo {
                        offset: start + rsrccomplen,
                        complen: datacomplen,
                        method: datamethod,
                        crc: datacrc,
                    }),
                });
            }
            pos = start + rsrccomplen + datacomplen;
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    // === mirror StuffIt-Huffman encoder (balanced tree) ======================

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

    fn walk_codes(
        symbols: &[u8],
        prefix: u32,
        len: u32,
        codes: &mut std::collections::HashMap<u8, (u32, u32)>,
    ) {
        if symbols.len() == 1 {
            codes.insert(symbols[0], (prefix, len));
            return;
        }
        let mid = symbols.len() / 2;
        walk_codes(&symbols[..mid], prefix << 1, len + 1, codes);
        walk_codes(&symbols[mid..], (prefix << 1) | 1, len + 1, codes);
    }

    fn huffman_encode(content: &[u8]) -> Vec<u8> {
        let mut symbols: Vec<u8> = content.to_vec();
        symbols.sort_unstable();
        symbols.dedup();
        let mut w = BitW::new();
        write_tree(&mut w, &symbols);
        let mut codes = std::collections::HashMap::new();
        walk_codes(&symbols, 0, 0, &mut codes);
        for &b in content {
            let (c, l) = codes[&b];
            w.put_bits(c, l);
        }
        w.finish()
    }

    // === mirror Unix-compress (LZW) encoder ==================================

    /// Greedy LZW encoder mirroring `CompressReader` in block mode. Fixtures are
    /// kept small so the code width never leaves 9 bits (the table never reaches
    /// 512 entries) and no clear code is ever needed. The shared LSB-first
    /// [`newtua_testutil::BitWriter`] matches `CompressReader`'s bit order.
    fn lzw_encode(input: &[u8]) -> Vec<u8> {
        use std::collections::HashMap;
        let mut dict: HashMap<Vec<u8>, u32> = HashMap::new();
        for b in 0..=255u32 {
            dict.insert(vec![b as u8], b);
        }
        let mut next_code = 257u32; // 256 is the reserved block-mode clear code
        let mut bits = newtua_testutil::BitWriter::default();
        if input.is_empty() {
            return bits.finish();
        }
        let mut current = vec![input[0]];
        for &c in &input[1..] {
            let mut cand = current.clone();
            cand.push(c);
            if dict.contains_key(&cand) {
                current = cand;
            } else {
                bits.bits(dict[&current], 9);
                dict.insert(cand, next_code);
                next_code += 1;
                assert!(
                    next_code < 512,
                    "lzw oracle fixture too large; the code width would grow past 9 bits"
                );
                current = vec![c];
            }
        }
        bits.bits(dict[&current], 9);
        bits.finish()
    }

    // === mirror container builder ============================================

    /// One fork to place in the archive.
    struct ForkSpec {
        method: u8,
        content: Vec<u8>,
    }

    /// Compress `content` by `method`, returning the stored (compressed) bytes.
    fn compress(method: u8, content: &[u8]) -> Vec<u8> {
        match method & 0x0f {
            0 => content.to_vec(),
            1 => content.to_vec(), // RLE90 identity (content has no 0x90)
            2 => lzw_encode(content),
            3 => huffman_encode(content),
            m => panic!("mirror builder cannot compress method {m}"),
        }
    }

    fn fork(method: u8, content: &[u8]) -> ForkSpec {
        ForkSpec {
            method,
            content: content.to_vec(),
        }
    }

    struct FileSpec {
        name: &'static [u8],
        file_type: [u8; 4],
        creator: [u8; 4],
        rsrc: Option<ForkSpec>,
        data: Option<ForkSpec>,
    }

    impl FileSpec {
        fn plain(name: &'static [u8], data: Option<ForkSpec>, rsrc: Option<ForkSpec>) -> Self {
            FileSpec {
                name,
                file_type: *b"TEXT",
                creator: *b"ttxt",
                rsrc,
                data,
            }
        }
    }

    enum Node {
        Dir(&'static [u8], Vec<Node>),
        File(FileSpec),
    }

    /// Build one 112-byte entry header with a correct CRC.
    #[allow(clippy::too_many_arguments)]
    fn make_header(
        rsrcmethod: u8,
        datamethod: u8,
        name: &[u8],
        file_type: [u8; 4],
        creator: [u8; 4],
        rsrclength: u32,
        datalength: u32,
        rsrccomplen: u32,
        datacomplen: u32,
        rsrccrc: u16,
        datacrc: u16,
    ) -> Vec<u8> {
        let mut h = vec![0u8; FILE_HEADER_SIZE];
        h[0] = rsrcmethod;
        h[1] = datamethod;
        let namelen = name.len().min(31);
        h[2] = namelen as u8;
        h[3..3 + namelen].copy_from_slice(&name[..namelen]);
        h[66..70].copy_from_slice(&file_type);
        h[70..74].copy_from_slice(&creator);
        h[84..88].copy_from_slice(&rsrclength.to_be_bytes());
        h[88..92].copy_from_slice(&datalength.to_be_bytes());
        h[92..96].copy_from_slice(&rsrccomplen.to_be_bytes());
        h[96..100].copy_from_slice(&datacomplen.to_be_bytes());
        h[100..102].copy_from_slice(&rsrccrc.to_be_bytes());
        h[102..104].copy_from_slice(&datacrc.to_be_bytes());
        let crc = crc16_arc(&h[0..110]);
        h[110..112].copy_from_slice(&crc.to_be_bytes());
        h
    }

    fn emit_nodes(nodes: &[Node], out: &mut Vec<u8>) {
        for node in nodes {
            match node {
                Node::Dir(name, children) => {
                    // Start-folder marker (in the data-method byte).
                    out.extend_from_slice(&make_header(
                        0,
                        START_FOLDER,
                        name,
                        *b"fold",
                        *b"MACS",
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    ));
                    emit_nodes(children, out);
                    // End-folder marker.
                    out.extend_from_slice(&make_header(
                        0, END_FOLDER, b"", [0; 4], [0; 4], 0, 0, 0, 0, 0, 0,
                    ));
                }
                Node::File(f) => {
                    let rcomp = f.rsrc.as_ref().map(|r| compress(r.method, &r.content));
                    let dcomp = f.data.as_ref().map(|d| compress(d.method, &d.content));
                    let rsrclength = f.rsrc.as_ref().map_or(0, |r| r.content.len()) as u32;
                    let datalength = f.data.as_ref().map_or(0, |d| d.content.len()) as u32;
                    let rsrccomplen = rcomp.as_ref().map_or(0, |c| c.len()) as u32;
                    let datacomplen = dcomp.as_ref().map_or(0, |c| c.len()) as u32;
                    let rsrcmethod = f.rsrc.as_ref().map_or(0, |r| r.method);
                    let datamethod = f.data.as_ref().map_or(0, |d| d.method);
                    let rsrccrc = f.rsrc.as_ref().map_or(0, |r| crc16_arc(&r.content));
                    let datacrc = f.data.as_ref().map_or(0, |d| crc16_arc(&d.content));

                    out.extend_from_slice(&make_header(
                        rsrcmethod,
                        datamethod,
                        f.name,
                        f.file_type,
                        f.creator,
                        rsrclength,
                        datalength,
                        rsrccomplen,
                        datacomplen,
                        rsrccrc,
                        datacrc,
                    ));
                    if let Some(c) = rcomp {
                        out.extend_from_slice(&c);
                    }
                    if let Some(c) = dcomp {
                        out.extend_from_slice(&c);
                    }
                }
            }
        }
    }

    fn count_files(nodes: &[Node]) -> usize {
        let mut n = 0;
        for node in nodes {
            match node {
                Node::Dir(_, children) => n += count_files(children),
                Node::File(_) => n += 1,
            }
        }
        n
    }

    fn build_archive(nodes: &[Node]) -> Vec<u8> {
        let mut out = vec![0u8; ARCHIVE_HEADER_SIZE];
        out[0..4].copy_from_slice(b"SIT!");
        out[10..14].copy_from_slice(b"rLau");
        emit_nodes(nodes, &mut out);
        let numfiles = count_files(nodes) as u16;
        out[4..6].copy_from_slice(&numfiles.to_be_bytes());
        let totalsize = out.len() as u32;
        out[6..10].copy_from_slice(&totalsize.to_be_bytes());
        out
    }

    fn read(a: &StuffItArchive, idx: usize) -> Vec<u8> {
        let mut out = Vec::new();
        a.read_entry(idx, &mut out).unwrap();
        out
    }

    // === recognition =========================================================

    #[test]
    fn recognizes_valid_signature() {
        let arc = build_archive(&[Node::File(FileSpec::plain(
            b"f",
            Some(fork(0, b"hi")),
            None,
        ))]);
        assert!(StuffItArchive::recognize(&arc));
    }

    #[test]
    fn rejects_garbage_and_short_input() {
        assert!(!StuffItArchive::recognize(b"not an archive"));
        assert!(!StuffItArchive::recognize(b"SIT!"));
        let mut buf = vec![0u8; 22];
        buf[0..4].copy_from_slice(b"SIT!");
        assert!(!StuffItArchive::recognize(&buf));
    }

    // === container / fork emission ===========================================

    #[test]
    fn parses_both_forks_resource_first() {
        let arc = build_archive(&[Node::File(FileSpec::plain(
            b"both",
            Some(fork(0, b"DATA")),
            Some(fork(0, b"RES")),
        ))]);
        let a = StuffItArchive::open(&arc[..]).unwrap();
        assert_eq!(a.entries().len(), 2);
        assert!(a.entries()[0].is_resource_fork());
        assert!(!a.entries()[1].is_resource_fork());
        assert_eq!(a.entries()[0].name(), b"both");
        assert_eq!(a.entries()[1].name(), b"both");
        assert_eq!(read(&a, 0), b"RES");
        assert_eq!(read(&a, 1), b"DATA");
    }

    #[test]
    fn data_only_file() {
        let arc = build_archive(&[Node::File(FileSpec::plain(
            b"d",
            Some(fork(0, b"only data")),
            None,
        ))]);
        let a = StuffItArchive::open(&arc[..]).unwrap();
        assert_eq!(a.entries().len(), 1);
        assert!(!a.entries()[0].is_resource_fork());
        assert_eq!(read(&a, 0), b"only data");
    }

    #[test]
    fn resource_only_file() {
        let arc = build_archive(&[Node::File(FileSpec::plain(
            b"r",
            None,
            Some(fork(0, b"only rsrc")),
        ))]);
        let a = StuffItArchive::open(&arc[..]).unwrap();
        assert_eq!(a.entries().len(), 1);
        assert!(a.entries()[0].is_resource_fork());
        assert_eq!(read(&a, 0), b"only rsrc");
    }

    #[test]
    fn empty_file_yields_one_empty_data_fork() {
        let arc = build_archive(&[Node::File(FileSpec::plain(b"empty", None, None))]);
        let a = StuffItArchive::open(&arc[..]).unwrap();
        assert_eq!(a.entries().len(), 1);
        assert!(!a.entries()[0].is_resource_fork());
        assert_eq!(a.entries()[0].size(), 0);
        assert_eq!(read(&a, 0), b"");
    }

    // === folder tree =========================================================

    #[test]
    fn nested_directory_paths() {
        let arc = build_archive(&[Node::Dir(
            b"dir",
            vec![Node::File(FileSpec::plain(
                b"inner",
                Some(fork(0, b"hi")),
                None,
            ))],
        )]);
        let a = StuffItArchive::open(&arc[..]).unwrap();
        assert_eq!(a.entries().len(), 2);
        assert!(a.entries()[0].is_directory());
        assert_eq!(a.entries()[0].name(), b"dir");
        assert_eq!(a.entries()[1].name(), b"dir/inner");
        assert_eq!(read(&a, 1), b"hi");
    }

    #[test]
    fn folder_exit_returns_to_parent() {
        // dir/{a}, then a sibling at the root after the folder closes.
        let arc = build_archive(&[
            Node::Dir(
                b"dir",
                vec![Node::File(FileSpec::plain(
                    b"a",
                    Some(fork(0, b"AA")),
                    None,
                ))],
            ),
            Node::File(FileSpec::plain(b"top", Some(fork(0, b"TT")), None)),
        ]);
        let a = StuffItArchive::open(&arc[..]).unwrap();
        let names: Vec<&[u8]> = a.entries().iter().map(|e| e.name()).collect();
        assert_eq!(names, vec![&b"dir"[..], &b"dir/a"[..], &b"top"[..]]);
        assert_eq!(read(&a, 2), b"TT");
    }

    // === methods 0/1/2/3 round-trip ==========================================

    fn roundtrip_method(method: u8, content: &[u8]) {
        let arc = build_archive(&[Node::File(FileSpec::plain(
            b"f",
            Some(fork(method, content)),
            None,
        ))]);
        let a = StuffItArchive::open(&arc[..]).unwrap();
        assert_eq!(read(&a, 0), content, "method {method}");
    }

    #[test]
    fn method0_store_roundtrip() {
        roundtrip_method(0, b"stored bytes, verbatim");
    }

    #[test]
    fn method1_rle90_roundtrip() {
        // RLE90 identity: content carries no 0x90 marker byte.
        roundtrip_method(1, b"the quick brown fox");
    }

    #[test]
    fn method2_compress_roundtrip() {
        roundtrip_method(2, b"abcabcabcabcabcabc compress me please");
    }

    #[test]
    fn method3_huffman_roundtrip() {
        roundtrip_method(3, b"huffman huffman huffman tree");
    }

    // === CRC + error handling ================================================

    #[test]
    fn fork_crc_mismatch_is_error() {
        let content = b"crc me";
        let mut arc = build_archive(&[Node::File(FileSpec::plain(
            b"f",
            Some(fork(0, content)),
            None,
        ))]);
        // Corrupt the data CRC field (header offset 102) and restamp header CRC.
        let h = ARCHIVE_HEADER_SIZE;
        let bad = crc16_arc(content) ^ 0xffff;
        arc[h + 102..h + 104].copy_from_slice(&bad.to_be_bytes());
        let newcrc = crc16_arc(&arc[h..h + 110]);
        arc[h + 110..h + 112].copy_from_slice(&newcrc.to_be_bytes());

        let a = StuffItArchive::open(&arc[..]).unwrap();
        let mut out = Vec::new();
        assert!(a.read_entry(0, &mut out).is_err());
    }

    #[test]
    fn bad_header_checksum_is_error() {
        let mut arc =
            build_archive(&[Node::File(FileSpec::plain(b"f", Some(fork(0, b"x")), None))]);
        // Flip a header byte without fixing the header CRC.
        arc[ARCHIVE_HEADER_SIZE + 2] ^= 0xff;
        assert!(StuffItArchive::open(&arc[..]).is_err());
    }

    #[test]
    fn encrypted_fork_is_unsupported() {
        let arc = build_archive(&[Node::File(FileSpec::plain(
            b"enc",
            Some(fork(ENCRYPTED_FLAG, b"xxxx")),
            None,
        ))]);
        let a = StuffItArchive::open(&arc[..]).unwrap();
        assert!(a.entries()[0].is_encrypted());
        let mut out = Vec::new();
        let err = a.read_entry(0, &mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn unsupported_method_is_unsupported() {
        // Method 14 (Installer) is still a later sub-stage.
        let arc = build_archive(&[Node::File(FileSpec {
            name: b"lz",
            file_type: *b"TEXT",
            creator: *b"ttxt",
            rsrc: None,
            // Build with method 0 bytes (so the body is store), but stamp the
            // header method to 14 afterwards.
            data: Some(fork(0, b"payload")),
        })]);
        let mut arc = arc;
        arc[ARCHIVE_HEADER_SIZE + 1] = 14; // datamethod
        let h = ARCHIVE_HEADER_SIZE;
        let newcrc = crc16_arc(&arc[h..h + 110]);
        arc[h + 110..h + 112].copy_from_slice(&newcrc.to_be_bytes());
        let a = StuffItArchive::open(&arc[..]).unwrap();
        let mut out = Vec::new();
        let err = a.read_entry(0, &mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn read_entry_out_of_range_errors() {
        let arc = build_archive(&[Node::File(FileSpec::plain(b"f", Some(fork(0, b"x")), None))]);
        let a = StuffItArchive::open(&arc[..]).unwrap();
        let mut out = Vec::new();
        assert!(a.read_entry(9, &mut out).is_err());
    }

    #[test]
    fn directory_read_is_empty() {
        let arc = build_archive(&[Node::Dir(
            b"dir",
            vec![Node::File(FileSpec::plain(
                b"a",
                Some(fork(0, b"AA")),
                None,
            ))],
        )]);
        let a = StuffItArchive::open(&arc[..]).unwrap();
        assert!(a.entries()[0].is_directory());
        assert_eq!(read(&a, 0), b"");
    }

    #[test]
    fn metadata_is_parsed() {
        let arc = build_archive(&[Node::File(FileSpec {
            name: b"meta",
            file_type: *b"APPL",
            creator: *b"CODE",
            rsrc: None,
            data: Some(fork(0, b"x")),
        })]);
        let a = StuffItArchive::open(&arc[..]).unwrap();
        assert_eq!(a.entries()[0].file_type(), *b"APPL");
        assert_eq!(a.entries()[0].creator(), *b"CODE");
    }
}
