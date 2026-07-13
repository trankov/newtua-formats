// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! StuffIt 5 (`.sit`) — the 1997 container that superseded classic StuffIt.
//!
//! Unlike the flat classic format, StuffIt 5 stores a real directory tree: each
//! entry links to its parent by the parent's byte offset, and folders declare
//! how many direct children follow. The archive opens with a fixed text banner
//! (`StuffIt (c)1997-…`); all integers are big-endian.
//!
//! The compression methods are exactly the classic ones (0/1/2/3/5/13/15),
//! decoded through the shared [`crate::methods`] dispatch. Each file carries up
//! to two forks, resource then data, emitted as separate entries — as in classic
//! StuffIt, Compact Pro and BinHex.
//!
//! Faithful port of XADMaster's `XADStuffIt5Parser` (and the self-extracting
//! `XADStuffIt5ExeParser`).
//!
//! Encryption (archive flag `0x80` / entry flag `0x20`) is supported: the
//! archive password hash and each fork's 40-bit key are parsed, the password is
//! verified via MD5, and the fork is decrypted with RC4 before decompression —
//! see [`StuffIt5Archive::open_with_password`]. Faithful port of
//! `keyForEntryWithDictionary:` + `decryptHandleForEntryWithDictionary:`.
//!
//! # Known limitations (out of scope)
//!
//! * The archive comment and per-entry comments are skipped, not exposed.
//! * Filenames are kept as raw bytes (MacRoman), full path joined with `/`.
//! * Dates and Finder flags are parsed into entry fields only.

use std::collections::HashMap;
use std::io::{self, Read, Write};

use newtua_common::md5::md5;
use newtua_common::rc4::Rc4;

use crate::methods;

/// Entry header magic (`headid`).
const SIT5_ID: u32 = 0xA5A5_A5A5;
/// The only archive version this parser accepts.
const SIT5_VERSION: u8 = 5;
/// Encryption key / password-hash length (40 bits).
const KEY_LENGTH: usize = 5;

/// Archive-header flags.
const ARCHIVEFLAGS_14BYTES: u8 = 0x10;
const ARCHIVEFLAGS_20: u8 = 0x20;
const ARCHIVEFLAGS_40: u8 = 0x40;
const ARCHIVEFLAGS_CRYPTED: u8 = 0x80;

/// Per-entry flags.
const ENTRYFLAGS_DIRECTORY: u8 = 0x40;
const ENTRYFLAGS_CRYPTED: u8 = 0x20;

/// Records start right after the base archive header (with archive flags = 0).
const HEADER_LEN: usize = 100;
/// Bytes skipped past the signature banner before the version byte.
const SIGNATURE_SKIP: usize = 82;
/// Length of the fixed `.exe` self-extracting stub prefix.
const EXE_STUB_LEN: usize = 0x1a000;

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn unsupported(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, msg.into())
}

// === public types =============================================================

/// How to extract one fork's bytes.
struct ForkInfo {
    /// Absolute offset of the compressed bytes within the archive body.
    offset: usize,
    /// Compressed length in bytes.
    complen: usize,
    /// Compression method byte (low nibble selects the codec).
    method: u8,
    /// Stored CRC-16/ARC of the decoded fork (unused for method 15).
    crc: u16,
    /// 40-bit entry key, present only for encrypted forks.
    key: Option<[u8; KEY_LENGTH]>,
}

/// One catalog node: a directory, or one fork (resource or data) of a file.
pub struct StuffIt5Entry {
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

impl StuffIt5Entry {
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
    /// Whether this fork is encrypted. Reading it returns
    /// [`io::ErrorKind::Unsupported`] in 15a.
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

/// A parsed StuffIt 5 archive: its raw body bytes plus the flattened catalog.
pub struct StuffIt5Archive {
    data: Vec<u8>,
    entries: Vec<StuffIt5Entry>,
    /// Archive password hash, present when the archive is encrypted.
    password_hash: Option<[u8; KEY_LENGTH]>,
    /// Whether the archive as a whole is marked encrypted.
    #[allow(dead_code)]
    is_encrypted: bool,
    /// The password supplied to [`Self::open_with_password`], raw bytes.
    password: Option<Vec<u8>>,
}

impl StuffIt5Archive {
    /// Whether `data` looks like a StuffIt 5 archive (the fixed 1997 banner), or
    /// a self-extracting `.exe` wrapping one.
    pub fn recognize(data: &[u8]) -> bool {
        recognize(data) || recognize_exe(data)
    }

    /// Read and parse a StuffIt 5 archive from `r`. Handles the plain container
    /// and the self-extracting `.exe` variant transparently. Reading an
    /// encrypted fork then returns [`io::ErrorKind::InvalidInput`]; use
    /// [`open_with_password`](Self::open_with_password) for encrypted archives.
    pub fn open<R: Read>(r: R) -> io::Result<Self> {
        Self::open_inner(r, None)
    }

    /// Like [`open`](Self::open), but remembers `password` (raw MacRoman bytes;
    /// encoding is the caller's choice) so encrypted forks can be decrypted.
    /// Unencrypted forks ignore the password.
    pub fn open_with_password<R: Read>(r: R, password: &[u8]) -> io::Result<Self> {
        Self::open_inner(r, Some(password.to_vec()))
    }

    fn open_inner<R: Read>(mut r: R, password: Option<Vec<u8>>) -> io::Result<Self> {
        let mut data = Vec::new();
        r.read_to_end(&mut data)?;

        // Strip the self-extracting stub if present, so all offsets are relative
        // to the archive body (as they are in a plain `.sit`).
        if !recognize(&data) && recognize_exe(&data) {
            data.drain(..EXE_STUB_LEN);
        }

        let parsed = parse(&data)?;
        Ok(Self {
            data,
            entries: parsed.entries,
            password_hash: parsed.password_hash,
            is_encrypted: parsed.is_encrypted,
            password,
        })
    }

    /// The flattened catalog: directories and fork entries in archive order,
    /// each file's resource fork before its data fork.
    pub fn entries(&self) -> &[StuffIt5Entry] {
        &self.entries
    }

    /// Write entry `idx`'s decoded fork bytes to `out`. Directories write
    /// nothing. An unsupported-method fork returns [`io::ErrorKind::Unsupported`];
    /// an encrypted fork opened without a password (or with a wrong one) returns
    /// [`io::ErrorKind::InvalidInput`].
    pub fn read_entry(&self, idx: usize, out: &mut dyn Write) -> io::Result<()> {
        let e = self
            .entries
            .get(idx)
            .ok_or_else(|| invalid("stuffit5: entry index out of range"))?;
        let fork = match &e.fork {
            None => return Ok(()), // a directory: no data
            Some(f) => f,
        };
        let raw = self
            .data
            .get(fork.offset..fork.offset + fork.complen)
            .ok_or_else(|| invalid("stuffit5: fork data past end of archive"))?;
        let size = e.size as usize;

        // For an encrypted fork, decrypt the whole compressed block with RC4
        // first; both paths then share the same decode + CRC tail.
        let mut decrypted;
        let input: &[u8] = if e.is_encrypted {
            decrypted = raw.to_vec();
            Rc4::new(&self.entry_key(fork)?).apply(&mut decrypted);
            &decrypted
        } else {
            raw
        };
        let decoded = methods::decode_fork(fork.method, input, size)?;
        methods::verify_content_crc(fork.method, &decoded, fork.crc)?;
        out.write_all(&decoded)
    }

    /// Derive the 10-byte RC4 key for an encrypted `fork`, verifying the password
    /// against the archive hash. Port of `keyForEntryWithDictionary:`:
    /// `archivekey = MD5(password)[..5]`, checked via `MD5(archivekey)[..5] ==
    /// stored hash`, then the entry key is `archivekey ++ entrykey`.
    fn entry_key(&self, fork: &ForkInfo) -> io::Result<[u8; 2 * KEY_LENGTH]> {
        let password = self.password.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "stuffit5: password required for encrypted entry",
            )
        })?;
        let hash = self
            .password_hash
            .ok_or_else(|| invalid("stuffit5: encrypted entry without an archive password hash"))?;
        let archivekey = stuffit_md5(password);
        if stuffit_md5(&archivekey) != hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stuffit5: incorrect password",
            ));
        }
        let entrykey = fork
            .key
            .ok_or_else(|| invalid("stuffit5: encrypted fork without a key"))?;
        let mut key = [0u8; 2 * KEY_LENGTH];
        key[..KEY_LENGTH].copy_from_slice(&archivekey);
        key[KEY_LENGTH..].copy_from_slice(&entrykey);
        Ok(key)
    }
}

/// The first five bytes of `MD5(data)` — StuffIt 5's `StuffItMD5`.
fn stuffit_md5(data: &[u8]) -> [u8; KEY_LENGTH] {
    let h = md5(data);
    [h[0], h[1], h[2], h[3], h[4]]
}

// === recognition ==============================================================

/// The fixed StuffIt 5 banner; `\xFF` marks the four wildcard year bytes.
const BANNER: &[u8] =
    b"StuffIt (c)1997-\xFF\xFF\xFF\xFF Aladdin Systems, Inc., http://www.aladdinsys.com/StuffIt/\x0d\x0a";

fn recognize(data: &[u8]) -> bool {
    if data.len() < HEADER_LEN {
        return false;
    }
    BANNER.iter().zip(data).all(|(&m, &b)| m == 0xFF || m == b)
}

fn recognize_exe(data: &[u8]) -> bool {
    data.len() >= 4104
        && &data[0..2] == b"MZ"
        && u32::from_be_bytes([data[4100], data[4101], data[4102], data[4103]]) == 0x4203_E853
}

// === parsing ==================================================================

/// A minimal big-endian cursor over the archive body, bounds-checked.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn pos(&self) -> usize {
        self.pos
    }
    fn seek(&mut self, pos: usize) -> io::Result<()> {
        if pos > self.data.len() {
            return Err(unexpected_eof());
        }
        self.pos = pos;
        Ok(())
    }
    fn skip(&mut self, n: usize) -> io::Result<()> {
        self.seek(self.pos + n)
    }
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(unexpected_eof)?;
        let slice = self.data.get(self.pos..end).ok_or_else(unexpected_eof)?;
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> io::Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> io::Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn array4(&mut self) -> io::Result<[u8; 4]> {
        let b = self.take(4)?;
        Ok([b[0], b[1], b[2], b[3]])
    }
    fn key(&mut self) -> io::Result<[u8; KEY_LENGTH]> {
        let b = self.take(KEY_LENGTH)?;
        Ok([b[0], b[1], b[2], b[3], b[4]])
    }
}

fn unexpected_eof() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "stuffit5: unexpected end of data",
    )
}

struct Parsed {
    entries: Vec<StuffIt5Entry>,
    password_hash: Option<[u8; KEY_LENGTH]>,
    is_encrypted: bool,
}

/// Join a parent path and a leaf name with `/` (root parent is empty).
fn join_path(parent: &[u8], name: &[u8]) -> Vec<u8> {
    if parent.is_empty() {
        return name.to_vec();
    }
    let mut p = parent.to_vec();
    p.push(b'/');
    p.extend_from_slice(name);
    p
}

fn parse(data: &[u8]) -> io::Result<Parsed> {
    if !recognize(data) {
        return Err(invalid("stuffit5: not a StuffIt 5 archive"));
    }
    let mut c = Cursor::new(data);
    c.skip(SIGNATURE_SKIP)?;
    let version = c.u8()?;
    let flags = c.u8()?;
    if version != SIT5_VERSION {
        return Err(invalid("stuffit5: unsupported archive version"));
    }
    let _totalsize = c.u32()?;
    let _something = c.u32()?;
    let numfiles = c.u16()?;
    let firstoffs = c.u32()? as usize;
    let _crc = c.u16()?;

    if flags & ARCHIVEFLAGS_14BYTES != 0 {
        c.skip(14)?;
    }
    let mut commentsize = 0usize;
    let mut length_b = 0usize;
    if flags & ARCHIVEFLAGS_20 != 0 {
        commentsize = c.u16()? as usize;
        length_b = c.u16()? as usize;
    }
    let mut password_hash = None;
    let mut is_encrypted = false;
    if flags & ARCHIVEFLAGS_CRYPTED != 0 {
        let hashsize = c.u8()?;
        if hashsize as usize != KEY_LENGTH {
            return Err(invalid("stuffit5: bad password hash length"));
        }
        password_hash = Some(c.key()?);
        is_encrypted = true;
    }
    if flags & ARCHIVEFLAGS_40 != 0 {
        let length_n = c.u16()?;
        for _ in 0..length_n {
            c.skip(20)?;
        }
    }
    if flags & ARCHIVEFLAGS_20 != 0 {
        if commentsize != 0 {
            c.skip(commentsize)?;
        }
        c.skip(length_b)?;
    }

    c.seek(firstoffs)?;
    let entries = parse_tree(&mut c, numfiles as usize)?;
    Ok(Parsed {
        entries,
        password_hash,
        is_encrypted,
    })
}

/// Read a fork's password data (the byte right after its method byte). For an
/// encrypted archive with a non-empty fork the reference expects a 5-byte key;
/// otherwise `passlen` must be 0. Returns the key when present. Data and resource
/// forks read these bytes identically.
fn read_fork_key(
    c: &mut Cursor,
    crypted: bool,
    forklen: u32,
) -> io::Result<Option<[u8; KEY_LENGTH]>> {
    let passlen = c.u8()? as usize;
    if crypted && forklen != 0 {
        if passlen != KEY_LENGTH {
            return Err(unsupported("stuffit5: bad key length"));
        }
        Ok(Some(c.key()?))
    } else if passlen != 0 {
        Err(unsupported("stuffit5: unexpected password data"))
    } else {
        Ok(None)
    }
}

fn parse_tree(c: &mut Cursor, toplevel: usize) -> io::Result<Vec<StuffIt5Entry>> {
    let mut entries = Vec::new();
    let mut dirs: HashMap<u32, Vec<u8>> = HashMap::new();
    let mut count = toplevel;
    let mut i = 0;

    while i < count {
        let offs = c.pos() as u32;

        let headid = c.u32()?;
        if headid != SIT5_ID {
            return Err(invalid("stuffit5: bad entry id"));
        }
        let version = c.u8()?;
        c.skip(1)?;
        let headersize = c.u16()? as usize;
        let headerend = offs as usize + headersize;
        c.skip(1)?;
        let flags = c.u8()?;
        let creation_date = c.u32()?;
        let modification_date = c.u32()?;
        let _prevoffs = c.u32()?;
        let _nextoffs = c.u32()?;
        let diroffs = c.u32()?;
        let namelength = c.u16()? as usize;
        let _headercrc = c.u16()?;
        let datalength = c.u32()?;
        let datacomplen = c.u32()? as usize;
        let datacrc = c.u16()?;
        c.skip(2)?;

        let is_dir = flags & ENTRYFLAGS_DIRECTORY != 0;
        let crypted = flags & ENTRYFLAGS_CRYPTED != 0;
        let mut datamethod = 0u8;
        let mut numfiles = 0usize;
        let mut datakey = None;
        if is_dir {
            numfiles = c.u16()? as usize;
            if datalength == 0xFFFF_FFFF {
                // Phantom entry after each directory; skip it.
                count += 1;
                i += 1;
                continue;
            }
        } else {
            datamethod = c.u8()?;
            datakey = read_fork_key(c, crypted, datalength)?;
        }

        let namedata = c.take(namelength)?;

        // Optional comment, present only when the header has room left for it.
        if c.pos() < headerend {
            let commentsize = c.u16()? as usize;
            c.skip(2)?;
            c.skip(commentsize)?;
        }

        // Second header block.
        let something = c.u16()?;
        c.skip(2)?;
        let file_type = c.array4()?;
        let creator = c.array4()?;
        let finder_flags = c.u16()?;
        if version == 1 {
            c.skip(22)?;
        } else {
            c.skip(18)?;
        }

        let hasresource = something & 0x01 != 0;
        let mut resourcelength = 0u32;
        let mut resourcecomplen = 0usize;
        let mut resourcecrc = 0u16;
        let mut resourcemethod = 0u8;
        let mut rsrckey = None;
        if hasresource {
            resourcelength = c.u32()?;
            resourcecomplen = c.u32()? as usize;
            resourcecrc = c.u16()?;
            c.skip(2)?;
            resourcemethod = c.u8()?;
            rsrckey = read_fork_key(c, crypted, resourcelength)?;
        }

        let datastart = c.pos();
        let parent = dirs.get(&diroffs).map(Vec::as_slice).unwrap_or(&[]);
        let path = join_path(parent, namedata);

        if is_dir {
            dirs.insert(offs, path.clone());
            entries.push(StuffIt5Entry {
                name: path,
                is_directory: true,
                is_resource_fork: false,
                is_encrypted: false,
                size: 0,
                file_type,
                creator,
                finder_flags,
                creation_date,
                modification_date,
                fork: None,
            });
            c.seek(datastart)?;
            count += numfiles;
        } else {
            if hasresource {
                entries.push(StuffIt5Entry {
                    name: path.clone(),
                    is_directory: false,
                    is_resource_fork: true,
                    is_encrypted: rsrckey.is_some(),
                    size: resourcelength,
                    file_type,
                    creator,
                    finder_flags,
                    creation_date,
                    modification_date,
                    fork: Some(ForkInfo {
                        offset: datastart,
                        complen: resourcecomplen,
                        method: resourcemethod,
                        crc: resourcecrc,
                        key: rsrckey,
                    }),
                });
            }
            if datalength != 0 || !hasresource {
                entries.push(StuffIt5Entry {
                    name: path,
                    is_directory: false,
                    is_resource_fork: false,
                    is_encrypted: datakey.is_some(),
                    size: datalength,
                    file_type,
                    creator,
                    finder_flags,
                    creation_date,
                    modification_date,
                    fork: Some(ForkInfo {
                        offset: datastart + resourcecomplen,
                        complen: datacomplen,
                        method: datamethod,
                        crc: datacrc,
                        key: datakey,
                    }),
                });
            }
            c.seek(datastart + resourcecomplen + datacomplen)?;
        }
        i += 1;
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    // === mirror StuffIt-Huffman encoder (balanced tree) ======================
    //
    // A faithful copy of the classic StuffIt test machinery, kept local per the
    // house oracle convention. Enough to compress fork fixtures with methods
    // 0/1/2/3 so the container round-trips through our own decoder.

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

    fn huffman_encode(content: &[u8]) -> Vec<u8> {
        let mut symbols: Vec<u8> = content.to_vec();
        symbols.sort_unstable();
        symbols.dedup();
        let mut w = BitW::new();
        write_tree(&mut w, &symbols);
        let mut codes = HashMap::new();
        walk_codes(&symbols, 0, 0, &mut codes);
        for &b in content {
            let (c, l) = codes[&b];
            w.put_bits(c, l);
        }
        w.finish()
    }

    // === mirror Unix-compress (LZW) encoder ==================================

    fn lzw_encode(input: &[u8]) -> Vec<u8> {
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
                assert!(next_code < 512, "lzw fixture too large for 9-bit codes");
                current = vec![c];
            }
        }
        bits.bits(dict[&current], 9);
        bits.finish()
    }

    fn compress(method: u8, content: &[u8]) -> Vec<u8> {
        match method & 0x0f {
            0 => content.to_vec(),
            1 => content.to_vec(), // RLE90 identity (content has no 0x90)
            2 => lzw_encode(content),
            3 => huffman_encode(content),
            m => panic!("mirror builder cannot compress method {m}"),
        }
    }

    // === mirror StuffIt 5 container builder ==================================

    struct ForkSpec {
        method: u8,
        content: Vec<u8>,
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

    /// The 48-byte fixed entry prefix (identical length for files and folders).
    #[allow(clippy::too_many_arguments)]
    fn entry_prefix(
        flags: u8,
        diroffs: u32,
        namelen: usize,
        datalength: u32,
        datacomplen: u32,
        datacrc: u16,
        method_or_numfiles: u16,
    ) -> Vec<u8> {
        let mut h = vec![0u8; 48];
        h[0..4].copy_from_slice(&SIT5_ID.to_be_bytes());
        h[4] = 1; // version
        let headersize = (48 + namelen) as u16;
        h[6..8].copy_from_slice(&headersize.to_be_bytes());
        h[9] = flags;
        h[26..30].copy_from_slice(&diroffs.to_be_bytes());
        h[30..32].copy_from_slice(&(namelen as u16).to_be_bytes());
        h[34..38].copy_from_slice(&datalength.to_be_bytes());
        h[38..42].copy_from_slice(&datacomplen.to_be_bytes());
        h[42..44].copy_from_slice(&datacrc.to_be_bytes());
        if flags & ENTRYFLAGS_DIRECTORY != 0 {
            h[46..48].copy_from_slice(&method_or_numfiles.to_be_bytes());
        } else {
            h[46] = method_or_numfiles as u8; // datamethod
            h[47] = 0; // passlen
        }
        h
    }

    /// The second header block (14 fixed bytes + 22 filler for version 1),
    /// optionally followed by the resource-fork descriptor.
    fn second_block(
        file_type: [u8; 4],
        creator: [u8; 4],
        rsrc: Option<(u32, u32, u16, u8)>, // len, complen, crc, method
    ) -> Vec<u8> {
        let mut b = Vec::new();
        let something: u16 = if rsrc.is_some() { 0x01 } else { 0x00 };
        b.extend_from_slice(&something.to_be_bytes());
        b.extend_from_slice(&[0, 0]); // ???
        b.extend_from_slice(&file_type);
        b.extend_from_slice(&creator);
        b.extend_from_slice(&[0, 0]); // finder flags
        b.extend_from_slice(&[0u8; 22]); // version-1 filler
        if let Some((len, complen, crc, method)) = rsrc {
            b.extend_from_slice(&len.to_be_bytes());
            b.extend_from_slice(&complen.to_be_bytes());
            b.extend_from_slice(&crc.to_be_bytes());
            b.extend_from_slice(&[0, 0]); // ???
            b.push(method);
            b.push(0); // passlen
        }
        b
    }

    fn emit(node: &Node, parent_offs: u32, records: &mut Vec<u8>) {
        let offs = (HEADER_LEN + records.len()) as u32;
        match node {
            Node::Dir(name, children) => {
                let numfiles = children.len() as u16;
                records.extend_from_slice(&entry_prefix(
                    ENTRYFLAGS_DIRECTORY,
                    parent_offs,
                    name.len(),
                    0,
                    0,
                    0,
                    numfiles,
                ));
                records.extend_from_slice(name);
                records.extend_from_slice(&second_block(*b"fold", *b"MACS", None));
                for child in children {
                    emit(child, offs, records);
                }
            }
            Node::File(f) => {
                let rcomp = f.rsrc.as_ref().map(|r| compress(r.method, &r.content));
                let dcomp = f.data.as_ref().map(|d| compress(d.method, &d.content));
                let rlen = f.rsrc.as_ref().map_or(0, |r| r.content.len()) as u32;
                let dlen = f.data.as_ref().map_or(0, |d| d.content.len()) as u32;
                let rcomplen = rcomp.as_ref().map_or(0, |c| c.len()) as u32;
                let dcomplen = dcomp.as_ref().map_or(0, |c| c.len()) as u32;
                let rmethod = f.rsrc.as_ref().map_or(0, |r| r.method);
                let dmethod = f.data.as_ref().map_or(0, |d| d.method);
                let rcrc = f.rsrc.as_ref().map_or(0, |r| crc16(&r.content, r.method));
                let dcrc = f.data.as_ref().map_or(0, |d| crc16(&d.content, d.method));

                records.extend_from_slice(&entry_prefix(
                    0,
                    parent_offs,
                    f.name.len(),
                    dlen,
                    dcomplen,
                    dcrc,
                    dmethod as u16,
                ));
                records.extend_from_slice(f.name);

                let rsrc_desc = f.rsrc.as_ref().map(|_| (rlen, rcomplen, rcrc, rmethod));
                records.extend_from_slice(&second_block(f.file_type, f.creator, rsrc_desc));

                if let Some(c) = rcomp {
                    records.extend_from_slice(&c);
                }
                if let Some(c) = dcomp {
                    records.extend_from_slice(&c);
                }
            }
        }
    }

    /// CRC-16/ARC of `content`, except 0 for method 15 (Arsenic has its own CRC).
    fn crc16(content: &[u8], method: u8) -> u16 {
        if method & 0x0f == 15 {
            0
        } else {
            newtua_common::crc16::crc16_arc(content)
        }
    }

    /// The 100-byte base archive header: banner (wildcards filled with "2000"),
    /// version 5, `flags`, top-level `numfiles`, and `firstoffs`. `totalsize`
    /// (offset 84) is left zero for the caller to patch after appending records.
    fn base_header(flags: u8, numfiles: u16, firstoffs: u32) -> Vec<u8> {
        let mut arc = vec![0u8; HEADER_LEN];
        let mut banner = BANNER.to_vec();
        for (i, b) in banner.iter_mut().enumerate() {
            if *b == 0xFF {
                *b = b"2000"[i - 16];
            }
        }
        arc[..banner.len()].copy_from_slice(&banner);
        arc[82] = SIT5_VERSION;
        arc[83] = flags;
        arc[92..94].copy_from_slice(&numfiles.to_be_bytes());
        arc[94..98].copy_from_slice(&firstoffs.to_be_bytes());
        arc
    }

    fn build_archive(nodes: &[Node]) -> Vec<u8> {
        let mut records = Vec::new();
        for node in nodes {
            emit(node, 0, &mut records);
        }
        let mut arc = base_header(0, nodes.len() as u16, HEADER_LEN as u32);
        arc.extend_from_slice(&records);
        let totalsize = arc.len() as u32;
        arc[84..88].copy_from_slice(&totalsize.to_be_bytes());
        arc
    }

    fn open(arc: &[u8]) -> StuffIt5Archive {
        StuffIt5Archive::open(arc).unwrap()
    }

    fn read(a: &StuffIt5Archive, idx: usize) -> Vec<u8> {
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
        assert!(StuffIt5Archive::recognize(&arc));
    }

    #[test]
    fn rejects_garbage_and_short_input() {
        assert!(!StuffIt5Archive::recognize(
            b"not a stuffit 5 archive at all"
        ));
        assert!(!StuffIt5Archive::recognize(b"StuffIt (c)1997-"));
        assert!(!StuffIt5Archive::recognize(&[0u8; 200]));
    }

    // === single file, one fork ===============================================

    #[test]
    fn single_data_fork_store() {
        let arc = build_archive(&[Node::File(FileSpec::plain(
            b"d",
            Some(fork(0, b"only data")),
            None,
        ))]);
        let a = open(&arc);
        assert_eq!(a.entries().len(), 1);
        assert!(!a.entries()[0].is_resource_fork());
        assert_eq!(a.entries()[0].name(), b"d");
        assert_eq!(read(&a, 0), b"only data");
    }

    #[test]
    fn empty_file_yields_one_empty_data_fork() {
        let arc = build_archive(&[Node::File(FileSpec::plain(b"empty", None, None))]);
        let a = open(&arc);
        assert_eq!(a.entries().len(), 1);
        assert!(!a.entries()[0].is_resource_fork());
        assert_eq!(a.entries()[0].size(), 0);
        assert_eq!(read(&a, 0), b"");
    }

    // === both forks, resource first ==========================================

    #[test]
    fn both_forks_resource_first() {
        let arc = build_archive(&[Node::File(FileSpec::plain(
            b"both",
            Some(fork(0, b"DATA")),
            Some(fork(0, b"RES")),
        ))]);
        let a = open(&arc);
        assert_eq!(a.entries().len(), 2);
        assert!(a.entries()[0].is_resource_fork());
        assert!(!a.entries()[1].is_resource_fork());
        assert_eq!(a.entries()[0].name(), b"both");
        assert_eq!(a.entries()[1].name(), b"both");
        assert_eq!(read(&a, 0), b"RES");
        assert_eq!(read(&a, 1), b"DATA");
    }

    #[test]
    fn resource_only_file() {
        let arc = build_archive(&[Node::File(FileSpec::plain(
            b"r",
            None,
            Some(fork(0, b"only rsrc")),
        ))]);
        let a = open(&arc);
        assert_eq!(a.entries().len(), 1);
        assert!(a.entries()[0].is_resource_fork());
        assert_eq!(read(&a, 0), b"only rsrc");
    }

    // === nested folder tree ==================================================

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
        let a = open(&arc);
        assert_eq!(a.entries().len(), 2);
        assert!(a.entries()[0].is_directory());
        assert_eq!(a.entries()[0].name(), b"dir");
        assert_eq!(a.entries()[1].name(), b"dir/inner");
        assert_eq!(read(&a, 1), b"hi");
    }

    #[test]
    fn sibling_after_folder_returns_to_root() {
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
        let a = open(&arc);
        let names: Vec<&[u8]> = a.entries().iter().map(|e| e.name()).collect();
        assert_eq!(names, vec![&b"dir"[..], &b"dir/a"[..], &b"top"[..]]);
        assert_eq!(read(&a, 2), b"TT");
    }

    #[test]
    fn deeply_nested_paths() {
        let arc = build_archive(&[Node::Dir(
            b"a",
            vec![Node::Dir(
                b"b",
                vec![Node::File(FileSpec::plain(
                    b"c",
                    Some(fork(0, b"deep")),
                    None,
                ))],
            )],
        )]);
        let a = open(&arc);
        let names: Vec<&[u8]> = a.entries().iter().map(|e| e.name()).collect();
        assert_eq!(names, vec![&b"a"[..], &b"a/b"[..], &b"a/b/c"[..]]);
        assert_eq!(read(&a, 2), b"deep");
    }

    // === methods 0/1/2/3 round-trip ==========================================

    fn roundtrip_method(method: u8, content: &[u8]) {
        let arc = build_archive(&[Node::File(FileSpec::plain(
            b"f",
            Some(fork(method, content)),
            None,
        ))]);
        let a = open(&arc);
        assert_eq!(read(&a, 0), content, "method {method}");
    }

    #[test]
    fn method0_store_roundtrip() {
        roundtrip_method(0, b"stored bytes, verbatim");
    }

    #[test]
    fn method1_rle90_roundtrip() {
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

    // === metadata ============================================================

    #[test]
    fn metadata_is_parsed() {
        let arc = build_archive(&[Node::File(FileSpec {
            name: b"meta",
            file_type: *b"APPL",
            creator: *b"CODE",
            rsrc: None,
            data: Some(fork(0, b"x")),
        })]);
        let a = open(&arc);
        assert_eq!(a.entries()[0].file_type(), *b"APPL");
        assert_eq!(a.entries()[0].creator(), *b"CODE");
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
        let a = open(&arc);
        assert!(a.entries()[0].is_directory());
        assert_eq!(read(&a, 0), b"");
    }

    // === encryption (RC4 + MD5 + password) ===================================

    /// Build a one-file archive with an encrypted data fork: the archive header
    /// carries the CRYPTED flag and hash, the entry carries the CRYPTED flag and
    /// a 5-byte key, and the compressed fork is RC4-encrypted with the key
    /// `MD5(password)[..5] ++ entrykey`.
    fn build_encrypted_sit(name: &[u8], content: &[u8], method: u8, password: &[u8]) -> Vec<u8> {
        let archivekey = stuffit_md5(password);
        let hash = stuffit_md5(&archivekey);
        let entrykey = [0x11u8, 0x22, 0x33, 0x44, 0x55];
        let mut rc4_key = archivekey.to_vec();
        rc4_key.extend_from_slice(&entrykey);

        let mut fork_bytes = compress(method, content);
        Rc4::new(&rc4_key).apply(&mut fork_bytes);

        // Entry: CRYPTED prefix, patched passlen, 5-byte key, name, second block.
        let mut prefix = entry_prefix(
            ENTRYFLAGS_CRYPTED,
            0,
            name.len(),
            content.len() as u32,
            fork_bytes.len() as u32,
            crc16(content, method),
            method as u16,
        );
        prefix[47] = KEY_LENGTH as u8; // passlen
        let mut records = Vec::new();
        records.extend_from_slice(&prefix);
        records.extend_from_slice(&entrykey);
        records.extend_from_slice(name);
        records.extend_from_slice(&second_block(*b"TEXT", *b"ttxt", None));
        records.extend_from_slice(&fork_bytes);

        // Archive header with CRYPTED flag + (hashsize=5, hash) block after it.
        let mut block = vec![KEY_LENGTH as u8];
        block.extend_from_slice(&hash);
        let mut arc = base_header(ARCHIVEFLAGS_CRYPTED, 1, (HEADER_LEN + block.len()) as u32);
        arc.extend_from_slice(&block);
        arc.extend_from_slice(&records);
        let totalsize = arc.len() as u32;
        arc[84..88].copy_from_slice(&totalsize.to_be_bytes());
        arc
    }

    #[test]
    fn encrypted_store_fork_roundtrip() {
        let arc = build_encrypted_sit(b"secret", b"the treasure is buried here", 0, b"hunter2");
        let a = StuffIt5Archive::open_with_password(&arc[..], b"hunter2").unwrap();
        assert_eq!(a.entries().len(), 1);
        assert!(a.entries()[0].is_encrypted());
        assert_eq!(read(&a, 0), b"the treasure is buried here");
    }

    #[test]
    fn encrypted_huffman_fork_roundtrip() {
        // A real codec (method 3) through RC4: decrypt then decompress.
        let arc = build_encrypted_sit(b"doc", b"huffman huffman under encryption", 3, b"pass");
        let a = StuffIt5Archive::open_with_password(&arc[..], b"pass").unwrap();
        assert_eq!(read(&a, 0), b"huffman huffman under encryption");
    }

    #[test]
    fn wrong_password_errors() {
        let arc = build_encrypted_sit(b"secret", b"payload", 0, b"correct");
        let a = StuffIt5Archive::open_with_password(&arc[..], b"wrong").unwrap();
        let mut out = Vec::new();
        let err = a.read_entry(0, &mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn missing_password_errors() {
        let arc = build_encrypted_sit(b"secret", b"payload", 0, b"correct");
        let a = open(&arc); // opened without a password
        assert!(a.entries()[0].is_encrypted());
        let mut out = Vec::new();
        let err = a.read_entry(0, &mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn password_ignored_for_unencrypted_fork() {
        let arc = build_archive(&[Node::File(FileSpec::plain(
            b"plain",
            Some(fork(0, b"not encrypted")),
            None,
        ))]);
        let a = StuffIt5Archive::open_with_password(&arc[..], b"irrelevant").unwrap();
        assert!(!a.entries()[0].is_encrypted());
        assert_eq!(read(&a, 0), b"not encrypted");
    }

    #[test]
    fn archive_password_hash_is_parsed() {
        // Build a normal archive, then splice in the archive-level CRYPTED block:
        // set flag 0x80 and insert `hashsize=5` + 5 hash bytes after the header,
        // shifting firstoffs. Simpler: rebuild by hand with the crypted header.
        let mut arc = build_archive(&[Node::File(FileSpec::plain(
            b"f",
            Some(fork(0, b"hi")),
            None,
        ))]);
        // Insert the 6-byte crypted block (hashsize + 5 hash bytes) right after
        // the 100-byte header and bump firstoffs / offsets by 6.
        let hash = [1u8, 2, 3, 4, 5];
        let mut block = vec![KEY_LENGTH as u8];
        block.extend_from_slice(&hash);
        arc[83] |= ARCHIVEFLAGS_CRYPTED;
        let shift = block.len();
        arc.splice(HEADER_LEN..HEADER_LEN, block);
        // The records now start `shift` bytes later, so firstoffs must follow.
        // diroffs are root-level (0) here, so no per-entry offset fix is needed.
        arc[94..98].copy_from_slice(&((HEADER_LEN + shift) as u32).to_be_bytes());
        let a = open(&arc);
        assert_eq!(a.password_hash, Some(hash));
        assert!(a.is_encrypted);
        assert_eq!(read(&a, 0), b"hi");
    }

    // === error handling ======================================================

    #[test]
    fn bad_entry_id_is_error() {
        let mut arc =
            build_archive(&[Node::File(FileSpec::plain(b"f", Some(fork(0, b"x")), None))]);
        // Corrupt the first entry's SIT5_ID.
        arc[HEADER_LEN] ^= 0xff;
        assert!(StuffIt5Archive::open(&arc[..]).is_err());
    }

    #[test]
    fn wrong_version_is_error() {
        let mut arc =
            build_archive(&[Node::File(FileSpec::plain(b"f", Some(fork(0, b"x")), None))]);
        arc[82] = 4; // version != 5
        assert!(StuffIt5Archive::open(&arc[..]).is_err());
    }

    #[test]
    fn truncated_input_is_error() {
        let arc = build_archive(&[Node::File(FileSpec::plain(
            b"f",
            Some(fork(0, b"payload")),
            None,
        ))]);
        assert!(StuffIt5Archive::open(&arc[..arc.len() - 3]).is_err());
    }

    #[test]
    fn read_entry_out_of_range_errors() {
        let arc = build_archive(&[Node::File(FileSpec::plain(b"f", Some(fork(0, b"x")), None))]);
        let a = open(&arc);
        let mut out = Vec::new();
        assert!(a.read_entry(9, &mut out).is_err());
    }

    // === self-extracting .exe ================================================

    fn wrap_exe(archive: &[u8]) -> Vec<u8> {
        let mut exe = vec![0u8; EXE_STUB_LEN];
        exe[0] = b'M';
        exe[1] = b'Z';
        exe[4100..4104].copy_from_slice(&0x4203_E853u32.to_be_bytes());
        exe.extend_from_slice(archive);
        exe
    }

    #[test]
    fn exe_variant_is_recognized_and_opened() {
        let arc = build_archive(&[Node::File(FileSpec::plain(
            b"sfx",
            Some(fork(3, b"self extracting payload payload")),
            None,
        ))]);
        let exe = wrap_exe(&arc);
        assert!(StuffIt5Archive::recognize(&exe));
        assert!(!recognize(&exe)); // not a plain archive
        let a = open(&exe);
        assert_eq!(a.entries().len(), 1);
        assert_eq!(a.entries()[0].name(), b"sfx");
        assert_eq!(read(&a, 0), b"self extracting payload payload");
    }
}
