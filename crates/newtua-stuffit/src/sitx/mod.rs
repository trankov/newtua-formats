// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! StuffItX (`.sitx`) archive support.
//!
//! A pure-Rust port of XADMaster's `XADStuffItXParser` and its low-level
//! helpers (`StuffItXUtilities`, `XADStuffItXBlockHandle`, `XADStuffItXX86Handle`).
//! StuffItX is Aladdin/Allume's post-2002 container: a bit-packed stream of
//! *elements* (files, forks, directories, a catalog) whose data areas are wrapped
//! in a length-prefixed *block* stream and fed through one of several codecs.
//!
//! Stage 19a brought up the whole container plus the simple codecs — **None**,
//! the StuffItX **Deflate** variant, and **RC4** (method 5) — with the **x86**
//! preprocessor. Stage 19g added **Brimstone** (PPMd variant G, `ppmd/`). Stage
//! 19c added **Cyanide**, 19d added **Darkhorse**, 19e added **Iron**, and 19f
//! added **Blend** (a meta-codec dispatching to the other three by marker).
//! Stage 19h added the **English** preprocessor (`english.rs`), gated behind
//! the `english-dict` cargo feature because it embeds a ~414 KB dictionary
//! asset; without that feature it surfaces as [`io::ErrorKind::Unsupported`].

mod blend;
mod brimstone;
mod bwt;
mod cyanide;
mod darkhorse;
#[cfg(feature = "english-dict")]
mod english;
mod iron;
mod p2;
mod ppmd;
mod rangecoder;
mod x86;

use std::collections::{HashMap, HashSet};
use std::io::{self, Write};

use newtua_common::{crc32, deflate, rc4::Rc4};

use p2::Reader;

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn unsupported(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, msg.into())
}

// === recognition ==============================================================

/// Whether `data` opens with the StuffItX banner `StuffIt` followed by `!` (a
/// plain archive) or `?` (a base-N encoded body). Port of
/// `+recognizeFileWithHandle:` (`XADStuffItXParser.m:260`).
fn recognize(data: &[u8]) -> bool {
    data.len() >= 8 && &data[0..7] == b"StuffIt" && (data[7] == b'!' || data[7] == b'?')
}

// === element model ============================================================

/// One raw element header (`StuffItXElement`, `XADStuffItXParser.m:17`). Attribute
/// and algorithm slots default to `-1` ("absent"); `dataoffset`/`actualsize`/
/// `datacrc` are filled while scanning the data area.
#[derive(Clone)]
struct Element {
    typ: u64,
    attribs: [i64; 10],
    alglist: [i64; 6],
    dataoffset: usize,
    actualsize: u64,
    datacrc: u32,
}

/// Read one element header (`ReadElement`, `:32`): a discarded bit, the element
/// type, the attribute list, then the algorithm list (algorithm 4 carries an
/// extra crypto parameter). Leaves the reader positioned at the data area.
///
/// `saw_unknown_field` is set (never cleared) when an attribute type is > 10 or
/// an algorithm-list type is > 6. The reference logs these as "attrib type too
/// big" / "alglist type too big" — they're the signature of a recovery-record
/// (mac "recoverability") or redundancy (win) element, whose layout the
/// reference doesn't model either; the stream desyncs and reads eventually run
/// off the end. The value is still read and discarded (matching the reference,
/// which keeps going rather than bailing here) — only the flag lets `parse`
/// relabel a later `UnexpectedEof` as `Unsupported` instead of a raw truncation.
fn read_element(r: &mut Reader, saw_unknown_field: &mut bool) -> io::Result<Element> {
    r.bit()?; // discarded "something" bit (only its side effect matters)
    let mut el = Element {
        typ: r.read_p2()?,
        attribs: [-1; 10],
        alglist: [-1; 6],
        dataoffset: 0,
        actualsize: 0,
        datacrc: 0,
    };

    loop {
        let atype = r.read_p2()?;
        if atype == 0 {
            break;
        }
        let value = r.read_p2()?;
        if atype <= 10 {
            el.attribs[(atype - 1) as usize] = value as i64;
        } else {
            *saw_unknown_field = true;
        }
    }

    loop {
        let altype = r.read_p2()?;
        if altype == 0 {
            break;
        }
        let value = r.read_p2()?;
        if altype <= 6 {
            el.alglist[(altype - 1) as usize] = value as i64;
        } else {
            *saw_unknown_field = true;
        }
        if altype == 4 {
            r.read_p2()?; // crypto's extra parameter, read but currently unused
        }
    }

    el.dataoffset = r.offset();
    Ok(el)
}

/// Skip an element's block-stream body and capture its trailing CRC32
/// (`ScanElementData`, `:66`). The body is `[len:P2][len bytes]…` ended by a
/// zero-length block; the tail may hold a four-byte CRC block.
fn scan_element_data(r: &mut Reader, el: &mut Element) -> io::Result<()> {
    r.seek(el.dataoffset);
    r.flush();

    loop {
        let len = r.read_p2()? as usize;
        if len == 0 {
            break;
        }
        r.skip(len)?;
    }

    r.flush();
    let mut len = r.read_p2()? as usize;
    if len == 0 {
        return Ok(());
    }
    if len == 4 {
        // `-[CSHandle readUInt32BE]` reads four raw byte-aligned bytes (not the
        // bit-path `ReadSitxUInt32` the catalog uses).
        el.datacrc = r.read_raw_u32_be()?;
        len = r.read_p2()? as usize;
    }
    while len != 0 {
        r.skip(len)?;
        len = r.read_p2()? as usize;
    }
    Ok(())
}

// === decode chain =============================================================

/// A fully-described compressed stream (one data or catalog element), enough to
/// reproduce its decoded bytes on demand without re-walking the archive.
#[derive(Clone)]
struct StreamDescriptor {
    dataoffset: usize,
    compression: i64,
    checksum: i64,
    preprocess: i64,
    crypto: i64,
    actualsize: u64,
    datacrc: u32,
}

impl StreamDescriptor {
    fn from_element(el: &Element) -> Self {
        Self {
            dataoffset: el.dataoffset,
            compression: el.alglist[0],
            checksum: el.alglist[1],
            preprocess: el.alglist[2],
            crypto: el.alglist[3],
            actualsize: el.actualsize,
            datacrc: el.datacrc,
        }
    }
}

/// Build the decoded bytes of a stream (`HandleForElement`, `:97`): unwrap the
/// block layer, run the compression codec, apply the preprocessor, and optionally
/// verify the IEEE CRC32. Unsupported codecs/preprocessors surface as
/// [`io::ErrorKind::Unsupported`].
fn decode_stream(data: &[u8], desc: &StreamDescriptor, want_checksum: bool) -> io::Result<Vec<u8>> {
    if desc.crypto >= 0 {
        return Err(unsupported("sitx: encrypted streams are not supported"));
    }

    let mut r = Reader::new(data);
    let blocks = p2::read_block_stream(&mut r, desc.dataoffset)?;
    let size = desc.actualsize as usize;

    let decompressed = match desc.compression {
        -1 => blocks,
        0 => {
            // `allocsize=1<<readUInt8()`, `order=readUInt8()`, read from the
            // deblocked stream by the container's switch before handing off
            // to the codec (`XADStuffItXParser.m:123-124`).
            let allocsize_exp = *blocks
                .first()
                .ok_or_else(|| invalid("sitx: empty brimstone stream"))?;
            let order = *blocks
                .get(1)
                .ok_or_else(|| invalid("sitx: truncated brimstone stream"))?;
            let allocsize = 1usize << allocsize_exp;
            brimstone::decode(&blocks[2..], size, order as u32, allocsize)?
        }
        1 => cyanide::decode(&blocks, size)?,
        2 => darkhorse::decode(&blocks, size)?,
        3 => {
            // Modified deflate: one window-size byte, then the deflate stream.
            let windowsize = *blocks
                .first()
                .ok_or_else(|| invalid("sitx: empty deflate stream"))?;
            if windowsize != 15 {
                return Err(unsupported(format!(
                    "sitx: deflate window size {windowsize} is not supported"
                )));
            }
            deflate::inflate_sitx(&blocks[1..], size)?
        }
        4 => blend::decode(&blocks, size)?,
        5 => {
            // No compression, obscured by RC4: skip two bytes, one key byte, then
            // RC4 over the rest (`XADStuffItXParser.m:158`).
            let key = blocks
                .get(2..3)
                .ok_or_else(|| invalid("sitx: truncated RC4 stream"))?;
            let mut out = blocks
                .get(3..)
                .ok_or_else(|| invalid("sitx: truncated RC4 stream"))?
                .to_vec();
            Rc4::new(key).apply(&mut out);
            out
        }
        6 => iron::decode(&blocks, size)?,
        other => {
            return Err(unsupported(format!(
                "sitx: unknown compression method {other}"
            )))
        }
    };

    let preprocessed = match desc.preprocess {
        -1 => decompressed,
        0 => {
            #[cfg(feature = "english-dict")]
            {
                english::decode(&decompressed, size)?
            }
            #[cfg(not(feature = "english-dict"))]
            {
                return Err(unsupported(
                    "sitx: English preprocessor requires the `english-dict` feature",
                ));
            }
        }
        2 => x86::decode(&decompressed, size),
        other => return Err(unsupported(format!("sitx: unknown preprocessor {other}"))),
    };

    if want_checksum && desc.checksum == 0 && crc32::crc32_ieee(&preprocessed) != desc.datacrc {
        return Err(invalid("sitx: stream CRC32 mismatch"));
    }

    Ok(preprocessed)
}

// === fork bookkeeping =========================================================

/// One fork slot in a stream (`streamforks`): the entries sharing it, its fork
/// type (0 data, 1 resource), and its decoded length.
#[derive(Clone)]
struct Fork {
    entries: Vec<i64>,
    typ: u64,
    length: u64,
}

/// A catalog node being assembled: identity plus the metadata the catalog fills
/// in. Snapshotted into a [`SitxEntry`] when its data element is emitted.
#[derive(Clone)]
struct EntryBuilder {
    id: i64,
    parent: i64,
    is_directory: bool,
    path: Option<Vec<u8>>,
    is_link: bool,
    finder_info: Option<[u8; 32]>,
    posix_permissions: Option<u32>,
    posix_uid: Option<u32>,
    posix_gid: Option<u32>,
    mtime_1601: Option<u64>,
    ctime_1601: Option<u64>,
    comment: Option<Vec<u8>>,
}

impl EntryBuilder {
    fn new(id: i64, parent: i64, is_directory: bool) -> Self {
        Self {
            id,
            parent,
            is_directory,
            path: None,
            is_link: false,
            finder_info: None,
            posix_permissions: None,
            posix_uid: None,
            posix_gid: None,
            mtime_1601: None,
            ctime_1601: None,
            comment: None,
        }
    }
}

// === public types =============================================================

/// How to extract one fork's bytes from its solid stream.
#[derive(Clone)]
struct ForkExtract {
    stream: StreamDescriptor,
    /// Offset of this fork inside the decoded stream.
    solid_offset: usize,
    /// This fork's decoded length.
    length: usize,
}

/// One StuffItX catalog entry: a directory, an empty file, or one fork (data or
/// resource) of a file, flattened in emission order.
pub struct SitxEntry {
    name: Vec<u8>,
    is_directory: bool,
    is_resource_fork: bool,
    is_link: bool,
    size: u64,
    compressed_size: u64,
    compression_name: String,
    finder_info: Option<[u8; 32]>,
    posix_permissions: Option<u32>,
    posix_uid: Option<u32>,
    posix_gid: Option<u32>,
    mtime_1601: Option<u64>,
    ctime_1601: Option<u64>,
    comment: Option<Vec<u8>>,
    fork: Option<ForkExtract>,
}

impl SitxEntry {
    /// The full path from the archive root, raw bytes, joined with `/`. A file's
    /// two forks share the same path.
    pub fn name(&self) -> &[u8] {
        &self.name
    }
    /// The fork's decoded length in bytes (0 for directories and empty files).
    pub fn size(&self) -> u64 {
        self.size
    }
    /// The fork's approximate compressed size: its proportional share of the
    /// solid stream's compressed length (`XADCompressedSizeKey`). 0 for
    /// directories and empty files.
    pub fn compressed_size(&self) -> u64 {
        self.compressed_size
    }
    /// Whether this entry is a directory.
    pub fn is_directory(&self) -> bool {
        self.is_directory
    }
    /// Whether this entry is a resource fork (`false` for data forks, empty files
    /// and directories).
    pub fn is_resource_fork(&self) -> bool {
        self.is_resource_fork
    }
    /// Whether the catalog marks this entry as a symbolic link (its Finder info
    /// began with `slnkrhap`).
    pub fn is_link(&self) -> bool {
        self.is_link
    }
    /// A human-readable compression method name (e.g. `None`, `Deflate`,
    /// `Deflate+x86`), matching `XADCompressionNameKey`.
    pub fn compression_name(&self) -> &str {
        &self.compression_name
    }
    /// The 32-byte Finder info, when the catalog carried it.
    pub fn finder_info(&self) -> Option<&[u8; 32]> {
        self.finder_info.as_ref()
    }
    /// POSIX permission bits, when present.
    pub fn posix_permissions(&self) -> Option<u32> {
        self.posix_permissions
    }
    /// POSIX owner uid, when present.
    pub fn posix_uid(&self) -> Option<u32> {
        self.posix_uid
    }
    /// POSIX owner gid, when present.
    pub fn posix_gid(&self) -> Option<u32> {
        self.posix_gid
    }
    /// Last-modification time as raw Windows FILETIME ticks (100-ns units since
    /// 1601-01-01); divide by 10_000_000 for seconds since 1601.
    pub fn modification_filetime(&self) -> Option<u64> {
        self.mtime_1601
    }
    /// Creation time as raw Windows FILETIME ticks (see [`Self::modification_filetime`]).
    pub fn creation_filetime(&self) -> Option<u64> {
        self.ctime_1601
    }
    /// The entry comment, raw bytes, when the catalog carried a non-empty one.
    pub fn comment(&self) -> Option<&[u8]> {
        self.comment.as_deref()
    }
}

/// A parsed StuffItX archive: its raw bytes plus the flattened catalog.
pub struct SitxArchive {
    data: Vec<u8>,
    entries: Vec<SitxEntry>,
}

impl SitxArchive {
    /// Whether `data` looks like a StuffItX archive.
    pub fn recognize(data: &[u8]) -> bool {
        recognize(data)
    }

    /// Parse a StuffItX archive from an in-memory byte buffer. A base-N encoded
    /// body (`StuffIt?`) returns [`io::ErrorKind::Unsupported`].
    pub fn open(data: impl Into<Vec<u8>>) -> io::Result<Self> {
        let data = data.into();
        let entries = parse(&data)?;
        Ok(Self { data, entries })
    }

    /// The flattened catalog in emission order: empty entries (directories and
    /// fork-less files) first, then each stream's forks.
    pub fn entries(&self) -> &[SitxEntry] {
        &self.entries
    }

    /// Write entry `idx`'s decoded fork bytes to `out`. Directories and empty
    /// files write nothing. Unsupported codecs return [`io::ErrorKind::Unsupported`].
    pub fn read_entry(&self, idx: usize, out: &mut dyn Write) -> io::Result<()> {
        let entry = self
            .entries
            .get(idx)
            .ok_or_else(|| invalid("sitx: entry index out of range"))?;
        let fork = match &entry.fork {
            None => return Ok(()),
            Some(f) => f,
        };
        let decoded = decode_stream(&self.data, &fork.stream, true)?;
        let slice = decoded
            .get(fork.solid_offset..fork.solid_offset + fork.length)
            .ok_or_else(|| invalid("sitx: fork range past end of decoded stream"))?;
        out.write_all(slice)
    }
}

// === compression / preprocessor names =========================================

/// The `XADCompressionNameKey` string for a data element (`:362`).
fn method_name(compression: i64, preprocess: i64) -> String {
    let comp = match compression {
        0 => "Brimstone/PPMd".to_string(),
        1 => "Cyanide".to_string(),
        2 => "Darkhorse".to_string(),
        3 => "Deflate".to_string(),
        4 => "Blend".to_string(),
        5 => "None".to_string(),
        6 => "Iron".to_string(),
        other => format!("Method {other}"),
    };
    let pre = match preprocess {
        -1 => None,
        0 => Some("English"),
        1 => Some("Biff"),
        2 => Some("x86"),
        3 => Some("PEFF"),
        4 => Some("M68k"),
        5 => Some("Sparc"),
        6 => Some("TIFF"),
        7 => Some("WAV"),
        8 => Some("WRT"),
        _ => None,
    };
    match pre {
        Some(p) => format!("{comp}+{p}"),
        None => comp,
    }
}

// === main parse loop ==========================================================

/// The parser working set (`-parse`, `:288`).
struct Parser {
    entries: Vec<EntryBuilder>,
    entrydict: HashMap<i64, usize>,
    streamforks: HashMap<i64, Vec<Option<Fork>>>,
    forkedset: Option<HashSet<i64>>,
    output: Vec<SitxEntry>,
}

/// Snapshot a builder's shared metadata into a fresh output entry (without the
/// fork specifics), the copy `addEntryWithDictionary` stores.
fn snapshot(b: &EntryBuilder) -> SitxEntry {
    SitxEntry {
        name: b.path.clone().unwrap_or_default(),
        is_directory: b.is_directory,
        is_resource_fork: false,
        is_link: b.is_link,
        size: 0,
        compressed_size: 0,
        compression_name: String::new(),
        finder_info: b.finder_info,
        posix_permissions: b.posix_permissions,
        posix_uid: b.posix_uid,
        posix_gid: b.posix_gid,
        mtime_1601: b.mtime_1601,
        ctime_1601: b.ctime_1601,
        comment: b.comment.clone(),
        fork: None,
    }
}

fn parse(data: &[u8]) -> io::Result<Vec<SitxEntry>> {
    if !recognize(data) {
        return Err(invalid("sitx: not a StuffItX archive"));
    }

    let mut r = Reader::new(data);
    r.skip(7)?;
    let marker = r.raw(1)?[0];
    if marker == b'?' {
        return Err(unsupported("sitx: base-N encoded bodies are not supported"));
    }

    let mut p = Parser {
        entries: Vec::new(),
        entrydict: HashMap::new(),
        streamforks: HashMap::new(),
        forkedset: Some(HashSet::new()),
        output: Vec::new(),
    };

    // Recovery-record (mac "recoverability") and redundancy (win) elements use a
    // layout the reference doesn't model either: `read_element` desyncs on them
    // (an attribute/algorithm type outside the known range) and the parse
    // eventually runs off the end of the stream. Relabel that specific
    // UnexpectedEof as Unsupported so it reads as "format not supported" rather
    // than "corrupt archive" — but only when we've actually seen that signature,
    // so a genuinely truncated ordinary archive still reports UnexpectedEof.
    let mut saw_unknown_element_field = false;
    if let Err(e) = parse_elements(data, &mut r, &mut p, &mut saw_unknown_element_field) {
        if e.kind() == io::ErrorKind::UnexpectedEof && saw_unknown_element_field {
            return Err(unsupported(
                "sitx: recovery-record / redundancy archives are not supported",
            ));
        }
        return Err(e);
    }

    Ok(p.output)
}

/// The element-parsing loop (`-parse`'s main `while` body, `:288-...`), factored
/// out of [`parse`] so a resulting `UnexpectedEof` can be inspected — and
/// potentially relabeled — before it leaves `parse`.
fn parse_elements(
    data: &[u8],
    r: &mut Reader,
    p: &mut Parser,
    saw_unknown_element_field: &mut bool,
) -> io::Result<()> {
    loop {
        let mut el = read_element(r, saw_unknown_element_field)?;
        match el.typ {
            0 => break, // end
            1 => handle_data(p, r, &mut el)?,
            2 => {
                let (id, parent) = (el.attribs[0], el.attribs[1]);
                let idx = p.entries.len();
                p.entries.push(EntryBuilder::new(id, parent, false));
                p.entrydict.insert(id, idx);
            }
            3 => handle_fork(p, r, &el)?,
            4 => {
                let (id, parent) = (el.attribs[0], el.attribs[1]);
                let idx = p.entries.len();
                p.entries.push(EntryBuilder::new(id, parent, true));
                p.entrydict.insert(id, idx);
            }
            5 => {
                scan_element_data(r, &mut el)?;
                el.actualsize = el.attribs[4].max(0) as u64;
                let pos = r.offset();
                let catalog = decode_stream(data, &StreamDescriptor::from_element(&el), false)?;
                parse_catalog(&catalog, p)?;
                r.seek(pos);
            }
            6 => {
                let size = el.attribs[4].max(0) as usize;
                r.skip(size)?;
            }
            7 => {
                r.read_p2()?; // root: one discarded value
            }
            8 | 9 => {}
            _ => {
                if el.typ > 10 {
                    scan_element_data(r, &mut el)?;
                } else {
                    return Err(unsupported(format!(
                        "sitx: unsupported element type {}",
                        el.typ
                    )));
                }
            }
        }
        r.flush();
    }

    Ok(())
}

/// Insert a fork element into its stream (`case 3`, `:470`). Forks may arrive out
/// of order (padded with empty slots) and several files may share one fork slot.
fn handle_fork(p: &mut Parser, r: &mut Reader, el: &Element) -> io::Result<()> {
    let entry = el.attribs[1];
    let stream = el.attribs[2];
    let index = el.attribs[3];
    let length = el.attribs[4];
    let typ = r.read_p2()?;

    if let Some(set) = p.forkedset.as_mut() {
        set.insert(entry);
    }
    let length = u64::try_from(length).map_err(|_| invalid("sitx: negative fork length"))?;
    let index = usize::try_from(index).map_err(|_| invalid("sitx: negative fork index"))?;

    let forks = p.streamforks.entry(stream).or_default();
    let count = forks.len();
    let fork = Fork {
        entries: vec![entry],
        typ,
        length,
    };
    if index >= count {
        forks.resize_with(index, || None);
        forks.push(Some(fork));
    } else {
        match &mut forks[index] {
            slot @ None => *slot = Some(fork),
            Some(existing) => {
                if existing.length != length {
                    return Err(invalid("sitx: replicated fork length mismatch"));
                }
                existing.entries.push(entry);
            }
        }
    }
    Ok(())
}

/// Materialise a data stream (`case 1`, `:321`): size its forks, emit fork-less
/// entries once, then emit each fork's entries with their extraction offsets.
fn handle_data(p: &mut Parser, r: &mut Reader, el: &mut Element) -> io::Result<()> {
    let objid = el.attribs[0];
    let uncompsize = el.attribs[4].max(0) as u64;
    let compression = el.alglist[0];
    let preprocess = el.alglist[2];

    scan_element_data(r, el)?;
    let pos = r.offset();

    // Total decoded size = sum of the stream's fork lengths. Borrow the fork list
    // (never mutated here) rather than cloning it; the later mutations of `p`
    // touch only disjoint fields (`forkedset`, `output`, `entries`, `entrydict`).
    let no_forks = Vec::new();
    let forks = p.streamforks.get(&objid).unwrap_or(&no_forks);
    let mut actualsize = 0u64;
    for fork in forks {
        let fork = fork
            .as_ref()
            .ok_or_else(|| invalid("sitx: data stream has a gap in its forks"))?;
        actualsize += fork.length;
    }
    el.actualsize = actualsize;

    // On the first data element, emit every entry that has no fork (directories
    // and empty files) as a zero-length entry, then retire the forked set.
    if let Some(forkedset) = p.forkedset.take() {
        for b in &p.entries {
            if !forkedset.contains(&b.id) {
                p.output.push(snapshot(b));
            }
        }
    }

    let compsize = (pos - el.dataoffset) as u64;
    let compname = method_name(compression, preprocess);
    let stream = StreamDescriptor::from_element(el);

    let mut offs = 0u64;
    for fork in forks {
        let fork = fork.as_ref().expect("gap already rejected above");
        if fork.typ == 0 || fork.typ == 1 {
            let is_resource = fork.typ == 1;
            // Proportional share of the stream's compressed size (`length*compsize/
            // uncompsize`, 0 when uncompsize is 0). Widened to u128 so an
            // attacker-controlled `length` can't overflow the multiply.
            let currcompsize = if uncompsize == 0 {
                0
            } else {
                (u128::from(fork.length) * u128::from(compsize) / u128::from(uncompsize)) as u64
            };
            for &entry_id in &fork.entries {
                let idx = *p
                    .entrydict
                    .get(&entry_id)
                    .ok_or_else(|| invalid("sitx: fork references an unknown entry"))?;
                let mut out = snapshot(&p.entries[idx]);
                out.is_resource_fork = is_resource;
                out.size = fork.length;
                out.compressed_size = currcompsize;
                out.compression_name = compname.clone();
                out.fork = Some(ForkExtract {
                    stream: stream.clone(),
                    solid_offset: offs as usize,
                    length: fork.length as usize,
                });
                p.output.push(out);
            }
        }
        offs += fork.length;
    }

    r.seek(pos);
    Ok(())
}

/// Parse the decoded catalog stream (`parseCatalogWithHandle:`, `:609`), filling
/// each entry's name, timestamps, Finder info, permissions and comment.
fn parse_catalog(catalog: &[u8], p: &mut Parser) -> io::Result<()> {
    let mut r = Reader::new(catalog);
    for i in 0..p.entries.len() {
        loop {
            let key = r.read_p2()?;
            if key == 0 {
                break;
            }
            match key {
                1 => {
                    let filename = r.read_string()?;
                    let parent_id = p.entries[i].parent;
                    let parent_path = p
                        .entrydict
                        .get(&parent_id)
                        .and_then(|&pi| p.entries[pi].path.clone());
                    let path = match parent_path {
                        Some(mut pp) => {
                            pp.push(b'/');
                            pp.extend_from_slice(&filename);
                            pp
                        }
                        None => filename,
                    };
                    p.entries[i].path = Some(path);
                }
                2 => p.entries[i].mtime_1601 = Some(r.read_u64_be()?),
                3 => {
                    r.read_u32_be()?;
                }
                4 | 5 => {
                    let data = r.read_data(32)?;
                    if data.len() >= 8 && &data[0..8] == b"slnkrhap" {
                        p.entries[i].is_link = true;
                    } else {
                        let mut fi = [0u8; 32];
                        fi.copy_from_slice(&data);
                        p.entries[i].finder_info = Some(fi);
                    }
                }
                6 => {
                    let hasowner = r.byte()?;
                    p.entries[i].posix_permissions = Some(r.read_u32_be()?);
                    if hasowner != 0 {
                        p.entries[i].posix_uid = Some(r.read_u32_be()?);
                        p.entries[i].posix_gid = Some(r.read_u32_be()?);
                    }
                }
                7 => {
                    r.read_p2()?;
                }
                8 => p.entries[i].ctime_1601 = Some(r.read_u64_be()?),
                9 => {
                    let comment = r.read_string()?;
                    if !comment.is_empty() {
                        p.entries[i].comment = Some(comment);
                    }
                }
                10 => {
                    let num = r.read_p2()?;
                    for _ in 0..num {
                        r.read_string()?;
                    }
                }
                11 | 12 => {
                    r.read_string()?;
                }
                other => {
                    return Err(unsupported(format!("sitx: unknown catalog tag {other}")));
                }
            }
        }
        r.flush();
    }
    Ok(())
}
