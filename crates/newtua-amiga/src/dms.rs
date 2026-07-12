//! Amiga DMS (DiskMasher) disk-image archive.
//!
//! Faithful port of XADMaster's `libxad/clients/DMS.c` container logic. DMS
//! streams an Amiga floppy image track by track, each track independently
//! compressed. This module covers the container (header, tracks, disk
//! geometry, recognition, checksums), banner/DIZ text tracks, and all seven
//! compression methods: NOCOMP (0), SIMPLE (1, an RLE scheme with a `0x90`
//! escape byte), QUICK (2) / MEDIUM (3) (two small LZ77 variants sharing one
//! sliding window), DEEP (4, an adaptive-Huffman-coded LZ77 over the same
//! window), and HEAVY1 (5) / HEAVY2 (6) (an LZ77 over a 4 KB/8 KB window
//! whose literal/length and distance alphabets are each coded with a
//! canonical Huffman table read from the bitstream itself — the tables can
//! also be *omitted* from a track and reused from whichever earlier track
//! last defined them). All six LZ-based methods share running state across
//! tracks (`DmsState`), carried forward when a track's `NOINIT` flag is set;
//! QUICK/MEDIUM/DEEP's output always feeds back through the same RLE stage
//! as SIMPLE, HEAVY's only when its own `DMSCFLAG_HEAVYRLE` bit is set.
//! Whole-disk encryption is supported (a stream XOR cipher keyed off a
//! password, applied to a track's packed bytes before decompression, with a
//! "retry without decryption" fallback for the odd unencrypted text track).
//! The FMS file sub-format (named files instead of a disk image, sharing the
//! same container) is also supported — see [`DmsArchive::files`] and
//! [`DmsArchive::read_file`]. SFX variants remain out of scope (until
//! needed).

use std::borrow::Cow;
use std::io::{self, Read};

use newtua_common::bitreader::BitReaderMsb;
use newtua_common::crc16::crc16_arc;

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Additive checksum over decompressed track/text bytes (`CheckSumDMS`,
/// `DMS.c:939-947`). Not a CRC — a plain wrapping sum of bytes as `u16`.
pub fn checksum_dms(data: &[u8]) -> u16 {
    data.iter()
        .fold(0u16, |acc, &b| acc.wrapping_add(u16::from(b)))
}

fn rle_byte(input: &[u8], pos: &mut usize) -> io::Result<u8> {
    let b = *input
        .get(*pos)
        .ok_or_else(|| invalid("DMS: RLE input truncated"))?;
    *pos += 1;
    Ok(b)
}

/// DMSCOMP_SIMPLE decoder: RLE with a `0x90` escape byte (`DMSUnpRLE`,
/// `DMS.c:315-358`). Stops once `upsize` output bytes have been produced.
fn unp_rle(input: &[u8], upsize: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(upsize);
    let mut pos = 0usize;
    while out.len() < upsize {
        let a = rle_byte(input, &mut pos)?;
        if a != 0x90 {
            out.push(a);
            continue;
        }
        let b = rle_byte(input, &mut pos)?;
        if b == 0 {
            out.push(0x90); // escaped literal 0x90
            continue;
        }
        let v = rle_byte(input, &mut pos)?;
        let n: usize = if b == 0xFF {
            let hi = rle_byte(input, &mut pos)?;
            let lo = rle_byte(input, &mut pos)?;
            ((u16::from(hi) << 8) | u16::from(lo)) as usize
        } else {
            b as usize
        };
        if out.len() + n > upsize {
            return Err(invalid("DMS: RLE run overruns track size"));
        }
        if n == 0 {
            break; // DMS.c:348 — a zero-length run ends decoding early
        }
        out.resize(out.len() + n, v);
    }
    Ok(out)
}

const DMS_MAGIC: [u8; 4] = *b"DMS!";
const HEADER_LEN: usize = 56;
const TRACK_HEADER_LEN: usize = 20;

const DMSINFO_ENCRYPT: u32 = 1 << 1;
const DMSTYPE_FMS: u16 = 7;

const DMSCOMP_NOCOMP: u8 = 0;
const DMSCOMP_SIMPLE: u8 = 1;
const DMSCOMP_QUICK: u8 = 2;
const DMSCOMP_MEDIUM: u8 = 3;
const DMSCOMP_DEEP: u8 = 4;
const DMSCOMP_HEAVY1: u8 = 5;
const DMSCOMP_HEAVY2: u8 = 6;

const DMSCFLAG_NOINIT: u8 = 1 << 0;
/// "This track carries fresh `c_table`/`pt_table` headers" (`DMS.c:137`).
const DMSCFLAG_HEAVY_C: u8 = 1 << 1;
/// "Run the shared RLE stage after HEAVY decodes" (`DMS.c:138`).
const DMSCFLAG_HEAVYRLE: u8 = 1 << 2;
/// Not a real on-disk bit: `DecrunchDMS` force-sets or force-clears this bit
/// in the `flags` byte it hands to `DMSUnpHEAVY`, based purely on which of
/// the two methods (`DMSCOMP_HEAVY1` vs `DMSCOMP_HEAVY2`) is being decoded
/// (`DMS.c:139,1037-1041`) — it selects the 4 KB vs 8 KB window. Reproduced
/// the same way here: [`decrunch_track`] sets/clears it in the `flags` it
/// passes to [`unp_heavy`], independent of whatever this track's actual
/// on-disk `cflag` byte happens to hold at that bit position.
const DMSCFLAG_HEAVY2: u8 = 1 << 3;

/// HEAVY's c-alphabet size: 256 literal byte values plus 254 match-length
/// codes (`DMSNC`/`DMSN1`, `DMS.c:188,190`).
const DMSNC: usize = 510;
/// HEAVY's position-alphabet ceiling (`DMSNPT`, `DMS.c:189`); the live size
/// is `np` (14 for HEAVY1, 15 for HEAVY2), set per-track.
const DMSNPT: usize = 30;
/// Threshold in `decode_c`'s result distinguishing a direct table symbol
/// from an internal tree-node index needing a `left`/`right` walk
/// (`DMSN1`, `DMS.c:190`) — equal to [`DMSNC`].
const DMSN1: usize = DMSNC;
/// `match length = c - DMSOFFSET` for a c-alphabet code `c >= 256`
/// (`DMSOFFSET`, `DMS.c:191`).
const DMSOFFSET: u16 = 253;

/// DEEP's adaptive-Huffman tree constants (`DMS.c:193-198`).
const DMSF: usize = 60; // lookahead buffer size (max match length)
const DMSTHRESHOLD: u16 = 2;
/// Alphabet size: 256 literal byte values, minus the threshold, plus the
/// lookahead range of match lengths.
const DMSN_BYTE: usize = 256 - DMSTHRESHOLD as usize + DMSF; // 314
/// Table size: every leaf plus every internal node of a full binary tree.
const DMST: usize = DMSN_BYTE * 2 - 1; // 627
/// Position of the tree root.
const DMSR: usize = DMST - 1; // 626
/// Frequency threshold that triggers [`reconst_tree`].
const DMSMAX_FREQ: u16 = 0x8000;

const DMSTRTYPE_DIZ: i16 = 80;
/// FMS's file-name track number (`DMS.c:141`) — always the first track of
/// an FMS entry, read literally (never decrunched).
const DMSTRTYPE_FILENAME: i16 = 0x03E7;
/// The first FMS file-data track number (`DMS.c:142`); subsequent data
/// tracks are numbered sequentially from here.
const DMSTRTYPE_FILESTART: i16 = 0x03E8;

/// Two-level static code tables for MEDIUM's (and later DEEP's) LZ distance
/// coding (`DMS.c:243-278`). Indexed by a raw 8-bit value read from the
/// bitstream: `DMS_D_CODE` gives the decoded value, `DMS_D_LEN` how many
/// extra bits that code consumed.
#[rustfmt::skip]
const DMS_D_CODE: [u8; 256] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A,
    0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0D, 0x0D, 0x0D, 0x0D,
    0x0E, 0x0E, 0x0E, 0x0E, 0x0F, 0x0F, 0x0F, 0x0F,
    0x10, 0x10, 0x10, 0x10, 0x11, 0x11, 0x11, 0x11,
    0x12, 0x12, 0x12, 0x12, 0x13, 0x13, 0x13, 0x13,
    0x14, 0x14, 0x14, 0x14, 0x15, 0x15, 0x15, 0x15,
    0x16, 0x16, 0x16, 0x16, 0x17, 0x17, 0x17, 0x17,
    0x18, 0x18, 0x19, 0x19, 0x1A, 0x1A, 0x1B, 0x1B,
    0x1C, 0x1C, 0x1D, 0x1D, 0x1E, 0x1E, 0x1F, 0x1F,
    0x20, 0x20, 0x21, 0x21, 0x22, 0x22, 0x23, 0x23,
    0x24, 0x24, 0x25, 0x25, 0x26, 0x26, 0x27, 0x27,
    0x28, 0x28, 0x29, 0x29, 0x2A, 0x2A, 0x2B, 0x2B,
    0x2C, 0x2C, 0x2D, 0x2D, 0x2E, 0x2E, 0x2F, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
];

#[rustfmt::skip]
const DMS_D_LEN: [u8; 256] = [
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
];

/// Total size of the shared sliding window `Text` (`struct DMSData`,
/// `DMS.c:207`).
const TEXT_LEN: usize = 0x8000;
/// How much of `Text` a mid-stream reinit actually clears (`DMSInitData`,
/// `DMS.c:991`) — *not* the whole buffer. Only the very first allocation
/// (`DmsState::new`) is fully zeroed; every later reinit leaves
/// `Text[0x3FC8..0x8000]` untouched, which can carry bytes from a previous
/// track. This is a deliberate reference quirk, not a bug to "fix".
const TEXT_INIT_LEN: usize = 0x3FC8;

/// LZ decoder state shared across every data track in one disk-image
/// extraction pass (`struct DMSData`'s `Text`/`RTV_*`/`DidInit` fields,
/// `DMS.c:207-213`). A single instance lives for the whole
/// [`DmsArchive::read_disk_image`] call; `open()`'s separate text-track scan
/// uses its own throwaway instance (`DMSOneArc` and `XADUNARCHIVE` use two
/// different `DMSData` allocations in the reference too).
struct DmsState {
    text: Vec<u8>,
    rtv_quick: u16,
    rtv_medium: u16,
    rtv_deep: u16,
    did_init: bool,
    /// Gate for the adaptive-Huffman tree build below, separate from
    /// `did_init` (`struct DMSData.DidInitDEEP`, `DMS.c:228`). See
    /// [`dms_init_data`]'s doc comment for why it exists.
    did_init_deep: bool,
    /// Frequency table (`struct DMSData.freq`, `DMS.c:222`).
    freq: [u16; DMST + 1],
    /// Parent-node pointers; `prnt[DMST..DMST + DMSN_BYTE]` map a leaf's
    /// symbol to its tree node (`struct DMSData.prnt`, `DMS.c:223-225`).
    prnt: [u16; DMST + DMSN_BYTE],
    /// Child-node pointers: `son[i]`/`son[i]+1` are node `i`'s two children
    /// (`struct DMSData.son`, `DMS.c:226`).
    son: [u16; DMST],
    /// HEAVY's running window index (`struct DMSData.RTV_Heavy`,
    /// `DMS.c:215`). Unlike `rtv_quick`/`rtv_medium`/`rtv_deep`,
    /// [`dms_init_data`] never resets this — see its doc comment.
    rtv_heavy: u16,
    /// Position-alphabet size for the current HEAVY track: 14 (HEAVY1, a
    /// 4 KB window) or 15 (HEAVY2, 8 KB) (`struct DMSData.np`, `DMS.c:219`).
    np: u16,
    /// The last non-recency match distance [`decode_p`] returned (`struct
    /// DMSData.lastlen`, `DMS.c:218`) — reused verbatim when a later
    /// position code is the "recency" symbol `np - 1`.
    lastlen: u16,
    /// HEAVY's c-alphabet (literals + match lengths) canonical-code lookup
    /// table, indexed by a 12-bit peek (`struct DMSData.c_table`,
    /// `DMS.c:216`).
    c_table: [u16; 4096],
    /// HEAVY's position-alphabet canonical-code lookup table, indexed by an
    /// 8-bit peek (`struct DMSData.pt_table`, `DMS.c:217`).
    pt_table: [u16; 256],
    /// Per-symbol code lengths driving [`make_table`]'s c-tree build
    /// (`struct DMSData.c_len`, `DMS.c:229`).
    c_len: [u8; DMSNC],
    /// Per-symbol code lengths driving [`make_table`]'s pt-tree build
    /// (`struct DMSData.pt_len`, `DMS.c:230`).
    pt_len: [u8; DMSNPT],
    /// Shared internal-tree-node children for both the c-tree and pt-tree
    /// canonical codes (`struct DMSData.left`, `DMS.c:220`) — the two
    /// trees' node-index ranges never overlap (c starts at `DMSNC`, pt at
    /// `np`), so one array safely serves both, as the reference does.
    left: [u16; 2 * DMSNC - 1],
    /// See [`left`](Self::left) (`struct DMSData.right`, `DMS.c:221`; sized
    /// with the same `+9` slack the reference declares, unexplained there
    /// but reproduced exactly).
    right: [u16; 2 * DMSNC - 1 + 9],
    /// The stream cipher's running 16-bit state (`struct DMSData.RTV_Pass`,
    /// `DMS.c:214`), advanced by [`decrypt_dms`] one byte at a time. Flows
    /// continuously across every track [`decrunch_and_verify`] decrypts in
    /// one pass — this is what keeps the cipher in sync track to track.
    rtv_pass: u16,
    /// `CRC-16/ARC` of the password, doubling as a "password was supplied"
    /// marker: `0` means no password, so decryption is skipped outright
    /// (`struct DMSData.PassCRC`, `DMS.c:212`; derived in
    /// [`DmsState::with_password`], mirroring `GetDMSData`, `DMS.c:1090`).
    pass_crc: u16,
    /// Whether decryption should currently be attempted (`struct
    /// DMSData.UsePwd`, `DMS.c:210`: `DMSPWD_USE`/`DMSPWD_NOUSE`). Starts as
    /// the archive's `DMSINFO_ENCRYPT` bit; [`decrunch_and_verify`]'s
    /// "retry without decryption" quirk can flip it `true -> false`
    /// permanently for the rest of the pass, never back.
    use_pwd: bool,
}

impl DmsState {
    /// A freshly allocated, no-password state (`GetDMSData(xadMasterBase,
    /// NULL)`, `DMS.c:1077-1094`). See [`with_password`](Self::with_password).
    /// Production code now always goes through `with_password` directly (it
    /// needs to thread the archive's actual password/`crypted` state); this
    /// shorthand survives only because most existing tests don't care about
    /// either.
    #[cfg(test)]
    fn new() -> Self {
        Self::with_password(None, false)
    }

    /// A freshly allocated state, as if just returned by `GetDMSData`
    /// (`XADMEMF_CLEAR`, `DMS.c:1081`): `Text` starts **entirely** zeroed,
    /// the tree arrays start zeroed too, then [`dms_init_data`] seeds the
    /// running indices and (since `did_init_deep` starts `false`) builds the
    /// starting Huffman tree.
    ///
    /// `pwd` seeds the cipher (`rtv_pass = pass_crc = crc16_arc(pwd)`,
    /// `DMS.c:1090`) when given; `crypted` seeds [`DmsState::use_pwd`]
    /// (`DMSPWD_USE` when the archive's header carries `DMSINFO_ENCRYPT`,
    /// regardless of whether a password was actually supplied — a crypted
    /// archive opened with no password just never finds `pass_crc != 0`, so
    /// [`decrunch_and_verify`] skips decryption outright and every data
    /// track fails its checksum instead of panicking).
    fn with_password(pwd: Option<&[u8]>, crypted: bool) -> Self {
        let pass_crc = pwd.map(crc16_arc).unwrap_or(0);
        let mut state = Self {
            text: vec![0u8; TEXT_LEN],
            rtv_quick: 0,
            rtv_medium: 0,
            rtv_deep: 0,
            did_init: false,
            did_init_deep: false,
            freq: [0u16; DMST + 1],
            prnt: [0u16; DMST + DMSN_BYTE],
            son: [0u16; DMST],
            rtv_heavy: 0,
            np: 0,
            lastlen: 0,
            c_table: [0u16; 4096],
            pt_table: [0u16; 256],
            c_len: [0u8; DMSNC],
            pt_len: [0u8; DMSNPT],
            left: [0u16; 2 * DMSNC - 1],
            right: [0u16; 2 * DMSNC - 1 + 9],
            rtv_pass: pass_crc,
            pass_crc,
            use_pwd: crypted,
        };
        dms_init_data(&mut state);
        state
    }
}

/// Reset the running LZ state for the next track (`DMSInitData`,
/// `DMS.c:961-993`). See [`TEXT_INIT_LEN`] for why only part of `Text` is
/// cleared.
///
/// The DEEP Huffman tree is rebuilt from scratch (uniform frequencies) only
/// when `did_init_deep` is `false` — a reference-level optimization: a
/// QUICK/MEDIUM-only disk never touches DEEP, so its tree (built once in
/// [`DmsState::new`]) never gets "dirtied" and never needs rebuilding again.
/// [`unp_deep`] clears *both* `did_init` and `did_init_deep` at the start of
/// every DEEP track (`DMS.c:596`), unlike QUICK/MEDIUM which only clear
/// `did_init` — so a DEEP track always forces its *own* tree (and window) to
/// be freshly rebuilt on the *next* track, unless that track's `NOINIT` flag
/// suppresses this call entirely (see [`decrunch_and_verify`]), in which
/// case the adapted tree, window, and `rtv_deep` all carry forward.
///
/// HEAVY's own running index and tables (`rtv_heavy`, `c_table`/`pt_table`/
/// `c_len`/`pt_len`, `left`/`right`, `lastlen`, `np`) are absent from this
/// function entirely (`DMS.c:961-993` never mentions them) — a reinit here
/// still wipes the low `TEXT_INIT_LEN` bytes of `Text`, which is HEAVY's
/// window too (4 KB/8 KB, both well under `TEXT_INIT_LEN`), but never
/// touches `rtv_heavy` or the Huffman tables themselves. So across *any*
/// track boundary, HEAVY's tables persist unconditionally (rebuilt only
/// when a track's own `DMSCFLAG_HEAVY_C` is set, in [`unp_heavy`]), while
/// its window content still depends on `NOINIT` exactly like QUICK/MEDIUM/
/// DEEP's does.
///
/// The cipher fields (`rtv_pass`, `pass_crc`, `use_pwd`) are likewise absent
/// — they're seeded once from the password in [`DmsState::with_password`]
/// and must keep flowing untouched across every track's reinit, or the
/// stream cipher would desynchronize from what `DecryptDMS` produced on
/// disk.
fn dms_init_data(state: &mut DmsState) {
    state.rtv_quick = 251;
    state.rtv_medium = 0x3FBE;
    state.rtv_deep = 0x3FC4;

    if !state.did_init_deep {
        for i in 0..DMSN_BYTE {
            state.freq[i] = 1;
            state.son[i] = (i + DMST) as u16;
            state.prnt[i + DMST] = i as u16;
        }
        let mut i = 0usize;
        let mut j = DMSN_BYTE;
        while j <= DMSR {
            state.freq[j] = state.freq[i] + state.freq[i + 1];
            state.son[j] = i as u16;
            state.prnt[i] = j as u16;
            state.prnt[i + 1] = j as u16;
            i += 2;
            j += 1;
        }
        state.freq[DMST] = 0xFFFF; // sentinel, always "heavier" than any real node
        state.prnt[DMSR] = 0;
    }

    state.did_init = true;
    state.did_init_deep = true;
    state.text[0..TEXT_INIT_LEN].fill(0);
}

/// Rebuild the tree from halved frequencies once a leaf's count would
/// overflow (`DMSreconst`, `DMS.c:472-513`): collect leaves into the front of
/// the table with `freq := (freq + 1) / 2`, then re-link them into a tree by
/// repeatedly merging adjacent pairs and inserting each merged node at its
/// sorted position among the nodes built so far.
fn reconst_tree(state: &mut DmsState) {
    let mut j = 0usize;
    for i in 0..DMST {
        if state.son[i] as usize >= DMST {
            state.freq[j] = state.freq[i].div_ceil(2); // DMS.c:484: (freq[i] + 1) / 2
            state.son[j] = state.son[i];
            j += 1;
        }
    }

    let mut i = 0usize;
    let mut j = DMSN_BYTE;
    while j < DMST {
        let k = i + 1;
        let f = state.freq[i] + state.freq[k];
        state.freq[j] = f;
        // Find this merged node's sorted insertion point among the nodes
        // built so far, walking down from `j - 1` (see DMS.c:494 — the
        // `freq[DMST] = 0xFFFF` sentinel and the tree's structure guarantee
        // this never needs to go below index 0 for valid state).
        let mut k2 = j - 1;
        while f < state.freq[k2] {
            k2 -= 1;
        }
        k2 += 1;
        let mut l = j;
        while l > k2 {
            state.freq[l] = state.freq[l - 1];
            state.son[l] = state.son[l - 1];
            l -= 1;
        }
        state.freq[k2] = f;
        state.son[k2] = i as u16;
        i += 2;
        j += 1;
    }

    for i in 0..DMST {
        let k = state.son[i];
        if k as usize >= DMST {
            state.prnt[k as usize] = i as u16;
        } else {
            state.prnt[k as usize] = i as u16;
            state.prnt[k as usize + 1] = i as u16;
        }
    }
}

/// Increment symbol `c`'s frequency by one and rebalance the tree so sibling
/// nodes stay sorted by frequency, swapping `c` outward as needed
/// (`DMSupdate`, `DMS.c:515-552`). Triggers [`reconst_tree`] first if the
/// root's frequency has hit [`DMSMAX_FREQ`].
fn update_tree(state: &mut DmsState, c: u16) {
    if state.freq[DMSR] == DMSMAX_FREQ {
        reconst_tree(state);
    }
    let mut c = state.prnt[c as usize + DMST];
    loop {
        state.freq[c as usize] += 1;
        let k = state.freq[c as usize];

        // If incrementing disturbed the sorted order, swap `c` with the
        // furthest same-or-lighter node to its right.
        let mut l = c + 1;
        if k > state.freq[l as usize] {
            loop {
                l += 1;
                if k <= state.freq[l as usize] {
                    break;
                }
            }
            l -= 1;
            state.freq[c as usize] = state.freq[l as usize];
            state.freq[l as usize] = k;

            let i = state.son[c as usize];
            state.prnt[i as usize] = l;
            if (i as usize) < DMST {
                state.prnt[i as usize + 1] = l;
            }

            let j = state.son[l as usize];
            state.son[l as usize] = i;

            state.prnt[j as usize] = c;
            if (j as usize) < DMST {
                state.prnt[j as usize + 1] = c;
            }
            state.son[c as usize] = j;

            c = l;
        }

        c = state.prnt[c as usize];
        if c == 0 {
            break; // reached the root's parent sentinel
        }
    }
}

/// Decode one symbol by descending the tree bit by bit — `0` picks the
/// smaller (`son[c]`) child, `1` the bigger (`son[c] + 1`) — then adapt the
/// tree for it (`DMSDecodeChar`, `DMS.c:554-571`). Returns `0..DMSN_BYTE`: a
/// raw byte value if `< 256`, otherwise a match-length code (see
/// [`unp_deep`]).
fn decode_char(state: &mut DmsState, reader: &mut DmsBits<'_>) -> u16 {
    let mut c = state.son[DMSR];
    while (c as usize) < DMST {
        let bit = get_bits(reader, 1) as u16;
        c = state.son[c as usize + bit as usize];
    }
    c -= DMST as u16;
    update_tree(state, c);
    c
}

/// Decode a 14-bit match distance: an 8-bit raw code selects a high byte via
/// [`DMS_D_CODE`] plus `DMS_D_LEN[code]` extra low-order bits, the same
/// two-level scheme [`unp_medium`] uses for its own distances (`DMSDecodePosition`,
/// `DMS.c:573-585`).
fn decode_position(reader: &mut DmsBits<'_>) -> u16 {
    let i = get_bits(reader, 8) as u16;
    let c = u16::from(DMS_D_CODE[i as usize]) << 8;
    let j = DMS_D_LEN[i as usize];
    let i = ((i << j) | get_bits(reader, j) as u16) & 0xFF;
    c | i
}

/// DMSCOMP_DEEP decoder (`DMSUnpDEEP`, `DMS.c:587-623`): an adaptive-Huffman-
/// coded LZ77 over a 16 KB window (the same `Text` buffer QUICK/MEDIUM share,
/// masked to `0x3FFF`), output length `rtsize`. A decoded symbol `< 256` is a
/// literal byte; `256..DMSN_BYTE` is a match of length `3..=60`
/// (`symbol - 253`) followed by a coded distance.
fn unp_deep(state: &mut DmsState, packed: &[u8], rtsize: usize) -> io::Result<Vec<u8>> {
    // DEEP clears *both* flags at the very start of its own decode — unlike
    // QUICK/MEDIUM, which only clear `did_init` (see `dms_init_data`'s doc
    // comment for what this means for the next track).
    state.did_init_deep = false;
    state.did_init = false;
    let mut reader = bit_reader(packed);
    let mut out = Vec::with_capacity(rtsize);

    while out.len() < rtsize {
        let c = decode_char(state, &mut reader);
        if c < 256 {
            let b = c as u8;
            state.text[(state.rtv_deep & 0x3FFF) as usize] = b;
            state.rtv_deep = state.rtv_deep.wrapping_add(1);
            out.push(b);
        } else {
            let j = c - 255 + DMSTHRESHOLD; // match length, 3..=60
            let pos = decode_position(&mut reader);
            let mut i = state.rtv_deep.wrapping_sub(pos).wrapping_sub(1);
            if out.len() + j as usize > rtsize {
                return Err(invalid("DMS: DEEP match runs past declared size"));
            }
            for _ in 0..j {
                let b = state.text[(i & 0x3FFF) as usize];
                state.text[(state.rtv_deep & 0x3FFF) as usize] = b;
                state.rtv_deep = state.rtv_deep.wrapping_add(1);
                i = i.wrapping_add(1);
                out.push(b);
            }
        }
    }
    state.rtv_deep = state.rtv_deep.wrapping_add(60) & 0x3FFF;
    Ok(out)
}

/// The packed track bytes followed by an infinite run of zero bytes.
/// `DMSGETBITS`/`DMSDROPBITS` read straight off the end of the packed input
/// without a bounds check (`DMS.c:365-368`, `*d->indata++`); the decode loop is
/// instead bounded by the declared output size, so bits "read" past the real
/// data are implicitly zero. Chaining `io::repeat(0)` reproduces that tail
/// exactly, so `BitReaderMsb` never signals EOF mid-decode. QUICK/MEDIUM/DEEP
/// all read through [`bit_reader`]/[`get_bits`] (full-consume reads).
/// HEAVY1/HEAVY2 share this same zero-padded source but additionally need
/// [`peek_bits`]/[`drop_bits`] (`BitReaderMsb::peek`/`consume`): their
/// table-driven [`decode_c`]/[`decode_p`] look a code up before knowing how
/// many bits it used, so they peek the table's full index width and drop
/// only the resolved code's real length.
type DmsBits<'a> = BitReaderMsb<io::Chain<&'a [u8], io::Repeat>>;

fn bit_reader(packed: &[u8]) -> DmsBits<'_> {
    BitReaderMsb::new(packed.chain(io::repeat(0)))
}

/// `n` bits, most-significant first; never runs out (the stream is zero-padded).
fn get_bits(reader: &mut DmsBits<'_>, n: u8) -> u32 {
    reader
        .read(n)
        .expect("zero-padded stream never errors")
        .expect("zero-padded stream never runs out of bits")
}

/// DMSCOMP_QUICK decoder (`DMSUnpQUICK`, `DMS.c:379-411`): a tiny LZ77 over a
/// 256-byte window, output length `rtsize` (the RLE-stage input, *not* the
/// final track size — RLE runs afterwards). Literal bit `1` copies one raw
/// byte; bit `0` starts a 2..=5-byte back-reference within the last 256
/// output bytes.
fn unp_quick(state: &mut DmsState, packed: &[u8], rtsize: usize) -> io::Result<Vec<u8>> {
    state.did_init = false;
    let mut reader = bit_reader(packed);
    let mut out = Vec::with_capacity(rtsize);

    while out.len() < rtsize {
        if get_bits(&mut reader, 1) != 0 {
            let v = get_bits(&mut reader, 8) as u8;
            state.text[(state.rtv_quick & 0xFF) as usize] = v;
            state.rtv_quick = state.rtv_quick.wrapping_add(1);
            out.push(v);
        } else {
            let j = get_bits(&mut reader, 2) as u16 + 2;
            let off = get_bits(&mut reader, 8) as u16;
            if out.len() + j as usize > rtsize {
                return Err(invalid("DMS: QUICK match runs past declared size"));
            }
            let mut i = state.rtv_quick.wrapping_sub(off).wrapping_sub(1);
            for _ in 0..j {
                let b = state.text[(i & 0xFF) as usize];
                state.text[(state.rtv_quick & 0xFF) as usize] = b;
                state.rtv_quick = state.rtv_quick.wrapping_add(1);
                i = i.wrapping_add(1);
                out.push(b);
            }
        }
    }
    state.rtv_quick = state.rtv_quick.wrapping_add(5) & 0xFF;
    Ok(out)
}

/// DMSCOMP_MEDIUM decoder (`DMSUnpMEDIUM`, `DMS.c:423-467`): the same literal/
/// match shape as QUICK but over a 16 KB window, with match distances coded
/// through the two-level [`DMS_D_CODE`]/[`DMS_D_LEN`] tables instead of a
/// flat 8-bit offset (match length is 3..=258).
fn unp_medium(state: &mut DmsState, packed: &[u8], rtsize: usize) -> io::Result<Vec<u8>> {
    state.did_init = false;
    let mut reader = bit_reader(packed);
    let mut out = Vec::with_capacity(rtsize);

    while out.len() < rtsize {
        if get_bits(&mut reader, 1) != 0 {
            let v = get_bits(&mut reader, 8) as u8;
            state.text[(state.rtv_medium & 0x3FFF) as usize] = v;
            state.rtv_medium = state.rtv_medium.wrapping_add(1);
            out.push(v);
        } else {
            let mut c = get_bits(&mut reader, 8) as u16;
            let j = u16::from(DMS_D_CODE[c as usize]) + 3;
            let mut u = DMS_D_LEN[c as usize];
            c = ((c << u) | (get_bits(&mut reader, u) as u16)) & 0xFF;
            u = DMS_D_LEN[c as usize];
            let dist = (u16::from(DMS_D_CODE[c as usize]) << 8)
                | (((c << u) | (get_bits(&mut reader, u) as u16)) & 0xFF);
            if out.len() + j as usize > rtsize {
                return Err(invalid("DMS: MEDIUM match runs past declared size"));
            }
            let mut i = state.rtv_medium.wrapping_sub(dist).wrapping_sub(1);
            for _ in 0..j {
                let b = state.text[(i & 0x3FFF) as usize];
                state.text[(state.rtv_medium & 0x3FFF) as usize] = b;
                state.rtv_medium = state.rtv_medium.wrapping_add(1);
                i = i.wrapping_add(1);
                out.push(b);
            }
        }
    }
    state.rtv_medium = state.rtv_medium.wrapping_add(66) & 0x3FFF;
    Ok(out)
}

/// `n` bits, most-significant first, peeked without consuming (the
/// zero-padded stream never runs out). HEAVY's `decode_c`/`decode_p` look a
/// code up in a table before knowing how many bits it actually used, so
/// they peek the table's full index width and [`drop_bits`] only the
/// resolved code's real length.
fn peek_bits(reader: &mut DmsBits<'_>, n: u8) -> u32 {
    reader
        .peek(n)
        .expect("zero-padded stream never errors")
        .expect("zero-padded stream never runs out of bits")
}

/// Drop `n` bits already made available by a prior [`peek_bits`] call.
fn drop_bits(reader: &mut DmsBits<'_>, n: u8) {
    reader.consume(n);
}

/// Working state for one [`make_table`] call (`struct DMSTableData`,
/// `DMS.c:627-643`). `left`/`right`/`table` are borrows into the caller's
/// [`DmsState`] fields; `blen` is the per-symbol code-length array driving
/// the build (`c_len` or `pt_len`).
struct TableBuilder<'a> {
    left: &'a mut [u16],
    right: &'a mut [u16],
    table: &'a mut [u16],
    blen: &'a [u8],
    n: u16,
    tblsiz: u16,
    len: u16,
    depth: u16,
    maxdepth: u16,
    avail: u16,
    c: i32,
    codeword: u16,
    bit: u16,
    tab_err: u16,
}

impl TableBuilder<'_> {
    /// Recursive canonical-code assignment (`DMSmktbl`, `DMS.c:645-702`):
    /// walk code lengths from shortest to longest (the shared `len`/`c`
    /// scan), assigning each symbol found at the current length the next
    /// available codeword. A code that fits within the table directly
    /// (`depth <= tablebits`) fills a run of `table` slots; a longer one
    /// allocates an internal `left`/`right` tree node instead, walked bit
    /// by bit by [`decode_c`]/[`decode_p`] beyond the initial table lookup.
    /// `tab_err` short-circuits every call once set, matching the
    /// reference's early-return-on-error propagation through the recursion.
    fn mktbl(&mut self) -> u16 {
        let mut i: u16 = 0;
        if self.tab_err != 0 {
            return 0;
        }
        if self.len == self.depth {
            loop {
                self.c += 1;
                if self.c >= i32::from(self.n) {
                    break;
                }
                if self.blen[self.c as usize] == self.len as u8 {
                    let mut slot = self.codeword;
                    self.codeword += self.bit;
                    if self.codeword > self.tblsiz {
                        self.tab_err = 1;
                        return 0;
                    }
                    while slot < self.codeword {
                        self.table[slot as usize] = self.c as u16;
                        slot += 1;
                    }
                    return self.c as u16;
                }
            }
            self.c = -1;
            self.len += 1;
            self.bit >>= 1;
        }
        self.depth += 1;
        if self.depth < self.maxdepth {
            self.mktbl();
            self.mktbl();
        } else if self.depth > 32 {
            self.tab_err = 2;
            return 0;
        } else {
            i = self.avail;
            self.avail += 1;
            if usize::from(i) >= 2 * usize::from(self.n) - 1 {
                self.tab_err = 3;
                return 0;
            }
            self.left[i as usize] = self.mktbl();
            self.right[i as usize] = self.mktbl();
            if self.codeword >= self.tblsiz {
                self.tab_err = 4;
                return 0;
            }
            if self.depth == self.maxdepth {
                self.table[self.codeword as usize] = i;
                self.codeword += 1;
            }
        }
        self.depth -= 1;
        i
    }
}

/// Build a canonical-Huffman lookup table from per-symbol code lengths
/// (`DMSmake_table`, `DMS.c:704-729`), shared verbatim by the decoder
/// ([`read_tree_c`]/[`read_tree_p`]) and by this module's test-only mirror
/// encoder — neither side hand-derives codes independently. Fails if the
/// lengths don't satisfy the Kraft equality (an incomplete or
/// over-subscribed code) or the recursion runs structurally out of bounds.
fn make_table(
    nchar: u16,
    blen: &[u8],
    tablebits: u8,
    table: &mut [u16],
    left: &mut [u16],
    right: &mut [u16],
) -> io::Result<()> {
    let tblsiz = 1u16 << tablebits;
    let mut t = TableBuilder {
        left,
        right,
        table,
        blen,
        n: nchar,
        tblsiz,
        len: 1,
        depth: 1,
        maxdepth: u16::from(tablebits) + 1,
        avail: nchar,
        c: -1,
        codeword: 0,
        bit: tblsiz / 2,
        tab_err: 0,
    };
    t.mktbl();
    t.mktbl();
    if t.tab_err != 0 {
        return Err(invalid(format!(
            "DMS: HEAVY make_table structural error {}",
            t.tab_err
        )));
    }
    if t.codeword != t.tblsiz {
        return Err(invalid(
            "DMS: HEAVY make_table incomplete code (Kraft equality violated)",
        ));
    }
    Ok(())
}

/// Decode one c-alphabet symbol — a literal byte (`< 256`) or a
/// match-length code (`256..DMSN1`) — via the canonical table
/// [`make_table`]/[`read_tree_c`] built (`DMSdecode_c`, `DMS.c:731-756`): a
/// direct 12-bit table lookup, falling back to a `left`/`right` tree walk
/// (guided by 16 more peeked bits) for codes longer than the table holds
/// directly.
fn decode_c(state: &mut DmsState, reader: &mut DmsBits<'_>) -> u16 {
    let mut j = state.c_table[peek_bits(reader, 12) as usize];
    if usize::from(j) < DMSN1 {
        drop_bits(reader, state.c_len[j as usize]);
    } else {
        drop_bits(reader, 12);
        let i = peek_bits(reader, 16) as u16;
        let mut m: u16 = 0x8000;
        loop {
            j = if i & m != 0 {
                state.right[j as usize]
            } else {
                state.left[j as usize]
            };
            m >>= 1;
            if usize::from(j) < DMSN1 {
                break;
            }
        }
        drop_bits(reader, state.c_len[j as usize] - 12);
    }
    j
}

/// Decode one match distance (`DMSdecode_p`, `DMS.c:758-794`): a
/// canonical-coded position-slot symbol (same table-then-tree-walk shape as
/// [`decode_c`], over `pt_table`/`left`/`right`), then that slot's extra raw
/// bits — except the top slot (`np - 1`), a "recency" code that returns
/// whatever distance this function last resolved instead of reading any
/// extra bits or updating [`DmsState::lastlen`].
fn decode_p(state: &mut DmsState, reader: &mut DmsBits<'_>) -> u16 {
    let mut j = state.pt_table[peek_bits(reader, 8) as usize];
    if j < state.np {
        drop_bits(reader, state.pt_len[j as usize]);
    } else {
        drop_bits(reader, 8);
        let i = peek_bits(reader, 16) as u16;
        let mut m: u16 = 0x8000;
        loop {
            j = if i & m != 0 {
                state.right[j as usize]
            } else {
                state.left[j as usize]
            };
            m >>= 1;
            if j < state.np {
                break;
            }
        }
        drop_bits(reader, state.pt_len[j as usize] - 8);
    }

    if j != state.np - 1 {
        if j > 0 {
            let bits = (j - 1) as u8;
            let extra = peek_bits(reader, bits) as u16;
            drop_bits(reader, bits);
            j = extra | (1 << (j - 1));
        }
        state.lastlen = j;
    }
    state.lastlen
}

/// Read the c-alphabet's canonical code lengths from the bitstream and
/// build its lookup table (`DMSread_tree_c`, `DMS.c:796-824`). A `n == 0`
/// header means "only one symbol total" — the degenerate branch skips
/// [`make_table`] and fills [`DmsState::c_table`] directly with that one
/// constant symbol id, so every [`decode_c`] call in this track resolves to
/// it without consuming any of its own code bits.
fn read_tree_c(state: &mut DmsState, reader: &mut DmsBits<'_>) -> io::Result<()> {
    let n = get_bits(reader, 9) as usize;
    if n > 0 {
        for i in 0..n {
            state.c_len[i] = get_bits(reader, 5) as u8;
        }
        for i in n..DMSNC {
            state.c_len[i] = 0;
        }
        make_table(
            DMSNC as u16,
            &state.c_len,
            12,
            &mut state.c_table,
            &mut state.left,
            &mut state.right,
        )?;
    } else {
        let filler = get_bits(reader, 9) as u16;
        state.c_len = [0u8; DMSNC];
        state.c_table = [filler; 4096];
    }
    Ok(())
}

/// Position-alphabet counterpart of [`read_tree_c`] (`DMSread_tree_p`,
/// `DMS.c:826-854`), over the current track's `np` (14 or 15) symbols.
fn read_tree_p(state: &mut DmsState, reader: &mut DmsBits<'_>) -> io::Result<()> {
    let n = get_bits(reader, 5) as usize;
    if n > 0 {
        for i in 0..n {
            state.pt_len[i] = get_bits(reader, 4) as u8;
        }
        for i in n..state.np as usize {
            state.pt_len[i] = 0;
        }
        make_table(
            state.np,
            &state.pt_len,
            8,
            &mut state.pt_table,
            &mut state.left,
            &mut state.right,
        )?;
    } else {
        let filler = get_bits(reader, 5) as u16;
        for i in 0..state.np as usize {
            state.pt_len[i] = 0;
        }
        state.pt_table = [filler; 256];
    }
    Ok(())
}

/// DMSCOMP_HEAVY1/HEAVY2 decoder (`DMSUnpHEAVY`, `DMS.c:856-922`): a
/// canonical-Huffman-coded LZ77 whose two code tables (`c_table` for
/// literals/match-lengths, `pt_table` for match distances) are read fresh
/// from the bitstream when this track's [`DMSCFLAG_HEAVY_C`] bit is set,
/// and otherwise reused exactly as they were left by whichever earlier
/// track last set that bit (`DMS.c:883-895`; see [`DmsState`]'s HEAVY
/// fields, which [`dms_init_data`] never resets). `flags` is this track's
/// on-disk `cflag` with [`DMSCFLAG_HEAVY2`] forced by the caller
/// ([`decrunch_track`]) — it picks a 4 KB window (`np = 14`) for HEAVY1 or
/// an 8 KB window (`np = 15`) for HEAVY2. Unlike QUICK/MEDIUM/DEEP, HEAVY
/// has no final `rtv_heavy` bump at end of track (`DMS.c:916-920`).
fn unp_heavy(state: &mut DmsState, packed: &[u8], rtsize: usize, flags: u8) -> io::Result<Vec<u8>> {
    state.did_init = false;
    let bitmask: u16 = if flags & DMSCFLAG_HEAVY2 != 0 {
        state.np = 15;
        0x1FFF
    } else {
        state.np = 14;
        0x0FFF
    };
    let mut reader = bit_reader(packed);

    if flags & DMSCFLAG_HEAVY_C != 0 {
        read_tree_c(state, &mut reader)?;
        read_tree_p(state, &mut reader)?;
    }

    let mut out = Vec::with_capacity(rtsize);
    while out.len() < rtsize {
        let c = decode_c(state, &mut reader);
        if c < 256 {
            let b = c as u8;
            state.text[(state.rtv_heavy & bitmask) as usize] = b;
            state.rtv_heavy = state.rtv_heavy.wrapping_add(1);
            out.push(b);
        } else {
            let j = c - DMSOFFSET;
            let p = decode_p(state, &mut reader);
            let mut i = state.rtv_heavy.wrapping_sub(p).wrapping_sub(1);
            if out.len() + j as usize > rtsize {
                return Err(invalid("DMS: HEAVY match runs past declared size"));
            }
            for _ in 0..j {
                let b = state.text[(i & bitmask) as usize];
                state.text[(state.rtv_heavy & bitmask) as usize] = b;
                state.rtv_heavy = state.rtv_heavy.wrapping_add(1);
                i = i.wrapping_add(1);
                out.push(b);
            }
        }
    }
    Ok(out)
}

/// Decrypt a track's packed bytes in place (`DecryptDMS`, `DMS.c:949-959`): a
/// stream XOR cipher with a 16-bit running state. Each byte's replacement is
/// `ct ^ (rtv_pass & 0xFF)`, and `rtv_pass` is then advanced by `ct` — the
/// *original ciphertext* byte, not the just-recovered plaintext. That choice
/// is what keeps the cipher self-synchronizing even when a track turns out
/// to have been unencrypted after all: [`decrunch_and_verify`]'s retry
/// re-reads the same bytes without calling this function again, but
/// `rtv_pass` has already moved past them from this (failed) attempt, so
/// later tracks' decryption stays in step with what `DecryptDMS` would have
/// produced on the reference decoder.
fn decrypt_dms(data: &mut [u8], rtv_pass: &mut u16) {
    for b in data.iter_mut() {
        let ct = *b;
        *b = ct ^ (*rtv_pass & 0xFF) as u8;
        *rtv_pass = (*rtv_pass >> 1).wrapping_add(ct as u16);
    }
}

/// Compression-method dispatch for one track (`DecrunchDMS`, `DMS.c:996-1075`).
/// `packed` is the track's raw on-disk bytes (`cmode` of them); `upsize` is
/// the final decompressed size, `rtsize` the intermediate size QUICK/MEDIUM/
/// DEEP/HEAVY must produce before the (conditional, for HEAVY) RLE stage
/// runs. `cflag` is only consulted by the HEAVY branch, to force
/// [`DMSCFLAG_HEAVY2`] and to gate the post-decode RLE pass.
fn decrunch_track(
    state: &mut DmsState,
    method: u8,
    cflag: u8,
    packed: &[u8],
    upsize: usize,
    rtsize: usize,
) -> io::Result<Vec<u8>> {
    match method {
        DMSCOMP_NOCOMP => packed
            .get(..upsize)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| invalid("DMS: NOCOMP track shorter than declared size")),
        DMSCOMP_SIMPLE => unp_rle(packed, upsize),
        DMSCOMP_QUICK => unp_rle(&unp_quick(state, packed, rtsize)?, upsize),
        DMSCOMP_MEDIUM => unp_rle(&unp_medium(state, packed, rtsize)?, upsize),
        DMSCOMP_DEEP => unp_rle(&unp_deep(state, packed, rtsize)?, upsize),
        DMSCOMP_HEAVY1 | DMSCOMP_HEAVY2 => {
            let flags = if method == DMSCOMP_HEAVY1 {
                cflag & !DMSCFLAG_HEAVY2
            } else {
                cflag | DMSCFLAG_HEAVY2
            };
            let decoded = unp_heavy(state, packed, rtsize, flags)?;
            if cflag & DMSCFLAG_HEAVYRLE != 0 {
                unp_rle(&decoded, upsize)
            } else {
                Ok(decoded)
            }
        }
        _ => Err(invalid(format!("DMS: unknown compression method {method}"))),
    }
}

/// Decrypt (if a password is in play), decrunch a track, verify its
/// additive checksum (`CheckSumDMS` compared against `UncrunchedCRC`,
/// `DMS.c:1018-1060`), retrying once without decryption on a mismatch, then
/// apply the post-track LZ-state reinit rule (`DMS.c:1062-1063`): unless
/// this track's `NOINIT` flag is set *and* the decoder already
/// reinitialized itself this track (QUICK/MEDIUM clear `did_init` at the
/// very start of their own decode, `DMS.c:384,429`), reset the shared state
/// so the next track starts clean. `NOINIT` skips that reset, letting a
/// track's LZ window and running indices carry into the next one — this is
/// how DMS links "solid" tracks together.
///
/// Decryption (`DMS.c:1018-1019`) runs before decompression, only when
/// `state.use_pwd` and `state.pass_crc != 0`; [`decrypt_dms`] advances
/// `state.rtv_pass` by consuming exactly `packed.len()` bytes, regardless of
/// whether the decode that follows succeeds.
///
/// If the checksum still doesn't match afterward *and* decryption was
/// attempted, DMS.c:1050-1057 retries: re-decrunch the same `packed` bytes
/// **unencrypted** (some text tracks — e.g. a `FILEID.DIZ` — are
/// occasionally left in the clear inside an otherwise-encrypted archive).
/// `state.use_pwd` flips to `false` for this retry and — faithfully — stays
/// `false` for every later call sharing this `state`, a one-way transition
/// that is never reset. `state.rtv_pass` is *not* rolled back before the
/// retry: it already advanced past these bytes via the failed decrypt
/// attempt, which is exactly what keeps the cipher synchronized for
/// whichever later track really is encrypted. The retry also reuses
/// whatever the failed first attempt already did to `state`'s LZ
/// window/tree (DMS.c behaves the same way) — faithful, not "fixed".
fn decrunch_and_verify(
    state: &mut DmsState,
    method: u8,
    cflag: u8,
    upsize: u16,
    rtsize: u16,
    uncrunched_crc: u16,
    packed: &[u8],
) -> io::Result<Vec<u8>> {
    let decrypting = state.use_pwd && state.pass_crc != 0;
    let packed_to_use: Cow<'_, [u8]> = if decrypting {
        let mut dec = packed.to_vec();
        decrypt_dms(&mut dec, &mut state.rtv_pass);
        Cow::Owned(dec)
    } else {
        Cow::Borrowed(packed)
    };

    let decode = |state: &mut DmsState, packed: &[u8]| {
        decrunch_track(
            state,
            method,
            cflag,
            packed,
            upsize as usize,
            rtsize as usize,
        )
    };

    let mut decoded = decode(state, &packed_to_use)?;

    if checksum_dms(&decoded) != uncrunched_crc {
        if !decrypting {
            return Err(invalid("DMS: track checksum mismatch after decompression"));
        }
        // Retry on the raw (undecrypted) bytes — see this function's doc.
        state.use_pwd = false;
        decoded = decode(state, packed)?;
        if checksum_dms(&decoded) != uncrunched_crc {
            return Err(invalid("DMS: track checksum mismatch after decompression"));
        }
    }

    if cflag & DMSCFLAG_NOINIT == 0 && !state.did_init {
        dms_init_data(state);
    }
    Ok(decoded)
}

struct DmsHeaderFields {
    info_flags: u32,
    disk_type: u16,
    disk_type2: u16,
    /// `h.UnpackedSize` (`DMS.c:152`) — an FMS file's full size, and the
    /// data-track walk's stop condition in [`parse_fms_file`].
    unpacked_size: u32,
}

/// Parse the fields of the 56-byte header that 18a/18f need (`DMS.c:149-172`).
/// Callers must have already checked [`DmsArchive::recognize`].
fn parse_header(data: &[u8]) -> DmsHeaderFields {
    DmsHeaderFields {
        info_flags: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
        disk_type2: u16::from_be_bytes([data[38], data[39]]),
        disk_type: u16::from_be_bytes([data[50], data[51]]),
        unpacked_size: u32::from_be_bytes([data[24], data[25], data[26], data[27]]),
    }
}

/// One 20-byte track header (`DMS.c:174-186`). `pad` and `RuntimePacked` are
/// intentionally not kept: the former is unused, the latter only matters for
/// the LZ-based methods added in 18b.
struct TrackHeader {
    track_number: i16,
    /// Bytes of packed data on disk following this header (`cmode`).
    cmode: u16,
    /// Intermediate (post-LZ, pre-RLE) buffer size QUICK/MEDIUM/DEEP/HEAVY
    /// must produce (`RuntimePacked`); unused by NOCOMP/SIMPLE.
    rtsize: u16,
    upsize: u16,
    /// `DMSCFLAG_*` bits, only `DMSCFLAG_NOINIT` matters so far.
    cflag: u8,
    method: u8,
    uncrunched_crc: u16,
}

/// Validate and parse a 20-byte track header (`testDMSTrack`, `DMS.c:928-937`).
/// Returns `None` on a bad magic or checksum — in the container scan this
/// means "not a track", i.e. clean end of useful data, not a hard error.
fn parse_track_header(b: &[u8]) -> Option<TrackHeader> {
    if b.len() != TRACK_HEADER_LEN {
        return None;
    }
    if u16::from_be_bytes([b[0], b[1]]) != 0x5452 {
        return None;
    }
    if crc16_arc(&b[0..18]) != u16::from_be_bytes([b[18], b[19]]) {
        return None;
    }
    Some(TrackHeader {
        track_number: i16::from_be_bytes([b[2], b[3]]),
        cmode: u16::from_be_bytes([b[6], b[7]]),
        rtsize: u16::from_be_bytes([b[8], b[9]]),
        upsize: u16::from_be_bytes([b[10], b[11]]),
        cflag: b[12],
        method: b[13],
        uncrunched_crc: u16::from_be_bytes([b[14], b[15]]),
    })
}

/// Disk geometry derived from the track sequence (`DMS.c:1254-1278`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmsDiskInfo {
    pub low_cyl: u16,
    pub high_cyl: u16,
    /// Sectors per track: 9 or 18 (MSDOS disk), 11 or 22 (Amiga disk).
    pub track_sectors: u16,
    pub sector_size: u16,
    pub heads: u16,
    pub cylinders: u16,
    pub total_sectors: u32,
}

/// A non-image text track: banner, `FILEID.DIZ`, or a fake advertising boot
/// block (`DMS.c:1179-1200`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmsText {
    pub is_diz: bool,
    pub bytes: Vec<u8>,
}

/// One disk-image data track's location in the archive, ready to be
/// decrunched by [`DmsArchive::read_disk_image`].
struct DataTrack {
    method: u8,
    cflag: u8,
    rtsize: u16,
    upsize: u16,
    uncrunched_crc: u16,
    packed_offset: usize,
    packed_len: usize,
}

/// One file inside an FMS-form DMS archive (`XADGETINFO`'s FMS branch,
/// `DMS.c:1332-1393`). DMS has two unrelated archive shapes sharing one
/// container format: a disk image (`DmsContent::Disk`) or named files
/// (`DmsContent::Files`) — see [`DmsContent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmsFile {
    /// Raw name bytes as stored in the archive; charset is not decoded.
    pub name: Vec<u8>,
    /// Full decompressed file size (`h.UnpackedSize`).
    pub size: u32,
    /// Whether this file was encrypted (the archive header's
    /// `DMSINFO_ENCRYPT` bit; DMS has no per-file crypto flag distinct from
    /// the whole-archive one, but `xfi_Flags` mirrors it per-file).
    pub is_crypted: bool,
    /// Amiga protection bits — only present in a 2.04-format name track.
    pub protection: Option<u32>,
    /// An optional comment — only present in a 2.04-format name track that
    /// actually carries one.
    pub comment: Option<Vec<u8>>,
    /// Archive offset of this file's first `DMSTRTYPE_FILESTART` track
    /// header, established by [`parse_fms_file`]'s data-track walk
    /// (`DataPos`, `DMS.c:1341` — captured before that walk runs).
    data_offset: usize,
}

/// The two unrelated shapes a DMS archive can take (`DMS.c:1334`'s FMS/disk
/// branch): most DMS archives are Amiga floppy images, but the same
/// container can instead hold ordinary named files.
enum DmsContent {
    Disk {
        info: DmsDiskInfo,
        tracks: Vec<DataTrack>,
        texts: Vec<DmsText>,
    },
    /// MVP: only the archive's first FMS entry is parsed (symmetric to
    /// disk mode only parsing the first disk — see `DmsArchive::open`'s
    /// sub-archive-boundary handling). A single-element `Vec` for now;
    /// widening this to walk appended entries is future work.
    Files(Vec<DmsFile>),
}

/// A parsed DMS archive: either one Amiga floppy image, spread across
/// compressed tracks (plus any text tracks found along the way), or a set
/// of named files — see [`DmsContent`].
pub struct DmsArchive {
    data: Vec<u8>,
    content: DmsContent,
    /// Whether the header's `DMSINFO_ENCRYPT` bit was set. Track headers are
    /// always plaintext (`DMS.c:1018-1019` only decrypts *after* a track
    /// header is parsed), so geometry/text scanning in [`open_with_password`]
    /// works the same with or without a password even on a crypted archive.
    crypted: bool,
    /// The password [`open_with_password`] was called with, if any — kept so
    /// [`read_disk_image`](Self::read_disk_image)/[`read_file`](Self::read_file)
    /// can each seed their own, separate [`DmsState`] with the same key.
    password: Option<Vec<u8>>,
}

/// A data track tentatively deferred because it's track 0: might turn out to
/// be an information text once the next track is seen (`DMS.c:1149-1176,
/// 1211-1217`).
struct PendingZero {
    decoded: Vec<u8>,
    data_track: DataTrack,
}

/// Parse a file-name track's payload into `(name, protection, comment)`.
///
/// The track's `UnpackedSize` bytes are stored **literally** — the name
/// track is never decrunched, only the raw bytes copied
/// (`XADGETINFO`, `DMS.c:1338-1339`). Two layouts share this payload
/// (`DMS.c:49-57`, the raw-bytes version of the pointer-walk at
/// `DMS.c:1359-1382`):
///
/// - **pre-2.04**: the payload *is* the file name, verbatim.
/// - **2.04**: `[4B protection][12B DateStamp][1B size]…`, where `size`'s
///   low 7 bits are a text length and bit 7 marks that text as a *comment*
///   rather than the name; when it's a comment, one more size byte (whose
///   *value* the reference computes but then discards, relying on the name
///   simply running to the end of the payload) precedes the actual name.
///
/// The heuristic that tells the two apart: a 2.04 payload's first byte is
/// always `0` (the high byte of `protection`, a 32-bit Amiga permission
/// mask that practically never sets it) — `DMS.c:1358`, `!fi->xfi_FileName[0]`.
///
/// The reference does not track a name-track date field on the returned
/// file info in any form this port exposes; both branches simply skip it
/// (pre-2.04's date comes from the *header's* `Date` field instead, which
/// [`DmsFile`] likewise does not carry — see the task notes).
/// `(name, protection, comment)`, as returned by [`parse_fms_name`].
type FmsNameParts = (Vec<u8>, Option<u32>, Option<Vec<u8>>);

fn parse_fms_name(name_bytes: &[u8]) -> io::Result<FmsNameParts> {
    if name_bytes.first() != Some(&0) {
        return Ok((name_bytes.to_vec(), None, None));
    }
    // 2.04: protection(4) + DateStamp(12) + at least one size byte.
    if name_bytes.len() < 17 {
        return Err(invalid("DMS: FMS 2.04 file-name track truncated"));
    }
    let protection =
        u32::from_be_bytes([name_bytes[0], name_bytes[1], name_bytes[2], name_bytes[3]]);
    let mut pos = 16usize; // past protection(4) + DateStamp(12)
    let size1 = name_bytes[pos];
    pos += 1;
    let comment = if size1 & 0x80 != 0 {
        let comment_len = (size1 & 0x7F) as usize;
        let comment_bytes = name_bytes
            .get(pos..pos + comment_len)
            .ok_or_else(|| invalid("DMS: FMS 2.04 comment text truncated"))?
            .to_vec();
        pos += comment_len;
        pos += 1; // the filename-size byte: computed, then discarded (DMS.c:1378)
        Some(comment_bytes)
    } else {
        None
    };
    let name = name_bytes.get(pos..).unwrap_or(&[]).to_vec();
    Ok((name, Some(protection), comment))
}

/// Parse the single FMS file embedded in a DMS archive whose `DiskType` (or
/// `DiskType2`) is `DMSTYPE_FMS` (`XADGETINFO`'s FMS branch,
/// `DMS.c:1332-1393`). `pos` is the archive offset right after the 56-byte
/// header, where the file-name track begins.
fn parse_fms_file(
    data: &[u8],
    pos: usize,
    header: &DmsHeaderFields,
    crypted: bool,
) -> io::Result<DmsFile> {
    let name_th = data
        .get(pos..pos + TRACK_HEADER_LEN)
        .and_then(parse_track_header)
        .ok_or_else(|| invalid("DMS: FMS archive missing a valid file-name track"))?;
    if name_th.track_number != DMSTRTYPE_FILENAME {
        return Err(invalid(
            "DMS: FMS archive's first track is not a file-name track",
        ));
    }
    let name_start = pos + TRACK_HEADER_LEN;
    let name_len = name_th.upsize as usize;
    let name_bytes = data
        .get(name_start..name_start + name_len)
        .ok_or_else(|| invalid("DMS: FMS file-name track truncated"))?;

    // DataPos: captured right after the name track's payload, before the
    // validation walk below advances further (`DMS.c:1341`).
    let data_offset = name_start + name_len;

    // Walk the data-track sequence, accumulating `UnpackedSize` to confirm
    // the archive actually holds `header.unpacked_size` bytes worth of
    // tracks (`DMS.c:1342-1350`). Only `testDMSTrack` + bookkeeping here —
    // no decrunching yet, matching the reference (decrunching happens only
    // once at extraction time, in `read_file`).
    let mut walk_pos = data_offset;
    let mut accumulated: u32 = 0;
    while accumulated < header.unpacked_size {
        let t = data
            .get(walk_pos..walk_pos + TRACK_HEADER_LEN)
            .and_then(parse_track_header)
            .ok_or_else(|| invalid("DMS: FMS file data truncated or corrupt"))?;
        let next_pos = walk_pos + TRACK_HEADER_LEN + t.cmode as usize;
        if next_pos > data.len() {
            return Err(invalid("DMS: FMS file data truncated"));
        }
        walk_pos = next_pos;
        accumulated += u32::from(t.upsize);
    }

    let (name, protection, comment) = parse_fms_name(name_bytes)?;
    Ok(DmsFile {
        name,
        size: header.unpacked_size,
        is_crypted: crypted,
        protection,
        comment,
        data_offset,
    })
}

impl DmsArchive {
    /// Structural format check: the `"DMS!"` magic plus a valid header CRC
    /// (`DMS_RecogData`, `DMS.c:1098-1105`).
    pub fn recognize(data: &[u8]) -> bool {
        if data.len() < HEADER_LEN || data[0..4] != DMS_MAGIC {
            return false;
        }
        let calc = crc16_arc(&data[4..54]);
        let stored = u16::from_be_bytes([data[54], data[55]]);
        calc == stored
    }

    /// Parse a DMS archive with no password (`DMSArchive::open_with_password`
    /// with `password = None`). Works even on an encrypted archive — track
    /// headers are plaintext, so geometry is always recoverable — but
    /// [`read_disk_image`](Self::read_disk_image) will fail every crypted
    /// data track's checksum, since decryption is skipped when no password
    /// is known.
    pub fn open(data: &[u8]) -> io::Result<Self> {
        Self::open_with_password(data, None)
    }

    /// Parse a DMS archive: validate the header, then either parse it as an
    /// FMS file archive (see [`parse_fms_file`]) or scan the track sequence
    /// to recover disk geometry, text tracks, and the location of every
    /// disk-image data track (`DMSOneArc`, `DMS.c:1113-1307`), depending on
    /// `DiskType`/`DiskType2` (`DMS.c:1334`). `password` seeds the stream
    /// cipher for both this scan's text tracks and (via the saved
    /// `crypted`/`password` fields) [`read_disk_image`](Self::read_disk_image)'s
    /// or [`read_file`](Self::read_file)'s later data-track pass.
    ///
    /// All internal offsets are relative to `data`, so a future DMSSFX handler
    /// would just recognize the exe wrapper and call this on the embedded
    /// payload sub-slice (`&data[payload_off..]`) — no offset parameter needed.
    pub fn open_with_password(data: &[u8], password: Option<&[u8]>) -> io::Result<Self> {
        if !Self::recognize(data) {
            return Err(invalid("DMS: not a DMS archive (magic/checksum mismatch)"));
        }
        let header = parse_header(data);
        let crypted = header.info_flags & DMSINFO_ENCRYPT != 0;
        if header.disk_type == DMSTYPE_FMS || header.disk_type2 == DMSTYPE_FMS {
            let file = parse_fms_file(data, HEADER_LEN, &header, crypted)?;
            return Ok(DmsArchive {
                data: data.to_vec(),
                content: DmsContent::Files(vec![file]),
                crypted,
                password: password.map(<[u8]>::to_vec),
            });
        }

        let mut pos = HEADER_LEN;
        let mut texts: Vec<DmsText> = Vec::new();
        let mut tracks: Vec<DataTrack> = Vec::new();
        let mut low_cyl: i32 = -1;
        let mut high_cyl: i32 = -1;
        let mut tracksize: u32 = 0;
        let mut pending_zero: Option<PendingZero> = None;
        // A scan-local LZ state, separate from `read_disk_image`'s (the
        // reference likewise uses two distinct `DMSData` allocations: one for
        // `DMSOneArc`'s text-track scan, one for `XADUNARCHIVE`'s extraction
        // pass). Text tracks are NOCOMP/SIMPLE in practice, so this never
        // actually drives the QUICK/MEDIUM window, but the dispatcher needs a
        // state to thread through regardless. Its own cipher stream is
        // therefore independent of `read_disk_image`'s too — each starts
        // fresh from `pass_crc`, matching the reference's two allocations.
        let mut scan_state = DmsState::with_password(password, crypted);

        while let Some(th) = data
            .get(pos..pos + TRACK_HEADER_LEN)
            .and_then(parse_track_header)
        {
            let packed_offset = pos + TRACK_HEADER_LEN;
            let packed_len = th.cmode as usize;
            let packed = data
                .get(packed_offset..packed_offset + packed_len)
                .ok_or_else(|| invalid("DMS: track data truncated"))?;
            let tr = th.track_number;
            let next_pos = packed_offset + packed_len;

            // Resolve any track 0 deferred by the previous iteration.
            if let Some(pz) = pending_zero.take() {
                let mut trimmed = pz.decoded;
                while trimmed.last() == Some(&0) {
                    trimmed.pop();
                }
                if tr != 1 && !trimmed.is_empty() && trimmed.len() <= 2048 {
                    // Was actually an information text, not disk data.
                    low_cyl = -1;
                    high_cyl = -1;
                    texts.push(DmsText {
                        is_diz: false,
                        bytes: trimmed,
                    });
                } else {
                    tracks.push(pz.data_track);
                }
            }

            // Special (non-image) tracks: banner, FILEID.DIZ, fake boot block.
            if tr < 0 || tr == DMSTRTYPE_DIZ || (tr == 0 && th.upsize == 1024) {
                let decoded = decrunch_and_verify(
                    &mut scan_state,
                    th.method,
                    th.cflag,
                    th.upsize,
                    th.rtsize,
                    th.uncrunched_crc,
                    packed,
                )
                .unwrap_or_default();
                texts.push(DmsText {
                    is_diz: tr == DMSTRTYPE_DIZ,
                    bytes: decoded,
                });
                pos = next_pos;
                continue;
            }

            // A disk-image data track.
            let data_track = DataTrack {
                method: th.method,
                cflag: th.cflag,
                rtsize: th.rtsize,
                upsize: th.upsize,
                uncrunched_crc: th.uncrunched_crc,
                packed_offset,
                packed_len,
            };
            if high_cyl == -1 {
                high_cyl = i32::from(tr);
                low_cyl = i32::from(tr);
                tracksize = u32::from(th.upsize);
                if tr == 0 {
                    // Defer: might turn out to be an information text once
                    // the next track is seen.
                    let decoded = decrunch_and_verify(
                        &mut scan_state,
                        th.method,
                        th.cflag,
                        th.upsize,
                        th.rtsize,
                        th.uncrunched_crc,
                        packed,
                    )
                    .unwrap_or_default();
                    pending_zero = Some(PendingZero {
                        decoded,
                        data_track,
                    });
                    pos = next_pos;
                    continue;
                }
            } else if i32::from(tr) != high_cyl + 1 || tracksize != u32::from(th.upsize) {
                break; // a different "sub-archive" starts here: stop at this disk
            } else {
                high_cyl += 1;
            }
            tracks.push(data_track);
            pos = next_pos;
        }
        // If the archive ends with a deferred track 0 still unresolved,
        // DMS.c:1245-1249 only frees the text-detection *buffer* (`zerotxt`);
        // the disk geometry keeps cylinder 0 and `DataPos` still points at the
        // track, so the reference's separate extraction pass (XADUNARCHIVE,
        // DMS.c:1516-1539) re-reads and writes it. Reproduce that by keeping
        // the track as disk data. (Verified against `unar`: a lone track 0
        // yields cylinder 0's bytes, not an empty image.)
        if let Some(pz) = pending_zero.take() {
            tracks.push(pz.data_track);
        }

        if tracksize == 0 || low_cyl < 0 || high_cyl < 0 || tracksize % 1024 != 0 {
            return Err(invalid("DMS: no valid disk geometry found"));
        }
        let track_sectors = (tracksize / 1024) as u16;
        if !matches!(track_sectors, 9 | 18 | 11 | 22) {
            return Err(invalid(format!(
                "DMS: unsupported sectors-per-track value {track_sectors}"
            )));
        }
        let heads = 2u16;
        let cylinders = 80u16;
        let info = DmsDiskInfo {
            low_cyl: low_cyl as u16,
            high_cyl: high_cyl as u16,
            track_sectors,
            sector_size: 512,
            heads,
            cylinders,
            total_sectors: u32::from(cylinders) * u32::from(heads) * u32::from(track_sectors),
        };

        Ok(DmsArchive {
            data: data.to_vec(),
            content: DmsContent::Disk {
                info,
                tracks,
                texts,
            },
            crypted,
            password: password.map(<[u8]>::to_vec),
        })
    }

    /// Disk geometry, for a disk-image archive. `None` for an FMS archive
    /// (use [`files`](Self::files) instead).
    pub fn info(&self) -> Option<&DmsDiskInfo> {
        match &self.content {
            DmsContent::Disk { info, .. } => Some(info),
            DmsContent::Files(_) => None,
        }
    }

    /// Banner/DIZ text tracks found while scanning a disk-image archive.
    /// Always empty for an FMS archive — the reference does not collect
    /// these in the FMS branch either.
    pub fn texts(&self) -> &[DmsText] {
        match &self.content {
            DmsContent::Disk { texts, .. } => texts,
            DmsContent::Files(_) => &[],
        }
    }

    /// The files inside an FMS archive. Always empty for a disk-image
    /// archive (use [`read_disk_image`](Self::read_disk_image) instead).
    pub fn files(&self) -> &[DmsFile] {
        match &self.content {
            DmsContent::Files(files) => files,
            DmsContent::Disk { .. } => &[],
        }
    }

    /// Assemble the ADF disk image: concatenate every data track's
    /// decrunched bytes in cylinder order (analogous to the disk branch of
    /// `XADUNARCHIVE(DMS)`, `DMS.c:1508-1540`). Errors if this archive is an
    /// FMS file archive instead — use [`files`](Self::files) and
    /// [`read_file`](Self::read_file).
    pub fn read_disk_image(&self) -> io::Result<Vec<u8>> {
        let DmsContent::Disk { tracks, .. } = &self.content else {
            return Err(invalid(
                "DMS: this is a file archive (FMS), not a disk image — use files()/read_file()",
            ));
        };
        // One LZ state shared across the whole pass: QUICK/MEDIUM (and later
        // DEEP/HEAVY) advance a common `Text` window and running indices
        // track-to-track, reset or carried per track based on `NOINIT`
        // (`decrunch_and_verify`). Its cipher stream is independent of
        // `open`'s scan-time `scan_state` — see the note there.
        let mut state = DmsState::with_password(self.password.as_deref(), self.crypted);
        let capacity = tracks.iter().map(|t| t.upsize as usize).sum();
        let mut out = Vec::with_capacity(capacity);
        for track in tracks {
            let packed = self
                .data
                .get(track.packed_offset..track.packed_offset + track.packed_len)
                .ok_or_else(|| invalid("DMS: track data out of range"))?;
            let decoded = decrunch_and_verify(
                &mut state,
                track.method,
                track.cflag,
                track.upsize,
                track.rtsize,
                track.uncrunched_crc,
                packed,
            )?;
            out.extend_from_slice(&decoded);
        }
        Ok(out)
    }

    /// Extract one file from an FMS archive: its data tracks
    /// (`DMSTRTYPE_FILESTART`, `+1`, …) run through the same
    /// `decrunch_and_verify` disk tracks use — same codecs, same RLE stage,
    /// same encryption/retry handling (`XADUNARCHIVE`'s file branch,
    /// `DMS.c:1480-1497`). `file` must have come from
    /// [`files`](Self::files) on this same archive.
    pub fn read_file(&self, file: &DmsFile) -> io::Result<Vec<u8>> {
        let mut state = DmsState::with_password(self.password.as_deref(), file.is_crypted);
        let mut out = Vec::with_capacity(file.size as usize);
        let mut pos = file.data_offset;
        let mut track_number = DMSTRTYPE_FILESTART;
        while out.len() < file.size as usize {
            let th = self
                .data
                .get(pos..pos + TRACK_HEADER_LEN)
                .and_then(parse_track_header)
                .ok_or_else(|| invalid("DMS: FMS file data track truncated or invalid"))?;
            if th.track_number != track_number {
                return Err(invalid("DMS: FMS file data track out of sequence"));
            }
            let packed_offset = pos + TRACK_HEADER_LEN;
            let packed_len = th.cmode as usize;
            let packed = self
                .data
                .get(packed_offset..packed_offset + packed_len)
                .ok_or_else(|| invalid("DMS: track data truncated"))?;
            let decoded = decrunch_and_verify(
                &mut state,
                th.method,
                th.cflag,
                th.upsize,
                th.rtsize,
                th.uncrunched_crc,
                packed,
            )?;
            out.extend_from_slice(&decoded);
            pos = packed_offset + packed_len;
            track_number += 1;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_empty_is_zero() {
        assert_eq!(checksum_dms(&[]), 0);
    }

    #[test]
    fn checksum_sums_bytes() {
        assert_eq!(checksum_dms(&[1, 2, 3]), 6);
    }

    #[test]
    fn checksum_wraps_on_overflow() {
        // 257 * 0xFF == 65535 == u16::MAX; one more byte pushes the sum past
        // 65536, which must wrap back to 0, not panic or saturate.
        let mut data = vec![0xFFu8; 257];
        data.push(1);
        assert_eq!(checksum_dms(&data), 0);
    }

    #[test]
    fn rle_passes_through_literals() {
        let out = unp_rle(&[1, 2, 3], 3).unwrap();
        assert_eq!(out, vec![1, 2, 3]);
    }

    #[test]
    fn rle_expands_short_run() {
        // 0x90 <count> <value>: 5 copies of 0x41.
        let out = unp_rle(&[0x90, 0x05, 0x41], 5).unwrap();
        assert_eq!(out, vec![0x41; 5]);
    }

    #[test]
    fn rle_decodes_escaped_marker_byte() {
        // 0x90 0x00 emits one literal 0x90.
        let out = unp_rle(&[0x90, 0x00, 0x41], 2).unwrap();
        assert_eq!(out, vec![0x90, 0x41]);
    }

    #[test]
    fn rle_expands_long_run_with_16bit_count() {
        // 0x90 0xFF <value> <hi> <lo>: 300 (0x012C) copies of 0x5A.
        let out = unp_rle(&[0x90, 0xFF, 0x5A, 0x01, 0x2C], 300).unwrap();
        assert_eq!(out, vec![0x5A; 300]);
    }

    #[test]
    fn rle_explicit_zero_count_run_stops_decoding_early() {
        // The 16-bit count form can encode n == 0 (hi = lo = 0), which ends
        // decoding immediately (DMS.c:347-348) even though `upsize` bytes
        // haven't been produced yet — the reference does the same.
        let out = unp_rle(&[0x90, 0xFF, 0x41, 0x00, 0x00, 0x99], 10).unwrap();
        assert_eq!(out, Vec::<u8>::new());
    }

    #[test]
    fn rle_run_overrunning_upsize_is_an_error() {
        let out = unp_rle(&[0x90, 0x05, 0x41], 3);
        assert!(out.is_err());
    }

    #[test]
    fn rle_truncated_input_is_an_error() {
        let out = unp_rle(&[0x90, 0x05], 5);
        assert!(out.is_err());
    }

    /// A minimal 56-byte header with a correct checksum, `InfoFlags` and
    /// `DiskType`/`DiskType2` left at 0.
    fn build_header() -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h[0..4].copy_from_slice(b"DMS!");
        let crc = crc16_arc(&h[4..54]);
        h[54..56].copy_from_slice(&crc.to_be_bytes());
        h
    }

    /// A 20-byte track header with a correct checksum. `rtsize`/`cflag`
    /// default to 0 — irrelevant to NOCOMP/SIMPLE, which every existing
    /// `build_track_header` call site exercises.
    fn build_track_header(
        track_number: i16,
        cmode: u16,
        upsize: u16,
        method: u8,
        uncrunched_crc: u16,
    ) -> [u8; TRACK_HEADER_LEN] {
        build_track_header_full(track_number, cmode, 0, upsize, 0, method, uncrunched_crc)
    }

    /// Like [`build_track_header`], with `rtsize`/`cflag` also settable —
    /// needed by the QUICK/MEDIUM/DEEP container fixtures below.
    #[allow(clippy::too_many_arguments)]
    fn build_track_header_full(
        track_number: i16,
        cmode: u16,
        rtsize: u16,
        upsize: u16,
        cflag: u8,
        method: u8,
        uncrunched_crc: u16,
    ) -> [u8; TRACK_HEADER_LEN] {
        let mut t = [0u8; TRACK_HEADER_LEN];
        t[0..2].copy_from_slice(&0x5452u16.to_be_bytes());
        t[2..4].copy_from_slice(&track_number.to_be_bytes());
        t[6..8].copy_from_slice(&cmode.to_be_bytes());
        t[8..10].copy_from_slice(&rtsize.to_be_bytes());
        t[10..12].copy_from_slice(&upsize.to_be_bytes());
        t[12] = cflag;
        t[13] = method;
        t[14..16].copy_from_slice(&uncrunched_crc.to_be_bytes());
        let crc = crc16_arc(&t[0..18]);
        t[18..20].copy_from_slice(&crc.to_be_bytes());
        t
    }

    #[test]
    fn recognizes_valid_header() {
        assert!(DmsArchive::recognize(&build_header()));
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut h = build_header();
        h[0] = b'X';
        assert!(!DmsArchive::recognize(&h));
    }

    #[test]
    fn rejects_bad_header_checksum() {
        let mut h = build_header();
        h[55] ^= 0xFF;
        assert!(!DmsArchive::recognize(&h));
    }

    #[test]
    fn rejects_short_data() {
        assert!(!DmsArchive::recognize(&build_header()[..40]));
    }

    #[test]
    fn track_header_parses_valid_fields() {
        let t = build_track_header(5, 100, 200, DMSCOMP_SIMPLE, 0x1234);
        let parsed = parse_track_header(&t).unwrap();
        assert_eq!(parsed.track_number, 5);
        assert_eq!(parsed.cmode, 100);
        assert_eq!(parsed.upsize, 200);
        assert_eq!(parsed.method, DMSCOMP_SIMPLE);
        assert_eq!(parsed.uncrunched_crc, 0x1234);
    }

    #[test]
    fn track_header_rejects_bad_trid() {
        let mut t = build_track_header(0, 0, 0, 0, 0);
        t[0] = b'X';
        assert!(parse_track_header(&t).is_none());
    }

    #[test]
    fn track_header_rejects_bad_checksum() {
        let mut t = build_track_header(0, 0, 0, 0, 0);
        t[19] ^= 0xFF;
        assert!(parse_track_header(&t).is_none());
    }

    #[test]
    fn track_header_signed_track_number() {
        let t = build_track_header(-1, 10, 10, DMSCOMP_NOCOMP, 0);
        assert_eq!(parse_track_header(&t).unwrap().track_number, -1);
    }

    // --- FMS: file-name track parsing (pre-2.04 / 2.04) ---

    #[test]
    fn fms_name_pre204_is_the_payload_verbatim() {
        let (name, protection, comment) = parse_fms_name(b"HELLO.TXT").unwrap();
        assert_eq!(name, b"HELLO.TXT");
        assert_eq!(protection, None);
        assert_eq!(comment, None);
    }

    #[test]
    fn fms_name_pre204_empty_payload_is_an_empty_name() {
        // No leading zero byte (there's no byte at all), so this must not be
        // mistaken for the 2.04 layout.
        let (name, protection, comment) = parse_fms_name(&[]).unwrap();
        assert!(name.is_empty());
        assert_eq!(protection, None);
        assert_eq!(comment, None);
    }

    /// Build a 2.04 name-track payload: `[4B protection][12B DateStamp][size
    /// byte(s)][comment?][name]` (`DMS.c:49-57`). `protection`'s top byte
    /// must be 0 — that's the pre-2.04/2.04 discriminator itself.
    fn build_204_payload(protection: u32, comment: Option<&[u8]>, name: &[u8]) -> Vec<u8> {
        assert_eq!(protection >> 24, 0, "top byte must be 0 by construction");
        let mut v = protection.to_be_bytes().to_vec();
        v.extend([0u8; 12]); // DateStamp: not carried by DmsFile, content irrelevant here
        match comment {
            Some(c) => {
                assert!(c.len() <= 0x7F);
                v.push(0x80 | c.len() as u8);
                v.extend_from_slice(c);
                v.push(name.len() as u8); // discarded by the parser; included for realism
            }
            None => v.push(name.len() as u8),
        }
        v.extend_from_slice(name);
        v
    }

    #[test]
    fn fms_name_204_without_comment() {
        let payload = build_204_payload(0x0000_0021, None, b"PROG.EXE");
        let (name, protection, comment) = parse_fms_name(&payload).unwrap();
        assert_eq!(name, b"PROG.EXE");
        assert_eq!(protection, Some(0x0000_0021));
        assert_eq!(comment, None);
    }

    #[test]
    fn fms_name_204_with_comment() {
        let payload = build_204_payload(0x0000_0001, Some(b"a short comment"), b"DOC.TXT");
        let (name, protection, comment) = parse_fms_name(&payload).unwrap();
        assert_eq!(name, b"DOC.TXT");
        assert_eq!(protection, Some(0x0000_0001));
        assert_eq!(comment, Some(b"a short comment".to_vec()));
    }

    #[test]
    fn fms_name_204_truncated_before_the_size_byte_is_an_error() {
        // 16 bytes: protection + DateStamp, but no size byte at all.
        let payload = vec![0u8; 16];
        assert!(parse_fms_name(&payload).is_err());
    }

    #[test]
    fn fms_name_204_comment_longer_than_payload_is_an_error() {
        let mut payload = build_204_payload(0, Some(b"short"), b"X");
        payload.truncate(17 + 2); // cut the comment text short
        assert!(parse_fms_name(&payload).is_err());
    }

    #[test]
    fn decrunch_nocomp_takes_first_upsize_bytes() {
        let mut state = DmsState::new();
        let out = decrunch_track(&mut state, DMSCOMP_NOCOMP, 0, &[1, 2, 3, 4, 5], 3, 0).unwrap();
        assert_eq!(out, vec![1, 2, 3]);
    }

    #[test]
    fn decrunch_nocomp_rejects_short_input() {
        let mut state = DmsState::new();
        assert!(decrunch_track(&mut state, DMSCOMP_NOCOMP, 0, &[1, 2], 3, 0).is_err());
    }

    #[test]
    fn decrunch_simple_delegates_to_rle() {
        let mut state = DmsState::new();
        let out = decrunch_track(&mut state, DMSCOMP_SIMPLE, 0, &[0x90, 0x03, 0x41], 3, 0).unwrap();
        assert_eq!(out, vec![0x41; 3]);
    }

    #[test]
    fn decrunch_unknown_method_is_invalid() {
        let mut state = DmsState::new();
        let err = decrunch_track(&mut state, 7, 0, &[], 0, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    // --- DmsState / dms_init_data --------------------------------------

    #[test]
    fn new_state_starts_with_fully_zeroed_text() {
        let state = DmsState::new();
        assert!(state.text[TEXT_INIT_LEN..].iter().all(|&b| b == 0));
    }

    #[test]
    fn new_state_seeds_running_indices_and_did_init() {
        let state = DmsState::new();
        assert_eq!(state.rtv_quick, 251);
        assert_eq!(state.rtv_medium, 0x3FBE);
        assert!(state.did_init);
    }

    #[test]
    fn dms_init_data_only_zeroes_the_first_0x3fc8_bytes_of_text() {
        // The reference's `memset(d->Text, 0, 0x3fc8)` leaves the tail
        // (0x3FC8..0x8000) untouched on a *mid-stream* reinit — a previous
        // track's bytes can still be sitting there. Not a bug to "fix".
        let mut state = DmsState::new();
        state.text[TEXT_INIT_LEN] = 0xAB; // just past the cleared region
        state.text[0] = 0xCD; // inside the cleared region
        state.rtv_quick = 999;
        state.rtv_medium = 999;
        state.did_init = false;

        dms_init_data(&mut state);

        assert_eq!(state.text[0], 0, "cleared region must be reset");
        assert_eq!(state.text[TEXT_INIT_LEN], 0xAB, "tail must survive reinit");
        assert_eq!(state.rtv_quick, 251);
        assert_eq!(state.rtv_medium, 0x3FBE);
        assert!(state.did_init);
    }

    // --- unp_quick / unp_medium ------------------------------------------

    /// Encode `bytes` as an all-literal QUICK/MEDIUM bitstream: `1` flag bit
    /// then 8 raw bits per byte, MSB-first — the "mini-encoder" from the
    /// task brief. Valid input for both decoders (literal coding is
    /// identical in QUICK and MEDIUM).
    fn literal_stream(bytes: &[u8]) -> Vec<u8> {
        let mut w = newtua_testutil::BitWriterMsb::default();
        for &b in bytes {
            w.bit(true);
            w.bits(u32::from(b), 8);
        }
        w.finish()
    }

    #[test]
    fn quick_decodes_an_all_literal_stream() {
        let mut state = DmsState::new();
        let packed = literal_stream(&[0x11, 0x22, 0x33]);
        let out = unp_quick(&mut state, &packed, 3).unwrap();
        assert_eq!(out, vec![0x11, 0x22, 0x33]);
    }

    #[test]
    fn quick_match_copies_from_window() {
        // Literal 0x7A, then a match: flag 0, length bits 00 (-> j=2),
        // offset bits 00000000 (-> i = rtv_quick-0-1, the byte just
        // written). Expected: [0x7A, 0x7A, 0x7A] (one literal + a
        // 2-byte self-referential copy).
        let mut w = newtua_testutil::BitWriterMsb::default();
        w.bit(true);
        w.bits(0x7A, 8);
        w.bit(false);
        w.bits(0, 2); // length selector 0 -> j = 2
        w.bits(0, 8); // offset 0 -> copy from the byte just written
        let packed = w.finish();

        let mut state = DmsState::new();
        let out = unp_quick(&mut state, &packed, 3).unwrap();
        assert_eq!(out, vec![0x7A, 0x7A, 0x7A]);
    }

    #[test]
    fn quick_end_of_track_advances_rtv_by_5_wrapped() {
        let mut state = DmsState::new();
        state.rtv_quick = 254; // 254 + 3 (literals) + 5 = 262 & 0xFF = 6
        let packed = literal_stream(&[1, 2, 3]);
        unp_quick(&mut state, &packed, 3).unwrap();
        assert_eq!(state.rtv_quick, 6);
    }

    #[test]
    fn quick_clears_did_init_even_when_reinit_pending() {
        let mut state = DmsState::new();
        state.did_init = false; // simulate a carried-over track
        let packed = literal_stream(&[1]);
        unp_quick(&mut state, &packed, 1).unwrap();
        assert!(!state.did_init, "QUICK must clear DidInit at decode start");
    }

    #[test]
    fn quick_empty_track_decodes_to_empty_output() {
        let mut state = DmsState::new();
        let out = unp_quick(&mut state, &[], 0).unwrap();
        assert_eq!(out, Vec::<u8>::new());
    }

    #[test]
    fn quick_match_overrunning_rtsize_is_an_error() {
        let mut w = newtua_testutil::BitWriterMsb::default();
        w.bit(false);
        w.bits(3, 2); // j = 5
        w.bits(0, 8);
        let packed = w.finish();
        let mut state = DmsState::new();
        assert!(unp_quick(&mut state, &packed, 3).is_err());
    }

    #[test]
    fn quick_short_input_is_padded_with_zero_bits_not_a_panic() {
        // No exception in the reference: reads past the packed buffer just
        // see zero bytes. A stream truncated right after the first literal
        // flag bit must still decode (as zero bits) instead of panicking.
        let mut state = DmsState::new();
        let out = unp_quick(&mut state, &[], 2);
        assert!(out.is_ok());
    }

    #[test]
    fn medium_decodes_an_all_literal_stream() {
        let mut state = DmsState::new();
        let packed = literal_stream(&[0xAA, 0xBB]);
        let out = unp_medium(&mut state, &packed, 2).unwrap();
        assert_eq!(out, vec![0xAA, 0xBB]);
    }

    #[test]
    fn medium_match_with_zero_coded_distance_copies_previous_byte() {
        // DMS_D_CODE[0] == 0, DMS_D_LEN[0] == 3: raw byte 0 -> j=3, then two
        // more 3-bit-zero refinement rounds both keep c==0 -> dist=0, i.e.
        // "copy the byte just written" (hand-verified against DMSUnpMEDIUM).
        let mut w = newtua_testutil::BitWriterMsb::default();
        w.bit(true);
        w.bits(0x5C, 8); // seed byte
        w.bit(false);
        w.bits(0, 8); // raw c = 0
        w.bits(0, 3); // first refinement round, 3 bits (DMS_D_LEN[0])
        w.bits(0, 3); // second refinement round, 3 bits (DMS_D_LEN[0] again)
        let packed = w.finish();

        let mut state = DmsState::new();
        let out = unp_medium(&mut state, &packed, 4).unwrap();
        assert_eq!(out, vec![0x5C, 0x5C, 0x5C, 0x5C]);
    }

    #[test]
    fn medium_end_of_track_advances_rtv_by_66_wrapped_0x3fff() {
        let mut state = DmsState::new();
        state.rtv_medium = 0x3FFE; // + 2 literals -> 0x4000; + 66 = 0x4042 & 0x3FFF = 0x42
        let packed = literal_stream(&[1, 2]);
        unp_medium(&mut state, &packed, 2).unwrap();
        assert_eq!(state.rtv_medium, 0x42);
    }

    #[test]
    fn medium_match_overrunning_rtsize_is_an_error() {
        let mut w = newtua_testutil::BitWriterMsb::default();
        w.bit(false);
        w.bits(0, 8);
        w.bits(0, 3);
        w.bits(0, 3);
        let packed = w.finish();
        let mut state = DmsState::new();
        assert!(unp_medium(&mut state, &packed, 2).is_err());
    }

    // --- dispatcher / post-track reinit -----------------------------------

    #[test]
    fn decrunch_track_quick_runs_lz_then_rle() {
        // Intermediate (post-LZ) bytes are RLE-coded: 0x90 03 0x41 -> three
        // 0x41s once unp_rle expands them.
        let mut state = DmsState::new();
        let packed = literal_stream(&[0x90, 0x03, 0x41]);
        let out = decrunch_track(&mut state, DMSCOMP_QUICK, 0, &packed, 3, 3).unwrap();
        assert_eq!(out, vec![0x41; 3]);
    }

    #[test]
    fn decrunch_track_medium_runs_lz_then_rle() {
        let mut state = DmsState::new();
        let packed = literal_stream(&[0x90, 0x03, 0x42]);
        let out = decrunch_track(&mut state, DMSCOMP_MEDIUM, 0, &packed, 3, 3).unwrap();
        assert_eq!(out, vec![0x42; 3]);
    }

    #[test]
    fn decrunch_and_verify_reinits_state_when_noinit_is_absent() {
        let mut state = DmsState::new();
        state.did_init = false; // as if left dangling by a previous NOINIT track
        let raw = vec![7u8; 4];
        let packed = literal_stream(&raw);
        decrunch_and_verify(
            &mut state,
            DMSCOMP_QUICK,
            0, // no NOINIT
            4,
            4,
            checksum_dms(&raw),
            &packed,
        )
        .unwrap();
        assert!(state.did_init, "reinit must run when NOINIT is absent");
        assert_eq!(state.rtv_quick, 251);
    }

    #[test]
    fn decrunch_and_verify_skips_reinit_when_noinit_is_set() {
        let mut state = DmsState::new();
        let raw = vec![7u8; 4];
        let packed = literal_stream(&raw);
        decrunch_and_verify(
            &mut state,
            DMSCOMP_QUICK,
            DMSCFLAG_NOINIT,
            4,
            4,
            checksum_dms(&raw),
            &packed,
        )
        .unwrap();
        assert!(
            !state.did_init,
            "NOINIT must carry the LZ state into the next track"
        );
    }

    #[test]
    fn decrunch_and_verify_wrong_checksum_is_an_error_before_reinit() {
        let mut state = DmsState::new();
        let raw = vec![7u8; 4];
        let packed = literal_stream(&raw);
        let err = decrunch_and_verify(
            &mut state,
            DMSCOMP_QUICK,
            0,
            4,
            4,
            checksum_dms(&raw) ^ 0xFFFF,
            &packed,
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    // --- Encryption: DecryptDMS + password key derivation ------------------

    /// Mirror of [`decrypt_dms`], inverted for encryption: given a plaintext
    /// byte `pt`, `ct = pt ^ (rtv_pass & 0xFF)`, then `rtv_pass` advances by
    /// `ct` — the same update rule [`decrypt_dms`] uses, driven by the same
    /// value, so decrypting this output with the same starting `rtv_pass`
    /// recovers `pt` and walks through the identical state sequence.
    fn encrypt_dms_mirror(data: &mut [u8], rtv_pass: &mut u16) {
        for b in data.iter_mut() {
            let pt = *b;
            let ct = pt ^ (*rtv_pass & 0xFF) as u8;
            *rtv_pass = (*rtv_pass >> 1).wrapping_add(u16::from(ct));
            *b = ct;
        }
    }

    #[test]
    fn decrypt_dms_round_trips_with_a_mirror_encryptor() {
        let plain: Vec<u8> = (0..=255u8).cycle().take(300).collect();
        let mut rtv_pass_enc = 0xBEEFu16;
        let mut encrypted = plain.clone();
        encrypt_dms_mirror(&mut encrypted, &mut rtv_pass_enc);
        assert_ne!(
            encrypted, plain,
            "a non-trivial cipher must change the bytes"
        );

        let mut rtv_pass_dec = 0xBEEFu16;
        let mut decrypted = encrypted;
        decrypt_dms(&mut decrypted, &mut rtv_pass_dec);
        assert_eq!(decrypted, plain);
        assert_eq!(
            rtv_pass_dec, rtv_pass_enc,
            "both directions must walk through the identical state sequence"
        );
    }

    #[test]
    fn with_password_derives_pass_crc_and_rtv_pass_from_crc16_arc() {
        let state = DmsState::with_password(Some(b"hunter2"), true);
        let expected = crc16_arc(b"hunter2");
        assert_eq!(state.pass_crc, expected);
        assert_eq!(state.rtv_pass, expected);
        assert!(state.use_pwd);
    }

    #[test]
    fn with_password_none_leaves_cipher_key_fields_zero() {
        let state = DmsState::with_password(None, true);
        assert_eq!(state.pass_crc, 0);
        assert_eq!(state.rtv_pass, 0);
        assert!(
            state.use_pwd,
            "use_pwd tracks the archive's crypted flag, independent of whether a password was given"
        );
    }

    #[test]
    fn with_password_use_pwd_is_false_when_the_archive_is_not_crypted() {
        let state = DmsState::with_password(Some(b"hunter2"), false);
        assert!(!state.use_pwd);
    }

    #[test]
    fn dms_init_data_does_not_touch_cipher_state() {
        let mut state = DmsState::with_password(Some(b"hunter2"), true);
        state.rtv_pass = 0x1234; // as if advanced mid-track by decrypt_dms
        dms_init_data(&mut state);
        assert_eq!(state.rtv_pass, 0x1234);
        assert_eq!(state.pass_crc, crc16_arc(b"hunter2"));
        assert!(state.use_pwd);
    }

    #[test]
    fn decrunch_and_verify_skips_decryption_when_pass_crc_is_zero() {
        // crypted == true (use_pwd starts true) but no password was given,
        // so pass_crc == 0 and decryption must be skipped outright: an
        // unencrypted NOCOMP track decodes as-is.
        let mut state = DmsState::with_password(None, true);
        let raw = vec![1u8, 2, 3, 4];
        let out = decrunch_and_verify(
            &mut state,
            DMSCOMP_NOCOMP,
            0,
            4,
            0,
            checksum_dms(&raw),
            &raw,
        )
        .unwrap();
        assert_eq!(out, raw);
        assert_eq!(state.rtv_pass, 0, "decrypt_dms must never have run");
    }

    #[test]
    fn decrunch_and_verify_decrypts_before_decoding_when_password_is_set() {
        let pwd = b"hunter2";
        let raw = vec![0x41u8; 64];
        let mut encrypted = raw.clone();
        let mut rtv_pass_expected = crc16_arc(pwd);
        encrypt_dms_mirror(&mut encrypted, &mut rtv_pass_expected);

        let mut state = DmsState::with_password(Some(pwd), true);
        let out = decrunch_and_verify(
            &mut state,
            DMSCOMP_NOCOMP,
            0,
            raw.len() as u16,
            0,
            checksum_dms(&raw),
            &encrypted,
        )
        .unwrap();
        assert_eq!(out, raw);
        assert!(
            state.use_pwd,
            "a successful first attempt must not flip use_pwd"
        );
        assert_eq!(state.rtv_pass, rtv_pass_expected);
    }

    #[test]
    fn decrunch_and_verify_retries_without_decryption_when_the_track_was_never_encrypted() {
        // A DIZ-style quirk: the archive is crypted, but this particular
        // track's bytes were left in the clear on disk. The first (decrypt)
        // attempt corrupts them and fails the checksum; the retry re-reads
        // the same raw bytes without decrypting and succeeds.
        let pwd = b"hunter2";
        let raw = b"not actually encrypted".to_vec();
        let upsize = raw.len() as u16;

        let mut state = DmsState::with_password(Some(pwd), true);
        let out = decrunch_and_verify(
            &mut state,
            DMSCOMP_NOCOMP,
            0,
            upsize,
            0,
            checksum_dms(&raw),
            &raw,
        )
        .unwrap();
        assert_eq!(out, raw);
        assert!(
            !state.use_pwd,
            "the USE -> NOUSE transition must persist after a successful retry"
        );

        // rtv_pass is NOT rolled back: it already advanced past these bytes
        // via the failed decrypt attempt, keeping the cipher synchronized
        // for any later, genuinely-encrypted track sharing this state.
        let mut rtv_pass_after_failed_attempt = crc16_arc(pwd);
        let mut consumed = raw.clone();
        decrypt_dms(&mut consumed, &mut rtv_pass_after_failed_attempt);
        assert_eq!(state.rtv_pass, rtv_pass_after_failed_attempt);
    }

    #[test]
    fn decrunch_and_verify_wrong_password_fails_even_after_the_retry() {
        let raw = vec![0x41u8; 32];
        let mut encrypted = raw.clone();
        encrypt_dms_mirror(&mut encrypted, &mut crc16_arc(b"right"));

        let mut state = DmsState::with_password(Some(b"wrong"), true);
        let err = decrunch_and_verify(
            &mut state,
            DMSCOMP_NOCOMP,
            0,
            raw.len() as u16,
            0,
            checksum_dms(&raw),
            &encrypted,
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            !state.use_pwd,
            "the retry must still have run and flipped use_pwd"
        );
    }

    // --- DEEP: adaptive-Huffman tree --------------------------------------

    #[test]
    fn new_state_seeds_rtv_deep() {
        let state = DmsState::new();
        assert_eq!(state.rtv_deep, 0x3FC4);
    }

    #[test]
    fn dms_init_data_builds_uniform_leaf_tree_on_first_init() {
        // did_init_deep starts false, so DmsState::new()'s dms_init_data call
        // must build the starting tree: every leaf has frequency 1 and a
        // deterministic position (DMS.c:967-975).
        let state = DmsState::new();
        for i in 0..DMSN_BYTE {
            assert_eq!(state.freq[i], 1, "leaf {i} freq");
            assert_eq!(state.son[i] as usize, i + DMST, "leaf {i} son");
            assert_eq!(state.prnt[i + DMST] as usize, i, "leaf {i} prnt-of-leaf");
        }
        assert_eq!(state.freq[DMST], 0xFFFF, "sentinel");
        assert_eq!(state.prnt[DMSR], 0, "root's own parent slot");
    }

    #[test]
    fn dms_init_data_root_frequency_sums_every_leaf() {
        let state = DmsState::new();
        assert_eq!(state.freq[DMSR], DMSN_BYTE as u16);
    }

    #[test]
    fn dms_init_data_skips_tree_rebuild_once_did_init_deep_is_true() {
        let mut state = DmsState::new(); // did_init_deep is now true
        state.freq[0] = 999; // a rebuild would reset this back to 1
        dms_init_data(&mut state);
        assert_eq!(
            state.freq[0], 999,
            "tree must not rebuild when did_init_deep was already true"
        );
    }

    #[test]
    fn dms_init_data_rebuilds_tree_when_did_init_deep_is_false() {
        let mut state = DmsState::new();
        state.freq[0] = 999;
        state.did_init_deep = false;
        dms_init_data(&mut state);
        assert_eq!(
            state.freq[0], 1,
            "tree must rebuild fresh when did_init_deep was false"
        );
    }

    #[test]
    fn update_tree_increments_the_targeted_symbols_frequency() {
        let mut state = DmsState::new();
        let node_before = state.prnt[DMST]; // symbol 0's node
        let freq_before = state.freq[node_before as usize];
        update_tree(&mut state, 0);
        let node_after = state.prnt[DMST]; // may have moved after rebalancing
        assert_eq!(state.freq[node_after as usize], freq_before + 1);
    }

    #[test]
    fn update_tree_keeps_tree_navigable_after_many_updates() {
        let mut state = DmsState::new();
        for i in 0..1000u16 {
            update_tree(&mut state, i % DMSN_BYTE as u16);
        }
        // Structural sanity: the tree must still be a valid, terminating
        // binary structure decode_char can walk without panicking.
        let mut reader = bit_reader(&[]);
        let sym = decode_char(&mut state, &mut reader);
        assert!((sym as usize) < DMSN_BYTE);
    }

    #[test]
    fn reconst_tree_reduces_root_frequency_and_keeps_leaves_reachable() {
        let mut state = DmsState::new();
        state.freq[DMSR] = DMSMAX_FREQ;
        reconst_tree(&mut state);
        assert!(
            state.freq[DMSR] < DMSMAX_FREQ,
            "reconst must reduce the root frequency"
        );
        let mut reader = bit_reader(&[0xFFu8; 40]);
        for _ in 0..20 {
            let sym = decode_char(&mut state, &mut reader);
            assert!((sym as usize) < DMSN_BYTE);
        }
    }

    #[test]
    fn update_tree_triggers_reconst_when_root_frequency_hits_max() {
        let mut state = DmsState::new();
        state.freq[DMSR] = DMSMAX_FREQ;
        update_tree(&mut state, 1);
        assert!(
            state.freq[DMSR] < DMSMAX_FREQ,
            "reconst must have run first"
        );
    }

    #[test]
    fn decode_position_hand_built_zero_distance() {
        // DMS_D_CODE[0] == 0, DMS_D_LEN[0] == 3: raw byte 0 followed by three
        // zero extra bits decodes to distance 0 (hand-verified against
        // DMSDecodePosition).
        let mut w = newtua_testutil::BitWriterMsb::default();
        w.bits(0, 8);
        w.bits(0, 3);
        let packed = w.finish();
        let mut reader = bit_reader(&packed);
        assert_eq!(decode_position(&mut reader), 0);
    }

    /// A mirror DEEP encoder sharing [`update_tree`]/[`reconst_tree`] with
    /// the decoder, so the adaptive tree stays synchronized the same way a
    /// real encoder/decoder pair would (see `encode_char`'s doc comment).
    /// There is no DEEP encoder anywhere in XADMaster (it only ever reads
    /// archives), so this is the only way to produce valid DEEP fixtures;
    /// the mandatory `unar` oracle tests below are what actually cross-check
    /// this against an independent implementation.
    enum DeepToken {
        Literal(u8),
        Match { len: u16, dist: u16 },
    }

    /// Inverse of [`decode_char`] (classic LZHUF `Encode`): walk from the
    /// symbol's leaf up to the root via `prnt`, collecting one bit per level
    /// (odd position = "bigger"/right child = bit 1), then emit those bits
    /// root-first — the order `decode_char`'s bit-by-bit descent expects.
    fn encode_char(state: &mut DmsState, writer: &mut newtua_testutil::BitWriterMsb, sym: u16) {
        let mut code: u16 = 0;
        let mut len: u32 = 0;
        let mut k = state.prnt[sym as usize + DMST];
        loop {
            code >>= 1;
            if k & 1 != 0 {
                code |= 0x8000;
            }
            len += 1;
            k = state.prnt[k as usize];
            if k as usize == DMSR {
                break;
            }
        }
        writer.bits(u32::from(code >> (16 - len)), len);
        update_tree(state, sym);
    }

    /// Inverse of [`decode_position`]: brute-force the raw 8-bit code (and
    /// its `DMS_D_LEN` extra bits) that makes `decode_position` reproduce
    /// `dist`, since [`DMS_D_CODE`] isn't easily invertible by formula.
    fn encode_position(writer: &mut newtua_testutil::BitWriterMsb, dist: u16) {
        let high = dist >> 8;
        let low = dist & 0xFF;
        for i_raw in 0u16..256 {
            if u16::from(DMS_D_CODE[i_raw as usize]) != high {
                continue;
            }
            let j = DMS_D_LEN[i_raw as usize];
            let masked = (i_raw << j) & 0xFF;
            let mask = (1u16 << j) - 1;
            let extra = low & mask;
            if (masked | extra) == low {
                writer.bits(u32::from(i_raw), 8);
                writer.bits(u32::from(extra), u32::from(j));
                return;
            }
        }
        panic!("DMS DEEP test encoder: no raw byte encodes distance {dist:#06x}");
    }

    /// Encode a full DEEP track from a token sequence, clearing both init
    /// flags up front exactly as [`unp_deep`] does at the start of a real
    /// decode (`DMS.c:596`) — relevant for the NOINIT-carry oracle below,
    /// which checks those flags between tracks.
    fn deep_encode(state: &mut DmsState, tokens: &[DeepToken]) -> Vec<u8> {
        state.did_init_deep = false;
        state.did_init = false;
        let mut writer = newtua_testutil::BitWriterMsb::default();
        for tok in tokens {
            match *tok {
                DeepToken::Literal(b) => encode_char(state, &mut writer, u16::from(b)),
                DeepToken::Match { len, dist } => {
                    encode_char(state, &mut writer, 253 + len);
                    encode_position(&mut writer, dist);
                }
            }
        }
        writer.finish()
    }

    #[test]
    fn deep_char_round_trips_many_symbols_through_shared_tree() {
        let mut enc_state = DmsState::new();
        let mut writer = newtua_testutil::BitWriterMsb::default();
        let symbols: Vec<u16> = (0..300)
            .map(|i| (i * 37 % DMSN_BYTE as i32) as u16)
            .collect();
        for &s in &symbols {
            encode_char(&mut enc_state, &mut writer, s);
        }
        let packed = writer.finish();

        let mut dec_state = DmsState::new();
        let mut reader = bit_reader(&packed);
        for &expected in &symbols {
            assert_eq!(decode_char(&mut dec_state, &mut reader), expected);
        }
    }

    #[test]
    fn deep_position_round_trips_across_full_distance_range() {
        for dist in (0u16..0x4000).step_by(37) {
            let mut writer = newtua_testutil::BitWriterMsb::default();
            encode_position(&mut writer, dist);
            let packed = writer.finish();
            let mut reader = bit_reader(&packed);
            assert_eq!(decode_position(&mut reader), dist, "dist={dist:#06x}");
        }
    }

    #[test]
    fn deep_decodes_an_all_literal_stream_via_shared_encoder() {
        let mut enc_state = DmsState::new();
        let tokens: Vec<DeepToken> = [0x11u8, 0x22, 0x33, 0xAA]
            .iter()
            .map(|&b| DeepToken::Literal(b))
            .collect();
        let packed = deep_encode(&mut enc_state, &tokens);

        let mut dec_state = DmsState::new();
        let out = unp_deep(&mut dec_state, &packed, 4).unwrap();
        assert_eq!(out, vec![0x11, 0x22, 0x33, 0xAA]);
    }

    #[test]
    fn deep_match_path_round_trips_via_shared_encoder() {
        // Literal 0x7A, then a length-3 self-referential match (dist=0):
        // copies the byte just written, three more times.
        let mut enc_state = DmsState::new();
        let tokens = [
            DeepToken::Literal(0x7A),
            DeepToken::Match { len: 3, dist: 0 },
        ];
        let packed = deep_encode(&mut enc_state, &tokens);

        let mut dec_state = DmsState::new();
        let out = unp_deep(&mut dec_state, &packed, 4).unwrap();
        assert_eq!(out, vec![0x7A, 0x7A, 0x7A, 0x7A]);
    }

    #[test]
    fn deep_end_of_track_advances_rtv_by_60_wrapped_0x3fff() {
        let mut enc_state = DmsState::new();
        let tokens = [DeepToken::Literal(1), DeepToken::Literal(2)];
        let packed = deep_encode(&mut enc_state, &tokens);

        let mut state = DmsState::new();
        state.rtv_deep = 0x3FFE; // + 2 literals -> 0x4000; + 60 = 0x403C & 0x3FFF = 0x3C
        unp_deep(&mut state, &packed, 2).unwrap();
        assert_eq!(state.rtv_deep, 0x3C);
    }

    #[test]
    fn deep_clears_both_init_flags_even_when_reinit_pending() {
        let mut enc_state = DmsState::new();
        let packed = deep_encode(&mut enc_state, &[DeepToken::Literal(9)]);

        let mut state = DmsState::new(); // did_init == did_init_deep == true
        unp_deep(&mut state, &packed, 1).unwrap();
        assert!(!state.did_init, "DEEP must clear DidInit at decode start");
        assert!(
            !state.did_init_deep,
            "DEEP must also clear DidInitDEEP, unlike QUICK/MEDIUM"
        );
    }

    #[test]
    fn deep_empty_track_decodes_to_empty_output() {
        let mut state = DmsState::new();
        let out = unp_deep(&mut state, &[], 0).unwrap();
        assert_eq!(out, Vec::<u8>::new());
    }

    #[test]
    fn deep_short_input_is_padded_with_zero_bits_not_a_panic() {
        let mut state = DmsState::new();
        let _ = unp_deep(&mut state, &[], 5); // must not panic; Ok or Err both fine
    }

    #[test]
    fn deep_match_overrunning_rtsize_is_an_error() {
        let mut enc_state = DmsState::new();
        let packed = deep_encode(
            &mut enc_state,
            &[DeepToken::Literal(1), DeepToken::Match { len: 3, dist: 0 }],
        );
        let mut state = DmsState::new();
        assert!(unp_deep(&mut state, &packed, 2).is_err());
    }

    #[test]
    fn decrunch_track_deep_runs_lz_then_rle() {
        let mut enc_state = DmsState::new();
        let intermediate = [0x90u8, 0x03, 0x43];
        let tokens: Vec<DeepToken> = intermediate
            .iter()
            .map(|&b| DeepToken::Literal(b))
            .collect();
        let packed = deep_encode(&mut enc_state, &tokens);

        let mut state = DmsState::new();
        let out = decrunch_track(&mut state, DMSCOMP_DEEP, 0, &packed, 3, 3).unwrap();
        assert_eq!(out, vec![0x43; 3]);
    }

    // --- DEEP: container + `unar` oracle -----------------------------------

    const DEEP_TRACK_LEN: usize = 9 * 1024; // smallest valid track_sectors (9)

    /// Build one DEEP track header + payload from `raw`, which must contain
    /// no `0x90` bytes so the shared RLE stage is a no-op passthrough
    /// (`unp_rle` copies non-`0x90` bytes straight through) — sidesteps
    /// needing a real RLE compressor here, matching QUICK/MEDIUM's own
    /// container fixtures in `tests/dms_oracle.rs`.
    fn build_deep_track(state: &mut DmsState, track_number: i16, cflag: u8, raw: &[u8]) -> Vec<u8> {
        assert!(
            !raw.contains(&0x90),
            "fixture must avoid the RLE escape byte"
        );
        let tokens: Vec<DeepToken> = raw.iter().map(|&b| DeepToken::Literal(b)).collect();
        let packed = deep_encode(state, &tokens);
        let th = build_track_header_full(
            track_number,
            packed.len() as u16,
            raw.len() as u16,
            raw.len() as u16,
            cflag,
            DMSCOMP_DEEP,
            checksum_dms(raw),
        );
        let mut out = th.to_vec();
        out.extend_from_slice(&packed);
        out
    }

    #[test]
    fn deep_literal_roundtrip_through_container_and_unar() {
        let raw: Vec<u8> = (0..DEEP_TRACK_LEN).map(|i| (i % 137) as u8).collect();
        let mut enc_state = DmsState::new();
        let track = build_deep_track(&mut enc_state, 0, 0, &raw);

        let mut archive_bytes = build_header().to_vec();
        archive_bytes.extend_from_slice(&track);

        let archive = DmsArchive::open(&archive_bytes).unwrap();
        assert_eq!(archive.read_disk_image().unwrap(), raw);

        if newtua_testutil::unar_installed() {
            let outputs = newtua_testutil::unar_extract_all(&archive_bytes, "deep_lit.dms");
            assert_eq!(outputs.len(), 1, "unar produced {} outputs", outputs.len());
            assert_eq!(outputs.into_values().next().unwrap(), raw);
        } else {
            eprintln!("skipping unar cross-check: unar not installed");
        }
    }

    #[test]
    fn deep_match_path_roundtrip_through_container_and_unar() {
        // One literal, then length-60 self-referential matches (dist=0)
        // filling the rest of the track (9215 = 153*60 + 35, so the final
        // chunk is a valid length-35 match — no remainder below the
        // minimum match length of 3).
        let raw = vec![0x41u8; DEEP_TRACK_LEN];
        let mut tokens = vec![DeepToken::Literal(0x41)];
        let mut remaining = DEEP_TRACK_LEN - 1;
        while remaining > 0 {
            let len = remaining.min(60) as u16;
            assert!(
                len >= 3,
                "chunk length below the minimum encodable match length"
            );
            tokens.push(DeepToken::Match { len, dist: 0 });
            remaining -= len as usize;
        }
        let mut enc_state = DmsState::new();
        let packed = deep_encode(&mut enc_state, &tokens);
        let th = build_track_header_full(
            0,
            packed.len() as u16,
            raw.len() as u16,
            raw.len() as u16,
            0,
            DMSCOMP_DEEP,
            checksum_dms(&raw),
        );
        let mut archive_bytes = build_header().to_vec();
        archive_bytes.extend_from_slice(&th);
        archive_bytes.extend_from_slice(&packed);

        let archive = DmsArchive::open(&archive_bytes).unwrap();
        assert_eq!(archive.read_disk_image().unwrap(), raw);

        if newtua_testutil::unar_installed() {
            let outputs = newtua_testutil::unar_extract_all(&archive_bytes, "deep_match.dms");
            assert_eq!(outputs.len(), 1, "unar produced {} outputs", outputs.len());
            assert_eq!(outputs.into_values().next().unwrap(), raw);
        } else {
            eprintln!("skipping unar cross-check: unar not installed");
        }
    }

    /// Two DEEP tracks sharing one encoder-side tree: track 0 heavily biases
    /// several symbols (short adaptive codes result), track 1 is pure
    /// literals whose bits are only meaningful against that *adapted* tree —
    /// no window/match involved, isolating that it's the **tree state**
    /// (not just `Text`) that must carry across a `NOINIT` track boundary.
    fn build_deep_noinit_disk(cyl0_cflag: u8) -> (Vec<u8>, Vec<u8>) {
        let mut raw0 = vec![0x41u8; 4000];
        raw0.extend((0..DEEP_TRACK_LEN - 4000).map(|i| (i % 131) as u8));
        let raw1 = vec![0x41u8; DEEP_TRACK_LEN];

        let mut enc_state = DmsState::new();
        let track0 = build_deep_track(&mut enc_state, 0, cyl0_cflag, &raw0);
        // No `dms_init_data` call here when `cyl0_cflag` carries NOINIT — the
        // encoder must mirror whatever the real container does between
        // tracks, so the caller decides by passing `cyl0_cflag` through.
        let track1 = build_deep_track(&mut enc_state, 1, 0, &raw1);

        let mut archive_bytes = build_header().to_vec();
        archive_bytes.extend_from_slice(&track0);
        archive_bytes.extend_from_slice(&track1);

        let mut expected = raw0;
        expected.extend_from_slice(&raw1);
        (archive_bytes, expected)
    }

    #[test]
    fn deep_noinit_carries_adapted_tree_into_next_track() {
        let (archive_bytes, expected) = build_deep_noinit_disk(DMSCFLAG_NOINIT);
        let archive = DmsArchive::open(&archive_bytes).unwrap();
        assert_eq!(archive.read_disk_image().unwrap(), expected);

        if newtua_testutil::unar_installed() {
            let outputs = newtua_testutil::unar_extract_all(&archive_bytes, "deep_noinit.dms");
            assert_eq!(outputs.len(), 1, "unar produced {} outputs", outputs.len());
            assert_eq!(outputs.into_values().next().unwrap(), expected);
        } else {
            eprintln!("skipping unar cross-check: unar not installed");
        }
    }

    #[test]
    fn deep_without_noinit_the_carried_tree_is_gone_so_extraction_fails() {
        // Same encoded bytes, minus NOINIT on track 0: the real decoder now
        // rebuilds a fresh uniform tree between tracks (dms_init_data), so
        // track 1's bits — encoded assuming the *adapted* tree — decode to
        // the wrong symbols and fail the checksum check.
        let (archive_bytes, _expected) = build_deep_noinit_disk(0);
        let archive = DmsArchive::open(&archive_bytes).unwrap();
        assert!(archive.read_disk_image().is_err());
    }

    // --- HEAVY: canonical-code table builder + decode_c/decode_p ----------

    #[test]
    fn make_table_builds_a_complete_code_and_resolves_it_via_decode_c() {
        // 4-symbol alphabet, uniform length 2 (Kraft sum = 4 * 2^-2 = 1).
        // Canonical assignment in increasing symbol order gives symbol `c`
        // code `c` itself (2 bits, MSB-first) at this uniform length.
        let blen = [2u8, 2, 2, 2];
        let mut c_table = [0u16; 4096];
        let mut left = [0u16; 2 * DMSNC - 1];
        let mut right = [0u16; 2 * DMSNC - 1 + 9];
        make_table(4, &blen, 12, &mut c_table, &mut left, &mut right).unwrap();

        let mut state = DmsState::new();
        state.c_table = c_table;
        state.c_len[..4].copy_from_slice(&blen);
        state.left = left;
        state.right = right;
        for want in 0u16..4 {
            let mut w = newtua_testutil::BitWriterMsb::default();
            w.bits(u32::from(want), 2);
            let packed = w.finish();
            let mut reader = bit_reader(&packed);
            assert_eq!(decode_c(&mut state, &mut reader), want);
        }
    }

    #[test]
    fn make_table_reports_an_incomplete_code() {
        // Only one of four symbols gets a length; Kraft sum = 2^-2 != 1.
        let blen = [2u8, 0, 0, 0];
        let mut c_table = [0u16; 4096];
        let mut left = [0u16; 2 * DMSNC - 1];
        let mut right = [0u16; 2 * DMSNC - 1 + 9];
        assert!(make_table(4, &blen, 12, &mut c_table, &mut left, &mut right).is_err());
    }

    #[test]
    fn decode_c_walks_left_right_for_a_code_longer_than_the_direct_table() {
        let mut state = DmsState::new();
        // c_table[0] (the all-zero 12-bit prefix) points at internal node
        // DMSN1 — the first node index a real `make_table` build would ever
        // hand out — instead of a direct symbol; one more peeked bit picks
        // between its two leaves.
        state.c_table[0] = DMSN1 as u16;
        state.left[DMSN1] = 5;
        state.right[DMSN1] = 9;
        state.c_len[5] = 13; // 12 (table) + 1 (tree-walk step)
        state.c_len[9] = 13;

        let mut w = newtua_testutil::BitWriterMsb::default();
        w.bits(0, 12); // selects c_table[0] -> node DMSN1
        w.bit(false); // left child -> symbol 5
        let packed = w.finish();
        let mut reader = bit_reader(&packed);
        assert_eq!(decode_c(&mut state, &mut reader), 5);
    }

    #[test]
    fn decode_p_recency_slot_returns_previous_lastlen_unchanged() {
        let mut state = DmsState::new();
        state.np = 14;
        state.lastlen = 0x1234;
        // pt_table[0] (the all-zero 8-bit prefix) resolves directly to
        // symbol np-1 = 13, the recency slot.
        state.pt_table[0] = 13;
        state.pt_len[13] = 1;

        let mut w = newtua_testutil::BitWriterMsb::default();
        w.bits(0, 8);
        let packed = w.finish();
        let mut reader = bit_reader(&packed);
        assert_eq!(decode_p(&mut state, &mut reader), 0x1234);
        assert_eq!(
            state.lastlen, 0x1234,
            "the recency slot must not overwrite lastlen"
        );
    }

    #[test]
    fn decode_p_extra_bits_path_combines_slot_and_raw_bits() {
        // j=3 -> 2 extra bits. Byte 0b0_10_00000 = 0x40: the top bit
        // (consumed by pt_len[3]=1) selects pt_table[0x40]=3; the next 2
        // bits (extra=0b10=2) immediately follow in the same peeked byte.
        // dist = extra | (1 << (j-1)) = 2 | 4 = 6.
        let mut state = DmsState::new();
        state.np = 14;
        state.pt_table[0x40] = 3;
        state.pt_len[3] = 1;

        let mut w = newtua_testutil::BitWriterMsb::default();
        w.bits(0x40, 8);
        let packed = w.finish();
        let mut reader = bit_reader(&packed);
        assert_eq!(decode_p(&mut state, &mut reader), 6);
        assert_eq!(state.lastlen, 6);
    }

    #[test]
    fn read_tree_c_real_branch_builds_table_from_explicit_lengths() {
        let mut w = newtua_testutil::BitWriterMsb::default();
        w.bits(2, 9); // n = 2 explicit entries
        w.bits(1, 5); // c_len[0] = 1
        w.bits(1, 5); // c_len[1] = 1
        let packed = w.finish();
        let mut state = DmsState::new();
        let mut reader = bit_reader(&packed);
        read_tree_c(&mut state, &mut reader).unwrap();
        assert_eq!(state.c_len[0], 1);
        assert_eq!(state.c_len[1], 1);
        assert_eq!(state.c_len[2], 0);
    }

    #[test]
    fn read_tree_c_propagates_make_table_incomplete_code_error() {
        let mut w = newtua_testutil::BitWriterMsb::default();
        w.bits(1, 9); // n = 1: only symbol 0 gets an explicit length
        w.bits(1, 5); // c_len[0] = 1 -> Kraft sum 0.5, incomplete
        let packed = w.finish();
        let mut state = DmsState::new();
        let mut reader = bit_reader(&packed);
        assert!(read_tree_c(&mut state, &mut reader).is_err());
    }

    #[test]
    fn read_tree_c_degenerate_branch_fills_table_with_one_constant_symbol() {
        let mut w = newtua_testutil::BitWriterMsb::default();
        w.bits(0, 9); // n = 0 -> degenerate: a single symbol, everywhere
        w.bits(42, 9); // the constant symbol id
        let packed = w.finish();
        let mut state = DmsState::new();
        let mut reader = bit_reader(&packed);
        read_tree_c(&mut state, &mut reader).unwrap();
        assert!(state.c_table.iter().all(|&s| s == 42));
        assert!(state.c_len.iter().all(|&l| l == 0));
    }

    #[test]
    fn read_tree_p_degenerate_branch_fills_table_with_one_constant_symbol() {
        let mut w = newtua_testutil::BitWriterMsb::default();
        w.bits(0, 5); // n = 0 -> degenerate
        w.bits(7, 5); // the constant symbol id
        let packed = w.finish();
        let mut state = DmsState::new();
        state.np = 14;
        let mut reader = bit_reader(&packed);
        read_tree_p(&mut state, &mut reader).unwrap();
        assert!(state.pt_table.iter().all(|&s| s == 7));
        assert!(state.pt_len[..14].iter().all(|&l| l == 0));
    }

    #[test]
    fn dms_init_data_never_touches_heavy_fields() {
        let mut state = DmsState::new();
        state.rtv_heavy = 1234;
        state.np = 15;
        state.lastlen = 42;
        state.c_table[0] = 99;
        state.c_len[0] = 7;
        state.pt_table[0] = 3;
        state.pt_len[0] = 2;
        state.left[0] = 11;
        state.right[0] = 22;

        dms_init_data(&mut state);

        assert_eq!(state.rtv_heavy, 1234);
        assert_eq!(state.np, 15);
        assert_eq!(state.lastlen, 42);
        assert_eq!(state.c_table[0], 99);
        assert_eq!(state.c_len[0], 7);
        assert_eq!(state.pt_table[0], 3);
        assert_eq!(state.pt_len[0], 2);
        assert_eq!(state.left[0], 11);
        assert_eq!(state.right[0], 22);
    }

    #[test]
    fn unp_heavy_empty_track_decodes_to_empty_output() {
        let mut state = DmsState::new();
        let out = unp_heavy(&mut state, &[], 0, 0).unwrap();
        assert_eq!(out, Vec::<u8>::new());
    }

    #[test]
    fn unp_heavy_short_input_is_padded_with_zero_bits_not_a_panic() {
        // No DMSCFLAG_HEAVY_C: reuses the freshly allocated (all-zero)
        // tables, so every decode resolves to literal symbol 0 with a
        // zero-length code. Must not panic even with zero packed bytes.
        let mut state = DmsState::new();
        let out = unp_heavy(&mut state, &[], 5, 0);
        assert!(out.is_ok());
    }

    #[test]
    fn unp_heavy_match_overrunning_rtsize_is_an_error() {
        let mut state = DmsState::new();
        // c_table[0] resolves straight to match-length symbol 256 (length
        // 3); c_len/pt_table/pt_len all default to 0, resolving a zero
        // distance the same way — no headers needed for this fixture.
        state.c_table[0] = 256;
        let out = unp_heavy(&mut state, &[], 2, 0); // rtsize=2, match wants 3
        assert!(out.is_err());
    }

    #[test]
    fn balanced_lengths_satisfies_the_kraft_equality() {
        for n in [2usize, 3, 14, 15, 256, 257, 510] {
            let lens = balanced_lengths(n);
            assert_eq!(lens.len(), n);
            let kraft: f64 = lens.iter().map(|&l| 2f64.powi(-i32::from(l))).sum();
            assert!((kraft - 1.0).abs() < 1e-9, "n={n} kraft={kraft}");
        }
    }

    // --- HEAVY: mirror encoder ---------------------------------------------
    //
    // HEAVY's codes are canonical: `make_table` assigns them in increasing
    // (length, symbol) order, so a test encoder must reproduce that exact
    // assignment rather than invent its own. Rather than duplicate the
    // algorithm, this shares `make_table` with the decoder (same pattern as
    // 18c's DEEP mirror encoder sharing `update_tree`/`reconst_tree`) and
    // recovers each symbol's resulting code by reverse-scanning the table
    // `make_table` built — the inverse of `decode_c`/`decode_p`'s
    // `table[peek(tablebits)]` lookup.

    /// Assign prefix-code lengths satisfying the Kraft equality for `n`
    /// symbols with no frequency information: `2^l - n` symbols get length
    /// `l - 1`, the rest get length `l`, where `l = ceil(log2(n))` — the
    /// standard "balanced" complete-code construction. A real Huffman build
    /// from frequencies isn't needed here since `make_table` only cares
    /// that the lengths it's given are Kraft-complete, not where they came
    /// from.
    fn balanced_lengths(n: usize) -> Vec<u8> {
        assert!(n >= 2, "need at least 2 symbols for a prefix code");
        let l = (usize::BITS - (n - 1).leading_zeros()) as u8; // ceil(log2(n))
        let short_count = (1usize << l) - n;
        let mut lens = vec![l; n];
        for len in lens.iter_mut().take(short_count) {
            *len = l - 1;
        }
        lens
    }

    /// The canonical code occupying table `slot` for a `len`-bit code in a
    /// `tablebits`-wide table: `make_table` fills a contiguous run of slots
    /// per code, so the code is the slot index with the padding low bits
    /// (`tablebits - len` of them) shifted off.
    fn slot_to_code(slot: usize, len: u8, tablebits: u8) -> u32 {
        u32::try_from(slot).unwrap() >> (tablebits - len)
    }

    /// Recover the canonical code `make_table` assigned to `sym` by
    /// scanning `table` for the (leftmost) slot it occupies. Only valid for
    /// codes that fit directly in the table (`len <= tablebits`) — true for
    /// every alphabet this module's fixtures use.
    fn code_for_symbol(table: &[u16], len: &[u8], sym: u16, tablebits: u8) -> (u32, u8) {
        let l = len[sym as usize];
        let idx = table
            .iter()
            .position(|&s| s == sym)
            .unwrap_or_else(|| panic!("HEAVY test encoder: symbol {sym} not in the table"));
        (slot_to_code(idx, l, tablebits), l)
    }

    #[derive(Clone, Copy)]
    enum HeavyToken {
        Literal(u8),
        Match { len: u16, dist: u16 },
    }

    /// The union of symbols `tokens` needs: every literal byte (0..256,
    /// unconditionally — simpler than tracking which bytes a fixture
    /// actually uses, and cheap since the alphabet is tiny) plus each
    /// distinct match-length symbol a `Match` token references.
    fn heavy_used_symbols(tokens: &[HeavyToken]) -> Vec<u16> {
        let mut syms: Vec<u16> = (0u16..256).collect();
        for tok in tokens {
            if let HeavyToken::Match { len, .. } = *tok {
                let sym = DMSOFFSET + len;
                if !syms.contains(&sym) {
                    syms.push(sym);
                }
            }
        }
        syms.sort_unstable();
        syms
    }

    /// A built pair of canonical-code tables plus a precomputed
    /// symbol-to-code reverse lookup for the c-alphabet (built once instead
    /// of rescanning `c_table` per literal — fixtures encode thousands of
    /// literals).
    struct HeavyTables {
        c_len: [u8; DMSNC],
        c_codes: Vec<(u32, u8)>,
        pt_table: [u16; 256],
        pt_len: [u8; DMSNPT],
        np: u16,
    }

    fn build_heavy_tables(np: u16, tokens: &[HeavyToken]) -> HeavyTables {
        let symbols = heavy_used_symbols(tokens);
        let sym_lens = balanced_lengths(symbols.len());
        let mut c_len = [0u8; DMSNC];
        for (&sym, &l) in symbols.iter().zip(&sym_lens) {
            c_len[sym as usize] = l;
        }
        let mut pt_len = [0u8; DMSNPT];
        pt_len[..np as usize].copy_from_slice(&balanced_lengths(np as usize));

        let mut c_table = [0u16; 4096];
        let mut pt_table = [0u16; 256];
        let mut left = [0u16; 2 * DMSNC - 1];
        let mut right = [0u16; 2 * DMSNC - 1 + 9];
        make_table(
            DMSNC as u16,
            &c_len,
            12,
            &mut c_table,
            &mut left,
            &mut right,
        )
        .unwrap();
        make_table(np, &pt_len, 8, &mut pt_table, &mut left, &mut right).unwrap();

        let mut c_codes = vec![(0u32, 0u8); DMSNC];
        for (idx, &sym) in c_table.iter().enumerate() {
            let l = c_len[sym as usize];
            if l > 0 && c_codes[sym as usize].1 == 0 {
                c_codes[sym as usize] = (slot_to_code(idx, l, 12), l);
            }
        }

        HeavyTables {
            c_len,
            c_codes,
            pt_table,
            pt_len,
            np,
        }
    }

    fn write_c_tree_header(writer: &mut newtua_testutil::BitWriterMsb, c_len: &[u8; DMSNC]) {
        let n = c_len.iter().rposition(|&l| l != 0).map_or(0, |i| i + 1);
        writer.bits(n as u32, 9);
        for &l in &c_len[..n] {
            writer.bits(u32::from(l), 5);
        }
    }

    fn write_pt_tree_header(writer: &mut newtua_testutil::BitWriterMsb, pt_len: &[u8], np: usize) {
        writer.bits(np as u32, 5);
        for &l in &pt_len[..np] {
            writer.bits(u32::from(l), 4);
        }
    }

    fn encode_heavy_headers(writer: &mut newtua_testutil::BitWriterMsb, t: &HeavyTables) {
        write_c_tree_header(writer, &t.c_len);
        write_pt_tree_header(writer, &t.pt_len, t.np as usize);
    }

    /// Inverse of [`decode_p`]'s non-recency path: `j` is the position slot
    /// whose implied range `[1 << (j-1), 1 << j)` contains `dist` (or `0`
    /// for `dist == 0`), then `j - 1` raw extra bits carry `dist`'s low
    /// bits. The recency slot (`np - 1`) has no inverse (it reuses whatever
    /// distance was last decoded), so this helper doesn't produce it —
    /// every fixture in this module only ever encodes fresh distances.
    fn encode_p(
        writer: &mut newtua_testutil::BitWriterMsb,
        pt_table: &[u16],
        pt_len: &[u8],
        np: u16,
        dist: u16,
    ) {
        let j: u16 = if dist == 0 {
            0
        } else {
            (16 - dist.leading_zeros()) as u16
        };
        assert!(
            j < np - 1,
            "HEAVY test encoder: distance {dist} needs the recency slot (unsupported)"
        );
        let (code, len) = code_for_symbol(pt_table, pt_len, j, 8);
        writer.bits(code, u32::from(len));
        if j > 0 {
            let extra_bits = j - 1;
            let extra = dist - (1 << (j - 1));
            writer.bits(u32::from(extra), u32::from(extra_bits));
        }
    }

    fn encode_heavy_tokens(
        writer: &mut newtua_testutil::BitWriterMsb,
        t: &HeavyTables,
        tokens: &[HeavyToken],
    ) {
        for tok in tokens {
            match *tok {
                HeavyToken::Literal(b) => {
                    let (code, len) = t.c_codes[b as usize];
                    writer.bits(code, u32::from(len));
                }
                HeavyToken::Match { len: mlen, dist } => {
                    let sym = DMSOFFSET + mlen;
                    let (code, len) = t.c_codes[sym as usize];
                    writer.bits(code, u32::from(len));
                    encode_p(writer, &t.pt_table, &t.pt_len, t.np, dist);
                }
            }
        }
    }

    #[test]
    fn encode_p_and_decode_p_round_trip_several_distances() {
        let t = build_heavy_tables(14, &[]);
        for &dist in &[0u16, 1, 3, 7, 100, 2049, 4095] {
            let mut writer = newtua_testutil::BitWriterMsb::default();
            encode_p(&mut writer, &t.pt_table, &t.pt_len, t.np, dist);
            let packed = writer.finish();
            let mut state = DmsState::new();
            state.np = t.np;
            state.pt_table = t.pt_table;
            state.pt_len = t.pt_len;
            let mut reader = bit_reader(&packed);
            assert_eq!(decode_p(&mut state, &mut reader), dist, "dist={dist:#06x}");
        }
    }

    #[test]
    fn heavy_decodes_an_all_literal_stream_via_shared_encoder() {
        let tokens: Vec<HeavyToken> = [0x11u8, 0x22, 0x33, 0xAA]
            .iter()
            .map(|&b| HeavyToken::Literal(b))
            .collect();
        let t = build_heavy_tables(14, &tokens);
        let mut writer = newtua_testutil::BitWriterMsb::default();
        encode_heavy_headers(&mut writer, &t);
        encode_heavy_tokens(&mut writer, &t, &tokens);
        let packed = writer.finish();

        let mut state = DmsState::new();
        let out = unp_heavy(&mut state, &packed, 4, DMSCFLAG_HEAVY_C).unwrap();
        assert_eq!(out, vec![0x11, 0x22, 0x33, 0xAA]);
    }

    #[test]
    fn heavy_match_path_round_trips_via_shared_encoder() {
        let tokens = [
            HeavyToken::Literal(0x7A),
            HeavyToken::Match { len: 3, dist: 0 },
        ];
        let t = build_heavy_tables(14, &tokens);
        let mut writer = newtua_testutil::BitWriterMsb::default();
        encode_heavy_headers(&mut writer, &t);
        encode_heavy_tokens(&mut writer, &t, &tokens);
        let packed = writer.finish();

        let mut state = DmsState::new();
        let out = unp_heavy(&mut state, &packed, 4, DMSCFLAG_HEAVY_C).unwrap();
        assert_eq!(out, vec![0x7A, 0x7A, 0x7A, 0x7A]);
    }

    #[test]
    fn unp_heavy_clears_did_init_at_decode_start() {
        let tokens = [HeavyToken::Literal(9)];
        let t = build_heavy_tables(14, &tokens);
        let mut writer = newtua_testutil::BitWriterMsb::default();
        encode_heavy_headers(&mut writer, &t);
        encode_heavy_tokens(&mut writer, &t, &tokens);
        let packed = writer.finish();

        let mut state = DmsState::new();
        state.did_init = true;
        unp_heavy(&mut state, &packed, 1, DMSCFLAG_HEAVY_C).unwrap();
        assert!(!state.did_init, "HEAVY must clear DidInit at decode start");
    }

    #[test]
    fn unp_heavy_selects_np_by_heavy2_flag() {
        let tokens = [HeavyToken::Literal(1)];
        let t1 = build_heavy_tables(14, &tokens);
        let mut w1 = newtua_testutil::BitWriterMsb::default();
        encode_heavy_headers(&mut w1, &t1);
        encode_heavy_tokens(&mut w1, &t1, &tokens);
        let mut state1 = DmsState::new();
        unp_heavy(&mut state1, &w1.finish(), 1, DMSCFLAG_HEAVY_C).unwrap();
        assert_eq!(state1.np, 14, "HEAVY1 (no DMSCFLAG_HEAVY2) uses np=14");

        let t2 = build_heavy_tables(15, &tokens);
        let mut w2 = newtua_testutil::BitWriterMsb::default();
        encode_heavy_headers(&mut w2, &t2);
        encode_heavy_tokens(&mut w2, &t2, &tokens);
        let mut state2 = DmsState::new();
        unp_heavy(
            &mut state2,
            &w2.finish(),
            1,
            DMSCFLAG_HEAVY_C | DMSCFLAG_HEAVY2,
        )
        .unwrap();
        assert_eq!(state2.np, 15, "HEAVY2 uses np=15");
    }

    #[test]
    fn decrunch_track_heavy_runs_rle_only_when_heavyrle_flag_set() {
        // Intermediate HEAVY output [0x90, 0x03, 0x41]: with HEAVYRLE set
        // this expands to three 0x41s via the shared RLE stage; without it,
        // HEAVY's own output is the final track content, unchanged.
        let intermediate = [0x90u8, 0x03, 0x41];
        let tokens: Vec<HeavyToken> = intermediate
            .iter()
            .map(|&b| HeavyToken::Literal(b))
            .collect();
        let t = build_heavy_tables(14, &tokens);
        let mut writer = newtua_testutil::BitWriterMsb::default();
        encode_heavy_headers(&mut writer, &t);
        encode_heavy_tokens(&mut writer, &t, &tokens);
        let packed = writer.finish();

        let mut state = DmsState::new();
        let with_rle = decrunch_track(
            &mut state,
            DMSCOMP_HEAVY1,
            DMSCFLAG_HEAVY_C | DMSCFLAG_HEAVYRLE,
            &packed,
            3,
            3,
        )
        .unwrap();
        assert_eq!(with_rle, vec![0x41; 3]);

        let mut state2 = DmsState::new();
        let without_rle =
            decrunch_track(&mut state2, DMSCOMP_HEAVY1, DMSCFLAG_HEAVY_C, &packed, 3, 3).unwrap();
        assert_eq!(without_rle, intermediate.to_vec());
    }

    // --- HEAVY: container + `unar` oracle -----------------------------------

    const HEAVY_TRACK_LEN: usize = 9 * 1024; // smallest valid track_sectors (9)

    fn build_heavy_track_with_headers(
        track_number: i16,
        cflag_extra: u8,
        heavy2: bool,
        raw: &[u8],
        tokens: &[HeavyToken],
        t: &HeavyTables,
    ) -> Vec<u8> {
        let mut writer = newtua_testutil::BitWriterMsb::default();
        encode_heavy_headers(&mut writer, t);
        encode_heavy_tokens(&mut writer, t, tokens);
        let packed = writer.finish();
        let method = if heavy2 {
            DMSCOMP_HEAVY2
        } else {
            DMSCOMP_HEAVY1
        };
        let th = build_track_header_full(
            track_number,
            packed.len() as u16,
            raw.len() as u16,
            raw.len() as u16,
            cflag_extra | DMSCFLAG_HEAVY_C,
            method,
            checksum_dms(raw),
        );
        let mut out = th.to_vec();
        out.extend_from_slice(&packed);
        out
    }

    /// Like [`build_heavy_track_with_headers`], but omits the tree headers
    /// entirely (no `DMSCFLAG_HEAVY_C`) — the decoder must reuse whatever
    /// tables an earlier track left in `DmsState`, which must be `t` here
    /// too for the produced bits to mean anything.
    fn build_heavy_track_reusing_tables(
        track_number: i16,
        cflag_extra: u8,
        heavy2: bool,
        raw: &[u8],
        tokens: &[HeavyToken],
        t: &HeavyTables,
    ) -> Vec<u8> {
        let mut writer = newtua_testutil::BitWriterMsb::default();
        encode_heavy_tokens(&mut writer, t, tokens);
        let packed = writer.finish();
        let method = if heavy2 {
            DMSCOMP_HEAVY2
        } else {
            DMSCOMP_HEAVY1
        };
        let th = build_track_header_full(
            track_number,
            packed.len() as u16,
            raw.len() as u16,
            raw.len() as u16,
            cflag_extra,
            method,
            checksum_dms(raw),
        );
        let mut out = th.to_vec();
        out.extend_from_slice(&packed);
        out
    }

    #[test]
    fn heavy1_literal_roundtrip_through_container_and_unar() {
        let raw: Vec<u8> = (0..HEAVY_TRACK_LEN).map(|i| (i % 251) as u8).collect();
        let tokens: Vec<HeavyToken> = raw.iter().map(|&b| HeavyToken::Literal(b)).collect();
        let t = build_heavy_tables(14, &tokens);
        let track = build_heavy_track_with_headers(0, 0, false, &raw, &tokens, &t);

        let mut archive_bytes = build_header().to_vec();
        archive_bytes.extend_from_slice(&track);

        let archive = DmsArchive::open(&archive_bytes).unwrap();
        assert_eq!(archive.read_disk_image().unwrap(), raw);

        if newtua_testutil::unar_installed() {
            let outputs = newtua_testutil::unar_extract_all(&archive_bytes, "heavy1_lit.dms");
            assert_eq!(outputs.len(), 1, "unar produced {} outputs", outputs.len());
            assert_eq!(outputs.into_values().next().unwrap(), raw);
        } else {
            eprintln!("skipping unar cross-check: unar not installed");
        }
    }

    #[test]
    fn heavy2_literal_roundtrip_through_container_and_unar() {
        let raw: Vec<u8> = (0..HEAVY_TRACK_LEN).map(|i| (i % 199) as u8).collect();
        let tokens: Vec<HeavyToken> = raw.iter().map(|&b| HeavyToken::Literal(b)).collect();
        let t = build_heavy_tables(15, &tokens);
        let track = build_heavy_track_with_headers(0, 0, true, &raw, &tokens, &t);

        let mut archive_bytes = build_header().to_vec();
        archive_bytes.extend_from_slice(&track);

        let archive = DmsArchive::open(&archive_bytes).unwrap();
        assert_eq!(archive.read_disk_image().unwrap(), raw);

        if newtua_testutil::unar_installed() {
            let outputs = newtua_testutil::unar_extract_all(&archive_bytes, "heavy2_lit.dms");
            assert_eq!(outputs.len(), 1, "unar produced {} outputs", outputs.len());
            assert_eq!(outputs.into_values().next().unwrap(), raw);
        } else {
            eprintln!("skipping unar cross-check: unar not installed");
        }
    }

    #[test]
    fn heavy_match_path_roundtrip_through_container_and_unar() {
        // One literal, then length up-to-256 self-referential matches
        // (dist=0) filling the rest of the track.
        let raw = vec![0x41u8; HEAVY_TRACK_LEN];
        let mut tokens = vec![HeavyToken::Literal(0x41)];
        let mut remaining = HEAVY_TRACK_LEN - 1;
        while remaining > 0 {
            let len = remaining.min(256) as u16;
            assert!(
                len >= 3,
                "chunk length below the minimum encodable match length"
            );
            tokens.push(HeavyToken::Match { len, dist: 0 });
            remaining -= len as usize;
        }
        let t = build_heavy_tables(14, &tokens);
        let track = build_heavy_track_with_headers(0, 0, false, &raw, &tokens, &t);

        let mut archive_bytes = build_header().to_vec();
        archive_bytes.extend_from_slice(&track);

        let archive = DmsArchive::open(&archive_bytes).unwrap();
        assert_eq!(archive.read_disk_image().unwrap(), raw);

        if newtua_testutil::unar_installed() {
            let outputs = newtua_testutil::unar_extract_all(&archive_bytes, "heavy_match.dms");
            assert_eq!(outputs.len(), 1, "unar produced {} outputs", outputs.len());
            assert_eq!(outputs.into_values().next().unwrap(), raw);
        } else {
            eprintln!("skipping unar cross-check: unar not installed");
        }
    }

    /// Two HEAVY1 tracks sharing one encoder-side table build: track 0 is
    /// pure literals (defines the tables, `DMSCFLAG_HEAVY_C` set), track 1
    /// opens with a zero-distance match (proving `rtv_heavy`/window carry)
    /// and *omits* `DMSCFLAG_HEAVY_C` (proving table carry), filling the
    /// rest with more literals reusing the same inherited table.
    fn build_heavy_noinit_disk(cyl0_extra_cflag: u8) -> (Vec<u8>, Vec<u8>) {
        let raw0 = vec![0x41u8; HEAVY_TRACK_LEN];
        let raw1 = vec![0x41u8; HEAVY_TRACK_LEN];

        let tokens0: Vec<HeavyToken> = vec![HeavyToken::Literal(0x41); HEAVY_TRACK_LEN];
        let mut tokens1 = vec![HeavyToken::Match { len: 3, dist: 0 }];
        tokens1.extend(std::iter::repeat(HeavyToken::Literal(0x41)).take(HEAVY_TRACK_LEN - 3));

        let t = build_heavy_tables(14, &tokens1); // covers tokens0's alphabet too (full 0..256)
        let track0 =
            build_heavy_track_with_headers(0, cyl0_extra_cflag, false, &raw0, &tokens0, &t);
        let track1 = build_heavy_track_reusing_tables(1, 0, false, &raw1, &tokens1, &t);

        let mut archive_bytes = build_header().to_vec();
        archive_bytes.extend_from_slice(&track0);
        archive_bytes.extend_from_slice(&track1);

        let mut expected = raw0;
        expected.extend_from_slice(&raw1);
        (archive_bytes, expected)
    }

    #[test]
    fn heavy_noinit_carries_tables_and_window_into_next_track() {
        let (archive_bytes, expected) = build_heavy_noinit_disk(DMSCFLAG_NOINIT);
        let archive = DmsArchive::open(&archive_bytes).unwrap();
        assert_eq!(archive.read_disk_image().unwrap(), expected);

        if newtua_testutil::unar_installed() {
            let outputs = newtua_testutil::unar_extract_all(&archive_bytes, "heavy_noinit.dms");
            assert_eq!(outputs.len(), 1, "unar produced {} outputs", outputs.len());
            assert_eq!(outputs.into_values().next().unwrap(), expected);
        } else {
            eprintln!("skipping unar cross-check: unar not installed");
        }
    }

    #[test]
    fn heavy_without_noinit_the_carried_window_is_gone_so_extraction_fails() {
        // Same encoded bytes, minus NOINIT on track 0: dms_init_data now
        // zeroes the shared window between tracks (HEAVY's tables persist
        // regardless — dms_init_data never touches them either way), so
        // track 1's zero-distance match copies stale zero bytes instead of
        // 0x41, failing the checksum check.
        let (archive_bytes, _expected) = build_heavy_noinit_disk(0);
        let archive = DmsArchive::open(&archive_bytes).unwrap();
        assert!(archive.read_disk_image().is_err());
    }
}
