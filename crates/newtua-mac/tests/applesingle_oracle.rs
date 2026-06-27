//! End-to-end oracle for the AppleSingle / AppleDouble container.
//!
//! Fixtures are built by a mirror encoder (the inverse of our parser): a header,
//! an entry count, the 12-byte descriptors, then the section bodies. The
//! mirror-only assertions pin our encoder/decoder pair (both big- and
//! little-endian) and run everywhere.
//!
//! There is no system encoder for AppleSingle, so — as for BinHex — the second
//! oracle is `unar`: it decodes our fixture and must yield the same fork bytes.
//! The data fork lands as the output file (named after the AppleSingle "real
//! name" section); the resource fork is read back from the macOS named fork
//! (`<file>/..namedfork/rsrc`). Skipped when `unar` is absent.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use newtua_mac::applesingle::{AppleFormat, AppleSingleArchive};
use newtua_testutil::unar_installed;

// --- mirror encoder -----------------------------------------------------------

const AS_BE: u32 = 0x0005_1600;
const AS_LE: u32 = 0x0016_0500;
const VER_BE: u32 = 0x0002_0000;
const VER_LE: u32 = 0x0000_0200;

fn w16(v: u16, be: bool) -> [u8; 2] {
    if be {
        v.to_be_bytes()
    } else {
        v.to_le_bytes()
    }
}
fn w32(v: u32, be: bool) -> [u8; 4] {
    if be {
        v.to_be_bytes()
    } else {
        v.to_le_bytes()
    }
}

fn finder_info(ftype: &[u8; 4], creator: &[u8; 4], flags: u16) -> Vec<u8> {
    let mut v = vec![0u8; 32];
    v[0..4].copy_from_slice(ftype);
    v[4..8].copy_from_slice(creator);
    v[8..10].copy_from_slice(&flags.to_be_bytes());
    v
}

/// Assemble an AppleSingle/AppleDouble file from `(id, section bytes)` pairs.
fn build(magic: u32, version: u32, be: bool, sections: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let n = sections.len();
    let table = 24 + 2 + 12 * n;
    let mut out = vec![0u8; table];
    out[0..4].copy_from_slice(&magic.to_be_bytes());
    out[4..8].copy_from_slice(&version.to_be_bytes());
    out[24..26].copy_from_slice(&w16(n as u16, be));

    let mut off = table;
    let mut body = Vec::new();
    for (i, (id, sec)) in sections.iter().enumerate() {
        let d = 26 + i * 12;
        out[d..d + 4].copy_from_slice(&w32(*id, be));
        out[d + 4..d + 8].copy_from_slice(&w32(off as u32, be));
        out[d + 8..d + 12].copy_from_slice(&w32(sec.len() as u32, be));
        body.extend_from_slice(sec);
        off += sec.len();
    }
    out.extend_from_slice(&body);
    out
}

fn our_fork(file: &[u8], idx: usize) -> Vec<u8> {
    let arc = AppleSingleArchive::open(file).unwrap();
    let mut out = Vec::new();
    arc.read_entry(idx, &mut out).unwrap();
    out
}

const DATA: &[u8] = b"AppleSingle data fork: the quick brown fox.";
const RSRC: &[u8] = b"AppleSingle resource fork: icon + version.";

// --- mirror-only assertions (always run) --------------------------------------

#[test]
fn mirror_roundtrip_big_endian() {
    let f = build(
        AS_BE,
        VER_BE,
        true,
        &[
            (3, b"myfile.txt".to_vec()),
            (1, DATA.to_vec()),
            (2, RSRC.to_vec()),
            (9, finder_info(b"TEXT", b"ttxt", 0x2080)),
        ],
    );
    assert!(AppleSingleArchive::recognize(&f));
    let arc = AppleSingleArchive::open(&f[..]).unwrap();
    assert_eq!(arc.format(), AppleFormat::Single);
    assert_eq!(arc.entries()[0].name(), b"myfile.txt");
    assert_eq!(&arc.entries()[0].file_type(), b"TEXT");
    assert_eq!(arc.entries()[0].finder_flags(), 0x2080);
    assert_eq!(our_fork(&f, 0), DATA);
    assert_eq!(our_fork(&f, 1), RSRC);
}

#[test]
fn mirror_roundtrip_little_endian() {
    let f = build(
        AS_LE,
        VER_LE,
        false,
        &[(1, DATA.to_vec()), (2, RSRC.to_vec())],
    );
    assert_eq!(our_fork(&f, 0), DATA);
    assert_eq!(our_fork(&f, 1), RSRC);
}

// --- unar oracle (gated) ------------------------------------------------------

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("newtua_as_{}_{}_{}", std::process::id(), n, tag));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run `unar` on `file` and return (data fork, resource fork). `name` is the
/// AppleSingle real-name section, which `unar` uses for the output file.
fn unar_forks(file: &[u8], name: &str, tag: &str) -> (Vec<u8>, Vec<u8>) {
    let dir = temp_dir(tag);
    let archive = dir.join(format!("{tag}.as"));
    fs::write(&archive, file).unwrap();

    let status = Command::new("unar")
        .args(["-quiet", "-force-overwrite", "-no-directory"])
        .arg("-output-directory")
        .arg(&dir)
        .arg(&archive)
        .status()
        .expect("run unar");
    assert!(status.success(), "unar failed for {tag}");

    let out = dir.join(name);
    let data = fs::read(&out).unwrap();
    let rsrc = fs::read(out.join("..namedfork/rsrc")).unwrap_or_default();

    let _ = fs::remove_dir_all(&dir);
    (data, rsrc)
}

#[test]
fn unar_matches_both_forks() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let f = build(
        AS_BE,
        VER_BE,
        true,
        &[
            (3, b"myfile.txt".to_vec()),
            (1, DATA.to_vec()),
            (2, RSRC.to_vec()),
            (9, finder_info(b"TEXT", b"ttxt", 0)),
        ],
    );
    let (data, rsrc) = unar_forks(&f, "myfile.txt", "both");
    assert_eq!(data, DATA, "unar data fork mismatch");
    assert_eq!(rsrc, RSRC, "unar resource fork mismatch");
}
