//! End-to-end oracle for the MacBinary container.
//!
//! Fixtures are built by a mirror encoder (the inverse of our parser): a valid
//! 128-byte header with the correct CCITT header CRC, followed by the data and
//! resource forks each padded to a 128-byte block. The mirror-only assertions
//! pin our encoder/decoder pair and run everywhere.
//!
//! Two independent oracles cross-check our reading of the real format:
//!   * `unar` — decodes our fixtures and must yield the same fork bytes. The
//!     data fork lands as the output file; the resource fork is read back from
//!     the macOS named fork (`<file>/..namedfork/rsrc`). Skipped when `unar` is
//!     absent.
//!   * Apple's `/usr/bin/macbinary` — a third-party *encoder*. It produces a
//!     real MacBinary III file from a data fork that our crate must recognise
//!     and decode back unchanged. Skipped when the tool is absent.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use newtua_common::crc16::crc16_ccitt;
use newtua_mac::macbinary::MacBinaryArchive;
use newtua_testutil::unar_installed;

// --- mirror encoder -----------------------------------------------------------

fn block(x: u32) -> usize {
    ((x as u64 + 127) & !127) as usize
}

/// Build a complete MacBinary III file (header with `mBIN` signature and a valid
/// CRC, then the padded forks).
fn build_macbinary(
    name: &[u8],
    ftype: &[u8; 4],
    creator: &[u8; 4],
    data: &[u8],
    rsrc: &[u8],
) -> Vec<u8> {
    let mut h = vec![0u8; 128];
    h[1] = name.len() as u8;
    h[2..2 + name.len()].copy_from_slice(name);
    h[65..69].copy_from_slice(ftype);
    h[69..73].copy_from_slice(creator);
    h[83..87].copy_from_slice(&(data.len() as u32).to_be_bytes());
    h[87..91].copy_from_slice(&(rsrc.len() as u32).to_be_bytes());
    h[91..95].copy_from_slice(&1u32.to_be_bytes()); // creation date
    h[95..99].copy_from_slice(&1u32.to_be_bytes()); // modification date
    h[102..106].copy_from_slice(b"mBIN");
    let crc = crc16_ccitt(&h[0..124]);
    h[124..126].copy_from_slice(&crc.to_be_bytes());

    let mut f = h;
    f.extend_from_slice(data);
    f.resize(128 + block(data.len() as u32), 0);
    f.extend_from_slice(rsrc);
    f.resize(128 + block(data.len() as u32) + block(rsrc.len() as u32), 0);
    f
}

fn our_fork(file: &[u8], idx: usize) -> Vec<u8> {
    let arc = MacBinaryArchive::open(file).unwrap();
    let mut out = Vec::new();
    arc.read_entry(idx, &mut out).unwrap();
    out
}

// --- mirror-only assertions (always run) --------------------------------------

const DATA: &[u8] = b"The quick brown fox jumps over the lazy dog. 0123456789";
const RSRC: &[u8] = b"resource fork: icon + version + finder bits";

#[test]
fn mirror_roundtrip_both_forks() {
    let f = build_macbinary(b"mbfile.bin", b"TEXT", b"ttxt", DATA, RSRC);
    assert!(MacBinaryArchive::recognize(&f));
    let arc = MacBinaryArchive::open(&f[..]).unwrap();
    assert_eq!(arc.version(), 3);
    assert_eq!(our_fork(&f, 0), DATA);
    assert_eq!(our_fork(&f, 1), RSRC);
}

#[test]
fn mirror_roundtrip_data_only() {
    let f = build_macbinary(b"data.only", b"BINA", b"____", DATA, b"");
    let arc = MacBinaryArchive::open(&f[..]).unwrap();
    assert_eq!(arc.entries().len(), 1);
    assert_eq!(our_fork(&f, 0), DATA);
}

// --- unar oracle (gated) ------------------------------------------------------

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("newtua_mb_{}_{}_{}", std::process::id(), n, tag));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run `unar` on `file` and return (data fork, resource fork), the latter from
/// the macOS named fork. `name` is the internal MacBinary filename.
fn unar_forks(file: &[u8], name: &str, tag: &str) -> (Vec<u8>, Vec<u8>) {
    let dir = temp_dir(tag);
    let archive = dir.join(format!("{tag}.bin"));
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
    let f = build_macbinary(b"myfile.dat", b"TEXT", b"ttxt", DATA, RSRC);
    let (data, rsrc) = unar_forks(&f, "myfile.dat", "both");
    assert_eq!(data, DATA, "unar data fork mismatch");
    assert_eq!(rsrc, RSRC, "unar resource fork mismatch");
}

#[test]
fn unar_matches_data_only() {
    if !unar_installed() {
        eprintln!("skipping: unar not installed");
        return;
    }
    let f = build_macbinary(b"plain.txt", b"TEXT", b"ttxt", DATA, b"");
    let (data, _rsrc) = unar_forks(&f, "plain.txt", "dataonly");
    assert_eq!(data, DATA, "unar data fork mismatch");
}

// --- Apple macbinary oracle: independent third-party ENCODER (gated) ----------

fn apple_macbinary() -> Option<&'static str> {
    let path = "/usr/bin/macbinary";
    if Path::new(path).exists() {
        Some(path)
    } else {
        None
    }
}

#[test]
fn decodes_real_apple_macbinary_output() {
    let Some(macbinary) = apple_macbinary() else {
        eprintln!("skipping: /usr/bin/macbinary not present");
        return;
    };

    let dir = temp_dir("apple");
    let src = dir.join("greeting.txt");
    let payload = b"Encoded by Apple's macbinary, decoded by newtua-mac.\nLine 2.\n";
    fs::write(&src, payload).unwrap();

    let out = dir.join("greeting.bin");
    let status = Command::new(macbinary)
        .arg("encode")
        .arg("-o")
        .arg(&out)
        .arg(&src)
        .status()
        .expect("run macbinary encode");
    assert!(status.success(), "macbinary encode failed");

    let file = fs::read(&out).unwrap();
    assert!(
        MacBinaryArchive::recognize(&file),
        "did not recognise Apple MacBinary"
    );

    let arc = MacBinaryArchive::open(&file[..]).unwrap();
    assert_eq!(
        arc.version(),
        3,
        "Apple macbinary should write MacBinary III"
    );

    let mut decoded = Vec::new();
    arc.read_entry(0, &mut decoded).unwrap();
    assert_eq!(decoded, payload, "decoded data fork != original");

    let _ = fs::remove_dir_all(&dir);
}
