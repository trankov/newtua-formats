//! Test-only helpers for cross-checking our decoders against the reference
//! `unar` decompressor. Used from the format crates' integration tests.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Whether the `unar` binary is available. Oracle tests skip themselves when it
/// is not (e.g. CI without The Unarchiver installed).
pub fn unar_installed() -> bool {
    Command::new("unar")
        .arg("-version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// The directory holding a StuffItX test corpus, or `None` if unset. Oracle
/// tests that walk a real corpus skip themselves when it is absent. Set
/// `NEWTUA_SITX_CORPUS` to the `build/` directory of
/// <https://github.com/ssokolow/stuffit-test-files> (CC0).
pub fn sitx_corpus_dir() -> Option<PathBuf> {
    let dir = std::env::var_os("NEWTUA_SITX_CORPUS")?;
    let path = PathBuf::from(dir);
    if path.is_dir() {
        Some(path)
    } else {
        None
    }
}

fn unique_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "newtua_oracle_{}_{}_{}",
        std::process::id(),
        n,
        tag.replace(['.', '/'], "_")
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Write `archive_bytes` into a unique temp dir and run `unar` on it (plus any
/// `extra_args`). Returns the output dir and the written archive path. Panics if
/// `unar` fails.
fn run_unar(archive_bytes: &[u8], archive_name: &str, extra_args: &[&str]) -> (PathBuf, PathBuf) {
    let dir = unique_dir(archive_name);
    let archive = dir.join(archive_name);
    fs::write(&archive, archive_bytes).unwrap();

    let status = Command::new("unar")
        .args(["-quiet", "-force-overwrite"])
        .args(extra_args)
        .arg("-output-directory")
        .arg(&dir)
        .arg(&archive)
        .status()
        .expect("run unar");
    assert!(status.success(), "unar failed for {archive_name}");

    (dir, archive)
}

/// Non-panicking sibling of [`run_unar`]: runs `unar` and returns the output
/// dir + archive path on success, or `None` (cleaning up the dir) on failure —
/// for oracle checks that must inspect a deliberate `unar` failure (wrong
/// password, or a known `unar` limitation) rather than treat it as our bug.
fn try_run_unar(
    archive_bytes: &[u8],
    archive_name: &str,
    extra_args: &[&str],
) -> Option<(PathBuf, PathBuf)> {
    let dir = unique_dir(archive_name);
    let archive = dir.join(archive_name);
    fs::write(&archive, archive_bytes).unwrap();

    let status = Command::new("unar")
        .args(["-quiet", "-force-overwrite"])
        .args(extra_args)
        .arg("-output-directory")
        .arg(&dir)
        .arg(&archive)
        .status()
        .expect("run unar");
    if status.success() {
        Some((dir, archive))
    } else {
        let _ = fs::remove_dir_all(&dir);
        None
    }
}

/// Extract a **single-file** archive with `unar` and return the decoded bytes.
///
/// `archive_name` is the on-disk filename (e.g. `"a.sq"`); `unar` names the
/// output after it minus the extension. Panics if `unar` fails — call only
/// after [`unar_installed`].
pub fn unar_extract_one(archive_bytes: &[u8], archive_name: &str) -> Vec<u8> {
    let (dir, _archive) = run_unar(archive_bytes, archive_name, &[]);
    let stem = Path::new(archive_name).file_stem().unwrap();
    let out = fs::read(dir.join(stem))
        .unwrap_or_else(|e| panic!("reading unar output for {archive_name}: {e}"));
    let _ = fs::remove_dir_all(&dir);
    out
}

/// Extract a **multi-file** archive with `unar` and return a map of each
/// extracted file's path (relative, `/`-separated) to its bytes.
///
/// Uses `-no-directory` so members land directly in the output dir (no wrapper
/// folder). Panics if `unar` fails — call only after [`unar_installed`].
pub fn unar_extract_all(archive_bytes: &[u8], archive_name: &str) -> BTreeMap<String, Vec<u8>> {
    let (dir, archive) = run_unar(archive_bytes, archive_name, &["-no-directory"]);
    let mut map = BTreeMap::new();
    collect(&dir, &dir, &archive, &mut map);
    let _ = fs::remove_dir_all(&dir);
    map
}

/// Like [`unar_extract_all`], but passes `-password <password>` so `unar` can
/// decrypt an encrypted archive (DMS, ZIP, ALZip, …). Panics if `unar` fails —
/// call only after [`unar_installed`].
pub fn unar_extract_all_with_password(
    archive_bytes: &[u8],
    archive_name: &str,
    password: &str,
) -> BTreeMap<String, Vec<u8>> {
    let (dir, archive) = run_unar(
        archive_bytes,
        archive_name,
        &["-no-directory", "-password", password],
    );
    let mut map = BTreeMap::new();
    collect(&dir, &dir, &archive, &mut map);
    let _ = fs::remove_dir_all(&dir);
    map
}

/// Like [`unar_extract_all_with_password`], but returns `None` when `unar`
/// fails instead of panicking — for oracle checks that need to inspect a
/// deliberate `unar` failure (wrong password, or a known `unar` limitation)
/// rather than treat it as this crate's bug.
pub fn try_unar_extract_all_with_password(
    archive_bytes: &[u8],
    archive_name: &str,
    password: &str,
) -> Option<BTreeMap<String, Vec<u8>>> {
    let (dir, archive) = try_run_unar(
        archive_bytes,
        archive_name,
        &["-no-directory", "-password", password],
    )?;
    let mut map = BTreeMap::new();
    collect(&dir, &dir, &archive, &mut map);
    let _ = fs::remove_dir_all(&dir);
    Some(map)
}

/// Like [`unar_extract_all`], but returns `None` when `unar` itself fails to
/// parse the archive instead of panicking. Used by corpus oracles to skip
/// archives the reference decoder cannot handle either (rather than treating
/// them as our bug).
pub fn try_unar_extract_all(
    archive_bytes: &[u8],
    archive_name: &str,
) -> Option<BTreeMap<String, Vec<u8>>> {
    let (dir, archive) = try_run_unar(archive_bytes, archive_name, &["-no-directory"])?;
    let mut map = BTreeMap::new();
    collect(&dir, &dir, &archive, &mut map);
    let _ = fs::remove_dir_all(&dir);
    Some(map)
}

/// Extract a **split** (multi-volume) archive with `unar`. The `volumes` are
/// written to a temp dir named `base.alz`, `base.a00`, `base.a01`, … (the scheme
/// `unar` scans for), then `unar` is run on the first part and its output
/// collected (path → bytes). Panics if `unar` fails — call only after
/// [`unar_installed`].
pub fn unar_extract_all_volumes(volumes: &[&[u8]], base: &str) -> BTreeMap<String, Vec<u8>> {
    let root = unique_dir(base);
    let voldir = root.join("vols");
    let outdir = root.join("out");
    fs::create_dir_all(&voldir).unwrap();
    fs::create_dir_all(&outdir).unwrap();

    let first = voldir.join(format!("{base}.alz"));
    fs::write(&first, volumes[0]).unwrap();
    for (k, vol) in volumes[1..].iter().enumerate() {
        fs::write(voldir.join(format!("{base}.a{k:02}")), vol).unwrap();
    }

    let status = Command::new("unar")
        .args(["-quiet", "-force-overwrite", "-no-directory"])
        .arg("-output-directory")
        .arg(&outdir)
        .arg(&first)
        .status()
        .expect("run unar");
    assert!(status.success(), "unar failed for split archive {base}.alz");

    let mut map = BTreeMap::new();
    collect(&outdir, &outdir, &first, &mut map);
    let _ = fs::remove_dir_all(&root);
    map
}

/// A least-significant-bit-first bit writer, used by the test-only encoders
/// that build fixtures for the LSB-first formats (Squeeze, Distill).
#[derive(Default)]
pub struct BitWriter {
    bytes: Vec<u8>,
    cur: u8,
    nbits: u8,
}

impl BitWriter {
    /// Append a single bit.
    pub fn bit(&mut self, b: bool) {
        if b {
            self.cur |= 1 << self.nbits;
        }
        self.nbits += 1;
        if self.nbits == 8 {
            self.bytes.push(self.cur);
            self.cur = 0;
            self.nbits = 0;
        }
    }

    /// Append the low `n` bits of `val`, least-significant bit first.
    pub fn bits(&mut self, val: u32, n: u32) {
        for i in 0..n {
            self.bit((val >> i) & 1 != 0);
        }
    }

    /// Flush any partial final byte and return the written bytes.
    pub fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            self.bytes.push(self.cur);
        }
        self.bytes
    }
}

/// A most-significant-bit-first bit writer, symmetric to
/// `newtua_common::bitreader::BitReaderMsb`. Used by test-only encoders that
/// build fixtures for MSB-first formats (DMS's QUICK/MEDIUM/DEEP/HEAVY).
#[derive(Default)]
pub struct BitWriterMsb {
    bytes: Vec<u8>,
    cur: u8,
    nbits: u8,
}

impl BitWriterMsb {
    /// Append a single bit.
    pub fn bit(&mut self, b: bool) {
        self.cur = (self.cur << 1) | u8::from(b);
        self.nbits += 1;
        if self.nbits == 8 {
            self.bytes.push(self.cur);
            self.cur = 0;
            self.nbits = 0;
        }
    }

    /// Append the low `n` bits of `val`, most-significant bit first (the bit
    /// order `BitReaderMsb::read` reassembles).
    pub fn bits(&mut self, val: u32, n: u32) {
        for i in (0..n).rev() {
            self.bit((val >> i) & 1 != 0);
        }
    }

    /// Flush any partial final byte (padded with zero low-order bits, as a
    /// real MSB bitstream reader would see past-EOF) and return the written
    /// bytes.
    pub fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            self.cur <<= 8 - self.nbits;
            self.bytes.push(self.cur);
        }
        self.bytes
    }
}

fn collect(root: &Path, dir: &Path, archive: &Path, map: &mut BTreeMap<String, Vec<u8>>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path == *archive {
            continue; // skip the archive we wrote in
        }
        if path.is_dir() {
            collect(root, &path, archive, map);
        } else {
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            map.insert(rel, fs::read(&path).unwrap());
        }
    }
}
