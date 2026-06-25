//! Test-only helpers for cross-checking our decoders against the reference
//! `unar` decompressor. Used from the format crates' integration tests.

#![forbid(unsafe_code)]

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

/// Extract a **single-file** archive with `unar` and return the decoded bytes.
///
/// `archive_name` is the on-disk filename (e.g. `"a.sq"`); `unar` names the
/// output after it minus the extension. Panics if `unar` fails — call only
/// after [`unar_installed`].
pub fn unar_extract_one(archive_bytes: &[u8], archive_name: &str) -> Vec<u8> {
    let dir = unique_dir(archive_name);
    let archive = dir.join(archive_name);
    fs::write(&archive, archive_bytes).unwrap();

    let status = Command::new("unar")
        .args(["-quiet", "-force-overwrite", "-output-directory"])
        .arg(&dir)
        .arg(&archive)
        .status()
        .expect("run unar");
    assert!(status.success(), "unar failed for {archive_name}");

    let stem = Path::new(archive_name).file_stem().unwrap();
    let out = fs::read(dir.join(stem))
        .unwrap_or_else(|e| panic!("reading unar output for {archive_name}: {e}"));

    let _ = fs::remove_dir_all(&dir);
    out
}
