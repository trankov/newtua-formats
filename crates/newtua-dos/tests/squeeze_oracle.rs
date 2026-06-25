//! End-to-end golden test: decode a real `.SQ` with our crate AND with the
//! reference `unar` decompressor, and assert they agree byte-for-byte.
//!
//! Skipped automatically when `unar` is not installed (e.g. CI without it).

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use newtua_dos::squeeze::SqueezeFile;

// A valid `.SQ` (verified accepted by `unar`): inner file "a", content "A".
const SQ_A: &[u8] = &[
    0x76, 0xFF, // magic
    0x41, 0x00, // checksum
    0x61, 0x00, // name "a\0"
    0x01, 0x00, 0xBE, 0xFF, 0xFF, 0xFE, 0x02, // squeeze stream
];

fn unar_installed() -> bool {
    Command::new("unar")
        .arg("-version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn workdir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("newtua_sq_oracle_{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn our_decode_matches_unar() {
    if !unar_installed() {
        eprintln!("skipping: `unar` not installed");
        return;
    }

    let dir = workdir();
    let archive = dir.join("a.sq");
    fs::write(&archive, SQ_A).unwrap();

    // Reference extraction.
    let status = Command::new("unar")
        .args(["-quiet", "-force-overwrite", "-output-directory"])
        .arg(&dir)
        .arg(&archive)
        .status()
        .expect("run unar");
    assert!(status.success(), "unar failed");
    let unar_out = fs::read(dir.join("a")).expect("unar output file");

    // Our extraction.
    let ours = SqueezeFile::open(SQ_A).unwrap().decode().unwrap();

    assert_eq!(ours, unar_out, "our decode disagrees with unar");
    assert_eq!(ours, b"A");

    let _ = fs::remove_dir_all(&dir);
}
