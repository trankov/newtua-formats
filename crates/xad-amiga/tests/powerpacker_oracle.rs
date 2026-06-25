//! End-to-end golden test: decrunch real `PP20` fixtures with our crate AND with
//! the reference `unar`, and assert they agree byte-for-byte.
//!
//! The fixtures were generated and verified against `unar`; they cover the
//! literal path (with the `add == 3` run continuation) and a class-5
//! back-reference. Skipped when `unar` is not installed.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use xad_amiga::powerpacker::PowerPackerFile;

const CASES: &[(&str, &[u8])] = &[("hello.pp", b"Hello, PowerPacker!"), ("six.pp", b"AAAAAA")];

fn unar_installed() -> bool {
    Command::new("unar")
        .arg("-version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    fs::read(path).unwrap()
}

#[test]
fn our_decode_matches_unar() {
    if !unar_installed() {
        eprintln!("skipping: `unar` not installed");
        return;
    }

    for (file, expected) in CASES {
        let data = fixture(file);

        let ours = PowerPackerFile::open(&data).unwrap().decode().unwrap();
        assert_eq!(ours, *expected, "our decode wrong for {file}");

        let dir: PathBuf = std::env::temp_dir().join(format!(
            "xad_pp_oracle_{}_{}",
            std::process::id(),
            file.replace('.', "_")
        ));
        fs::create_dir_all(&dir).unwrap();
        let archive = dir.join(file);
        fs::write(&archive, &data).unwrap();

        let status = Command::new("unar")
            .args(["-quiet", "-force-overwrite", "-output-directory"])
            .arg(&dir)
            .arg(&archive)
            .status()
            .expect("run unar");
        assert!(status.success(), "unar failed for {file}");

        // unar names the output after the source minus its extension.
        let stem = Path::new(file).file_stem().unwrap();
        let unar_out = fs::read(dir.join(stem)).expect("unar output");

        assert_eq!(ours, unar_out, "our decode disagrees with unar for {file}");
        let _ = fs::remove_dir_all(&dir);
    }
}
