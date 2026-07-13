// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! End-to-end golden test: decrunch real `PP20` fixtures with our crate AND with
//! the reference `unar`, and assert they agree byte-for-byte.
//!
//! The fixtures were generated and verified against `unar`; they cover the
//! literal path (with the `add == 3` run continuation) and a class-5
//! back-reference. Skipped when `unar` is not installed.

use std::fs;
use std::path::Path;

use newtua_amiga::powerpacker::PowerPackerFile;
use newtua_testutil::{unar_extract_one, unar_installed};

const CASES: &[(&str, &[u8])] = &[("hello.pp", b"Hello, PowerPacker!"), ("six.pp", b"AAAAAA")];

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

        let theirs = unar_extract_one(&data, file);
        assert_eq!(ours, theirs, "our decode disagrees with unar for {file}");
    }
}
