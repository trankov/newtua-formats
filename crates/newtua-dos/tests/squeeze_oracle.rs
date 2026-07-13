// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! End-to-end golden test: decode a real `.SQ` with our crate AND with the
//! reference `unar`, and assert they agree byte-for-byte. Skipped when `unar` is
//! not installed.

use newtua_dos::squeeze::SqueezeFile;
use newtua_testutil::{unar_extract_one, unar_installed};

// A valid `.SQ` (verified accepted by `unar`): inner file "a", content "A".
const SQ_A: &[u8] = &[
    0x76, 0xFF, // magic
    0x41, 0x00, // checksum
    0x61, 0x00, // name "a\0"
    0x01, 0x00, 0xBE, 0xFF, 0xFF, 0xFE, 0x02, // squeeze stream
];

#[test]
fn our_decode_matches_unar() {
    if !unar_installed() {
        eprintln!("skipping: `unar` not installed");
        return;
    }

    let ours = SqueezeFile::open(SQ_A).unwrap().decode().unwrap();
    let theirs = unar_extract_one(SQ_A, "a.sq");

    assert_eq!(ours, theirs, "our decode disagrees with unar");
    assert_eq!(ours, b"A");
}
