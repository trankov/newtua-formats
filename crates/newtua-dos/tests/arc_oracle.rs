// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! End-to-end golden tests: extract a multi-member `.arc` with our crate AND
//! with the reference `unar`, and assert every member agrees byte-for-byte.
//!
//! `multi.arc` holds a stored, a packed (RLE90) and a squeezed member;
//! `lzw.arc` holds a Squashed (method 9) and a Crunched-LZW (method 8) member.
//! Both fixtures were verified against `unar`. Skipped when `unar` is absent.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use newtua_dos::arc::ArcArchive;
use newtua_testutil::{unar_extract_all, unar_installed};

fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    fs::read(path).unwrap()
}

/// Decode every non-directory member of `data` with our crate.
fn ours(data: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let arc = ArcArchive::open(data).unwrap();
    let mut map = BTreeMap::new();
    for (i, entry) in arc.entries().iter().enumerate() {
        if entry.is_dir() {
            continue;
        }
        let mut out = Vec::new();
        arc.read_entry(i, &mut out).unwrap();
        map.insert(String::from_utf8(entry.name().to_vec()).unwrap(), out);
    }
    map
}

fn assert_matches_unar(name: &str) {
    if !unar_installed() {
        eprintln!("skipping: `unar` not installed");
        return;
    }
    let data = fixture(name);
    assert_eq!(
        ours(&data),
        unar_extract_all(&data, name),
        "our extraction of {name} disagrees with unar"
    );
}

#[test]
fn stored_packed_squeezed_match_unar() {
    assert_matches_unar("multi.arc");
}

#[test]
fn squashed_and_crunched_lzw_match_unar() {
    assert_matches_unar("lzw.arc");
}

#[test]
fn compressed_method_matches_unar() {
    assert_matches_unar("cmp.arc");
}

/// `crunch.arc` holds a stored anchor plus method-5 (no RLE90), method-6
/// (quadratic hash + RLE90) and method-7 (multiplicative hash + RLE90) members.
#[test]
fn crunch_methods_match_unar() {
    assert_matches_unar("crunch.arc");
}

/// `clear.arc` is a method-0x7f member at maxbits 9 whose ~800-byte payload
/// fills the table twice, forcing two block-mode clear codes (and their
/// group-of-8 padding) — the one compress path the smaller fixtures never hit.
#[test]
fn block_mode_clear_matches_unar() {
    assert_matches_unar("clear.arc");
}

/// `crush.arc` holds a stored anchor plus four method-0xa (Crushed) members:
/// short text, a repetitive run, a ~9.5 KB payload that drives the stream into
/// no-literal-bit mode, and a 12 KB payload that fills the 8192-slot table and
/// exercises the least-used eviction path.
#[test]
fn crush_method_matches_unar() {
    assert_matches_unar("crush.arc");
}
