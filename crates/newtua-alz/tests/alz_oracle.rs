//! End-to-end oracle for the ALZip container.
//!
//! No common tool writes `.alz`, so this test assembles one from a small
//! builder — a stored member, a raw-deflate member, a bzip2 member, and an
//! obfuscated-deflate (method 3) member — then asserts that BOTH our crate AND
//! the reference `unar` decode it to the same bytes. `unar` is the independent
//! check that our reading of the format (and the IEEE CRC-32 it verifies) is
//! correct. Skipped when `unar` is absent.

use std::collections::BTreeMap;
use std::io::Read;

use newtua_alz::AlzArchive;
use newtua_common::crc32::crc32_ieee;
use newtua_common::deflate::deflate_dynamic;
use newtua_testutil::{unar_extract_all, unar_installed};

const HEADER: [u8; 8] = [b'A', b'L', b'Z', 0x01, 0, 0, 0, 0];

fn deflate(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::DeflateEncoder::new(content, flate2::Compression::best())
        .read_to_end(&mut out)
        .unwrap();
    out
}

/// The method-3 meta-table order (mirror of the crate's private
/// `silly_meta_order` — house convention keeps oracle helpers self-contained).
fn silly_meta_order(param: usize) -> [u8; 19] {
    let mut table = [0u8; 19];
    for (i, v) in table.iter_mut().enumerate() {
        *v = i as u8;
    }
    for i in 0..19 {
        let mut swapindex = (i % 6) * 3 + param;
        if swapindex > 18 {
            swapindex %= 18;
        }
        if swapindex != i {
            table.swap(i, swapindex);
        }
    }
    table
}

/// Obfuscated-deflate (method 3) compressed stream for `content`.
fn silly_deflate(content: &[u8]) -> Vec<u8> {
    deflate_dynamic(content, &silly_meta_order(content.len() % 16))
}

fn bzip2(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    bzip2::read::BzEncoder::new(content, bzip2::Compression::new(9))
        .read_to_end(&mut out)
        .unwrap();
    out
}

/// One local file record (4-byte size fields, unencrypted).
fn record(name: &[u8], method: u8, content: &[u8], comp: &[u8]) -> Vec<u8> {
    let mut r = vec![b'B', b'L', b'Z', 0x01];
    r.extend_from_slice(&(name.len() as u16).to_le_bytes());
    r.push(0x00); // attrs: regular file
    r.extend_from_slice(&0u32.to_le_bytes()); // dostime
    r.push(4 << 4); // flags: size width 4, not encrypted
    r.push(0x00); // skipped byte
    r.push(method);
    r.push(0x00); // skipped byte
    r.extend_from_slice(&crc32_ieee(content).to_le_bytes());
    r.extend_from_slice(&(comp.len() as u32).to_le_bytes());
    r.extend_from_slice(&(content.len() as u32).to_le_bytes());
    r.extend_from_slice(name);
    r.extend_from_slice(comp);
    r
}

fn build(records: &[Vec<u8>]) -> Vec<u8> {
    let mut a = HEADER.to_vec();
    for rec in records {
        a.extend_from_slice(rec);
    }
    a.extend_from_slice(b"CLZ\x01"); // central directory ends the member stream
    a
}

fn ours(data: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let arc = AlzArchive::open(data).unwrap();
    let mut map = BTreeMap::new();
    for (i, e) in arc.entries().iter().enumerate() {
        let mut out = Vec::new();
        arc.read_entry(i, &mut out).unwrap();
        map.insert(String::from_utf8(e.name().to_vec()).unwrap(), out);
    }
    map
}

#[test]
fn four_methods_match_unar() {
    if !unar_installed() {
        eprintln!("skipping: `unar` not installed");
        return;
    }

    let stored = b"ALZip stored member, copied verbatim.\n".to_vec();
    let deflated = b"deflate this content over and over so it actually compresses. ".repeat(40);
    let bzipped = b"bzip2 wants a decent block of repeated text to compress well. ".repeat(60);
    let obfuscated = b"method 3 obfuscated deflate; unar must undo the silly meta order. ".to_vec();

    let alz = build(&[
        record(b"stored.txt", 0, &stored, &stored),
        record(b"deflated.bin", 2, &deflated, &deflate(&deflated)),
        record(b"bzipped.bin", 1, &bzipped, &bzip2(&bzipped)),
        record(
            b"obfuscated.bin",
            3,
            &obfuscated,
            &silly_deflate(&obfuscated),
        ),
    ]);

    let mine = ours(&alz);
    assert_eq!(mine.get("stored.txt"), Some(&stored));
    assert_eq!(mine.get("deflated.bin"), Some(&deflated));
    assert_eq!(mine.get("bzipped.bin"), Some(&bzipped));
    assert_eq!(mine.get("obfuscated.bin"), Some(&obfuscated));

    assert_eq!(
        mine,
        unar_extract_all(&alz, "test.alz"),
        "our ALZ extraction disagrees with unar"
    );
}
