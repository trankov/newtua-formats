// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! End-to-end oracle for the LBR container.
//!
//! No common tool writes `.lbr` files, so this test assembles one from a small,
//! self-contained builder (a stored member plus an embedded Squeeze member),
//! then asserts that BOTH our crate AND the reference `unar` decode it to the
//! same bytes. `unar` is the independent check on our reading of the format.
//! Skipped when `unar` is absent.

use std::collections::BTreeMap;

use newtua_common::crc16::crc16_ccitt;
use newtua_dos::lbr::LbrArchive;
use newtua_testutil::{unar_extract_all, unar_installed, BitWriter};

// ---------------------------------------------------------------------------
// Minimal Squeeze (`.SQ`) encoder (test-only; mirrors XADSqueezeHandle).
// ---------------------------------------------------------------------------

/// Encode `content` as a `.SQ` stream with the given internal name.
///
/// `content` must contain no `0x90` byte, so its RLE90 encoding is the identity
/// and the Huffman layer can emit the content bytes verbatim (then EOF).
fn squeeze(name: &str, content: &[u8]) -> Vec<u8> {
    assert!(!content.contains(&0x90), "RLE90 escape unsupported here");

    // Symbols: distinct bytes in first-appearance order, then EOF (256).
    let mut symbols: Vec<i32> = Vec::new();
    for &b in content {
        if !symbols.contains(&(b as i32)) {
            symbols.push(b as i32);
        }
    }
    symbols.push(256);
    let s = symbols.len();

    // Linear tree: node i -> (leaf symbols[i], node i+1 | leaf symbols[last]).
    let leaf = |v: i32| -(v + 1) as i16;
    let mut nodes = vec![0i16; 2 * (s - 1)];
    for i in 0..s - 1 {
        nodes[2 * i] = leaf(symbols[i]);
        nodes[2 * i + 1] = if i == s - 2 {
            leaf(symbols[s - 1])
        } else {
            (i + 1) as i16
        };
    }

    // Codes, by walking the tree (LSB-first bit order).
    let mut codes: BTreeMap<i32, Vec<bool>> = BTreeMap::new();
    fn walk(
        nodes: &[i16],
        node: usize,
        prefix: &mut Vec<bool>,
        out: &mut BTreeMap<i32, Vec<bool>>,
    ) {
        for (slot, bit) in [(2 * node, false), (2 * node + 1, true)] {
            let link = nodes[slot];
            prefix.push(bit);
            if link < 0 {
                out.insert(-(link as i32) - 1, prefix.clone());
            } else {
                walk(nodes, link as usize, prefix, out);
            }
            prefix.pop();
        }
    }
    walk(&nodes, 0, &mut Vec::new(), &mut codes);

    let checksum: u32 = content.iter().map(|&b| b as u32).sum();
    let mut out = vec![0x76, 0xff];
    out.extend_from_slice(&(checksum as u16).to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    out.extend_from_slice(&(nodes.len() as u16 / 2).to_le_bytes());
    for &link in &nodes {
        out.extend_from_slice(&link.to_le_bytes());
    }

    let mut bw = BitWriter::default();
    let emit = |bw: &mut BitWriter, sym: i32| {
        for &b in &codes[&sym] {
            bw.bit(b);
        }
    };
    for &b in content {
        emit(&mut bw, b as i32);
    }
    emit(&mut bw, 256);
    out.extend_from_slice(&bw.finish());
    out
}

// ---------------------------------------------------------------------------
// Minimal LBR builder.
// ---------------------------------------------------------------------------

struct Member {
    name: [u8; 8],
    ext: [u8; 3],
    content: Vec<u8>,
}

fn member(name: &str, ext: &str, content: Vec<u8>) -> Member {
    let mut n = [b' '; 8];
    let mut e = [b' '; 3];
    n[..name.len()].copy_from_slice(name.as_bytes());
    e[..ext.len()].copy_from_slice(ext.as_bytes());
    Member {
        name: n,
        ext: e,
        content,
    }
}

fn record(name: [u8; 8], ext: [u8; 3], index: u16, length: u16, crc: u16, padding: u8) -> [u8; 32] {
    let mut r = [0u8; 32];
    r[1..9].copy_from_slice(&name);
    r[9..12].copy_from_slice(&ext);
    r[12..14].copy_from_slice(&index.to_le_bytes());
    r[14..16].copy_from_slice(&length.to_le_bytes());
    r[16..18].copy_from_slice(&crc.to_le_bytes());
    r[26] = padding;
    r
}

fn build_lbr(members: &[Member]) -> Vec<u8> {
    let numsectors = ((members.len() + 1).div_ceil(4)).max(1) as u16;
    let mut dir = vec![0xffu8; numsectors as usize * 128];
    let mut data: Vec<u8> = Vec::new();
    let mut sector = numsectors;

    dir[0..32].copy_from_slice(&record([b' '; 8], [b' '; 3], 0, numsectors, 0, 0));

    for (i, mem) in members.iter().enumerate() {
        let clen = mem.content.len();
        let length = clen.div_ceil(128).max(1) as u16;
        let padding = (length as usize * 128 - clen) as u8;
        let crc = crc16_ccitt(&mem.content);

        let off = (i + 1) * 32;
        dir[off..off + 32]
            .copy_from_slice(&record(mem.name, mem.ext, sector, length, crc, padding));
        data.extend_from_slice(&mem.content);
        data.resize(data.len() + padding as usize, 0);
        sector += length;
    }

    let crc = crc16_ccitt(&dir);
    dir[16..18].copy_from_slice(&crc.to_le_bytes());
    dir.extend_from_slice(&data);
    dir
}

fn ours(data: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let arc = LbrArchive::open(data).unwrap();
    let mut map = BTreeMap::new();
    for (i, entry) in arc.entries().iter().enumerate() {
        let mut out = Vec::new();
        arc.read_entry(i, &mut out).unwrap();
        map.insert(String::from_utf8(entry.name().to_vec()).unwrap(), out);
    }
    map
}

/// A complete standalone Crunch (LZW, type 0xfe) file whose body decodes to
/// "AB" (the hand-built stream from the crunch_cpm tests), with `name` as its
/// internal name and no trailing checksum.
fn crunch_ab(name: &str) -> Vec<u8> {
    let mut v = vec![0x76, 0xfe];
    v.extend_from_slice(name.as_bytes());
    v.push(0);
    v.push(0x20); // version1
    v.push(0x20); // version2 → new variant
    v.push(0x01); // errordetection != 0 → no checksum
    v.push(0x00); // reserved
    v.extend_from_slice(&[0x20, 0x90, 0xA0, 0x00]); // LZW body → "AB"
    v
}

#[test]
fn crunched_member_matches_unar() {
    if !unar_installed() {
        eprintln!("skipping: `unar` not installed");
        return;
    }

    let stored = b"plain stored neighbour\n".to_vec();
    // Extension's 2nd char 'Z' marks Crunch; the embedded 0x76 0xfe confirms it.
    let lbr = build_lbr(&[
        member("PLAIN", "TXT", stored.clone()),
        member("CRUNCHED", "AZT", crunch_ab("abc.txt")),
    ]);

    let mine = ours(&lbr);
    assert_eq!(mine.get("PLAIN.TXT"), Some(&stored));
    assert_eq!(mine.get("abc.txt"), Some(&b"AB".to_vec())); // internal crunch name

    assert_eq!(
        mine,
        unar_extract_all(&lbr, "test.lbr"),
        "our LBR crunch extraction disagrees with unar"
    );
}

#[test]
fn stored_and_squeezed_members_match_unar() {
    if !unar_installed() {
        eprintln!("skipping: `unar` not installed");
        return;
    }

    let stored_content = b"The quick brown fox jumps over the lazy dog.\n".to_vec();
    let squeezed_content = b"Squeezed content stored inside an LBR library!".to_vec();
    let sq = squeeze("inside.txt", &squeezed_content);

    let lbr = build_lbr(&[
        member("FOX", "TXT", stored_content.clone()),
        member("INSIDE", "TQT", sq),
    ]);

    // Our decode: stored keeps its 8.3 name; squeezed reports its internal name.
    let mine = ours(&lbr);
    assert_eq!(mine.get("FOX.TXT"), Some(&stored_content));
    assert_eq!(mine.get("inside.txt"), Some(&squeezed_content));

    // ...and the reference decoder must agree on every member.
    assert_eq!(
        mine,
        unar_extract_all(&lbr, "test.lbr"),
        "our LBR extraction disagrees with unar"
    );
}
