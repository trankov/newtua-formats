// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! End-to-end golden test: assemble a store-method (method 0) LZX archive with
//! a small mirror encoder, then check both our own parser AND the reference
//! `unar`/`lsar` agree on entry names/count and on the extracted bytes.
//!
//! We use `unar_extract_all` (name -> bytes map) as the sole external oracle:
//! it verifies entry count, names, sizes (`bytes.len()`), and byte-for-byte
//! content all in one pass, which already covers what a separate `lsar -j`
//! JSON check would add — and the workspace carries no JSON dependency to
//! parse it with. Skipped when `unar` is not installed.

use newtua_amiga::lzx::LzxArchive;
use newtua_common::crc32::crc32_ieee;
use newtua_testutil::{unar_extract_all, unar_installed, BitWriter};

/// Mirror encoder for the LZX container (method 0 / store only): builds a
/// 10-byte archive header followed by one or more solid groups.
struct LzxBuilder {
    buf: Vec<u8>,
}

impl LzxBuilder {
    fn new() -> Self {
        Self {
            buf: b"LZX".iter().copied().chain([0u8; 7]).collect(),
        }
    }

    /// Write a solid group of `files` (name, content), all sharing one
    /// method-0 stream. The last file's record is the one that closes the
    /// group (`compsize != 0`).
    fn push_solid_group(&mut self, files: &[(&str, &[u8])]) {
        let solid_data: Vec<u8> = files
            .iter()
            .flat_map(|(_, data)| data.iter().copied())
            .collect();

        for (i, (name, data)) in files.iter().enumerate() {
            let compsize = if i == files.len() - 1 {
                solid_data.len() as u32
            } else {
                0
            };
            self.push_record(
                data.len() as u32,
                compsize,
                name.as_bytes(),
                crc32_ieee(data),
            );
        }
        self.buf.extend_from_slice(&solid_data);
    }

    fn push_record(&mut self, filesize: u32, compsize: u32, name: &[u8], datacrc: u32) {
        self.push_record_method(filesize, compsize, name, datacrc, 0);
    }

    fn push_record_method(
        &mut self,
        filesize: u32,
        compsize: u32,
        name: &[u8],
        datacrc: u32,
        method: u8,
    ) {
        self.buf.extend_from_slice(&0u16.to_le_bytes()); // attributes
        self.buf.extend_from_slice(&filesize.to_le_bytes());
        self.buf.extend_from_slice(&compsize.to_le_bytes());
        self.buf.push(0); // os = MSDOS (no Amiga protection bits to worry about)
        self.buf.push(method);
        self.buf.extend_from_slice(&0u16.to_le_bytes()); // flags
        self.buf.push(0); // commentlen
        self.buf.push(0); // version
        self.buf.extend_from_slice(&[0, 0]); // skipped
        self.buf.extend_from_slice(&0u32.to_le_bytes()); // date
        self.buf.extend_from_slice(&datacrc.to_le_bytes());
        self.buf.extend_from_slice(&0u32.to_le_bytes()); // headercrc, ignored
        self.buf.push(name.len() as u8);
        self.buf.extend_from_slice(name);
    }

    /// A method-2 (LZX-compressed) solid group: `files` gives each member's
    /// (name, filesize, CRC-32 of its own decompressed bytes); `compressed`
    /// is the already-encoded LZX stream for the whole group (built with
    /// [`Lzx2Encoder`]).
    fn push_solid_group_method2(&mut self, files: &[(&str, u32, u32)], compressed: &[u8]) {
        for (i, (name, filesize, crc)) in files.iter().enumerate() {
            let compsize = if i == files.len() - 1 {
                compressed.len() as u32
            } else {
                0
            };
            self.push_record_method(*filesize, compsize, name.as_bytes(), *crc, 2);
        }
        self.buf.extend_from_slice(compressed);
    }

    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

// --- Minimal mirror encoder for the LZX codec (method 2) ---
//
// A trimmed duplicate of the encoder in `src/lzx.rs`'s own `codec_tests`
// (block type 2 / no offset code only — this oracle only needs one real
// bitstream a third-party decoder also accepts, not full block-type-3
// coverage, which is already proven against our own decoder there).

/// Number of additional raw bits per offset/length class (`XADLZXHandle.m:32-36`).
const ADDITIONAL_BITS_TABLE: [u32; 32] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14,
];
/// Base value per offset/length class (`XADLZXHandle.m:37-41`).
const BASE_TABLE: [u32; 32] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152,
];

fn class_for(value: u32) -> usize {
    let mut class = 0;
    for (c, &base) in BASE_TABLE.iter().enumerate() {
        if base <= value {
            class = c;
        } else {
            break;
        }
    }
    class
}

fn swap_pairs(input: &[u8]) -> Vec<u8> {
    let mut out = input.to_vec();
    for pair in out.chunks_exact_mut(2) {
        pair.swap(0, 1);
    }
    out
}

fn canonical_codes(lengths: &[u32], max_length: u32) -> Vec<(u32, u32)> {
    let mut codes = vec![(0u32, 0u32); lengths.len()];
    let mut code = 0u32;
    for length in 1..=max_length {
        for (i, &len) in lengths.iter().enumerate() {
            if len == length {
                codes[i] = (code, length);
                code += 1;
            }
        }
        code <<= 1;
    }
    codes
}

fn encode_symbol(w: &mut BitWriter, codes: &[(u32, u32)], symbol: usize) {
    let (code, length) = codes[symbol];
    for bitpos in (0..length).rev() {
        w.bits((code >> bitpos) & 1, 1);
    }
}

fn uniform_length_for(n: usize) -> u32 {
    let mut length = 1u32;
    while (1usize << length) < n.max(1) {
        length += 1;
    }
    length
}

fn match_symbol(offsclass: usize, lenclass: usize) -> usize {
    256 + (lenclass << 5) + offsclass
}

enum Op {
    Literal(u8),
    Match { distance: u32, length: u32 },
}

fn op_main_symbol(op: &Op) -> usize {
    match op {
        Op::Literal(b) => *b as usize,
        Op::Match { distance, length } => {
            match_symbol(class_for(*distance), class_for(*length - 3))
        }
    }
}

/// Builds a method-2 LZX solid stream (block type 2 only) by inverting the
/// decoder in `src/lzx.rs`, the same way `codec_tests::LzxTestEncoder` does.
struct Lzx2Encoder {
    w: BitWriter,
    mainlengths: [u32; 768],
}

impl Lzx2Encoder {
    fn new() -> Self {
        Self {
            w: BitWriter::default(),
            mainlengths: [0u32; 768],
        }
    }

    fn encode_delta_lengths(&mut self, target: &[u32; 768], start: usize, count: usize) {
        for _ in 0..20 {
            self.w.bits(5, 4); // fixed flat 5-bit pre-code, as in codec_tests
        }
        let precode = canonical_codes(&[5u32; 20], 15);
        for i in 0..count {
            let old = self.mainlengths[start + i];
            let want = target[start + i];
            let val = (old + 17 - want) % 17;
            encode_symbol(&mut self.w, &precode, val as usize);
        }
    }

    fn write_block(&mut self, ops: &[Op], block_output_len: u32) {
        self.w.bits(2, 3); // block type 2: no offset code
        self.w.bits((block_output_len >> 16) & 0xFF, 8);
        self.w.bits((block_output_len >> 8) & 0xFF, 8);
        self.w.bits(block_output_len & 0xFF, 8);

        let mut used: Vec<usize> = ops.iter().map(op_main_symbol).collect();
        used.sort_unstable();
        used.dedup();
        let length = uniform_length_for(used.len());
        let mut target = [0u32; 768];
        for &s in &used {
            target[s] = length;
        }

        self.encode_delta_lengths(&target, 0, 256);
        self.encode_delta_lengths(&target, 256, 512);
        self.mainlengths = target;

        let codes = canonical_codes(&target, 16);
        for op in ops {
            match op {
                Op::Literal(b) => encode_symbol(&mut self.w, &codes, *b as usize),
                Op::Match { distance, length } => {
                    let offsclass = class_for(*distance);
                    let lenclass = class_for(*length - 3);
                    encode_symbol(&mut self.w, &codes, match_symbol(offsclass, lenclass));
                    self.w.bits(
                        *distance - BASE_TABLE[offsclass],
                        ADDITIONAL_BITS_TABLE[offsclass],
                    );
                    self.w.bits(
                        *length - 3 - BASE_TABLE[lenclass],
                        ADDITIONAL_BITS_TABLE[lenclass],
                    );
                }
            }
        }
    }

    fn finish(self) -> Vec<u8> {
        let mut bytes = self.w.finish();
        if bytes.len() % 2 != 0 {
            bytes.push(0);
        }
        swap_pairs(&bytes)
    }
}

#[test]
fn store_archive_matches_unar() {
    if !unar_installed() {
        eprintln!("skipping: `unar` not installed");
        return;
    }

    let mut builder = LzxBuilder::new();
    builder.push_solid_group(&[
        ("first.txt", b"The quick brown fox"),
        ("second.txt", b"jumps over the lazy dog"),
        ("third.txt", b"1234567890"),
    ]);
    let archive_bytes = builder.finish();

    let ours = LzxArchive::open(&archive_bytes).unwrap();
    assert_eq!(ours.entries().len(), 3);

    let theirs = unar_extract_all(&archive_bytes, "test.lzx");
    assert_eq!(theirs.len(), 3, "unar should see all 3 solid-group members");

    for entry in ours.entries() {
        let name = String::from_utf8(entry.name.clone()).unwrap();
        let our_bytes = ours.read_entry(entry).unwrap();
        let their_bytes = theirs
            .get(&name)
            .unwrap_or_else(|| panic!("unar did not extract {name}"));
        assert_eq!(&our_bytes, their_bytes, "content mismatch for {name}");
        assert_eq!(
            our_bytes.len() as u64,
            entry.size,
            "size mismatch for {name}"
        );
    }
}

#[test]
fn multiple_solid_groups_match_unar() {
    if !unar_installed() {
        eprintln!("skipping: `unar` not installed");
        return;
    }

    let mut builder = LzxBuilder::new();
    builder.push_solid_group(&[("a.txt", b"AAAA"), ("b.txt", b"BBBBBB")]);
    builder.push_solid_group(&[("c.txt", b"CC")]);
    let archive_bytes = builder.finish();

    let ours = LzxArchive::open(&archive_bytes).unwrap();
    assert_eq!(ours.entries().len(), 3);

    let theirs = unar_extract_all(&archive_bytes, "test2.lzx");
    assert_eq!(theirs.len(), 3);

    for entry in ours.entries() {
        let name = String::from_utf8(entry.name.clone()).unwrap();
        let our_bytes = ours.read_entry(entry).unwrap();
        assert_eq!(
            &our_bytes,
            theirs.get(&name).unwrap(),
            "content mismatch for {name}"
        );
    }
}

#[test]
fn method_2_single_file_matches_unar() {
    if !unar_installed() {
        eprintln!("skipping: `unar` not installed");
        return;
    }

    let data = b"The quick brown fox jumps over the lazy dog. The quick brown fox!";
    let mut enc = Lzx2Encoder::new();
    let ops: Vec<Op> = data.iter().map(|&b| Op::Literal(b)).collect();
    enc.write_block(&ops, data.len() as u32);
    let compressed = enc.finish();

    let mut builder = LzxBuilder::new();
    builder.push_solid_group_method2(
        &[("plain.txt", data.len() as u32, crc32_ieee(data))],
        &compressed,
    );
    let archive_bytes = builder.finish();

    let ours = LzxArchive::open(&archive_bytes).unwrap();
    assert_eq!(ours.entries().len(), 1);
    assert_eq!(ours.read_entry(&ours.entries()[0]).unwrap(), data);

    let theirs = unar_extract_all(&archive_bytes, "method2.lzx");
    assert_eq!(theirs.len(), 1, "unar should see the single member");
    assert_eq!(
        theirs.get("plain.txt").unwrap(),
        data,
        "unar's decode disagrees with the fixture's plaintext"
    );
}

#[test]
fn method_2_with_a_match_matches_unar() {
    if !unar_installed() {
        eprintln!("skipping: `unar` not installed");
        return;
    }

    // "abcabc" via 3 literals + a distance-3 length-3 match, so `unar`'s own
    // LZSS+Huffman decode is exercised, not just the literal path.
    let ops = vec![
        Op::Literal(b'a'),
        Op::Literal(b'b'),
        Op::Literal(b'c'),
        Op::Match {
            distance: 3,
            length: 3,
        },
    ];
    let mut enc = Lzx2Encoder::new();
    enc.write_block(&ops, 6);
    let compressed = enc.finish();

    let mut builder = LzxBuilder::new();
    builder.push_solid_group_method2(&[("m.txt", 6, crc32_ieee(b"abcabc"))], &compressed);
    let archive_bytes = builder.finish();

    let ours = LzxArchive::open(&archive_bytes).unwrap();
    assert_eq!(ours.read_entry(&ours.entries()[0]).unwrap(), b"abcabc");

    let theirs = unar_extract_all(&archive_bytes, "method2b.lzx");
    assert_eq!(theirs.get("m.txt").unwrap(), b"abcabc");
}
