// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Classic StuffIt compression method 5 (LZAH — dynamic LZH).
//!
//! Faithful port of XADMaster's active `XADLZHDynamicHandle`. An LZSS coder with
//! a 4096-byte window whose literals and match lengths come from an **adaptive**
//! Huffman tree (rebuilt as symbol frequencies grow), while match distances use a
//! static 64-symbol Huffman code plus six raw low bits. **Every** bit and symbol
//! is read most-significant-bit first (unlike method 13, which is LSB-first).
//!
//! The window is zeroed and then pre-filled with a fixed pattern (see
//! [`initial_window`]); with the emit position still at 0, an early
//! back-reference reaches into that pre-filled tail — exactly as the reference
//! does with `pos - offset` going negative and wrapping under the window mask.

use std::io::{self, Read};

use newtua_common::bitreader::BitReaderMsb;
use newtua_common::lzss::LzssWindow;
use newtua_common::prefixcode::PrefixCode;

/// The LZSS window is fixed at 4096 bytes.
const WINDOW_SIZE: usize = 4096;
/// Number of leaves in the adaptive tree (literals 0..=255 plus lengths).
const NUM_LEAVES: usize = 314;
/// Total nodes: `NUM_LEAVES * 2 - 1`.
const NUM_NODES: usize = NUM_LEAVES * 2 - 1;
/// Frequency at which the whole tree is rebuilt (halving every frequency).
const RECONSTRUCT_FREQ: i32 = 0x8000;

/// Per-symbol code lengths for the static distance (`distancecode`) Huffman
/// code, copied verbatim from the reference (`XADLZHDynamicHandle` init).
#[rustfmt::skip]
const DISTANCE_LENGTHS: [u32; 64] = [
    3,4,4,4,5,5,5,5,5,5,5,5,6,6,6,6,
    6,6,6,6,6,6,6,6,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
];

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn truncated() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "stuffit5: truncated stream")
}

/// Build the 4096-byte pre-fill pattern (`resetLZSSHandle`). Faithful to the
/// reference, quirks and all — including the constant `+18` shift on every
/// offset and the trailing space run whose length is written as `128 - 18`.
fn initial_window() -> Vec<u8> {
    let mut w = vec![0u8; WINDOW_SIZE];
    // 256 blocks of 13 bytes, block i filled with the value i (bytes 18..3346).
    for i in 0..256 {
        for byte in w[i * 13 + 18..i * 13 + 18 + 13].iter_mut() {
            *byte = i as u8;
        }
    }
    // 0,1,...,255 (bytes 3346..3602).
    for i in 0..256 {
        w[256 * 13 + 18 + i] = i as u8;
    }
    // 255,254,...,0 (bytes 3602..3858).
    for i in 0..256 {
        w[256 * 13 + 256 + 18 + i] = (255 - i) as u8;
    }
    // 128 zero bytes (bytes 3858..3986) — already zero, written for fidelity.
    for byte in w[256 * 13 + 512 + 18..256 * 13 + 512 + 18 + 128].iter_mut() {
        *byte = 0;
    }
    // A run of spaces; the reference records the length as `128 - 18` = 110
    // (bytes 3986..4096).
    for byte in w[256 * 13 + 512 + 128 + 18..256 * 13 + 512 + 128 + 18 + (128 - 18)].iter_mut() {
        *byte = b' ';
    }
    w
}

/// One node of the adaptive Huffman tree, mirroring `XADLZHDynamicNode`.
#[derive(Default)]
struct NodeData {
    /// Index into `storage` of the parent, or `None` at the root.
    parent: Option<usize>,
    /// Left child (`None` on a leaf).
    left: Option<usize>,
    /// Right child (`None` on a leaf).
    right: Option<usize>,
    /// Position of this node in `nodes` (`storage[s].index == p` iff `nodes[p] == s`).
    index: usize,
    /// Occurrence frequency.
    freq: i32,
    /// Symbol value on a leaf (`< 0x100` literal, else a length symbol).
    value: i32,
}

/// The adaptive literal/length tree.
///
/// Two arrays exactly as the reference keeps them:
/// * `storage` — the physical nodes; **the root is always `storage[0]`**.
/// * `nodes` — `nodes[p]` is the `storage` index of the node at position `p`,
///   kept sorted by descending frequency, so `nodes[0]` is the root.
struct AdaptiveTree {
    storage: Vec<NodeData>,
    nodes: Vec<usize>,
}

impl AdaptiveTree {
    /// Build the initial balanced tree (`resetLZSSHandle`, tree part): 314
    /// leaves (values 0..=313, frequency 1) in the tail slots, then internal
    /// nodes summing their children.
    fn new() -> Self {
        let mut storage: Vec<NodeData> = (0..NUM_NODES).map(|_| NodeData::default()).collect();
        let nodes: Vec<usize> = (0..NUM_NODES).collect();

        // Leaves live in the tail of the array: slot 626 holds value 0, ...,
        // slot 313 holds value 313.
        for i in 0..NUM_LEAVES {
            let idx = NUM_NODES - 1 - i;
            storage[idx].index = idx;
            storage[idx].freq = 1;
            storage[idx].value = i as i32;
        }
        // Internal nodes, from 312 down to 0; each sums its two children.
        for i in (0..=NUM_LEAVES - 2).rev() {
            storage[i].index = i;
            storage[i].left = Some(2 * i + 1);
            storage[i].right = Some(2 * i + 2);
            storage[2 * i + 1].parent = Some(i);
            storage[2 * i + 2].parent = Some(i);
            storage[i].freq = storage[2 * i + 1].freq + storage[2 * i + 2].freq;
        }
        // storage[0].parent stays None — the root.
        Self { storage, nodes }
    }

    /// Decode one symbol: descend from the root following MSB bits (1 -> left,
    /// 0 -> right), update frequencies, and return the leaf value.
    fn decode_symbol<R: Read>(&mut self, bits: &mut BitReaderMsb<R>) -> io::Result<i32> {
        let mut node = 0usize;
        while self.storage[node].left.is_some() || self.storage[node].right.is_some() {
            let bit = bits.read(1)?.ok_or_else(truncated)?;
            let child = if bit == 1 {
                self.storage[node].left
            } else {
                self.storage[node].right
            };
            // A valid tree never has one-child nodes, so this only fires on a
            // corrupt stream (defensive; unreachable with well-formed data).
            node = child.ok_or_else(|| invalid("stuffit5: descent into missing child"))?;
        }
        self.update_node(node);
        Ok(self.storage[node].value)
    }

    /// Bump `node`'s frequency and every ancestor's, rebuilding the tree first if
    /// the root frequency has saturated. `rearrange_node` may move `node`, so the
    /// step to the parent reads the *updated* parent link.
    fn update_node(&mut self, mut node: usize) {
        if self.storage[0].freq == RECONSTRUCT_FREQ {
            self.reconstruct_tree();
        }
        loop {
            self.storage[node].freq += 1;
            if self.storage[node].parent.is_none() {
                break;
            }
            self.rearrange_node(node);
            // `rearrange_node` may have moved `node`, so re-read its parent.
            node = self.storage[node].parent.unwrap();
        }
    }

    /// Promote `p` past any lower-frequency nodes that now sit ahead of it in
    /// `nodes`, swapping it with the node it lands on. `p` is never the root
    /// (called only for nodes with a parent), and the landing slot is >= 1.
    fn rearrange_node(&mut self, p: usize) {
        let p_index = self.storage[p].index;
        let p_freq = self.storage[p].freq;
        let mut q_index = p_index;
        while q_index > 0 && self.storage[self.nodes[q_index - 1]].freq < p_freq {
            q_index -= 1;
        }
        if q_index < p_index {
            let q = self.nodes[q_index];
            let pp = self.storage[p].parent.unwrap();
            let qp = self.storage[q].parent.unwrap();
            let p_is_right = self.storage[pp].right == Some(p);
            let q_is_right = self.storage[qp].right == Some(q);
            if p_is_right {
                self.storage[pp].right = Some(q);
            } else {
                self.storage[pp].left = Some(q);
            }
            if q_is_right {
                self.storage[qp].right = Some(p);
            } else {
                self.storage[qp].left = Some(p);
            }
            // p and q trade parents (read above, before the child-link writes).
            self.storage[p].parent = Some(qp);
            self.storage[q].parent = Some(pp);
            self.nodes[p_index] = q;
            self.storage[q].index = p_index;
            self.nodes[q_index] = p;
            self.storage[p].index = q_index;
        }
    }

    /// Rebuild the tree from scratch when the root frequency saturates: halve all
    /// leaf frequencies and reassemble internal nodes bottom-up, reusing the
    /// branch slots `storage[0..=312]`. Counters are signed because indices reach
    /// -1 at the end of a run.
    fn reconstruct_tree(&mut self) {
        // Collect the leaves in `nodes` order, halving each frequency.
        let mut leafs: Vec<usize> = Vec::with_capacity(NUM_LEAVES);
        for i in 0..NUM_NODES {
            let s = self.nodes[i];
            if self.storage[s].left.is_none() && self.storage[s].right.is_none() {
                self.storage[s].freq = (self.storage[s].freq + 1) / 2;
                leafs.push(s);
            }
        }

        let mut leaf_index: i32 = NUM_LEAVES as i32 - 1; // 313
        let mut branch_index: i32 = NUM_LEAVES as i32 - 2; // 312
        let mut node_index: i32 = NUM_NODES as i32 - 1; // 626
        let mut pair_index: i32 = NUM_NODES as i32 - 2; // 625

        while node_index >= 0 {
            while node_index >= pair_index {
                let leaf = leafs[leaf_index as usize];
                self.nodes[node_index as usize] = leaf;
                self.storage[leaf].index = node_index as usize;
                node_index -= 1;
                leaf_index -= 1;
            }

            let branch = branch_index as usize;
            branch_index -= 1;
            let l = self.nodes[pair_index as usize];
            let r = self.nodes[(pair_index + 1) as usize];
            self.storage[branch].left = Some(l);
            self.storage[branch].right = Some(r);
            self.storage[l].parent = Some(branch);
            self.storage[r].parent = Some(branch);
            self.storage[branch].freq = self.storage[l].freq + self.storage[r].freq;

            while leaf_index >= 0
                && self.storage[leafs[leaf_index as usize]].freq <= self.storage[branch].freq
            {
                let leaf = leafs[leaf_index as usize];
                self.nodes[node_index as usize] = leaf;
                self.storage[leaf].index = node_index as usize;
                node_index -= 1;
                leaf_index -= 1;
            }

            self.nodes[node_index as usize] = branch;
            self.storage[branch].index = node_index as usize;
            node_index -= 1;
            pair_index -= 2;
        }
        self.storage[self.nodes[0]].parent = None;
    }
}

/// Decode a method-5 (LZAH) fork: `outlen` decompressed bytes from `src`.
pub(crate) fn decode(src: &[u8], outlen: usize) -> io::Result<Vec<u8>> {
    if outlen == 0 {
        return Ok(Vec::new());
    }

    let mut bits = BitReaderMsb::new(src);
    let distancecode = PrefixCode::from_lengths(&DISTANCE_LENGTHS, 8, true);
    let mut tree = AdaptiveTree::new();
    let mut window = LzssWindow::new(WINDOW_SIZE);
    window.prefill(&initial_window());
    let mut out = Vec::with_capacity(outlen);

    while out.len() < outlen {
        let value = tree.decode_symbol(&mut bits)?;
        if value < 0x100 {
            // Literal.
            window.emit_literal(value as u8, &mut out);
        } else {
            // Match: length from the leaf value, distance from `distancecode`
            // (high 6+ bits) plus six raw low bits.
            let length = (value - 0x100 + 3) as usize;
            let highbits = distancecode
                .next_symbol_msb(&mut bits)?
                .ok_or_else(truncated)? as usize;
            let lowbits = bits.read(6)?.ok_or_else(truncated)? as usize;
            let offset = (highbits << 6) + lowbits + 1;

            // Stop exactly at `outlen`: a match crossing the end yields only the
            // bytes still needed (as the reference produces bytes one at a time).
            let remaining = outlen - out.len();
            window.emit_match(offset, length.min(remaining), &mut out);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // === MSB-first bit writer (testutil's BitWriter is LSB-first) =============

    #[derive(Default)]
    struct MsbWriter {
        bytes: Vec<u8>,
        acc: u32,
        nbits: u32,
    }

    impl MsbWriter {
        fn bit(&mut self, b: bool) {
            self.acc = (self.acc << 1) | u32::from(b);
            self.nbits += 1;
            if self.nbits == 8 {
                self.bytes.push(self.acc as u8);
                self.acc = 0;
                self.nbits = 0;
            }
        }
        fn bits(&mut self, val: u32, n: u32) {
            for i in (0..n).rev() {
                self.bit((val >> i) & 1 != 0);
            }
        }
        fn finish(mut self) -> Vec<u8> {
            if self.nbits > 0 {
                self.bytes.push((self.acc << (8 - self.nbits)) as u8);
            }
            self.bytes
        }
    }

    // === mirror encoder ======================================================
    //
    // An independent inverse of the decoder that keeps an *identical* adaptive
    // tree (the same `AdaptiveTree`, evolved in lockstep) and the same static
    // distance code, so it emits exactly the bits the decoder reads back.

    /// Canonical codes for `DISTANCE_LENGTHS`, replicating
    /// `PrefixCode::from_lengths(.., shortest_code_is_zeros = true)`.
    fn distance_codes() -> HashMap<usize, (u32, u32)> {
        let mut map = HashMap::new();
        let mut code = 0u32;
        for length in 1..=8u32 {
            for (i, &len) in DISTANCE_LENGTHS.iter().enumerate() {
                if len == length {
                    map.insert(i, (code, length));
                    code += 1;
                }
            }
            code <<= 1;
        }
        map
    }

    /// Emit the adaptive-tree code for `value` (walking leaf -> root: a left
    /// child contributes bit 1, a right child bit 0), then evolve the tree.
    fn encode_symbol(tree: &mut AdaptiveTree, w: &mut MsbWriter, value: i32) {
        // Leaf value v lives permanently at slot 626 - v.
        let leaf = NUM_NODES - 1 - value as usize;
        let mut path = Vec::new();
        let mut node = leaf;
        while let Some(p) = tree.storage[node].parent {
            path.push(tree.storage[p].left == Some(node));
            node = p;
        }
        for &bit in path.iter().rev() {
            w.bit(bit);
        }
        tree.update_node(leaf);
    }

    #[derive(Clone, Copy)]
    enum Op {
        Lit(u8),
        Match { dist: usize, len: usize },
    }

    /// Encode a sequence of ops into a method-5 stream.
    fn encode(ops: &[Op]) -> Vec<u8> {
        let mut tree = AdaptiveTree::new();
        let dcodes = distance_codes();
        let mut w = MsbWriter::default();
        for op in ops {
            match *op {
                Op::Lit(b) => encode_symbol(&mut tree, &mut w, i32::from(b)),
                Op::Match { dist, len } => {
                    // Length symbol: value = length - 3 + 0x100.
                    encode_symbol(&mut tree, &mut w, (len as i32) - 3 + 0x100);
                    let highbits = (dist - 1) >> 6;
                    let (c, l) = dcodes[&highbits];
                    w.bits(c, l);
                    w.bits(((dist - 1) & 0x3f) as u32, 6);
                }
            }
        }
        w.finish()
    }

    /// The bytes a sequence of ops expands to over the pre-filled window, using
    /// the same ring semantics as [`LzssWindow`] so early matches read pre-fill.
    fn expand(ops: &[Op]) -> Vec<u8> {
        let mut buf = initial_window();
        let mut pos = 0usize; // absolute emit position
        let mut out = Vec::new();
        for op in ops {
            let count = match *op {
                Op::Lit(_) => 1,
                Op::Match { len, .. } => len,
            };
            for _ in 0..count {
                let byte = match *op {
                    Op::Lit(b) => b,
                    Op::Match { dist, .. } => buf[pos.wrapping_sub(dist) & (WINDOW_SIZE - 1)],
                };
                buf[pos & (WINDOW_SIZE - 1)] = byte;
                pos += 1;
                out.push(byte);
            }
        }
        out
    }

    fn roundtrip(ops: &[Op]) {
        let expected = expand(ops);
        let stream = encode(ops);
        let got = decode(&stream, expected.len()).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn literals_only() {
        let ops: Vec<Op> = b"hello LZAH StuffIt method five"
            .iter()
            .map(|&b| Op::Lit(b))
            .collect();
        roundtrip(&ops);
    }

    #[test]
    fn literal_then_match() {
        // Four literals, then a length-4 back-reference (distance 4) copies them.
        let ops = [
            Op::Lit(b'a'),
            Op::Lit(b'b'),
            Op::Lit(b'c'),
            Op::Lit(b'd'),
            Op::Match { dist: 4, len: 4 },
        ];
        roundtrip(&ops);
    }

    #[test]
    fn match_distance_extra_bits() {
        // Distance 100 -> highbits = 99 >> 6 = 1, so `distancecode` yields a
        // non-zero symbol and the six low bits carry the remainder.
        let ops = [
            Op::Lit(b'x'),
            Op::Lit(b'y'),
            Op::Match { dist: 100, len: 5 },
        ];
        roundtrip(&ops);
    }

    #[test]
    fn overlapping_run() {
        // Distance 1, long length -> a run-length repeat of one byte.
        let ops = [Op::Lit(b'Z'), Op::Match { dist: 1, len: 40 }];
        roundtrip(&ops);
    }

    #[test]
    fn maximum_length_match() {
        // Value 313 -> length 60, the largest a single length symbol encodes.
        let ops = [Op::Lit(b'q'), Op::Match { dist: 1, len: 60 }];
        roundtrip(&ops);
    }

    #[test]
    fn zero_outlen_returns_empty_without_parsing() {
        // No bits are read at all, so even non-empty input is ignored.
        assert_eq!(decode(&[], 0).unwrap(), Vec::<u8>::new());
        assert_eq!(decode(&[0xFF, 0x00], 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn truncated_stream_is_unexpected_eof() {
        // Drop the tail so the match's distance/low bits cannot be read.
        let ops = [Op::Lit(b'a'), Op::Match { dist: 100, len: 5 }];
        let mut stream = encode(&ops);
        stream.truncate(1);
        let err = decode(&stream, expand(&ops).len()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
