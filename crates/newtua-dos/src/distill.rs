//! ARC "Distilled" (method 0x0b) — LZSS with a header-supplied Huffman code.
//!
//! Unlike the other ARC methods this one is not LZW. The compressed stream
//! begins with a serialised main Huffman tree (a `u16` node count, a code-width
//! byte, then that many fixed-width node links), after which symbols are decoded
//! least-significant-bit first:
//!
//! - `< 256` is a literal byte;
//! - `256` ends the stream;
//! - `> 256` is a match of length `symbol - 0x101 + 3`, whose offset is a
//!   6-bit value from a fixed prefix table (`offsetcode`) shifted by a number of
//!   extra bits that grows with the output position, plus those extra bits, plus
//!   one.
//!
//! Ported from XADMaster's `XADARCDistillHandle.m`, built on the shared
//! [`PrefixCode`] and [`LzssWindow`] primitives.

use std::io;

use newtua_common::bitreader::BitReaderLsb;
use newtua_common::lzss::LzssWindow;
use newtua_common::prefixcode::PrefixCode;

/// Window size (8 KiB), matching XADMaster.
const WINDOW_SIZE: usize = 8192;
/// Upper bound on the serialised node count (`XADARCDistillHandle` raises above this).
const MAX_NODES: usize = 0x274;

/// Bit length of each entry in the fixed offset prefix table.
const OFFSET_LENGTHS: [u32; 0x40] = [
    3, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, //
    6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, //
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, //
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, //
];

/// Codes (low-bit-first) of the fixed offset prefix table.
const OFFSET_CODES: [u32; 0x40] = [
    0x00, 0x02, 0x04, 0x0c, 0x01, 0x06, 0x0a, 0x0e, //
    0x11, 0x16, 0x1a, 0x1e, 0x05, 0x09, 0x0d, 0x15, //
    0x19, 0x1d, 0x25, 0x29, 0x2d, 0x35, 0x39, 0x3d, //
    0x03, 0x07, 0x0b, 0x13, 0x17, 0x1b, 0x23, 0x27, //
    0x2b, 0x33, 0x37, 0x3b, 0x43, 0x47, 0x4b, 0x53, //
    0x57, 0x5b, 0x63, 0x67, 0x6b, 0x73, 0x77, 0x7b, //
    0x0f, 0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x6f, 0x7f, //
    0x8f, 0x9f, 0xaf, 0xbf, 0xcf, 0xdf, 0xef, 0xff, //
];

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// Number of extra offset bits at output position `pos` (grows as the window
/// fills). Mirrors the ladder in `expandFromPosition:`.
fn extra_offset_bits(pos: u64) -> u8 {
    const BIAS: u64 = 0x3c;
    const EDGES: [u64; 7] = [0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000];
    for (i, edge) in EDGES.iter().enumerate() {
        if pos < edge - BIAS {
            return i as u8;
        }
    }
    7
}

/// Build the fixed offset prefix code shared by every Distilled stream.
fn build_offset_code() -> PrefixCode {
    let mut code = PrefixCode::new();
    for i in 0..0x40 {
        code.add_value_low_bit_first(i as i32, OFFSET_CODES[i], OFFSET_LENGTHS[i]);
    }
    code
}

/// Expand the header node array into `code`, mirroring `BuildCodeFromTree`. A
/// value `>= numnodes` is a leaf (`value - numnodes`); otherwise it indexes the
/// pair `nodes[value]`, `nodes[value+1]`. `budget` bounds recursion so malformed
/// (cyclic) trees error instead of overflowing the stack.
fn build_tree(
    code: &mut PrefixCode,
    nodes: &[u32],
    value: u32,
    budget: &mut i32,
) -> io::Result<()> {
    *budget -= 1;
    if *budget < 0 {
        return Err(invalid("distill: malformed Huffman tree"));
    }
    let numnodes = nodes.len() as u32;
    if value >= numnodes {
        code.make_leaf((value - numnodes) as i32);
        return Ok(());
    }
    let idx = value as usize;
    if idx + 1 >= nodes.len() {
        return Err(invalid("distill: node index out of range"));
    }
    code.start_zero_branch();
    build_tree(code, nodes, nodes[idx], budget)?;
    code.start_one_branch();
    build_tree(code, nodes, nodes[idx + 1], budget)?;
    code.finish_branches();
    Ok(())
}

/// Decode a full Distilled stream into its bytes.
pub fn decode(input: &[u8]) -> io::Result<Vec<u8>> {
    let header = input
        .get(..3)
        .ok_or_else(|| invalid("distill: truncated header"))?;
    let numnodes = u16::from_le_bytes([header[0], header[1]]) as usize;
    let codelength = header[2];

    if numnodes < 2 {
        return Err(invalid("distill: too few nodes"));
    }
    if numnodes > MAX_NODES {
        return Err(invalid("distill: too many nodes"));
    }
    if codelength == 0 || codelength > 24 {
        return Err(invalid("distill: invalid code width"));
    }

    let mut bits = BitReaderLsb::new(&input[3..]);

    let mut nodes = vec![0u32; numnodes];
    for slot in &mut nodes {
        *slot = bits
            .read_bits(codelength)?
            .ok_or_else(|| invalid("distill: truncated node table"))?;
    }

    let mut maincode = PrefixCode::new();
    maincode.start_building_tree();
    let mut budget = (numnodes as i32) * 4 + 16;
    build_tree(&mut maincode, &nodes, (numnodes - 2) as u32, &mut budget)?;

    let offsetcode = build_offset_code();
    let mut window = LzssWindow::new(WINDOW_SIZE);
    let mut out = Vec::new();

    loop {
        let symbol = maincode
            .next_symbol_le(&mut bits)?
            .ok_or_else(|| invalid("distill: truncated stream (no end symbol)"))?;

        if symbol == 256 {
            return Ok(out);
        }
        if symbol < 256 {
            window.emit_literal(symbol as u8, &mut out);
            continue;
        }

        let length = (symbol - 0x101 + 3) as usize;
        if length > WINDOW_SIZE {
            return Err(invalid("distill: match length exceeds window"));
        }
        let offsetsymbol = offsetcode
            .next_symbol_le(&mut bits)?
            .ok_or_else(|| invalid("distill: truncated offset code"))?;
        let extralength = extra_offset_bits(window.position());
        let extrabits = bits
            .read_bits(extralength)?
            .ok_or_else(|| invalid("distill: truncated offset bits"))?;
        let distance = ((offsetsymbol as u64) << extralength) + extrabits as u64 + 1;
        window.emit_match(distance as usize, length, &mut out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A binary tree used to drive the test encoder.
    enum Tree {
        Leaf(i32),
        Node(Box<Tree>, Box<Tree>),
    }

    fn leaf(v: i32) -> Box<Tree> {
        Box::new(Tree::Leaf(v))
    }
    fn node(l: Box<Tree>, r: Box<Tree>) -> Box<Tree> {
        Box::new(Tree::Node(l, r))
    }

    /// LSB-first bit writer used to assemble compressed streams in tests.
    #[derive(Default)]
    struct BitWriter {
        bytes: Vec<u8>,
        cur: u8,
        nbits: u8,
    }

    impl BitWriter {
        fn bit(&mut self, b: bool) {
            if b {
                self.cur |= 1 << self.nbits;
            }
            self.nbits += 1;
            if self.nbits == 8 {
                self.bytes.push(self.cur);
                self.cur = 0;
                self.nbits = 0;
            }
        }
        fn bits(&mut self, val: u32, n: u32) {
            for i in 0..n {
                self.bit((val >> i) & 1 != 0);
            }
        }
        fn finish(mut self) -> Vec<u8> {
            if self.nbits > 0 {
                self.bytes.push(self.cur);
            }
            self.bytes
        }
    }

    fn count_internal(t: &Tree) -> usize {
        match t {
            Tree::Leaf(_) => 0,
            Tree::Node(l, r) => 1 + count_internal(l) + count_internal(r),
        }
    }

    /// Serialise a tree into the header node array (post-order so the root is the
    /// last pair, at index `numnodes - 2`).
    fn serialise(t: &Tree) -> Vec<u32> {
        let numnodes = (2 * count_internal(t)) as u32;
        let mut pairs: Vec<[u32; 2]> = Vec::new();
        fn alloc(t: &Tree, numnodes: u32, pairs: &mut Vec<[u32; 2]>) -> u32 {
            match t {
                Tree::Leaf(v) => numnodes + *v as u32,
                Tree::Node(l, r) => {
                    let lc = alloc(l, numnodes, pairs);
                    let rc = alloc(r, numnodes, pairs);
                    pairs.push([lc, rc]);
                    ((pairs.len() - 1) * 2) as u32
                }
            }
        }
        alloc(t, numnodes, &mut pairs);
        pairs.into_iter().flatten().collect()
    }

    /// Map each leaf symbol to its bit path (root-to-leaf, decode order).
    fn code_table(t: &Tree) -> std::collections::HashMap<i32, Vec<bool>> {
        let mut map = std::collections::HashMap::new();
        fn walk(
            t: &Tree,
            prefix: &mut Vec<bool>,
            map: &mut std::collections::HashMap<i32, Vec<bool>>,
        ) {
            match t {
                Tree::Leaf(v) => {
                    map.insert(*v, prefix.clone());
                }
                Tree::Node(l, r) => {
                    prefix.push(false);
                    walk(l, prefix, map);
                    prefix.pop();
                    prefix.push(true);
                    walk(r, prefix, map);
                    prefix.pop();
                }
            }
        }
        walk(t, &mut Vec::new(), &mut map);
        map
    }

    /// A token in the symbol stream.
    enum Tok {
        Lit(u8),
        Match {
            distance: usize,
            length: usize,
        },
        /// Emit a raw main-code symbol with no following offset (for crafting
        /// malformed streams).
        Sym(i32),
        End,
    }

    /// Encode a Distilled stream from a tree and a token list.
    fn encode(tree: &Tree, toks: &[Tok]) -> Vec<u8> {
        let nodes = serialise(tree);
        let codes = code_table(tree);
        let maxval = *nodes.iter().max().unwrap_or(&0);
        let codelength = (32 - maxval.leading_zeros()).max(1);

        let numnodes = nodes.len() as u16;
        let mut out = numnodes.to_le_bytes().to_vec();
        out.push(codelength as u8);

        let mut bw = BitWriter::default();
        for &v in &nodes {
            bw.bits(v, codelength);
        }

        let mut pos: u64 = 0;
        let write_symbol = |bw: &mut BitWriter, sym: i32| {
            for &b in &codes[&sym] {
                bw.bit(b);
            }
        };
        for tok in toks {
            match tok {
                Tok::Lit(b) => {
                    write_symbol(&mut bw, *b as i32);
                    pos += 1;
                }
                Tok::Match { distance, length } => {
                    write_symbol(&mut bw, (*length as i32) - 3 + 0x101);
                    let extralen = extra_offset_bits(pos);
                    let v = (*distance as u32) - 1;
                    let offsym = (v >> extralen) as usize;
                    assert!(offsym < 0x40, "offset symbol {offsym} out of range");
                    bw.bits(OFFSET_CODES[offsym], OFFSET_LENGTHS[offsym]);
                    bw.bits(v & ((1 << extralen) - 1), extralen as u32);
                    pos += *length as u64;
                }
                Tok::Sym(s) => write_symbol(&mut bw, *s),
                Tok::End => write_symbol(&mut bw, 256),
            }
        }
        out.extend_from_slice(&bw.finish());
        out
    }

    /// A tree over a small literal alphabet plus EOF and the given match-length
    /// symbols, nested so every symbol is reachable.
    fn alphabet_tree(symbols: &[i32]) -> Box<Tree> {
        // Right-leaning chain: each symbol on a left branch, the rest to the right.
        let mut it = symbols.iter().rev();
        let last = *it.next().expect("non-empty alphabet");
        let mut t = leaf(last);
        for &s in it {
            t = node(leaf(s), t);
        }
        t
    }

    #[test]
    fn decodes_all_literal_stream() {
        // Tree: 0 -> 'A' (65), 1 -> EOF (256).
        let tree = node(leaf(65), leaf(256));
        let stream = encode(&tree, &[Tok::Lit(b'A'), Tok::End]);
        assert_eq!(decode(&stream).unwrap(), b"A");
    }

    #[test]
    fn decodes_multiple_literals() {
        let tree = alphabet_tree(&[b'B' as i32, b'A' as i32, b'N' as i32, 256]);
        let toks: Vec<Tok> = b"BANANA"
            .iter()
            .map(|&b| Tok::Lit(b))
            .chain([Tok::End])
            .collect();
        let stream = encode(&tree, &toks);
        assert_eq!(decode(&stream).unwrap(), b"BANANA");
    }

    #[test]
    fn decodes_match_back_reference() {
        // "AB" then a length-4 match at distance 2 -> "ABABAB".
        let tree = alphabet_tree(&[b'A' as i32, b'B' as i32, 0x101 + 1, 256]);
        let stream = encode(
            &tree,
            &[
                Tok::Lit(b'A'),
                Tok::Lit(b'B'),
                Tok::Match {
                    distance: 2,
                    length: 4,
                },
                Tok::End,
            ],
        );
        assert_eq!(decode(&stream).unwrap(), b"ABABAB");
    }

    #[test]
    fn truncated_stream_without_end_errors() {
        let tree = node(leaf(65), leaf(256));
        let stream = encode(&tree, &[Tok::Lit(b'A')]); // no End symbol
        assert!(decode(&stream).is_err());
    }

    #[test]
    fn match_length_over_window_errors() {
        // A symbol whose decoded length exceeds the 8 KiB window.
        let big = 0x101 + WINDOW_SIZE as i32; // length = WINDOW_SIZE + 3
        let tree = alphabet_tree(&[big, 256]);
        let stream = encode(&tree, &[Tok::Sym(big), Tok::End]);
        assert!(decode(&stream).is_err());
    }

    #[test]
    fn short_header_errors() {
        assert!(decode(&[]).is_err());
        assert!(decode(&[0x02, 0x00]).is_err());
    }

    #[test]
    fn too_few_nodes_errors() {
        // numnodes = 1 (< 2), codelength = 9.
        assert!(decode(&[0x01, 0x00, 0x09]).is_err());
    }
}
