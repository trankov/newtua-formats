//! StuffIt Huffman decoder — the compression used inside PackIt's `PMa4/5/6`
//! records and classic StuffIt's method 3.
//!
//! Faithful port of XADMaster's `XADStuffItHuffmanHandle`. The code tree is
//! written directly into the bit stream, most-significant-bit first:
//!
//! ```text
//! parse_tree:
//!     bit == 1 -> a leaf whose value is the next 8 bits
//!     bit == 0 -> an internal node: recurse zero-branch, then one-branch
//! ```
//!
//! After the tree, each output byte is one symbol decoded through it. The decoder
//! reads from an in-memory slice and tracks how many source bytes it has
//! consumed (rounded up to a byte boundary) so the container can find where the
//! next record begins — the bookkeeping `CSInputBufferOffset` provides in the
//! reference.

use std::io;

use crate::prefixcode::PrefixCode;

fn unexpected_eof() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "stuffit huffman: unexpected end",
    )
}

/// A most-significant-bit-first cursor over a byte slice that tracks its bit
/// position (so the consumed byte count can be reported).
struct BitCursor<'a> {
    data: &'a [u8],
    bitpos: usize,
}

impl<'a> BitCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, bitpos: 0 }
    }
    /// Next bit (MSB first), or `None` at end of input.
    fn read_bit(&mut self) -> io::Result<Option<bool>> {
        let byte = self.bitpos >> 3;
        if byte >= self.data.len() {
            return Ok(None);
        }
        let bit = (self.data[byte] >> (7 - (self.bitpos & 7))) & 1;
        self.bitpos += 1;
        Ok(Some(bit != 0))
    }
    /// Next `n`-bit value (MSB first); errors if fewer than `n` bits remain.
    fn read_bits(&mut self, n: u32) -> io::Result<u32> {
        let mut acc = 0u32;
        for _ in 0..n {
            match self.read_bit()? {
                Some(b) => acc = (acc << 1) | u32::from(b),
                None => return Err(unexpected_eof()),
            }
        }
        Ok(acc)
    }
    /// Bytes consumed so far, rounded up to a byte boundary — what the container
    /// uses to locate the next record (mirrors `CSInputSkipToByteBoundary` then
    /// `CSInputBufferOffset`).
    fn consumed_bytes(&self) -> usize {
        self.bitpos.div_ceil(8)
    }
}

/// A StuffIt Huffman stream: the decoded code tree plus the bit cursor over the
/// (already decrypted, if applicable) source bytes.
pub struct StuffItHuffman<'a> {
    cursor: BitCursor<'a>,
    code: PrefixCode,
}

impl<'a> StuffItHuffman<'a> {
    /// Read the code tree from the front of `data`, leaving the cursor at the
    /// first symbol.
    pub fn new(data: &'a [u8]) -> io::Result<Self> {
        let mut me = Self {
            cursor: BitCursor::new(data),
            code: PrefixCode::new(),
        };
        me.code.start_building_tree();
        me.parse_tree()?;
        Ok(me)
    }

    /// Recursively read one subtree. Port of `-parseTree`.
    fn parse_tree(&mut self) -> io::Result<()> {
        match self.cursor.read_bit()? {
            None => Err(unexpected_eof()),
            Some(true) => {
                let value = self.cursor.read_bits(8)? as i32;
                self.code.make_leaf(value);
                Ok(())
            }
            Some(false) => {
                self.code.start_zero_branch();
                self.parse_tree()?;
                self.code.start_one_branch();
                self.parse_tree()?;
                self.code.finish_branches();
                Ok(())
            }
        }
    }

    /// Decode one output byte (one symbol through the tree).
    fn next_byte(&mut self) -> io::Result<u8> {
        let cursor = &mut self.cursor;
        let code = &self.code;
        match code.next_symbol_msb_with(|| cursor.read_bit())? {
            Some(v) => Ok(v as u8),
            None => Err(unexpected_eof()),
        }
    }

    /// Decode exactly `n` output bytes.
    pub fn read_exact(&mut self, n: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.next_byte()?);
        }
        Ok(out)
    }

    /// Source bytes consumed so far, rounded up to a byte boundary.
    pub fn consumed_bytes(&self) -> usize {
        self.cursor.consumed_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal MSB-first bit writer mirroring `BitCursor`.
    struct BitW {
        out: Vec<u8>,
        acc: u8,
        n: u8,
    }
    impl BitW {
        fn new() -> Self {
            BitW {
                out: Vec::new(),
                acc: 0,
                n: 0,
            }
        }
        fn put_bit(&mut self, b: u32) {
            self.acc = (self.acc << 1) | (b as u8 & 1);
            self.n += 1;
            if self.n == 8 {
                self.out.push(self.acc);
                self.acc = 0;
                self.n = 0;
            }
        }
        fn put_bits(&mut self, val: u32, bits: u32) {
            for i in (0..bits).rev() {
                self.put_bit((val >> i) & 1);
            }
        }
        fn finish(mut self) -> Vec<u8> {
            if self.n > 0 {
                self.acc <<= 8 - self.n;
                self.out.push(self.acc);
            }
            self.out
        }
    }

    /// Mirror tree builder: balanced tree over the present byte set, serialised
    /// the way the decoder reads it (internal -> 0 + recurse; leaf -> 1 + value).
    fn write_tree(w: &mut BitW, symbols: &[u8]) {
        if symbols.len() == 1 {
            w.put_bit(1);
            w.put_bits(u32::from(symbols[0]), 8);
            return;
        }
        let mid = symbols.len() / 2;
        w.put_bit(0);
        write_tree(w, &symbols[..mid]);
        write_tree(w, &symbols[mid..]);
    }

    /// Encode `content` into a StuffIt Huffman stream using a balanced tree over
    /// its distinct bytes.
    fn encode(content: &[u8]) -> Vec<u8> {
        let mut symbols: Vec<u8> = content.to_vec();
        symbols.sort_unstable();
        symbols.dedup();

        let mut w = BitW::new();
        write_tree(&mut w, &symbols);

        // Build the code map by replaying the same recursive split.
        let mut codes: std::collections::HashMap<u8, (u32, u32)> = std::collections::HashMap::new();
        fn walk(
            symbols: &[u8],
            prefix: u32,
            len: u32,
            codes: &mut std::collections::HashMap<u8, (u32, u32)>,
        ) {
            if symbols.len() == 1 {
                codes.insert(symbols[0], (prefix, len));
                return;
            }
            let mid = symbols.len() / 2;
            walk(&symbols[..mid], prefix << 1, len + 1, codes);
            walk(&symbols[mid..], (prefix << 1) | 1, len + 1, codes);
        }
        walk(&symbols, 0, 0, &mut codes);

        for &b in content {
            let (code, len) = codes[&b];
            w.put_bits(code, len);
        }
        w.finish()
    }

    #[test]
    fn single_leaf_tree_decodes_repeated_symbol() {
        // A one-symbol alphabet: the tree is a single leaf, each symbol consumes
        // no bits.
        let stream = encode(b"AAAA");
        let mut h = StuffItHuffman::new(&stream).unwrap();
        assert_eq!(h.read_exact(4).unwrap(), b"AAAA");
    }

    #[test]
    fn nested_tree_decodes_bytes() {
        let content = b"hello huffman world";
        let stream = encode(content);
        let mut h = StuffItHuffman::new(&stream).unwrap();
        assert_eq!(h.read_exact(content.len()).unwrap(), content);
    }

    #[test]
    fn all_byte_values_round_trip() {
        let content: Vec<u8> = (0..=255u8).collect();
        let stream = encode(&content);
        let mut h = StuffItHuffman::new(&stream).unwrap();
        assert_eq!(h.read_exact(content.len()).unwrap(), content);
    }

    #[test]
    fn consumed_bytes_is_byte_aligned() {
        let content = b"abcabc";
        let stream = encode(content);
        let mut h = StuffItHuffman::new(&stream).unwrap();
        h.read_exact(content.len()).unwrap();
        // Whatever the bit length, the consumed count never exceeds the stream.
        assert!(h.consumed_bytes() <= stream.len());
        assert!(h.consumed_bytes() >= 1);
    }

    #[test]
    fn truncated_tree_is_error() {
        // All-zero bits promise ever-deeper internal nodes; the stream ends
        // before any leaf, so building the tree fails.
        assert!(StuffItHuffman::new(&[0x00]).is_err());
    }

    #[test]
    fn reading_past_end_errors() {
        let stream = encode(b"AB");
        let mut h = StuffItHuffman::new(&stream).unwrap();
        // Far more than encoded -> must hit end of input.
        assert!(h.read_exact(10_000).is_err());
    }
}
