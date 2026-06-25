//! Prefix (Huffman) code trees.
//!
//! A [`PrefixCode`] is a binary tree whose leaves carry symbol values. It is
//! built either incrementally (mirroring XADMaster's
//! `startBuildingTree`/`startZeroBranch`/`startOneBranch`/`finishBranches`/
//! `makeLeafWithValue`, used to expand a tree serialised in an archive header)
//! or one code at a time with [`PrefixCode::add_value_low_bit_first`]. Symbols
//! are then decoded least-significant-bit first via
//! [`PrefixCode::next_symbol_le`].
//!
//! Ported from XADMaster's `XADPrefixCode` (the plain tree-walk path; the
//! decode-acceleration tables are intentionally omitted).

use std::io::{self, Read};

use crate::bitreader::BitReaderLsb;

/// An empty (not-yet-assigned) tree node: both branches open. Encoded with the
/// same `-1`/`-2` sentinels as XADMaster so a half-built internal node (one
/// branch set, one still negative) is distinguishable from a leaf.
const EMPTY: [i32; 2] = [-1, -2];

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// A prefix-code tree mapping bit sequences to integer symbol values.
pub struct PrefixCode {
    /// Each node holds its two child links. A negative link is an open branch;
    /// a node whose two links are equal is a leaf carrying that value.
    tree: Vec<[i32; 2]>,
    /// Current node during an incremental build.
    currnode: usize,
    /// Saved nodes to return to when a branch subtree finishes.
    stack: Vec<usize>,
}

impl Default for PrefixCode {
    fn default() -> Self {
        Self::new()
    }
}

impl PrefixCode {
    /// A new tree containing just an empty root.
    pub fn new() -> Self {
        Self {
            tree: vec![EMPTY],
            currnode: 0,
            stack: Vec::new(),
        }
    }

    /// Append a fresh empty node and return its index.
    fn new_node(&mut self) -> usize {
        self.tree.push(EMPTY);
        self.tree.len() - 1
    }

    /// A leaf is a node whose two branch links are equal (they hold its value).
    fn is_leaf(&self, node: usize) -> bool {
        self.tree[node][0] == self.tree[node][1]
    }

    /// Descend into `bit` of the current node, creating that child.
    fn start_branch(&mut self, bit: usize) {
        let new = self.new_node() as i32;
        self.tree[self.currnode][bit] = new;
        self.stack.push(self.currnode);
        self.currnode = new as usize;
    }

    /// Begin an incremental top-down build at the root.
    pub fn start_building_tree(&mut self) {
        self.currnode = 0;
        self.stack.clear();
    }

    /// Descend into the `0` branch of the current node, creating it.
    pub fn start_zero_branch(&mut self) {
        self.start_branch(0);
    }

    /// Descend into the `1` branch of the current node, creating it.
    pub fn start_one_branch(&mut self) {
        self.start_branch(1);
    }

    /// Finish the current branch subtree and return to its parent.
    pub fn finish_branches(&mut self) {
        if let Some(parent) = self.stack.pop() {
            self.currnode = parent;
        }
    }

    /// Make the current node a leaf with `value`, then return to its parent.
    pub fn make_leaf(&mut self, value: i32) {
        self.tree[self.currnode] = [value, value];
        self.finish_branches();
    }

    /// Add one code for `value`, given as `length` bits with the
    /// least-significant bit consumed first (the order [`next_symbol_le`]
    /// reads). Used for statically-defined code tables.
    pub fn add_value_low_bit_first(&mut self, value: i32, code: u32, length: u32) {
        let mut node = 0usize;
        for i in 0..length {
            let bit = ((code >> i) & 1) as usize;
            if self.tree[node][bit] < 0 {
                let new = self.new_node() as i32;
                self.tree[node][bit] = new;
            }
            node = self.tree[node][bit] as usize;
        }
        self.tree[node] = [value, value];
    }

    /// Decode the next symbol, reading bits least-significant-first from `bits`.
    /// `Ok(None)` if the bitstream ends before a leaf is reached.
    pub fn next_symbol_le<R: Read>(&self, bits: &mut BitReaderLsb<R>) -> io::Result<Option<i32>> {
        let mut node = 0usize;
        while !self.is_leaf(node) {
            let bit = match bits.read_bit()? {
                Some(b) => b as usize,
                None => return Ok(None),
            };
            let next = self.tree[node][bit];
            if next < 0 {
                return Err(invalid("prefix code: invalid code in bitstream"));
            }
            node = next as usize;
        }
        Ok(Some(self.tree[node][0]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Decode exactly `count` symbols (the primitive has no built-in EOF; the
    /// caller decides when to stop, so a test must not over-drain trailing bits).
    fn decode_n(code: &PrefixCode, stream: &[u8], count: usize) -> Vec<i32> {
        let mut bits = BitReaderLsb::new(Cursor::new(stream.to_vec()));
        (0..count)
            .map(|_| code.next_symbol_le(&mut bits).unwrap().unwrap())
            .collect()
    }

    #[test]
    fn incremental_build_two_leaves_decodes_lsb_first() {
        // Root: branch 0 -> leaf 65, branch 1 -> leaf 66.
        let mut code = PrefixCode::new();
        code.start_building_tree();
        code.start_zero_branch();
        code.make_leaf(65);
        code.start_one_branch();
        code.make_leaf(66);
        code.finish_branches();

        // bits LSB-first [0,1] = byte 0b10 = 0x02 -> [65, 66].
        assert_eq!(decode_n(&code, &[0x02], 2), vec![65, 66]);
    }

    #[test]
    fn add_value_low_bit_first_full_two_bit_code() {
        // Four 2-bit codes (low-bit-first): 00->7, 10->8, 01->9, 11->10.
        let mut code = PrefixCode::new();
        code.add_value_low_bit_first(7, 0b00, 2);
        code.add_value_low_bit_first(8, 0b10, 2);
        code.add_value_low_bit_first(9, 0b01, 2);
        code.add_value_low_bit_first(10, 0b11, 2);

        // Symbols [7,8,9,10] -> LSB bit pairs 00 01 10 11 packed into 0xD8.
        assert_eq!(decode_n(&code, &[0xD8], 4), vec![7, 8, 9, 10]);
    }

    #[test]
    fn nested_tree_exercises_branch_stack() {
        // Codes (LSB-first): 0->10, 1,0->20, 1,1,0->30, 1,1,1->40.
        let mut code = PrefixCode::new();
        code.start_building_tree();
        code.start_zero_branch();
        code.make_leaf(10);
        code.start_one_branch();
        code.start_zero_branch();
        code.make_leaf(20);
        code.start_one_branch();
        code.start_zero_branch();
        code.make_leaf(30);
        code.start_one_branch();
        code.make_leaf(40);
        code.finish_branches();
        code.finish_branches();
        code.finish_branches();

        // bits 0 | 1,0 | 1,1,0 | 1,1,1 = 0,1,0,1,1,0,1,1,1 -> [0xDA, 0x01].
        assert_eq!(decode_n(&code, &[0xDA, 0x01], 4), vec![10, 20, 30, 40]);
    }

    #[test]
    fn unreachable_open_branch_is_invalid_code() {
        // Only the code 0,0 is defined; the 1 branch off the root stays open.
        let mut code = PrefixCode::new();
        code.add_value_low_bit_first(1, 0b00, 2);

        // First bit 1 (byte 0x01) steers into the open branch.
        let mut bits = BitReaderLsb::new(Cursor::new(vec![0x01u8]));
        assert!(code.next_symbol_le(&mut bits).is_err());
    }

    #[test]
    fn empty_bitstream_yields_none() {
        let mut code = PrefixCode::new();
        code.add_value_low_bit_first(1, 0b0, 1);
        code.add_value_low_bit_first(2, 0b1, 1);

        let mut bits = BitReaderLsb::new(Cursor::new(Vec::new()));
        assert_eq!(code.next_symbol_le(&mut bits).unwrap(), None);
    }
}
