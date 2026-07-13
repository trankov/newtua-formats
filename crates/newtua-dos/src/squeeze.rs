// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Squeeze (`.SQ`) — CP/M-era single-file Huffman compressor.
//!
//! File layout:
//! `0x76 0xFF`, a u16 LE checksum, a NUL-terminated original filename, then the
//! Huffman-compressed stream: a u16 LE node count followed by `count * 2` i16 LE
//! values (two child links per node). A child `< 0` is a leaf with value
//! `-(child + 1)`; value 256 marks end of stream. The decoded Huffman output is
//! then RLE90-decoded to yield the original file.

use std::io::{self, Read};

use newtua_common::bitreader::BitReaderLsb;
use newtua_common::bytes::{read_u16_le, read_u8};
use newtua_common::rle90::Rle90Reader;

const EOF_SYMBOL: u16 = 256;
const MAX_NODES: usize = 257;

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// The Huffman layer of Squeeze: a [`Read`] adapter that decodes the node-tree
/// compressed stream into its (still RLE90-encoded) byte sequence.
pub struct SqueezeReader<R: Read> {
    bits: BitReaderLsb<R>,
    /// Child links, two per node: node `n` has children `nodes[2n]`, `nodes[2n+1]`.
    nodes: Vec<i16>,
    done: bool,
}

impl<R: Read> SqueezeReader<R> {
    /// Read the node table from `inner`, leaving it positioned at the bitstream.
    pub fn new(mut inner: R) -> io::Result<Self> {
        let node_count = read_u16_le(&mut inner)? as usize;
        if node_count == 0 || node_count >= MAX_NODES {
            return Err(invalid("squeeze: invalid node count"));
        }
        let mut nodes = vec![0i16; node_count * 2];
        for slot in &mut nodes {
            *slot = read_u16_le(&mut inner)? as i16;
        }
        Ok(Self {
            bits: BitReaderLsb::new(inner),
            nodes,
            done: false,
        })
    }

    /// Walk the tree one bit at a time to the next symbol; `None` if the bits
    /// run out before a leaf is reached.
    fn next_symbol(&mut self) -> io::Result<Option<u16>> {
        // `node` is always a valid internal index here: 0 to start (the table
        // has >= 2 entries) and bounds-checked on every descent below.
        let mut node = 0usize;
        loop {
            let bit = match self.bits.read_bit()? {
                Some(b) => b as usize,
                None => return Ok(None),
            };
            let child = self.nodes[node * 2 + bit];
            if child < 0 {
                return Ok(Some((-(child as i32 + 1)) as u16));
            }
            node = child as usize;
            if node * 2 + 1 >= self.nodes.len() {
                return Err(invalid("squeeze: node index out of range"));
            }
        }
    }
}

impl<R: Read> Read for SqueezeReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut n = 0;
        while n < out.len() && !self.done {
            match self.next_symbol()? {
                Some(EOF_SYMBOL) => self.done = true,
                Some(sym) => {
                    out[n] = sym as u8;
                    n += 1;
                }
                None => return Err(invalid("squeeze: truncated stream (no EOF symbol)")),
            }
        }
        Ok(n)
    }
}

/// A parsed Squeeze archive: one file, decoded on demand.
pub struct SqueezeFile {
    name: Vec<u8>,
    checksum: u16,
    data: Vec<u8>,
}

impl SqueezeFile {
    /// Parse the `.SQ` header from `r` and buffer the compressed body.
    pub fn open<R: Read>(mut r: R) -> io::Result<Self> {
        if read_u8(&mut r)? != 0x76 || read_u8(&mut r)? != 0xff {
            return Err(invalid("squeeze: bad magic"));
        }
        let checksum = read_u16_le(&mut r)?;

        let mut name = Vec::new();
        loop {
            let b = read_u8(&mut r)?;
            if b == 0 {
                break;
            }
            name.push(b);
        }

        let mut data = Vec::new();
        r.read_to_end(&mut data)?;
        Ok(Self {
            name,
            checksum,
            data,
        })
    }

    /// The original filename, as raw bytes (charset decoding is the caller's job).
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Decode the file: Huffman → RLE90, then verify the stored checksum.
    pub fn decode(&self) -> io::Result<Vec<u8>> {
        let squeeze = SqueezeReader::new(&self.data[..])?;
        let mut rle = Rle90Reader::new(squeeze);
        let mut out = Vec::new();
        rle.read_to_end(&mut out)?;

        let sum: u32 = out.iter().map(|&b| u32::from(b)).sum();
        if (sum & 0xffff) as u16 != self.checksum {
            return Err(invalid("squeeze: checksum mismatch"));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode just the Huffman layer (no RLE90).
    fn squeeze_only(stream: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        SqueezeReader::new(stream)?.read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn decodes_single_symbol_then_eof() {
        // 1 node: root. left(bit0)=leaf 0x41 (-66), right(bit1)=leaf 256 (-257).
        // bitstream: 0x41 = bit 0, EOF = bit 1 → bits [0,1] = 0b10 = 0x02.
        let stream = [0x01, 0x00, 0xBE, 0xFF, 0xFF, 0xFE, 0x02];
        assert_eq!(squeeze_only(&stream).unwrap(), b"A");
    }

    #[test]
    fn decodes_two_symbols() {
        // 2 nodes. node0: L=leaf 0x41 (-66), R=node1 (1).
        //          node1: L=leaf 0x42 (-67), R=leaf 256 (-257).
        // bits: 'A'=0 ; 'B'=1,0 ; EOF=1,1 → [0,1,0,1,1] = 0b11010 = 0x1A.
        let stream = [
            0x02, 0x00, // node count = 2
            0xBE, 0xFF, // nodes[0] = -66  (leaf 'A')
            0x01, 0x00, // nodes[1] =  1   (node 1)
            0xBD, 0xFF, // nodes[2] = -67  (leaf 'B')
            0xFF, 0xFE, // nodes[3] = -257 (leaf EOF)
            0x1A, // bitstream
        ];
        assert_eq!(squeeze_only(&stream).unwrap(), b"AB");
    }

    #[test]
    fn rejects_too_many_nodes() {
        let stream = [0x01, 0x02]; // node count = 0x0201 = 513 >= 257
        assert!(SqueezeReader::new(&stream[..]).is_err());
    }

    #[test]
    fn rejects_zero_nodes() {
        let stream = [0x00, 0x00];
        assert!(SqueezeReader::new(&stream[..]).is_err());
    }

    #[test]
    fn truncated_node_table_errors() {
        let stream = [0x02, 0x00, 0xBE]; // promises 2 nodes, table cut short
        assert!(SqueezeReader::new(&stream[..]).is_err());
    }

    // A complete `.SQ` for content "A": magic, checksum 0x0041, name "a", then
    // the single-symbol squeeze stream from `decodes_single_symbol_then_eof`.
    const SQ_A: &[u8] = &[
        0x76, 0xFF, // magic
        0x41, 0x00, // checksum = 0x41 (sum of "A")
        0x61, 0x00, // name "a\0"
        0x01, 0x00, 0xBE, 0xFF, 0xFF, 0xFE, 0x02, // squeeze stream
    ];

    #[test]
    fn container_parses_name() {
        let f = SqueezeFile::open(SQ_A).unwrap();
        assert_eq!(f.name(), b"a");
    }

    #[test]
    fn container_decodes_single_byte() {
        let f = SqueezeFile::open(SQ_A).unwrap();
        assert_eq!(f.decode().unwrap(), b"A");
    }

    #[test]
    fn container_decodes_two_bytes() {
        let sq_ab: &[u8] = &[
            0x76, 0xFF, // magic
            0x83, 0x00, // checksum = 0x41 + 0x42
            0x61, 0x62, 0x00, // name "ab\0"
            0x02, 0x00, 0xBE, 0xFF, 0x01, 0x00, 0xBD, 0xFF, 0xFF, 0xFE, 0x1A,
        ];
        let f = SqueezeFile::open(sq_ab).unwrap();
        assert_eq!(f.name(), b"ab");
        assert_eq!(f.decode().unwrap(), b"AB");
    }

    #[test]
    fn rejects_bad_magic() {
        let bad = [0x00, 0xFF, 0x00, 0x00, 0x61, 0x00];
        assert!(SqueezeFile::open(&bad[..]).is_err());
    }

    #[test]
    fn checksum_mismatch_errors() {
        let mut bad = SQ_A.to_vec();
        bad[2] = 0x42; // wrong checksum (should be 0x41)
        let f = SqueezeFile::open(&bad[..]).unwrap();
        assert!(f.decode().is_err());
    }
}
