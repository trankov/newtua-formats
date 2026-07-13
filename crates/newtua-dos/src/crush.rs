// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! ARC "Crush" (method 0xa) — an adaptive LZW with usage-based code replacement
//! and a switchable literal-bit coding mode.
//!
//! Codes are read least-significant-bit first. The string table is a 8192-slot
//! LZW tree (256 literals, code 256 reserved as the end-of-data marker, strings
//! from 257). Two things make it unusual:
//!
//!   * **Literal-bit mode.** A 500-symbol sliding window tracks how many recent
//!     symbols were multi-byte strings. While literals dominate, each symbol is
//!     prefixed by one bit selecting literal (8 bits) or string (variable). Once
//!     strings dominate, the prefix is dropped and both share one width — and,
//!     due to a quirk of the original encoder, literal codes are bit-inverted.
//!   * **Replacement.** Once the table fills, new strings evict the
//!     least-recently-used entry instead of growing the table.
//!
//! Faithful port of XADMaster's `XADARCCrushHandle.m`.

use std::io::{self, Read};

use newtua_common::bitreader::BitReaderLsb;

const MAX_SYMBOLS: usize = 8192;
const EOF_CODE: usize = 0x100;
const RING: usize = 500;

/// Streaming ARC-Crush decoder, exposed as a [`Read`] adapter.
pub struct CrushReader<R> {
    bits: BitReaderLsb<R>,

    chr: Vec<u8>,
    parent: Vec<i32>,
    numsymbols: usize,
    prevsymbol: i32,

    symbolsize: u8,
    nextsizebump: i32,
    useliteralbit: bool,

    numrecentstrings: i32,
    ringindex: usize,
    stringring: Vec<bool>,
    usageindex: usize,
    usage: Vec<u8>,

    // Decoded bytes of the current symbol, in output order (front to back).
    out: Vec<u8>,
    outpos: usize,
    done: bool,
}

impl<R: Read> CrushReader<R> {
    /// Wrap `inner` as an ARC-Crush bit stream.
    pub fn new(inner: R) -> Self {
        let mut chr = vec![0u8; MAX_SYMBOLS];
        for (i, c) in chr.iter_mut().enumerate().take(256) {
            *c = i as u8;
        }
        CrushReader {
            bits: BitReaderLsb::new(inner),
            chr,
            parent: vec![-1; MAX_SYMBOLS],
            numsymbols: 257,
            prevsymbol: -1,
            symbolsize: 1,
            nextsizebump: 2,
            useliteralbit: true,
            numrecentstrings: 0,
            ringindex: 0,
            stringring: vec![false; RING],
            usageindex: 0x101,
            usage: vec![0u8; MAX_SYMBOLS],
            out: Vec::new(),
            outpos: 0,
            done: false,
        }
    }

    /// First byte of the string for `sym` (walk to the root of its tree).
    fn first_byte(&self, mut sym: usize) -> u8 {
        while self.parent[sym] >= 0 {
            sym = self.parent[sym] as usize;
        }
        self.chr[sym]
    }

    /// Read the next code. Returns `None` at the end-of-data marker or when the
    /// bit stream runs dry.
    fn read_symbol(&mut self) -> io::Result<Option<usize>> {
        let symbol = if self.useliteralbit {
            // A leading bit selects literal (8 bits) or string (variable).
            match self.bits.read_bits(1)? {
                None => return Ok(None),
                Some(0) => match self.bits.read_bits(8)? {
                    None => return Ok(None),
                    Some(v) => v as usize,
                },
                Some(_) => match self.bits.read_bits(self.symbolsize)? {
                    None => return Ok(None),
                    Some(v) => v as usize + 256,
                },
            }
        } else {
            // One width for both; literals come through bit-inverted.
            match self.bits.read_bits(self.symbolsize)? {
                None => return Ok(None),
                Some(v) => {
                    let s = v as usize;
                    if s < 0x100 {
                        s ^ 0xff
                    } else {
                        s
                    }
                }
            }
        };
        if symbol == EOF_CODE {
            Ok(None)
        } else {
            Ok(Some(symbol))
        }
    }

    /// Append a new string `string(prevsymbol) + first_byte(symbol)` to the tree
    /// (the classic LZW lag), or just seed `prevsymbol` on the first symbol.
    fn grow_tree(&mut self, symbol: usize) -> io::Result<()> {
        if self.prevsymbol < 0 {
            self.prevsymbol = symbol as i32;
            return Ok(());
        }
        let postfix = if symbol < self.numsymbols {
            self.first_byte(symbol)
        } else if symbol == self.numsymbols {
            self.first_byte(self.prevsymbol as usize)
        } else {
            return Err(corrupt());
        };
        let parent = self.prevsymbol;
        self.prevsymbol = symbol as i32;
        let n = self.numsymbols;
        self.parent[n] = parent;
        self.chr[n] = postfix;
        self.numsymbols += 1;
        Ok(())
    }

    /// Reassign the full table's least-used slot `old` to a new string.
    fn replace_tree(&mut self, old: usize, symbol: usize) -> io::Result<()> {
        if symbol >= self.numsymbols {
            return Err(corrupt());
        }
        self.parent[old] = self.prevsymbol;
        self.chr[old] = self.first_byte(symbol);
        self.prevsymbol = symbol as i32;
        Ok(())
    }

    /// Decode the bytes of `prevsymbol` into `self.out`, in output order.
    fn build_output(&mut self) {
        self.out.clear();
        let mut sym = self.prevsymbol;
        while sym >= 0 {
            self.out.push(self.chr[sym as usize]);
            sym = self.parent[sym as usize];
        }
        self.out.reverse();
        self.outpos = 0;
    }

    fn decode_one(&mut self) -> io::Result<()> {
        let symbol = match self.read_symbol()? {
            Some(s) => s,
            None => {
                self.done = true;
                return Ok(());
            }
        };

        // Bump the usage of the symbol and all its parents to the maximum, so a
        // freshly-seen string is not the next one evicted.
        let mut m = symbol as i32;
        while m >= 0 {
            self.usage[m as usize] = 4;
            m = self.parent[m as usize];
        }

        // Slide the 500-symbol window and recount how many were strings.
        if self.stringring[self.ringindex] {
            self.numrecentstrings -= 1;
        }
        let is_string = symbol >= 0x100;
        self.stringring[self.ringindex] = is_string;
        if is_string {
            self.numrecentstrings += 1;
        }
        self.ringindex = (self.ringindex + 1) % RING;

        // Switch coding mode if literals vs strings tipped over the threshold.
        let manyliterals = self.numrecentstrings < 375;
        if manyliterals != self.useliteralbit {
            self.useliteralbit = manyliterals;
            self.nextsizebump = 1 << self.symbolsize;
            if !self.useliteralbit {
                self.nextsizebump -= 0x100;
            }
        }

        // Add the symbol to the tree, growing it or evicting once it is full.
        if self.numsymbols != MAX_SYMBOLS {
            self.grow_tree(symbol)?;
            self.usage[self.numsymbols - 1] = 2;
        } else {
            let (mut minindex, mut minusage) = (0usize, i32::MAX);
            let mut index = self.usageindex;
            loop {
                index += 1;
                if index == 8192 {
                    index = 0x101;
                }
                let u = i32::from(self.usage[index]);
                if u < minusage {
                    minindex = index;
                    minusage = u;
                }
                self.usage[index] = self.usage[index].wrapping_sub(1);
                if self.usage[index] == 0 || index == self.usageindex {
                    break;
                }
            }
            self.usageindex = index;
            self.replace_tree(minindex, symbol)?;
            self.usage[minindex] = 2;
        }

        self.build_output();

        // Widen codes once enough strings exist; the trigger depends on mode.
        if self.numsymbols as i32 - 257 >= self.nextsizebump {
            self.symbolsize += 1;
            self.nextsizebump = 1 << self.symbolsize;
            if !self.useliteralbit {
                self.nextsizebump -= 0x100;
            }
        }
        Ok(())
    }
}

fn corrupt() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "crush: corrupt code stream")
}

impl<R: Read> Read for CrushReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut written = 0;
        while written < buf.len() {
            if self.outpos == self.out.len() {
                if self.done {
                    break;
                }
                self.decode_one()?;
                continue;
            }
            buf[written] = self.out[self.outpos];
            self.outpos += 1;
            written += 1;
        }
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhex::hex;

    fn decode(stream: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        CrushReader::new(stream).read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn decodes_run() {
        assert_eq!(decode(&hex(b"82041d")), b"AAAA");
    }

    #[test]
    fn decodes_alternating() {
        assert_eq!(decode(&hex(b"8208bd05")), b"ABABABAB");
    }

    #[test]
    fn decodes_repeated_word() {
        assert_eq!(decode(&hex(b"c48471ab3020731700")), b"banana banana");
    }

    #[test]
    fn decodes_sentence() {
        assert_eq!(
            decode(&hex(b"e8a02903224e9d3463d6801023e7cd1d3720ccbcc10b00")),
            b"the quick brown fox"
        );
    }

    #[test]
    fn empty_input_yields_nothing() {
        assert!(decode(&[]).is_empty());
    }

    #[test]
    fn lone_eof_marker_yields_nothing() {
        // 0x01 = literal-bit set then a 1-bit string code 0 → code 0x100 (EOF).
        assert!(decode(&hex(b"01")).is_empty());
    }

    #[test]
    fn truncated_stream_stops_without_hanging() {
        // First 3 bytes of the validated "banana banana" stream: decoding must
        // terminate at the short read and yield a prefix of the full output.
        let out = decode(&hex(b"c48471"));
        assert!(
            b"banana banana".starts_with(&out[..]),
            "got {out:?}, not a prefix of the expected output"
        );
    }
}
