// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Unix `compress` LZW decoder (the classic `.Z` algorithm).
//!
//! Codes are read least-significant-bit first at a width that starts at 9 bits
//! and grows by one each time the string table doubles, up to `maxbits`. In
//! *block mode* the code `256` is a reserved "clear" that resets the table; the
//! bytes after a clear are padded so that codes stay grouped in runs of eight,
//! and that padding is skipped.
//!
//! Used by several ARC compression methods (Crunched-LZW, Squashed, Compressed).

use std::io::{self, Read};

const CLEAR: u32 = 256;

/// Streaming Unix-`compress` (LZW) decoder, exposed as a [`Read`] adapter.
pub struct CompressReader<R> {
    bits: LsbBits<R>,
    maxbits: u8,
    blockmode: bool,

    // LZW string table: each entry is (parent, byte). Index < 256 are literals.
    parent: Vec<i32>,
    chr: Vec<u8>,
    numsymbols: usize,
    symbolsize: u8,
    prevsymbol: i32,
    symbolcounter: usize,

    // Decoded-but-not-yet-returned bytes.
    out: Vec<u8>,
    outpos: usize,
    done: bool,
}

impl<R: Read> CompressReader<R> {
    /// Wrap `inner`. `maxbits` is the maximum code width (typically 12–16);
    /// `blockmode` enables the reserved clear code and group padding.
    pub fn new(inner: R, maxbits: u8, blockmode: bool) -> Self {
        let size = 1usize << maxbits;
        let parent = vec![-1i32; size]; // literals (index < 256) have no parent
        let mut chr = vec![0u8; size];
        for (i, c) in chr.iter_mut().enumerate().take(256) {
            *c = i as u8;
        }
        let mut this = CompressReader {
            bits: LsbBits::new(inner),
            maxbits,
            blockmode,
            parent,
            chr,
            numsymbols: 0,
            symbolsize: 9,
            prevsymbol: -1,
            symbolcounter: 0,
            out: Vec::new(),
            outpos: 0,
            done: false,
        };
        this.clear_table();
        this
    }

    fn clear_table(&mut self) {
        // Block mode reserves one extra code (256) as the clear marker.
        self.numsymbols = 256 + usize::from(self.blockmode);
        self.prevsymbol = -1;
        self.symbolsize = 9;
    }

    fn first_byte(&self, mut symbol: usize) -> u8 {
        while self.parent[symbol] >= 0 {
            symbol = self.parent[symbol] as usize;
        }
        self.chr[symbol]
    }

    /// Append the byte string for `symbol` (root-to-leaf order) to `self.out`.
    fn emit(&mut self, symbol: usize) {
        let start = self.out.len();
        let mut s = symbol as i32;
        while s >= 0 {
            self.out.push(self.chr[s as usize]);
            s = self.parent[s as usize];
        }
        self.out[start..].reverse();
    }

    /// Read and decode one code, appending its expansion to `self.out`.
    /// Sets `self.done` at end of input. Returns an error on a corrupt code.
    fn decode_one(&mut self) -> io::Result<()> {
        // Read the next code, restarting the table on a block-mode clear.
        let symbol = loop {
            let symbol = match self.bits.read(self.symbolsize)? {
                Some(s) => s,
                None => {
                    self.done = true;
                    return Ok(());
                }
            };
            self.symbolcounter += 1;

            if symbol == CLEAR && self.blockmode {
                // Codes are packed in groups of eight; skip the padding that
                // follows a clear so the next code starts on a group boundary.
                let rem = self.symbolcounter % 8;
                if rem != 0 {
                    self.bits.skip(self.symbolsize as u32 * (8 - rem as u32))?;
                }
                self.clear_table();
                self.symbolcounter = 0;
                continue;
            }
            break symbol as usize;
        };

        if self.prevsymbol < 0 {
            self.prevsymbol = symbol as i32;
            self.emit(symbol);
            return Ok(());
        }

        let postfix = if symbol < self.numsymbols {
            self.first_byte(symbol)
        } else if symbol == self.numsymbols {
            self.first_byte(self.prevsymbol as usize)
        } else {
            return Err(corrupt());
        };

        let new_parent = self.prevsymbol;
        self.prevsymbol = symbol as i32;

        if self.numsymbols < (1usize << self.maxbits) {
            self.parent[self.numsymbols] = new_parent;
            self.chr[self.numsymbols] = postfix;
            self.numsymbols += 1;
            if self.numsymbols < (1usize << self.maxbits)
                && self.numsymbols & (self.numsymbols - 1) == 0
            {
                self.symbolsize += 1;
            }
        }

        self.emit(symbol);
        Ok(())
    }
}

fn corrupt() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "compress: invalid LZW code")
}

impl<R: Read> Read for CompressReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.outpos >= self.out.len() {
            if self.done {
                return Ok(0);
            }
            self.out.clear();
            self.outpos = 0;
            self.decode_one()?;
        }
        let n = (self.out.len() - self.outpos).min(buf.len());
        buf[..n].copy_from_slice(&self.out[self.outpos..self.outpos + n]);
        self.outpos += n;
        Ok(n)
    }
}

/// Variable-width least-significant-bit-first bit reader over an inner byte
/// stream.
struct LsbBits<R> {
    inner: R,
    acc: u64,
    nbits: u8,
}

impl<R: Read> LsbBits<R> {
    fn new(inner: R) -> Self {
        LsbBits {
            inner,
            acc: 0,
            nbits: 0,
        }
    }

    /// Read `n` bits (n ≤ 24), least-significant first. `None` once the input
    /// runs out before `n` bits are available.
    fn read(&mut self, n: u8) -> io::Result<Option<u32>> {
        while self.nbits < n {
            match crate::read_one_byte(&mut self.inner)? {
                Some(b) => {
                    self.acc |= u64::from(b) << self.nbits;
                    self.nbits += 8;
                }
                None => return Ok(None),
            }
        }
        let mask = (1u64 << n) - 1;
        let v = (self.acc & mask) as u32;
        self.acc >>= n;
        self.nbits -= n;
        Ok(Some(v))
    }

    /// Discard `n` bits, stopping early if the input ends.
    fn skip(&mut self, mut n: u32) -> io::Result<()> {
        while n > 0 {
            let take = n.min(24);
            if self.read(take as u8)?.is_none() {
                return Ok(());
            }
            n -= take;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode exactly `n` bytes from `stream`.
    fn decode_n(stream: &[u8], n: usize, maxbits: u8, blockmode: bool) -> Vec<u8> {
        let mut r = CompressReader::new(stream, maxbits, blockmode);
        let mut out = vec![0u8; n];
        r.read_exact(&mut out).unwrap();
        out
    }

    #[test]
    fn decodes_run_of_a() {
        // "AAAA", maxbits 12, block mode (Python-verified stream).
        let stream = [0x41, 0x02, 0x06, 0x01];
        assert_eq!(decode_n(&stream, 4, 12, true), b"AAAA");
    }

    #[test]
    fn decodes_alternating() {
        // "ABABABAB", maxbits 12, block mode.
        let stream = [0x41, 0x84, 0x04, 0x1c, 0x28, 0x04];
        assert_eq!(decode_n(&stream, 8, 12, true), b"ABABABAB");
    }

    #[test]
    fn decodes_longer_text() {
        // "Hello, Hello, Hello world!!!", 28 bytes.
        let stream = [
            0x48, 0xca, 0xb0, 0x61, 0xf3, 0x86, 0x05, 0x88, 0x80, 0x03, 0x0b, 0x1e, 0x14, 0x48,
            0x10, 0xc4, 0x9d, 0x37, 0x72, 0xd8, 0x90, 0x09, 0x41, 0x11,
        ];
        assert_eq!(
            decode_n(&stream, 28, 12, true),
            b"Hello, Hello, Hello world!!!"
        );
    }

    #[test]
    fn decodes_single_literal() {
        assert_eq!(decode_n(&[0x41, 0x00], 1, 12, true), b"A");
    }

    #[test]
    fn empty_stream_yields_nothing() {
        let mut out = Vec::new();
        CompressReader::new(&[][..], 12, true)
            .read_to_end(&mut out)
            .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn decodes_without_block_mode() {
        // Without block mode the first free code is 256 (no reserved clear),
        // so the same "AAAA" input encodes to a different stream.
        assert_eq!(decode_n(&[0x41, 0x00, 0x06, 0x01], 4, 12, false), b"AAAA");
    }

    #[test]
    fn truncated_stream_stops_cleanly() {
        // Fewer bits than a full code remain → decoder stops without erroring.
        let mut out = Vec::new();
        CompressReader::new(&[0x41][..], 12, true)
            .read_to_end(&mut out)
            .unwrap();
        assert!(out.is_empty());
    }
}
