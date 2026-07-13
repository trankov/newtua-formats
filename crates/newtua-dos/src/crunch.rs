// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! ARC "Crunch" (methods 5/6/7) — a fixed 12-bit LZW with a hash-coded string
//! table.
//!
//! Codes are 12 bits, most-significant-bit first. Unlike Unix `compress`, the
//! code values are not sequential: each new string `(parent, byte)` is placed
//! into a 4096-slot table at a position derived from a hash of its parent code
//! and byte, with linear probing on collision. The decoder rebuilds that table
//! as it goes, so the same hash must be reproduced exactly. Two hash variants
//! exist: a "fast" multiplicative one and the older quadratic one.
//!
//! Faithful port of XADMaster's `XADARCCrunchHandle.m`.

use std::io::{self, Read};

use newtua_common::bitreader::BitReaderMsb;

const TABLE_SIZE: usize = 4096;

/// Which hash places new strings into the Crunch table.
#[derive(Clone, Copy)]
pub enum CrunchHash {
    /// Older quadratic hash (methods 5 and 6).
    Quadratic,
    /// Faster multiplicative hash (method 7).
    Multiplicative,
}

/// Streaming ARC-Crunch decoder, exposed as a [`Read`] adapter.
pub struct CrunchReader<R> {
    bits: BitReaderMsb<R>,
    hash_kind: CrunchHash,

    used: Vec<bool>,
    byte: Vec<u8>,
    next: Vec<usize>,
    parent: Vec<i32>,

    numfreecodes: usize,
    lastcode: usize,
    lastbyte: u8,

    // Output bytes for the current code, in reverse (pop from the end).
    stack: Vec<u8>,
    started: bool,
    done: bool,
}

impl<R: Read> CrunchReader<R> {
    /// Wrap `inner`, selecting the hash variant for the ARC method.
    pub fn new(inner: R, hash_kind: CrunchHash) -> Self {
        let mut this = CrunchReader {
            bits: BitReaderMsb::new(inner),
            hash_kind,
            used: vec![false; TABLE_SIZE],
            byte: vec![0; TABLE_SIZE],
            next: vec![0; TABLE_SIZE],
            parent: vec![-1; TABLE_SIZE],
            numfreecodes: TABLE_SIZE - 256,
            lastcode: 0,
            lastbyte: 0,
            stack: Vec::new(),
            started: false,
            done: false,
        };
        for i in 0..256 {
            this.update(-1, i as u8);
        }
        this
    }

    fn hash(&self, parent: i32, byte: u8) -> usize {
        let pb = parent.wrapping_add(byte as i32);
        match self.hash_kind {
            CrunchHash::Multiplicative => ((pb & 0xffff).wrapping_mul(15073) & 0xfff) as usize,
            CrunchHash::Quadratic => {
                let index = (pb | 0x0800) & 0xffff;
                ((index.wrapping_mul(index) >> 6) & 0xfff) as usize
            }
        }
    }

    /// Insert `(parent, byte)` into the hash table, returning its slot.
    fn update(&mut self, parent: i32, byte: u8) -> usize {
        let mut index = self.hash(parent, byte);
        if self.used[index] {
            while self.next[index] != 0 {
                index = self.next[index];
            }
            let mut nxt = (index + 101) & 0xfff;
            while self.used[nxt] {
                nxt = (nxt + 1) & 0xfff;
            }
            self.next[index] = nxt;
            index = nxt;
        }
        self.used[index] = true;
        self.next[index] = 0;
        self.parent[index] = parent;
        self.byte[index] = byte;
        index
    }

    /// Decode the next code into `self.stack` (reversed). Sets `self.done` at
    /// end of input.
    fn decode_one(&mut self) -> io::Result<()> {
        if !self.started {
            self.started = true;
            match self.bits.read(12)? {
                Some(code) => {
                    let code = code as usize;
                    let b = self.byte[code];
                    self.stack.push(b);
                    self.lastcode = code;
                    self.lastbyte = b;
                }
                None => self.done = true,
            }
            return Ok(());
        }

        let code = match self.bits.read(12)? {
            Some(c) => c as usize,
            None => {
                self.done = true;
                return Ok(());
            }
        };

        let mut idx = code;
        if !self.used[idx] {
            // KwKwK: code not yet in the table — reuse the previous string plus
            // its own first byte.
            idx = self.lastcode;
            self.stack.push(self.lastbyte);
        }
        while self.parent[idx] != -1 {
            self.stack.push(self.byte[idx]);
            idx = self.parent[idx] as usize;
            // A valid string is at most TABLE_SIZE long; a longer walk means the
            // parent links form a cycle from corrupt input.
            if self.stack.len() > TABLE_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "crunch: corrupt code table (cycle)",
                ));
            }
        }
        let byte = self.byte[idx];
        self.stack.push(byte);

        if self.numfreecodes != 0 {
            self.update(self.lastcode as i32, byte);
            self.numfreecodes -= 1;
        }
        self.lastcode = code;
        self.lastbyte = byte;
        Ok(())
    }
}

impl<R: Read> Read for CrunchReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut written = 0;
        while written < buf.len() {
            if self.stack.is_empty() {
                if self.done {
                    break;
                }
                self.decode_one()?;
                continue;
            }
            buf[written] = self.stack.pop().unwrap();
            written += 1;
        }
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhex::hex;

    fn decode_n(stream: &[u8], n: usize, hash: CrunchHash) -> Vec<u8> {
        let mut r = CrunchReader::new(stream, hash);
        let mut out = vec![0u8; n];
        r.read_exact(&mut out).unwrap();
        out
    }

    #[test]
    fn decodes_run_slow_hash() {
        assert_eq!(
            decode_n(&hex(b"0a5d1f0a50"), 4, CrunchHash::Quadratic),
            b"AAAA"
        );
    }

    #[test]
    fn decodes_alternating_slow_hash() {
        assert_eq!(
            decode_n(&hex(b"0a5082d6698b0820"), 8, CrunchHash::Quadratic),
            b"ABABABAB"
        );
    }

    #[test]
    fn decodes_run_fast_hash() {
        assert_eq!(
            decode_n(&hex(b"8403618400"), 4, CrunchHash::Multiplicative),
            b"AAAA"
        );
    }

    #[test]
    fn decodes_text_slow_hash() {
        assert_eq!(
            decode_n(
                &hex(b"938890bf93d58907cf07523e23e0"),
                13,
                CrunchHash::Quadratic
            ),
            b"banana banana"
        );
    }

    #[test]
    fn empty_input_yields_nothing() {
        let mut out = Vec::new();
        CrunchReader::new(&[][..], CrunchHash::Quadratic)
            .read_to_end(&mut out)
            .unwrap();
        assert!(out.is_empty());
    }
}
