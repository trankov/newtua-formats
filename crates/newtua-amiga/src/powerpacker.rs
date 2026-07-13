// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! PowerPacker (`PP20`) decruncher.
//!
//! The file is
//! `"PP20"`, a 4-byte offset-width table, the crunched bitstream, and a trailing
//! longword: 3 bytes of decrunched length plus 1 byte giving how many alignment
//! bits to discard at the start. The bitstream is read **MSB-first from the end
//! of the file backward**, and output is produced **back to front** — an LZ77
//! scheme with literal runs and back-references.

use std::io;

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// Reads bits MSB-first from the end of `data` backward (PowerPacker layout).
/// `bitpos` starts just before the trailing 32-bit length/skip longword.
struct BackwardBits<'a> {
    data: &'a [u8],
    bitpos: usize,
}

impl<'a> BackwardBits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            bitpos: data.len() * 8 - 32,
        }
    }

    fn get(&mut self, n: u32) -> io::Result<u32> {
        let mut result = 0u32;
        for _ in 0..n {
            if self.bitpos == 0 {
                return Err(invalid("powerpacker: bitstream underrun"));
            }
            self.bitpos -= 1;
            let byte = self.bitpos / 8;
            let bit = 7 - (self.bitpos & 7);
            result = (result << 1) | u32::from((self.data[byte] >> bit) & 1);
        }
        Ok(result)
    }
}

/// A parsed PowerPacker file, decoded on demand.
pub struct PowerPackerFile {
    data: Vec<u8>,
}

impl PowerPackerFile {
    /// Parse the `PP20` header. PowerPacker carries no internal filename — the
    /// caller names the output (conventionally the source name without its
    /// extension).
    pub fn open(data: &[u8]) -> io::Result<Self> {
        // Need magic (4) + offset table (4) + trailing longword (4).
        if data.len() < 12 || &data[0..4] != b"PP20" {
            return Err(invalid("powerpacker: bad magic"));
        }
        Ok(Self {
            data: data.to_vec(),
        })
    }

    /// The decrunched length, from the 24-bit big-endian trailing field.
    pub fn decoded_len(&self) -> usize {
        let n = self.data.len();
        (usize::from(self.data[n - 4]) << 16)
            | (usize::from(self.data[n - 3]) << 8)
            | usize::from(self.data[n - 2])
    }

    /// Decrunch the file.
    pub fn decode(&self) -> io::Result<Vec<u8>> {
        unpack(&self.data[4..], self.decoded_len())
    }
}

fn unpack(packed: &[u8], out_len: usize) -> io::Result<Vec<u8>> {
    let mut out = vec![0u8; out_len];
    let mut bits = BackwardBits::new(packed);
    let mut dest = out_len;

    // Discard the alignment bits the cruncher padded the first word with.
    let skip = u32::from(packed[packed.len() - 1]);
    bits.get(skip)?;

    loop {
        if bits.get(1)? == 0 {
            // Literal run: a 1, then 2-bit groups (each 3 means "continue").
            let mut count = 1usize;
            loop {
                let add = bits.get(2)? as usize;
                count += add;
                if add != 3 {
                    break;
                }
            }
            for _ in 0..count {
                if dest == 0 {
                    return Err(invalid("powerpacker: output overrun"));
                }
                dest -= 1;
                out[dest] = bits.get(8)? as u8;
            }
            if dest == 0 {
                return Ok(out);
            }
        }

        // Back-reference. The 2-bit index selects a length class and the number
        // of offset bits from the table; class 3 (length >= 5) is extensible.
        let index = bits.get(2)? as usize;
        let offset_bits = u32::from(packed[index]);
        let mut count = index + 2;
        let offset = if count == 5 {
            let off = if bits.get(1)? == 0 {
                bits.get(7)? as usize
            } else {
                bits.get(offset_bits)? as usize
            };
            loop {
                let add = bits.get(3)? as usize;
                count += add;
                if add != 7 {
                    break;
                }
            }
            off
        } else {
            bits.get(offset_bits)? as usize
        };

        for _ in 0..count {
            if dest == 0 {
                return Err(invalid("powerpacker: output overrun"));
            }
            let src = dest + offset;
            if src >= out_len {
                return Err(invalid("powerpacker: back-reference out of range"));
            }
            out[dest - 1] = out[src];
            dest -= 1;
        }
        if dest == 0 {
            return Ok(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Validated against `unar`: decrunches to "A" (literal-only path).
    const PP_A: &[u8] = &[
        0x50, 0x50, 0x32, 0x30, // "PP20"
        0x09, 0x0A, 0x0C, 0x0D, // offset table
        0x04, 0x10, // bitstream
        0x00, 0x00, 0x01, 0x00, // length = 1, skip = 0
    ];

    // Validated against `unar`: decrunches to "AAA" (literal + back-reference).
    const PP_AAA: &[u8] = &[
        0x50, 0x50, 0x32, 0x30, // "PP20"
        0x01, 0x0A, 0x0C, 0x0D, // offset table (table[0]=1 → 1 offset bit)
        0x04, 0x10, // bitstream
        0x00, 0x00, 0x03, 0x00, // length = 3, skip = 0
    ];

    #[test]
    fn reports_decoded_len() {
        assert_eq!(PowerPackerFile::open(PP_A).unwrap().decoded_len(), 1);
        assert_eq!(PowerPackerFile::open(PP_AAA).unwrap().decoded_len(), 3);
    }

    #[test]
    fn decodes_literal_only() {
        assert_eq!(PowerPackerFile::open(PP_A).unwrap().decode().unwrap(), b"A");
    }

    #[test]
    fn decodes_with_back_reference() {
        assert_eq!(
            PowerPackerFile::open(PP_AAA).unwrap().decode().unwrap(),
            b"AAA"
        );
    }

    #[test]
    fn rejects_bad_magic() {
        let bad = [0x50, 0x50, 0x31, 0x31, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(PowerPackerFile::open(&bad).is_err());
    }

    #[test]
    fn rejects_too_short() {
        assert!(PowerPackerFile::open(b"PP20").is_err());
    }

    #[test]
    fn truncated_stream_errors() {
        // Same bytes as PP_A but the length field claims 10 bytes, so the
        // decoder runs the bitstream dry before reaching the start.
        let mut bad = PP_A.to_vec();
        bad[12] = 0x0A;
        assert!(PowerPackerFile::open(&bad).unwrap().decode().is_err());
    }
}
