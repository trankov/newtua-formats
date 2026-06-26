//! LZH-static decoder — the shared LZSS-plus-static-Huffman codec used by both
//! Zoo (method 2, 13-bit window) and ARJ (methods 1/2/3, 15-bit window).
//!
//! Each block carries two static prefix codes — one for literals and match
//! lengths, one for match distances — followed by that many literal/match
//! tokens driving an LZSS sliding window. The only parameter that varies
//! between formats is the window size; the distance-code field width follows
//! from it (`window_bits < 15 ? 4 : 5`).
//!
//! Faithful port of XADMaster's `XADLZHStaticHandle`.

use std::io::{self, Read};

use newtua_common::bitreader::BitReaderMsb;
use newtua_common::lzss::LzssWindow;
use newtua_common::prefixcode::PrefixCode;

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// LZH-static decoder: an LZSS sliding window driven by two per-block prefix
/// codes — one for literals and match lengths, one for match distances. Stops
/// once the caller has drained the expected number of bytes.
pub(crate) struct LzhStaticReader<R> {
    bits: BitReaderMsb<R>,
    window: LzssWindow,
    window_bits: u32,
    buffer: Vec<u8>,
    buffer_pos: usize,
    finished: bool,
}

impl<R: Read> LzhStaticReader<R> {
    pub(crate) fn new(inner: R, window_bits: u32) -> Self {
        Self {
            bits: BitReaderMsb::new(inner),
            window: LzssWindow::new(1 << window_bits),
            window_bits,
            buffer: Vec::new(),
            buffer_pos: 0,
            finished: false,
        }
    }

    /// Read an `n`-bit field, treating a short read as a truncated stream.
    fn rb(&mut self, n: u8, msg: &'static str) -> io::Result<u32> {
        self.bits.read(n)?.ok_or_else(|| invalid(msg))
    }

    /// Decode one whole block into `buffer`: its block size, the two prefix
    /// codes, then that many literal/match tokens. Returns `false` at end of
    /// input (no more blocks).
    fn decode_block(&mut self) -> io::Result<bool> {
        let blocksize = match self.bits.read(16)? {
            Some(n) => n,
            None => return Ok(false),
        };
        let literalcode = self.parse_literal_code()?;
        let width = if self.window_bits < 15 { 4 } else { 5 };
        let distancecode = self.parse_code_of_width(width, -1)?;

        for _ in 0..blocksize {
            let lit = literalcode
                .next_symbol_msb(&mut self.bits)?
                .ok_or_else(|| invalid("lzh: truncated LZH stream"))?;
            if lit < 0x100 {
                self.window.emit_literal(lit as u8, &mut self.buffer);
            } else {
                let length = (lit - 0x100 + 3) as usize;
                let bit = distancecode
                    .next_symbol_msb(&mut self.bits)?
                    .ok_or_else(|| invalid("lzh: truncated LZH stream"))?;
                let offset = match bit {
                    0 => 1,
                    1 => 2,
                    b => {
                        (1usize << (b - 1))
                            + self.rb((b - 1) as u8, "lzh: truncated LZH stream")? as usize
                            + 1
                    }
                };
                self.window.emit_match(offset, length, &mut self.buffer);
            }
        }
        Ok(true)
    }

    /// `allocAndParseCodeOfWidth:specialIndex:` — read a prefix code whose
    /// symbol count and per-symbol lengths are serialised `bits`-wide.
    fn parse_code_of_width(&mut self, bits: u8, special_index: i32) -> io::Result<PrefixCode> {
        let num = self.rb(bits, "lzh: truncated LZH code")? as i32;
        if num == 0 {
            let val = self.rb(bits, "lzh: truncated LZH code")?;
            return Ok(PrefixCode::single_symbol(val as i32));
        }

        let mut lengths = vec![0u32; num as usize];
        let mut n = 0i32;
        while n < num {
            let mut len = self.rb(3, "lzh: truncated LZH code")?;
            if len == 7 {
                while self.rb(1, "lzh: truncated LZH code")? != 0 {
                    len += 1;
                }
            }
            lengths[n as usize] = len;
            n += 1;

            if n == special_index {
                let zeroes = self.rb(2, "lzh: truncated LZH code")?;
                for _ in 0..zeroes {
                    if n >= num {
                        return Err(invalid("lzh: LZH code length overflow"));
                    }
                    lengths[n as usize] = 0;
                    n += 1;
                }
            }
        }
        Ok(PrefixCode::from_lengths(&lengths, 16, true))
    }

    /// `allocAndParseLiteralCode` — the literal/length code, whose own lengths
    /// are run-length coded through a 5-bit-wide meta code.
    fn parse_literal_code(&mut self) -> io::Result<PrefixCode> {
        let metacode = self.parse_code_of_width(5, 3)?;

        let num = self.rb(9, "lzh: truncated LZH literal code")? as i32;
        if num == 0 {
            let val = self.rb(9, "lzh: truncated LZH literal code")?;
            return Ok(PrefixCode::single_symbol(val as i32));
        }

        let mut lengths = vec![0u32; num as usize];
        let mut n = 0i32;
        while n < num {
            let c = metacode
                .next_symbol_msb(&mut self.bits)?
                .ok_or_else(|| invalid("lzh: truncated LZH literal code"))?;
            if c <= 2 {
                let zeros = match c {
                    0 => 1,
                    1 => self.rb(4, "lzh: truncated LZH literal code")? + 3,
                    _ => self.rb(9, "lzh: truncated LZH literal code")? + 20,
                };
                if n + zeros as i32 > num {
                    return Err(invalid("lzh: LZH literal length overflow"));
                }
                for _ in 0..zeros {
                    lengths[n as usize] = 0;
                    n += 1;
                }
            } else {
                lengths[n as usize] = (c - 2) as u32;
                n += 1;
            }
        }
        Ok(PrefixCode::from_lengths(&lengths, 16, true))
    }
}

impl<R: Read> Read for LzhStaticReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.buffer_pos >= self.buffer.len() && !self.finished {
            self.buffer.clear();
            self.buffer_pos = 0;
            if !self.decode_block()? {
                self.finished = true;
            }
        }
        let avail = self.buffer.len() - self.buffer_pos;
        let n = avail.min(out.len());
        out[..n].copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + n]);
        self.buffer_pos += n;
        Ok(n)
    }
}
