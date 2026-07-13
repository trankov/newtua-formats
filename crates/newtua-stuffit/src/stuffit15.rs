// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Classic StuffIt compression method 15 (Arsenic).
//!
//! Faithful port of XADMaster's `XADStuffItArsenicHandle` (+ `BWT.c`). Arsenic is
//! a bzip2-like pipeline; decompression runs it in reverse:
//!
//! ```text
//! .sit stream
//!   → adaptive binary arithmetic (range) coder
//!   → zero-RLE + selectors
//!   → MTF (move-to-front)
//!   → inverse BWT (Burrows–Wheeler)
//!   → final bzip2-style RLE (four equal bytes, then a repeat length)
//! original bytes
//! ```
//!
//! Plus optional bitwise randomization (XOR at pseudo-random positions) and an
//! internal CRC32. The whole stream is read most-significant-bit first; at end of
//! input the bit reader yields zeros rather than erroring (the reference pads
//! missing bits), and decoding stops at `outlen`, not at end of stream.

use std::io::{self, Read};

use newtua_common::bitreader::BitReaderMsb;

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn truncated() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "stuffit15: truncated stream")
}

// === range coder ==============================================================

/// Arithmetic-coder precision (`NumBits` in the reference).
const NUM_BITS: u32 = 26;
/// `1 << (NumBits - 1)` — the initial range.
const ONE: u32 = 1 << (NUM_BITS - 1);
/// `1 << (NumBits - 2)` — renormalize while the range drops to this or below.
const HALF: u32 = 1 << (NUM_BITS - 2);

/// MSB-first bit source that yields **zero** past end of input, matching the
/// reference `_CSInputFillBits` (it pads missing bits rather than erroring). The
/// arithmetic decoder reads ahead and may run past the compressed data.
struct Bits<R> {
    inner: BitReaderMsb<R>,
}

impl<R: Read> Bits<R> {
    fn new(inner: R) -> Self {
        Self {
            inner: BitReaderMsb::new(inner),
        }
    }

    /// One bit, MSB-first; `0` at end of input.
    fn bit(&mut self) -> io::Result<u32> {
        Ok(self.inner.read(1)?.unwrap_or(0))
    }

    /// `n` bits (n may exceed 24), most-significant first; zeros past the end.
    fn long(&mut self, n: u32) -> io::Result<u32> {
        let mut v = 0u32;
        for _ in 0..n {
            v = (v << 1) | self.bit()?;
        }
        Ok(v)
    }
}

/// One adaptive arithmetic model: symbol values `first..=last`, each carrying a
/// frequency that grows by `increment` on use and is halved when the total
/// exceeds `frequency_limit`.
struct Model {
    first: i32,
    increment: i32,
    frequency_limit: i32,
    total_frequency: i32,
    freqs: Vec<i32>,
}

impl Model {
    fn new(first: i32, last: i32, increment: i32, frequency_limit: i32) -> Self {
        let num = (last - first + 1) as usize;
        let mut model = Self {
            first,
            increment,
            frequency_limit,
            total_frequency: 0,
            freqs: vec![0; num],
        };
        model.reset();
        model
    }

    fn reset(&mut self) {
        self.total_frequency = self.increment * self.freqs.len() as i32;
        for f in &mut self.freqs {
            *f = self.increment;
        }
    }

    /// Bump symbol `index`'s frequency; rescale (halving, `(f + 1) >> 1`) when the
    /// running total passes the limit.
    fn increase(&mut self, index: usize) {
        self.freqs[index] += self.increment;
        self.total_frequency += self.increment;
        if self.total_frequency > self.frequency_limit {
            self.total_frequency = 0;
            for f in &mut self.freqs {
                *f += 1;
                *f >>= 1;
                self.total_frequency += *f;
            }
        }
    }
}

/// The binary arithmetic (range) decoder state.
struct Coder {
    range: u32,
    code: u32,
}

impl Coder {
    fn init<R: Read>(bits: &mut Bits<R>) -> io::Result<Self> {
        Ok(Self {
            range: ONE,
            code: bits.long(NUM_BITS)?,
        })
    }

    /// Narrow the interval to the decoded symbol and renormalize.
    fn read_next<R: Read>(
        &mut self,
        bits: &mut Bits<R>,
        symlow: i32,
        symsize: i32,
        symtot: i32,
    ) -> io::Result<()> {
        let renorm_factor = self.range / symtot as u32;
        let lowincr = renorm_factor * symlow as u32;
        self.code = self.code.wrapping_sub(lowincr);
        if symlow + symsize == symtot {
            self.range -= lowincr;
        } else {
            self.range = symsize as u32 * renorm_factor;
        }
        while self.range <= HALF {
            self.range <<= 1;
            self.code = (self.code << 1) | bits.bit()?;
        }
        Ok(())
    }
}

/// Decode one symbol from `model`, updating both the coder and the model.
fn next_symbol<R: Read>(
    coder: &mut Coder,
    bits: &mut Bits<R>,
    model: &mut Model,
) -> io::Result<i32> {
    let frequency = coder.code / (coder.range / model.total_frequency as u32);
    let mut cumulative = 0i32;
    let mut n = 0usize;
    while n < model.freqs.len() - 1 {
        if (cumulative + model.freqs[n]) as u32 > frequency {
            break;
        }
        cumulative += model.freqs[n];
        n += 1;
    }
    coder.read_next(bits, cumulative, model.freqs[n], model.total_frequency)?;
    model.increase(n);
    Ok(model.first + n as i32)
}

/// Decode `nbits` bits, each an independent 0/1 symbol from `model`, assembled
/// least-significant-bit first (as the reference `NextArithmeticBitString` does).
fn next_bitstring<R: Read>(
    coder: &mut Coder,
    bits: &mut Bits<R>,
    model: &mut Model,
    nbits: u32,
) -> io::Result<u32> {
    let mut res = 0u32;
    for i in 0..nbits {
        if next_symbol(coder, bits, model)? != 0 {
            res |= 1 << i;
        }
    }
    Ok(res)
}

// === inverse Burrows–Wheeler transform (BWT.c CalculateInverseBWT) ============

/// Build the inverse-BWT "next index" vector for `block`. Walking it from the
/// stored transform index reproduces the pre-BWT byte stream.
fn inverse_bwt(block: &[u8]) -> Vec<u32> {
    let n = block.len();
    let mut counts = [0u32; 256];
    for &b in block {
        counts[b as usize] += 1;
    }
    let mut cumulative = [0u32; 256];
    let mut total = 0u32;
    for b in 0..256 {
        cumulative[b] = total;
        total += counts[b];
        counts[b] = 0;
    }
    let mut transform = vec![0u32; n];
    for (i, &byte) in block.iter().enumerate() {
        let b = byte as usize;
        transform[(cumulative[b] + counts[b]) as usize] = i as u32;
        counts[b] += 1;
    }
    transform
}

// === move-to-front decoder (BWT.c ResetMTFDecoder / DecodeMTF) ================

/// The 256-entry move-to-front table.
struct Mtf {
    table: [u16; 256],
}

impl Mtf {
    fn new() -> Self {
        let mut mtf = Self { table: [0; 256] };
        mtf.reset();
        mtf
    }

    fn reset(&mut self) {
        self.table = core::array::from_fn(|i| i as u16);
    }

    /// Decode one MTF index: return `table[symbol]` and move it to the front.
    fn decode(&mut self, symbol: usize) -> u8 {
        let res = self.table[symbol];
        self.table.copy_within(0..symbol, 1);
        self.table[0] = res;
        res as u8
    }
}

// === randomization table (XADStuffItArsenicHandle.m, verbatim) ================

/// 256 `u16` values (some exceed 255) driving the optional bit randomization.
#[rustfmt::skip]
const RANDOMIZATION_TABLE: [u16; 256] = [
    0x0ee, 0x056, 0x0f8, 0x0c3, 0x09d, 0x09f, 0x0ae, 0x02c,
    0x0ad, 0x0cd, 0x024, 0x09d, 0x0a6, 0x101, 0x018, 0x0b9,
    0x0a1, 0x082, 0x075, 0x0e9, 0x09f, 0x055, 0x066, 0x06a,
    0x086, 0x071, 0x0dc, 0x084, 0x056, 0x096, 0x056, 0x0a1,
    0x084, 0x078, 0x0b7, 0x032, 0x06a, 0x003, 0x0e3, 0x002,
    0x011, 0x101, 0x008, 0x044, 0x083, 0x100, 0x043, 0x0e3,
    0x01c, 0x0f0, 0x086, 0x06a, 0x06b, 0x00f, 0x003, 0x02d,
    0x086, 0x017, 0x07b, 0x010, 0x0f6, 0x080, 0x078, 0x07a,
    0x0a1, 0x0e1, 0x0ef, 0x08c, 0x0f6, 0x087, 0x04b, 0x0a7,
    0x0e2, 0x077, 0x0fa, 0x0b8, 0x081, 0x0ee, 0x077, 0x0c0,
    0x09d, 0x029, 0x020, 0x027, 0x071, 0x012, 0x0e0, 0x06b,
    0x0d1, 0x07c, 0x00a, 0x089, 0x07d, 0x087, 0x0c4, 0x101,
    0x0c1, 0x031, 0x0af, 0x038, 0x003, 0x068, 0x01b, 0x076,
    0x079, 0x03f, 0x0db, 0x0c7, 0x01b, 0x036, 0x07b, 0x0e2,
    0x063, 0x081, 0x0ee, 0x00c, 0x063, 0x08b, 0x078, 0x038,
    0x097, 0x09b, 0x0d7, 0x08f, 0x0dd, 0x0f2, 0x0a3, 0x077,
    0x08c, 0x0c3, 0x039, 0x020, 0x0b3, 0x012, 0x011, 0x00e,
    0x017, 0x042, 0x080, 0x02c, 0x0c4, 0x092, 0x059, 0x0c8,
    0x0db, 0x040, 0x076, 0x064, 0x0b4, 0x055, 0x01a, 0x09e,
    0x0fe, 0x05f, 0x006, 0x03c, 0x041, 0x0ef, 0x0d4, 0x0aa,
    0x098, 0x029, 0x0cd, 0x01f, 0x002, 0x0a8, 0x087, 0x0d2,
    0x0a0, 0x093, 0x098, 0x0ef, 0x00c, 0x043, 0x0ed, 0x09d,
    0x0c2, 0x0eb, 0x081, 0x0e9, 0x064, 0x023, 0x068, 0x01e,
    0x025, 0x057, 0x0de, 0x09a, 0x0cf, 0x07f, 0x0e5, 0x0ba,
    0x041, 0x0ea, 0x0ea, 0x036, 0x01a, 0x028, 0x079, 0x020,
    0x05e, 0x018, 0x04e, 0x07c, 0x08e, 0x058, 0x07a, 0x0ef,
    0x091, 0x002, 0x093, 0x0bb, 0x056, 0x0a1, 0x049, 0x01b,
    0x079, 0x092, 0x0f3, 0x058, 0x04f, 0x052, 0x09c, 0x002,
    0x077, 0x0af, 0x02a, 0x08f, 0x049, 0x0d0, 0x099, 0x04d,
    0x098, 0x101, 0x060, 0x093, 0x100, 0x075, 0x031, 0x0ce,
    0x049, 0x020, 0x056, 0x057, 0x0e2, 0x0f5, 0x026, 0x02b,
    0x08a, 0x0bf, 0x0de, 0x0d0, 0x083, 0x034, 0x0f4, 0x017,
];

// === Arsenic decoder ==========================================================

/// The full Arsenic decode machine (port of `XADStuffItArsenicHandle`).
struct Arsenic<R> {
    bits: Bits<R>,
    coder: Coder,
    initialmodel: Model,
    selectormodel: Model,
    mtfmodel: [Model; 7],
    mtf: Mtf,

    blockbits: u32,
    blocksize: usize,
    block: Vec<u8>,
    transform: Vec<u32>,
    endofblocks: bool,

    numbytes: usize,
    bytecount: usize,
    transformindex: usize,

    randomized: i32,
    randcount: usize,
    randindex: usize,

    repeat: i32,
    count: i32,
    last: u8,
}

impl<R: Read> Arsenic<R> {
    /// Port of `resetByteStream`: init the coder and models, read the `'As'`
    /// signature, block-size field, and the first end-of-blocks marker.
    fn new(src: R) -> io::Result<Self> {
        let mut bits = Bits::new(src);
        let coder = Coder::init(&mut bits)?;
        let mut s = Self {
            bits,
            coder,
            initialmodel: Model::new(0, 1, 1, 256),
            selectormodel: Model::new(0, 10, 8, 1024),
            mtfmodel: [
                Model::new(2, 3, 8, 1024),
                Model::new(4, 7, 4, 1024),
                Model::new(8, 15, 4, 1024),
                Model::new(16, 31, 4, 1024),
                Model::new(32, 63, 2, 1024),
                Model::new(64, 127, 2, 1024),
                Model::new(128, 255, 1, 1024),
            ],
            mtf: Mtf::new(),
            blockbits: 0,
            blocksize: 0,
            block: Vec::new(),
            transform: Vec::new(),
            endofblocks: false,
            numbytes: 0,
            bytecount: 0,
            transformindex: 0,
            randomized: 0,
            randcount: 0,
            randindex: 0,
            repeat: 0,
            count: 0,
            last: 0,
        };

        if next_bitstring(&mut s.coder, &mut s.bits, &mut s.initialmodel, 8)? != u32::from(b'A') {
            return Err(invalid("stuffit15: bad Arsenic signature"));
        }
        if next_bitstring(&mut s.coder, &mut s.bits, &mut s.initialmodel, 8)? != u32::from(b's') {
            return Err(invalid("stuffit15: bad Arsenic signature"));
        }
        s.blockbits = next_bitstring(&mut s.coder, &mut s.bits, &mut s.initialmodel, 4)? + 9;
        s.blocksize = 1usize << s.blockbits;
        s.block = vec![0u8; s.blocksize];
        s.endofblocks = next_symbol(&mut s.coder, &mut s.bits, &mut s.initialmodel)? != 0;
        Ok(s)
    }

    /// Port of `readBlock`: decode selectors/MTF into `block`, reset the per-block
    /// models, read the end marker (and internal CRC, which we do not verify), and
    /// build the inverse-BWT vector.
    fn read_block(&mut self) -> io::Result<()> {
        self.mtf.reset();

        self.randomized = next_symbol(&mut self.coder, &mut self.bits, &mut self.initialmodel)?;
        self.transformindex = next_bitstring(
            &mut self.coder,
            &mut self.bits,
            &mut self.initialmodel,
            self.blockbits,
        )? as usize;

        let mut numbytes = 0usize;
        loop {
            let mut sel = next_symbol(&mut self.coder, &mut self.bits, &mut self.selectormodel)?;
            if sel == 0 || sel == 1 {
                // Bijective binary zero count.
                let mut zerostate = 1i64;
                let mut zerocount = 0i64;
                while sel < 2 {
                    if sel == 0 {
                        zerocount += zerostate;
                    } else {
                        zerocount += 2 * zerostate;
                    }
                    zerostate *= 2;
                    sel = next_symbol(&mut self.coder, &mut self.bits, &mut self.selectormodel)?;
                }
                if numbytes + zerocount as usize > self.blocksize {
                    return Err(invalid("stuffit15: zero run overruns block"));
                }
                let fill = self.mtf.decode(0);
                for _ in 0..zerocount {
                    self.block[numbytes] = fill;
                    numbytes += 1;
                }
            }

            if sel == 10 {
                break;
            }
            let symbol = if sel == 2 {
                1
            } else {
                next_symbol(
                    &mut self.coder,
                    &mut self.bits,
                    &mut self.mtfmodel[(sel - 3) as usize],
                )?
            };

            if numbytes >= self.blocksize {
                return Err(invalid("stuffit15: block overrun"));
            }
            self.block[numbytes] = self.mtf.decode(symbol as usize);
            numbytes += 1;
        }

        if self.transformindex >= numbytes {
            return Err(invalid("stuffit15: transform index out of range"));
        }

        self.selectormodel.reset();
        for m in &mut self.mtfmodel {
            m.reset();
        }

        if next_symbol(&mut self.coder, &mut self.bits, &mut self.initialmodel)? != 0 {
            // Internal CRC32 — read to stay in sync, but not verified (the
            // container's fork CRC-16 already guards integrity).
            let _compcrc =
                next_bitstring(&mut self.coder, &mut self.bits, &mut self.initialmodel, 32)?;
            self.endofblocks = true;
        }

        self.numbytes = numbytes;
        self.transform = inverse_bwt(&self.block[..numbytes]);
        Ok(())
    }

    /// Port of `produceByteAtOffset`: inverse-BWT walk + randomization + final
    /// bzip2-style RLE. `CSByteStreamEOF` (block exhausted at end of blocks) maps
    /// to a truncated-stream error, since we stop at `outlen`.
    fn produce_byte(&mut self) -> io::Result<u8> {
        let outbyte: u8;
        if self.repeat > 0 {
            self.repeat -= 1;
            outbyte = self.last;
        } else {
            loop {
                if self.bytecount >= self.numbytes {
                    if self.endofblocks {
                        return Err(truncated());
                    }
                    self.read_block()?;
                    self.bytecount = 0;
                    self.count = 0;
                    self.last = 0;
                    self.randindex = 0;
                    self.randcount = usize::from(RANDOMIZATION_TABLE[0]);
                }

                self.transformindex = self.transform[self.transformindex] as usize;
                let mut byte = i32::from(self.block[self.transformindex]);

                if self.randomized != 0 && self.randcount == self.bytecount {
                    byte ^= 1;
                    self.randindex = (self.randindex + 1) & 255;
                    self.randcount += usize::from(RANDOMIZATION_TABLE[self.randindex]);
                }

                self.bytecount += 1;

                if self.count == 4 {
                    self.count = 0;
                    if byte == 0 {
                        continue;
                    }
                    self.repeat = byte - 1;
                    outbyte = self.last;
                    break;
                }
                if byte == i32::from(self.last) {
                    self.count += 1;
                } else {
                    self.count = 1;
                    self.last = byte as u8;
                }
                outbyte = byte as u8;
                break;
            }
        }
        Ok(outbyte)
    }
}

/// Decode a method-15 (Arsenic) fork: `outlen` decompressed bytes from `src`.
pub(crate) fn decode(src: &[u8], outlen: usize) -> io::Result<Vec<u8>> {
    if outlen == 0 {
        return Ok(Vec::new());
    }
    let mut arsenic = Arsenic::new(src)?;
    let mut out = Vec::with_capacity(outlen);
    while out.len() < outlen {
        out.push(arsenic.produce_byte()?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // === BWT mirror (forward transform, test-only) ===========================

    /// Walk the inverse BWT from `index`, reproducing the pre-BWT stream.
    fn bwt_decode(block: &[u8], index: usize) -> Vec<u8> {
        let t = inverse_bwt(block);
        let mut idx = index;
        (0..block.len())
            .map(|_| {
                idx = t[idx] as usize;
                block[idx]
            })
            .collect()
    }

    /// Forward BWT: sort all rotations, take the last column, and find the start
    /// index that makes [`bwt_decode`] reproduce `s`.
    fn forward_bwt(s: &[u8]) -> (Vec<u8>, usize) {
        let n = s.len();
        let mut rot: Vec<usize> = (0..n).collect();
        rot.sort_by(|&a, &b| {
            for k in 0..n {
                let ca = s[(a + k) % n];
                let cb = s[(b + k) % n];
                if ca != cb {
                    return ca.cmp(&cb);
                }
            }
            std::cmp::Ordering::Equal
        });
        let block: Vec<u8> = rot.iter().map(|&r| s[(r + n - 1) % n]).collect();
        for idx in 0..n {
            if bwt_decode(&block, idx) == s {
                return (block, idx);
            }
        }
        panic!("forward_bwt: no index reproduces the input");
    }

    fn bwt_roundtrip(s: &[u8]) {
        let (block, index) = forward_bwt(s);
        assert_eq!(bwt_decode(&block, index), s);
    }

    #[test]
    fn bwt_roundtrips_various_strings() {
        bwt_roundtrip(b"a");
        bwt_roundtrip(b"banana");
        bwt_roundtrip(b"the quick brown fox");
        bwt_roundtrip(b"aaaaaaaa");
        bwt_roundtrip(b"abababababab");
        bwt_roundtrip(&(0u8..=255).collect::<Vec<u8>>());
    }

    // === MTF mirror (forward encode, test-only) ==============================

    /// Forward MTF: return the index of `byte` and move it to the front.
    fn mtf_encode(table: &mut [u16; 256], byte: u8) -> usize {
        let sym = table.iter().position(|&x| x == u16::from(byte)).unwrap();
        let res = table[sym];
        for i in (1..=sym).rev() {
            table[i] = table[i - 1];
        }
        table[0] = res;
        sym
    }

    #[test]
    fn mtf_encode_decode_roundtrip() {
        let data = b"mississippi river banana bandana";
        let mut enc_table: [u16; 256] = core::array::from_fn(|i| i as u16);
        let mut dec = Mtf::new();
        for &b in data {
            let sym = mtf_encode(&mut enc_table, b);
            assert_eq!(dec.decode(sym), b);
        }
    }

    // === arithmetic encoder mirror (test-only) ===============================

    /// The inverse of [`Coder`]: a carry-aware range encoder. Carries propagate
    /// directly into the already-emitted bit vector (simple and obviously
    /// correct; fixtures are small).
    struct ArithEncoder {
        low: u64,
        range: u32,
        bits: Vec<bool>,
    }

    const TOP: u64 = 1 << NUM_BITS;

    impl ArithEncoder {
        fn new() -> Self {
            Self {
                low: 0,
                range: ONE,
                bits: Vec::new(),
            }
        }

        fn carry(&mut self) {
            let mut i = self.bits.len();
            while i > 0 {
                i -= 1;
                if !self.bits[i] {
                    self.bits[i] = true;
                    return;
                }
                self.bits[i] = false;
            }
            panic!("arithmetic encoder: carry past start of stream");
        }

        fn encode(&mut self, symlow: u32, symsize: u32, symtot: u32, is_last: bool) {
            let renorm_factor = self.range / symtot;
            let lowincr = renorm_factor * symlow;
            self.low += u64::from(lowincr);
            if self.low >= TOP {
                self.low -= TOP;
                self.carry();
            }
            if is_last {
                self.range -= lowincr;
            } else {
                self.range = symsize * renorm_factor;
            }
            while self.range <= HALF {
                self.bits.push((self.low >> (NUM_BITS - 1)) & 1 != 0);
                self.low = (self.low << 1) & (TOP - 1);
                self.range <<= 1;
            }
        }

        fn finish(mut self) -> Vec<u8> {
            for _ in 0..NUM_BITS {
                self.bits.push((self.low >> (NUM_BITS - 1)) & 1 != 0);
                self.low = (self.low << 1) & (TOP - 1);
            }
            let mut bytes = Vec::new();
            for chunk in self.bits.chunks(8) {
                let mut b = 0u8;
                for (k, &bit) in chunk.iter().enumerate() {
                    if bit {
                        b |= 1 << (7 - k);
                    }
                }
                bytes.push(b);
            }
            bytes
        }
    }

    /// Encode symbol value `value` in `model`, mirroring the decoder's model math.
    fn enc_symbol(enc: &mut ArithEncoder, model: &mut Model, value: i32) {
        let n = (value - model.first) as usize;
        let cumulative: i32 = model.freqs[..n].iter().sum();
        let symsize = model.freqs[n];
        let is_last = n == model.freqs.len() - 1;
        enc.encode(
            cumulative as u32,
            symsize as u32,
            model.total_frequency as u32,
            is_last,
        );
        model.increase(n);
    }

    /// Encode `nbits` bits, least-significant first (mirror of `next_bitstring`).
    fn enc_bitstring(enc: &mut ArithEncoder, model: &mut Model, value: u32, nbits: u32) {
        for i in 0..nbits {
            enc_symbol(enc, model, ((value >> i) & 1) as i32);
        }
    }

    #[test]
    fn arithmetic_roundtrip_through_models() {
        // A sequence of symbols across two model shapes, evolving both.
        let syms_a: Vec<i32> = (0..200).map(|i| i % 11).collect(); // selector-like
        let syms_b: Vec<i32> = (0..200).map(|i| 2 + (i * 7) % 6).collect(); // mtf[1]-like

        let mut enc = ArithEncoder::new();
        let mut ma = Model::new(0, 10, 8, 1024);
        let mut mb = Model::new(2, 7, 4, 1024);
        for (&a, &b) in syms_a.iter().zip(&syms_b) {
            enc_symbol(&mut enc, &mut ma, a);
            enc_symbol(&mut enc, &mut mb, b);
        }
        let bytes = enc.finish();

        let mut bits = Bits::new(&bytes[..]);
        let mut coder = Coder::init(&mut bits).unwrap();
        let mut ma = Model::new(0, 10, 8, 1024);
        let mut mb = Model::new(2, 7, 4, 1024);
        for (&a, &b) in syms_a.iter().zip(&syms_b) {
            assert_eq!(next_symbol(&mut coder, &mut bits, &mut ma).unwrap(), a);
            assert_eq!(next_symbol(&mut coder, &mut bits, &mut mb).unwrap(), b);
        }
    }

    // === full pipeline mirror (test-only) ====================================

    /// Inverse of the final RLE: 4 equal bytes then a repeat-length byte, so a
    /// run of `m` copies becomes `min(4, m)` literals plus a length (per 259).
    fn rle_encode(content: &[u8]) -> Vec<u8> {
        let mut s = Vec::new();
        let mut i = 0;
        while i < content.len() {
            let b = content[i];
            let mut j = i;
            while j < content.len() && content[j] == b {
                j += 1;
            }
            let mut run = j - i;
            while run > 0 {
                if run < 4 {
                    for _ in 0..run {
                        s.push(b);
                    }
                    run = 0;
                } else {
                    for _ in 0..4 {
                        s.push(b);
                    }
                    let l = (run - 4).min(255);
                    s.push(l as u8);
                    run -= 4 + l;
                }
            }
            i = j;
        }
        s
    }

    /// Forward MTF over a block, yielding the index stream.
    fn mtf_encode_block(block: &[u8]) -> Vec<usize> {
        let mut table: [u16; 256] = core::array::from_fn(|i| i as u16);
        block.iter().map(|&b| mtf_encode(&mut table, b)).collect()
    }

    /// Selector (3..=9) and `mtfmodel` index for a non-zero, non-one MTF symbol.
    fn selector_for(sym: usize) -> (i32, usize) {
        match sym {
            2..=3 => (3, 0),
            4..=7 => (4, 1),
            8..=15 => (5, 2),
            16..=31 => (6, 3),
            32..=63 => (7, 4),
            64..=127 => (8, 5),
            _ => (9, 6),
        }
    }

    /// Encode a run of `z` zero MTF symbols as bijective-binary selectors 0/1.
    fn encode_zero_run(enc: &mut ArithEncoder, selector: &mut Model, mut z: usize) {
        while z > 0 {
            if z & 1 == 1 {
                enc_symbol(enc, selector, 0);
                z = (z - 1) / 2;
            } else {
                enc_symbol(enc, selector, 1);
                z = (z - 2) / 2;
            }
        }
    }

    fn encode_block_symbols(
        enc: &mut ArithEncoder,
        selector: &mut Model,
        mtfm: &mut [Model; 7],
        msyms: &[usize],
    ) {
        let mut i = 0;
        loop {
            let mut z = 0usize;
            while i < msyms.len() && msyms[i] == 0 {
                z += 1;
                i += 1;
            }
            if z > 0 {
                encode_zero_run(enc, selector, z);
            }
            if i == msyms.len() {
                enc_symbol(enc, selector, 10); // end of block
                break;
            }
            let sym = msyms[i];
            i += 1;
            if sym == 1 {
                enc_symbol(enc, selector, 2);
            } else {
                let (sel, k) = selector_for(sym);
                enc_symbol(enc, selector, sel);
                enc_symbol(enc, &mut mtfm[k], sym as i32);
            }
        }
    }

    /// Build one method-15 fork stream from `content` (single block, no
    /// randomization) — the inverse of the whole decode pipeline.
    fn encode_fork(content: &[u8]) -> Vec<u8> {
        use newtua_common::crc32::crc32_ieee;

        let s = rle_encode(content);
        let (block, transformindex) = forward_bwt(&s);
        let msyms = mtf_encode_block(&block);

        let mut blockbits = 9u32;
        while (1usize << blockbits) < s.len() {
            blockbits += 1;
        }
        assert!(blockbits <= 24, "fixture too large for a single block");

        let mut enc = ArithEncoder::new();
        let mut initial = Model::new(0, 1, 1, 256);
        let mut selector = Model::new(0, 10, 8, 1024);
        let mut mtfm = [
            Model::new(2, 3, 8, 1024),
            Model::new(4, 7, 4, 1024),
            Model::new(8, 15, 4, 1024),
            Model::new(16, 31, 4, 1024),
            Model::new(32, 63, 2, 1024),
            Model::new(64, 127, 2, 1024),
            Model::new(128, 255, 1, 1024),
        ];

        // Header: 'A', 's', blockbits-9, first end marker (0 = a block follows).
        enc_bitstring(&mut enc, &mut initial, u32::from(b'A'), 8);
        enc_bitstring(&mut enc, &mut initial, u32::from(b's'), 8);
        enc_bitstring(&mut enc, &mut initial, blockbits - 9, 4);
        enc_symbol(&mut enc, &mut initial, 0);

        // Block: randomized=0, transform index, selector/MTF stream.
        enc_symbol(&mut enc, &mut initial, 0);
        enc_bitstring(&mut enc, &mut initial, transformindex as u32, blockbits);
        encode_block_symbols(&mut enc, &mut selector, &mut mtfm, &msyms);

        selector.reset();
        for m in &mut mtfm {
            m.reset();
        }

        // End marker (1 = last block) + internal CRC32.
        enc_symbol(&mut enc, &mut initial, 1);
        enc_bitstring(&mut enc, &mut initial, crc32_ieee(content), 32);

        enc.finish()
    }

    fn roundtrip(content: &[u8]) {
        let stream = encode_fork(content);
        assert_eq!(decode(&stream, content.len()).unwrap(), content);
    }

    #[test]
    fn plain_literals() {
        roundtrip(b"Arsenic method fifteen, plain literal text.");
    }

    #[test]
    fn repeated_text_exercises_bwt_and_selectors() {
        roundtrip(b"the cat sat on the mat, the cat sat on the hat, the cat ran.");
    }

    #[test]
    fn final_rle_long_run() {
        // A run well past 4 identical bytes drives the final-RLE length path.
        let mut data = vec![b'x'; 300];
        data.extend_from_slice(b"tail");
        roundtrip(&data);
    }

    #[test]
    fn zero_runs_and_mixed_mtf_ranges() {
        // Byte values spanning several mtf[k] ranges, with repeats that produce
        // MTF-zero runs after the transform.
        let mut data = Vec::new();
        for round in 0..8u8 {
            for b in 0..40u8 {
                data.push(b.wrapping_mul(3).wrapping_add(round));
            }
        }
        roundtrip(&data);
    }

    #[test]
    fn single_byte() {
        roundtrip(b"Z");
    }

    #[test]
    fn zero_outlen_returns_empty_without_parsing() {
        assert_eq!(decode(&[], 0).unwrap(), Vec::<u8>::new());
        assert_eq!(decode(&[0xFF, 0x00], 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn stream_shorter_than_outlen_is_unexpected_eof() {
        // A valid stream decodes to N bytes; asking for more must report EOF when
        // the block is exhausted at end of blocks.
        let content = b"short content";
        let stream = encode_fork(content);
        let err = decode(&stream, content.len() + 5).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn bad_signature_is_invalid_data() {
        // All-zero input: the arithmetic decoder yields a non-'A' first byte.
        let err = decode(&[0u8; 32], 4).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
