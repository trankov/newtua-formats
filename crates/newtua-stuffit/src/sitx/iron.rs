// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! StuffItX Iron codec (`XADStuffItXIronHandle`), compression method 6.
//!
//! A block codec: the stream is split into blocks, each block holding either raw
//! bytes or a range-coded, BWT/ST4-permuted string. The block headers (and the
//! stream-wide reset parameters) are read bit-by-bit (LSB-first) directly from the
//! same byte buffer the range coder later reads byte-by-byte from, so a single
//! cursor (`p2::Reader`) is threaded through the whole decode, handed off to a
//! fresh [`RangeCoder`] for each compressed block's body. A faithful port of
//! `XADStuffItXIronHandle.m`.

use std::io;

use super::bwt::{unsort_bwt, unsort_st4, MtfState};
use super::p2::Reader;
use super::rangecoder::RangeCoder;

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Stream-wide parameters read once by `resetBlockStream` (`.m:53-68`).
struct Header {
    st4transform: bool,
    fancymtf: bool,
    maxfreq1: u32,
    maxfreq2: u32,
    maxfreq3: u32,
    byteshift1: u32,
    byteshift2: u32,
    byteshift3: u32,
    countshift1: u32,
    countshift2: u32,
    countshift3: u32,
}

/// A P2 value destined for a `u32` shift, rejecting anything `>= 32` rather than
/// panicking on hostile input (the reference trusts a well-formed archive and
/// never checks this). `what` names the field for the error.
fn read_p2_below_32(r: &mut Reader, what: &str) -> io::Result<u32> {
    let v = r.read_p2()?;
    if v >= 32 {
        return Err(invalid(&format!("sitx: iron {what} out of range")));
    }
    Ok(v as u32)
}

/// A P2 value used as a `<<` exponent (`maxfreq1..3`).
fn bounded_exponent(r: &mut Reader) -> io::Result<u32> {
    Ok(1u32 << read_p2_below_32(r, "maxfreq exponent")?)
}

/// A P2 value used as a `>>`/`<<` adaptation shift.
fn bounded_shift(r: &mut Reader) -> io::Result<u32> {
    read_p2_below_32(r, "shift amount")
}

fn reset_block_stream(r: &mut Reader) -> io::Result<Header> {
    let st4transform = r.bit()? == 1;
    let fancymtf = r.bit()? == 1;

    let maxfreq1 = bounded_exponent(r)?;
    let maxfreq2 = bounded_exponent(r)?;
    let maxfreq3 = bounded_exponent(r)?;

    let byteshift1 = bounded_shift(r)?;
    let byteshift2 = bounded_shift(r)?;
    let byteshift3 = bounded_shift(r)?;
    let countshift1 = bounded_shift(r)?;
    let countshift2 = bounded_shift(r)?;
    let countshift3 = bounded_shift(r)?;

    Ok(Header {
        st4transform,
        fancymtf,
        maxfreq1,
        maxfreq2,
        maxfreq3,
        byteshift1,
        byteshift2,
        byteshift3,
        countshift1,
        countshift2,
        countshift3,
    })
}

// === MTF variants ==============================================================

/// The "fancy" ranked MTF (`.m:239-283`, inlined rather than the flat
/// `MtfState`/`decode_m1ffn_block` primitives): a 257-entry table (256 real byte
/// values plus one phantom slot seeded with `256`) kept ordered by a decaying
/// recency-weight (`intarray3`), rather than plain move-to-front.
struct FancyMtf {
    /// `intarray1[rank] = byte` (masked to `u8` on read, matching `&0xff`).
    intarray1: Vec<u32>,
    /// `intarray2[byte] = rank`, the inverse of `intarray1`.
    intarray2: Vec<u32>,
    /// Decaying recency weight per byte value, `uint32_t` wraparound semantics.
    intarray3: Vec<u32>,
    /// `block[numbytes]` in the reference: every byte this MTF has emitted so
    /// far, used to look back at power-of-two distances.
    history: Vec<u8>,
    numbytes: usize,
}

impl FancyMtf {
    fn new(blocksize: usize) -> Self {
        let mut intarray1 = vec![0u32; 257];
        let mut intarray2 = vec![0u32; 257];
        let mut intarray3 = vec![0u32; 257];
        for i in 0..257u32 {
            intarray1[i as usize] = i;
            intarray2[i as usize] = i;
        }
        intarray3[256] = u32::MAX; // `intarray3[256]=-1;` on a uint32_t
        FancyMtf {
            intarray1,
            intarray2,
            intarray3,
            history: vec![0u8; blocksize],
            numbytes: 0,
        }
    }

    /// `index=(value+1)&0xff; byte=intarray1[index]&0xff; ...` (`.m:241-282`).
    fn decode(&mut self, value: u32) -> u8 {
        let index = ((value + 1) & 0xff) as usize;
        let byte = (self.intarray1[index] & 0xff) as u8;
        self.history[self.numbytes] = byte;
        self.intarray3[byte as usize] = self.intarray3[byte as usize].wrapping_add(0x4000);

        // Shift `byte`'s old slot toward the front (`.m:248-252`).
        let mut k = self.intarray2[byte as usize] as usize;
        while k > 0 {
            let prev = self.intarray1[k - 1];
            self.intarray1[k] = prev;
            self.intarray2[prev as usize] = k as u32;
            k -= 1;
        }
        self.intarray1[0] = byte as u32;
        self.intarray2[byte as usize] = 0;

        // Weaken the weight of every byte seen at a power-of-two lookback and
        // possibly bubble it further back (`.m:257-280`).
        for j in 0..12u32 {
            let n = 1usize << j;
            if n <= self.numbytes {
                let b2 = self.history[self.numbytes - n];
                if j == 0 {
                    self.intarray3[b2 as usize] = self.intarray3[b2 as usize].wrapping_sub(0x3801);
                } else {
                    self.intarray3[b2 as usize] =
                        self.intarray3[b2 as usize].wrapping_sub(0x800u32 >> j);
                }
                if b2 != byte {
                    // `intarray3[b2]` is not touched inside this loop (the body
                    // only rewrites `intarray1`/`intarray2` for the *other*
                    // element being lifted), so hoist it out of the comparison.
                    let b2weight = self.intarray3[b2 as usize];
                    let mut val = self.intarray2[b2 as usize] as usize;
                    // The reference reads `intarray1[val+1]` on a `[257]` array,
                    // so a byte sinking past the phantom rank-256 slot (weight
                    // `u32::MAX`) reads `intarray1[257]` — out of bounds. That is
                    // unreachable from a well-formed archive (a corrupt decode is
                    // caught downstream by the stream CRC32), but guard the index
                    // so hostile input errors via CRC rather than panicking.
                    while val + 1 < self.intarray1.len() {
                        let next = self.intarray1[val + 1];
                        if self.intarray3[next as usize] <= b2weight {
                            break;
                        }
                        self.intarray1[val] = next;
                        self.intarray2[next as usize] = val as u32;
                        val += 1;
                    }
                    self.intarray1[val] = b2 as u32;
                    self.intarray2[b2 as usize] = val as u32;
                }
            }
        }

        self.numbytes += 1;
        byte
    }

    /// The rank currently holding `byte` (test-only: an encoder needs to invert
    /// [`Self::decode`] to find which `value` would reproduce a target byte).
    #[cfg(test)]
    fn find_rank(&self, byte: u8) -> usize {
        (0..257)
            .find(|&i| (self.intarray1[i] & 0xff) as u8 == byte)
            .expect("every byte value is always present in the table")
    }
}

/// Either MTF variant `decodeBlockWithLength` may use, dispatched once per block
/// by `fancymtf` (`.m:161-176`).
enum Mtf {
    Fancy(FancyMtf),
    /// `mtfbuffer[256]`: plain move-to-front, indexed the same way as the fancy
    /// variant (`index=(value+1)&0xff`), so [`MtfState::decode`] (which takes the
    /// index, not the symbol) applies directly (`.m:286-289`).
    Plain(MtfState),
}

impl Mtf {
    fn decode(&mut self, value: u32) -> u8 {
        match self {
            Mtf::Fancy(f) => f.decode(value),
            Mtf::Plain(m) => {
                let index = ((value + 1) & 0xff) as u8;
                m.decode(index)
            }
        }
    }
}

// === per-block model ============================================================

/// Decode one block's model-coded body into its `sorted` (BWT/ST4-permuted)
/// string (`decodeBlockWithLength:`, `.m:114-328`).
fn decode_block_body(
    coder: &mut RangeCoder,
    blocksize: usize,
    header: &Header,
) -> io::Result<Vec<u8>> {
    let mut sorted = vec![0u8; blocksize];

    let mut mainfrequencies = [1u32; 4];
    let mut lastbytefrequencies = vec![[0u32; 4]; 256];
    // `somethingfrequencies[4][256][4]`: kept off the stack (1024 groups), per
    // the task's guidance, unlike the smaller tables below.
    let mut somethingfrequencies = vec![[0u32; 4]; 4 * 256];

    let mut bytelengthweights = [0x800u32; 8];
    let mut bytelengthweights2 = [[0x800u32; 8]; 8];
    let mut bytebitweights = [[0x800u32; 128]; 8];

    let mut countlengthweights = [[[0x800u32; 24]; 16]; 4];
    let mut countlengthweights2 = [[0x800u32; 24]; 256];
    let mut countbitweights = [[0x800u32; 24]; 24];

    let mut mtf = if header.fancymtf {
        Mtf::Fancy(FancyMtf::new(blocksize))
    } else {
        Mtf::Plain(MtfState::new())
    };

    let mut valuehistory: u32 = 0;
    let mut lengthhistory: u32 = 0;
    let mut lastbits: u32 = 0;
    let mut lastbyte: u8 = 0;

    let mut i = 0usize;
    while i < blocksize {
        let something_idx = (lengthhistory & 3) as usize * 256 + valuehistory as usize;
        let freqs1 = mainfrequencies;
        let freqs2 = lastbytefrequencies[lastbyte as usize];
        let freqs3 = somethingfrequencies[something_idx];
        let frequencies: [u32; 4] = std::array::from_fn(|j| freqs1[j] + freqs2[j] + freqs3[j]);

        let symbol = coder.next_symbol(&frequencies);

        mainfrequencies[symbol] += 2;
        lastbytefrequencies[lastbyte as usize][symbol] += 2;
        somethingfrequencies[something_idx][symbol] += 2;

        let total1: u32 = mainfrequencies.iter().sum();
        let total2: u32 = lastbytefrequencies[lastbyte as usize].iter().sum();
        let total3: u32 = somethingfrequencies[something_idx].iter().sum();

        if total1 > header.maxfreq1 {
            for f in mainfrequencies.iter_mut() {
                *f = f.div_ceil(2);
            }
        }
        if total2 > header.maxfreq2 {
            for f in lastbytefrequencies[lastbyte as usize].iter_mut() {
                *f /= 2;
            }
        }
        if total3 > header.maxfreq3 {
            for f in somethingfrequencies[something_idx].iter_mut() {
                *f /= 2;
            }
        }

        // `value`: direct for symbols 0..2, an escape-coded integer (>=3) for
        // symbol 3 (`.m:213-236`).
        let value: u32 = if symbol != 3 {
            symbol as u32
        } else {
            let mut bits: u32 = 0;
            while bits < 6 {
                let bit = coder.next_bit_with_double_weights(
                    &mut bytelengthweights[bits as usize],
                    header.byteshift1,
                    &mut bytelengthweights2[lastbits as usize][bits as usize],
                    header.byteshift2,
                );
                if bit == 0 {
                    break;
                }
                bits += 1;
            }

            let mut value: u32 = 1;
            for _ in 0..=bits {
                let bit = coder.next_bit_with_weight(
                    &mut bytebitweights[bits as usize][value as usize],
                    header.byteshift3,
                );
                value = (value << 1) | bit;
            }
            value += 1;
            lastbits = bits;
            value
        };

        let byte = mtf.decode(value);

        let shortvalue = value.min(3);

        // The RLE run length for `byte` (`.m:296-313`).
        let mut bits: u32 = 0;
        loop {
            let bit = coder.next_bit_with_double_weights(
                &mut countlengthweights[shortvalue as usize][lengthhistory as usize][bits as usize],
                header.countshift1,
                &mut countlengthweights2[byte as usize][bits as usize],
                header.countshift2,
            );
            if bit == 0 {
                break;
            }
            bits += 1;
            if bits >= 24 {
                return Err(invalid("sitx: iron count length overflow"));
            }
        }

        let mut count: u32 = 1;
        for j in 0..bits {
            let bit = coder.next_bit_with_weight(
                &mut countbitweights[bits as usize][j as usize],
                header.countshift3,
            );
            count = (count << 1) | bit;
        }

        for _ in 0..count {
            if i >= blocksize {
                return Err(invalid("sitx: iron run exceeds block size"));
            }
            sorted[i] = byte;
            i += 1;
        }

        valuehistory = ((valuehistory << 2) | shortvalue) & 0xff;
        lengthhistory = (lengthhistory << 1) & 0x0e;
        if bits > 1 {
            lengthhistory |= 1;
        }
        lastbyte = byte;
    }

    Ok(sorted)
}

// === block framing ==============================================================

/// Decode an Iron-compressed stream (`produceBlockAtOffset:` driven by
/// `CSBlockStreamHandle`, `.m:53-112`). `blocks` is the block layer's already
/// unwrapped output (`p2::read_block_stream`); `size` bounds the accumulated
/// output (the stream may also end early via the explicit end-of-blocks bit).
pub(crate) fn decode(blocks: &[u8], size: usize) -> io::Result<Vec<u8>> {
    let mut r = Reader::new(blocks);
    let header = reset_block_stream(&mut r)?;
    let mut out = Vec::with_capacity(size);

    while out.len() < size {
        r.flush(); // CSInputSkipToByteBoundary
        if r.bit()? == 1 {
            break; // explicit end marker
        }

        let blocksize = r.read_p2()? as usize;
        let uncompressed = r.bit()? == 1;

        if uncompressed {
            r.flush(); // "necessary?" in the reference, kept for fidelity
            out.extend_from_slice(r.raw(blocksize)?);
        } else {
            let firstindex = r.read_p2()? as usize;
            r.flush();

            r.skip(1)?; // CSInputSkipBytes(input,1) inside decodeBlockWithLength
            let coder_start = r.offset();
            let mut coder = RangeCoder::new(&blocks[coder_start..], false, 0);
            let sorted = decode_block_body(&mut coder, blocksize, &header)?;
            r.seek(coder_start + coder.position());

            let block = if header.st4transform {
                unsort_st4(&sorted, firstindex)
            } else {
                unsort_bwt(&sorted, firstindex)
            };
            out.extend_from_slice(&block);
        }
    }

    out.truncate(size);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::super::rangecoder::tests::CarryEncoder;
    use super::*;

    // === bit-level mirror writer, header + block framing =====================

    #[derive(Default)]
    struct Writer {
        out: Vec<u8>,
        cur: u8,
        nbits: u8,
    }

    impl Writer {
        fn bit(&mut self, b: u32) {
            if b & 1 != 0 {
                self.cur |= 1 << self.nbits;
            }
            self.nbits += 1;
            if self.nbits == 8 {
                self.out.push(self.cur);
                self.cur = 0;
                self.nbits = 0;
            }
        }

        fn p2(&mut self, result: u64) {
            let value = result + 1;
            let n = value.count_ones();
            for _ in 0..n - 1 {
                self.bit(1);
            }
            self.bit(0);
            let hb = 63 - value.leading_zeros();
            for i in 0..=hb {
                self.bit(((value >> i) & 1) as u32);
            }
        }

        fn flush(&mut self) {
            if self.nbits > 0 {
                self.out.push(self.cur);
                self.cur = 0;
                self.nbits = 0;
            }
        }

        fn raw(&mut self, data: &[u8]) {
            assert_eq!(self.nbits, 0, "raw write off a byte boundary");
            self.out.extend_from_slice(data);
        }

        fn finish(mut self) -> Vec<u8> {
            self.flush();
            self.out
        }
    }

    /// Write `resetBlockStream`'s header fields.
    #[allow(clippy::too_many_arguments)]
    fn write_header(
        w: &mut Writer,
        st4: bool,
        fancy: bool,
        maxfreq1: u32,
        maxfreq2: u32,
        maxfreq3: u32,
        byteshift1: u32,
        byteshift2: u32,
        byteshift3: u32,
        countshift1: u32,
        countshift2: u32,
        countshift3: u32,
    ) {
        w.bit(st4 as u32);
        w.bit(fancy as u32);
        w.p2(u64::from(maxfreq1.trailing_zeros()));
        w.p2(u64::from(maxfreq2.trailing_zeros()));
        w.p2(u64::from(maxfreq3.trailing_zeros()));
        w.p2(u64::from(byteshift1));
        w.p2(u64::from(byteshift2));
        w.p2(u64::from(byteshift3));
        w.p2(u64::from(countshift1));
        w.p2(u64::from(countshift2));
        w.p2(u64::from(countshift3));
        // `decode()`'s loop always flushes to a byte boundary before reading the
        // end-marker bit, even on the very first iteration right after
        // `resetBlockStream` — so every block-stream builder must match that here.
        w.flush();
    }

    /// A "default" header: st4=false, fancymtf=false, generous maxfreqs, modest
    /// shifts — used by tests that don't care about the specific values.
    fn write_default_header(w: &mut Writer, st4: bool, fancy: bool) {
        write_header(w, st4, fancy, 0x2000, 0x2000, 0x2000, 5, 5, 5, 4, 4, 4);
    }

    fn write_end_marker(w: &mut Writer) {
        w.bit(1);
    }

    #[test]
    fn header_fields_round_trip_in_declared_order() {
        let mut w = Writer::default();
        write_header(&mut w, true, false, 0x40, 0x8, 0x1000, 1, 2, 3, 4, 5, 6);
        write_end_marker(&mut w);
        let bytes = w.finish();

        let mut r = Reader::new(&bytes);
        let header = reset_block_stream(&mut r).unwrap();
        assert!(header.st4transform);
        assert!(!header.fancymtf);
        assert_eq!(header.maxfreq1, 0x40);
        assert_eq!(header.maxfreq2, 0x8);
        assert_eq!(header.maxfreq3, 0x1000);
        assert_eq!(header.byteshift1, 1);
        assert_eq!(header.byteshift2, 2);
        assert_eq!(header.byteshift3, 3);
        assert_eq!(header.countshift1, 4);
        assert_eq!(header.countshift2, 5);
        assert_eq!(header.countshift3, 6);
    }

    #[test]
    fn immediate_end_marker_decodes_to_nothing() {
        let mut w = Writer::default();
        write_default_header(&mut w, false, false);
        write_end_marker(&mut w);
        let bytes = w.finish();
        assert_eq!(decode(&bytes, 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn single_uncompressed_block_round_trips() {
        let payload = b"iron uncompressed block payload".to_vec();
        let mut w = Writer::default();
        write_default_header(&mut w, false, false);
        w.bit(0); // not the end
        w.p2(payload.len() as u64);
        w.bit(1); // uncompressed
        w.flush();
        w.raw(&payload);
        write_end_marker(&mut w);
        let bytes = w.finish();

        assert_eq!(decode(&bytes, payload.len()).unwrap(), payload);
    }

    #[test]
    fn multiple_uncompressed_blocks_concatenate() {
        let a = b"first block ".to_vec();
        let b = b"second block, longer than the first one".to_vec();
        let mut w = Writer::default();
        write_default_header(&mut w, false, false);
        for chunk in [&a, &b] {
            w.bit(0);
            w.p2(chunk.len() as u64);
            w.bit(1);
            w.flush();
            w.raw(chunk);
        }
        write_end_marker(&mut w);
        let bytes = w.finish();

        let mut expected = a.clone();
        expected.extend_from_slice(&b);
        assert_eq!(decode(&bytes, expected.len()).unwrap(), expected);
    }

    #[test]
    fn stream_stops_once_size_is_reached_even_without_an_end_marker() {
        // Declare a size smaller than the block actually holds: decode must not
        // read a second (absent) block.
        let payload = b"only this much matters".to_vec();
        let mut w = Writer::default();
        write_default_header(&mut w, false, false);
        w.bit(0);
        w.p2(payload.len() as u64);
        w.bit(1);
        w.flush();
        w.raw(&payload);
        // No end marker and no further blocks written.
        let bytes = w.finish();

        let want = 4usize;
        assert_eq!(decode(&bytes, want).unwrap(), payload[..want]);
    }

    #[test]
    fn truncated_header_is_rejected() {
        let bytes: Vec<u8> = vec![];
        let err = decode(&bytes, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn oversized_maxfreq_exponent_is_rejected_without_panicking() {
        let mut w = Writer::default();
        w.bit(0);
        w.bit(0);
        w.p2(63); // 1u32 << 63 would overflow
        let bytes = w.finish();
        let err = decode(&bytes, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    // === FancyMtf: unit behavior ==============================================

    #[test]
    fn fancy_mtf_first_symbol_of_each_rank_is_identity() {
        // Before any decode, intarray1[rank]=rank, so value=rank-1 (mod 256)
        // reproduces byte=rank on the very first call.
        let mut mtf = FancyMtf::new(4);
        assert_eq!(mtf.decode(0), 1); // index=(0+1)&0xff=1 -> intarray1[1]=1
                                      // After moving byte 1 to the front, its rank is now 0.
        assert_eq!(mtf.find_rank(1), 0);
    }

    #[test]
    fn fancy_mtf_find_rank_matches_a_freshly_decoded_value() {
        let mut mtf = FancyMtf::new(8);
        for v in [0u32, 5, 2, 9, 0] {
            let byte = mtf.decode(v);
            assert_eq!(mtf.find_rank(byte), mtf.intarray2[byte as usize] as usize);
        }
    }

    // === mirror encoder: full decode_block_body / decode() round trip ========
    //
    // The model's forward direction is unambiguous (no tie-break like Cyanide's
    // ternary model), so a genuine encoder is possible: given a target `sorted`
    // byte string, this encoder run-length-encodes it, and for each run finds the
    // MTF rank of the target byte (mirroring the *same* `FancyMtf`/`MtfState`
    // instance the decoder would build), derives the `value` that reproduces that
    // rank (`index=(value+1)&0xff`), and emits it through the identical adaptive
    // contexts, letting `CarryEncoder` (the `uselow=false` mirror shared with
    // Darkhorse's tests) keep it byte-for-byte invertible by `decode_block_body`.
    //
    // A real forward BWT/ST4 is *not* needed here: the model only ever sees the
    // `sorted` string as an opaque byte sequence, so any hand-picked target
    // string exercises the model just as well as a real transform would (BWT/ST4
    // themselves are already covered independently in `bwt.rs`). Full end-to-end
    // validation against a real Iron encoder happens via the `unar` corpus oracle.

    /// Run-length-encode `data` into maximal runs of identical bytes, the
    /// grouping this encoder feeds to the model one run at a time.
    fn runs_of(data: &[u8]) -> Vec<(u8, u32)> {
        let mut out = Vec::new();
        let mut it = data.iter();
        if let Some(&first) = it.next() {
            let mut cur = first;
            let mut count = 1u32;
            for &b in it {
                if b == cur {
                    count += 1;
                } else {
                    out.push((cur, count));
                    cur = b;
                    count = 1;
                }
            }
            out.push((cur, count));
        }
        out
    }

    struct ModelEncoder {
        bits: CarryEncoder,
        mainfrequencies: [u32; 4],
        lastbytefrequencies: Vec<[u32; 4]>,
        somethingfrequencies: Vec<[u32; 4]>,
        bytelengthweights: [u32; 8],
        bytelengthweights2: [[u32; 8]; 8],
        bytebitweights: [[u32; 128]; 8],
        countlengthweights: [[[u32; 24]; 16]; 4],
        countlengthweights2: [[u32; 24]; 256],
        countbitweights: [[u32; 24]; 24],
        mtf: Mtf,
        valuehistory: u32,
        lengthhistory: u32,
        lastbits: u32,
        lastbyte: u8,
    }

    impl ModelEncoder {
        fn new(fancymtf: bool, blocksize: usize) -> Self {
            ModelEncoder {
                bits: CarryEncoder::new(),
                mainfrequencies: [1u32; 4],
                lastbytefrequencies: vec![[0u32; 4]; 256],
                somethingfrequencies: vec![[0u32; 4]; 4 * 256],
                bytelengthweights: [0x800u32; 8],
                bytelengthweights2: [[0x800u32; 8]; 8],
                bytebitweights: [[0x800u32; 128]; 8],
                countlengthweights: [[[0x800u32; 24]; 16]; 4],
                countlengthweights2: [[0x800u32; 24]; 256],
                countbitweights: [[0x800u32; 24]; 24],
                mtf: if fancymtf {
                    Mtf::Fancy(FancyMtf::new(blocksize))
                } else {
                    Mtf::Plain(MtfState::new())
                },
                valuehistory: 0,
                lengthhistory: 0,
                lastbits: 0,
                lastbyte: 0,
            }
        }

        /// The rank `byte` currently occupies, mirroring `mtf.decode`'s lookup
        /// table without consuming/advancing it. Rank 256 (the fancy MTF's
        /// phantom slot) can never be produced by any `value` — `index=
        /// (value+1)&0xff` never reaches 256 — so a test sequence that pushes a
        /// real byte there is out of scope for this harness.
        fn rank_of(&self, byte: u8) -> usize {
            let rank = match &self.mtf {
                Mtf::Fancy(f) => f.find_rank(byte),
                Mtf::Plain(m) => m.find(byte),
            };
            assert_ne!(
                rank, 256,
                "test sequence pushed byte {byte} to the unreachable phantom slot"
            );
            rank
        }

        /// One run of `count` copies of `byte` (`decode_block_body`'s per-
        /// iteration body, in reverse).
        fn encode_run(&mut self, byte: u8, count: u32, header: &Header) {
            let rank = self.rank_of(byte);
            let value = ((rank + 255) % 256) as u32;

            let something_idx =
                (self.lengthhistory & 3) as usize * 256 + self.valuehistory as usize;
            let freqs1 = self.mainfrequencies;
            let freqs2 = self.lastbytefrequencies[self.lastbyte as usize];
            let freqs3 = self.somethingfrequencies[something_idx];
            let frequencies: [u32; 4] = std::array::from_fn(|j| freqs1[j] + freqs2[j] + freqs3[j]);

            let symbol = if value < 3 { value as usize } else { 3 };
            self.bits.encode_symbol(&frequencies, symbol);

            self.mainfrequencies[symbol] += 2;
            self.lastbytefrequencies[self.lastbyte as usize][symbol] += 2;
            self.somethingfrequencies[something_idx][symbol] += 2;

            let total1: u32 = self.mainfrequencies.iter().sum();
            let total2: u32 = self.lastbytefrequencies[self.lastbyte as usize]
                .iter()
                .sum();
            let total3: u32 = self.somethingfrequencies[something_idx].iter().sum();
            if total1 > header.maxfreq1 {
                for f in self.mainfrequencies.iter_mut() {
                    *f = f.div_ceil(2);
                }
            }
            if total2 > header.maxfreq2 {
                for f in self.lastbytefrequencies[self.lastbyte as usize].iter_mut() {
                    *f /= 2;
                }
            }
            if total3 > header.maxfreq3 {
                for f in self.somethingfrequencies[something_idx].iter_mut() {
                    *f /= 2;
                }
            }

            if symbol == 3 {
                let v0 = value - 1;
                let bitlen = 32 - v0.leading_zeros();
                let bits_final = bitlen - 2;
                assert!(
                    bits_final <= 6,
                    "value {value} needs an unreachable escape length"
                );

                let mut position = 0u32;
                while position < bits_final {
                    self.bits.encode_bit_with_double_weights(
                        1,
                        &mut self.bytelengthweights[position as usize],
                        header.byteshift1,
                        &mut self.bytelengthweights2[self.lastbits as usize][position as usize],
                        header.byteshift2,
                    );
                    position += 1;
                }
                if bits_final < 6 {
                    self.bits.encode_bit_with_double_weights(
                        0,
                        &mut self.bytelengthweights[bits_final as usize],
                        header.byteshift1,
                        &mut self.bytelengthweights2[self.lastbits as usize][bits_final as usize],
                        header.byteshift2,
                    );
                }

                let mut acc: u32 = 1;
                for j in (0..=bits_final).rev() {
                    let bit = (v0 >> j) & 1;
                    self.bits.encode_bit_with_weight(
                        bit,
                        &mut self.bytebitweights[bits_final as usize][acc as usize],
                        header.byteshift3,
                    );
                    acc = (acc << 1) | bit;
                }
                self.lastbits = bits_final;
            }

            // Consume `value` through the real decode-side MTF update so the
            // encoder and decoder states stay identical, sanity-checking it
            // reproduces the byte we started from.
            let produced = self.mtf.decode(value);
            debug_assert_eq!(produced, byte);

            let shortvalue = value.min(3);

            assert!(count >= 1);
            let count_bits = 32 - count.leading_zeros() - 1;
            assert!(
                count_bits < 24,
                "run count {count} needs an illegal-data length"
            );

            let mut position = 0u32;
            while position < count_bits {
                self.bits.encode_bit_with_double_weights(
                    1,
                    &mut self.countlengthweights[shortvalue as usize][self.lengthhistory as usize]
                        [position as usize],
                    header.countshift1,
                    &mut self.countlengthweights2[byte as usize][position as usize],
                    header.countshift2,
                );
                position += 1;
            }
            self.bits.encode_bit_with_double_weights(
                0,
                &mut self.countlengthweights[shortvalue as usize][self.lengthhistory as usize]
                    [count_bits as usize],
                header.countshift1,
                &mut self.countlengthweights2[byte as usize][count_bits as usize],
                header.countshift2,
            );

            for j in 0..count_bits {
                let bit = (count >> (count_bits - 1 - j)) & 1;
                self.bits.encode_bit_with_weight(
                    bit,
                    &mut self.countbitweights[count_bits as usize][j as usize],
                    header.countshift3,
                );
            }

            self.valuehistory = ((self.valuehistory << 2) | shortvalue) & 0xff;
            self.lengthhistory = (self.lengthhistory << 1) & 0x0e;
            if count_bits > 1 {
                self.lengthhistory |= 1;
            }
            self.lastbyte = byte;
        }

        fn finish(self) -> Vec<u8> {
            self.bits.finish()
        }
    }

    /// The `Header` matching [`write_default_header`]'s bit-for-bit encoding.
    fn default_header(st4transform: bool, fancymtf: bool) -> Header {
        Header {
            st4transform,
            fancymtf,
            maxfreq1: 0x2000,
            maxfreq2: 0x2000,
            maxfreq3: 0x2000,
            byteshift1: 5,
            byteshift2: 5,
            byteshift3: 5,
            countshift1: 4,
            countshift2: 4,
            countshift3: 4,
        }
    }

    /// Encode `sorted` through [`ModelEncoder`] and assemble a full Iron stream
    /// holding it as a single compressed block. Since BWT/ST4 preserve length,
    /// the block's declared size equals `sorted.len()`, so `decode()` stops
    /// right after this one block — no need to predict the range coder's exact
    /// byte consumption for anything that would otherwise have to follow it.
    fn single_compressed_block_stream(
        st4transform: bool,
        fancymtf: bool,
        firstindex: usize,
        sorted: &[u8],
    ) -> Vec<u8> {
        let header = default_header(st4transform, fancymtf);
        let mut enc = ModelEncoder::new(fancymtf, sorted.len());
        for (byte, count) in runs_of(sorted) {
            enc.encode_run(byte, count, &header);
        }
        let coded = enc.finish();

        let mut w = Writer::default();
        write_header(
            &mut w,
            st4transform,
            fancymtf,
            header.maxfreq1,
            header.maxfreq2,
            header.maxfreq3,
            header.byteshift1,
            header.byteshift2,
            header.byteshift3,
            header.countshift1,
            header.countshift2,
            header.countshift3,
        );
        w.bit(0); // not the end
        w.p2(sorted.len() as u64);
        w.bit(0); // compressed
        w.p2(firstindex as u64);
        w.flush();
        w.raw(&[0u8]); // the byte `CSInputSkipBytes(input,1)` discards
        w.raw(&coded);
        w.finish()
    }

    #[test]
    fn compressed_block_with_plain_mtf_and_bwt_round_trips() {
        let sorted = b"aaabbbcccaaabbbccc".to_vec();
        let firstindex = 3usize;
        let stream = single_compressed_block_stream(false, false, firstindex, &sorted);
        let expected = unsort_bwt(&sorted, firstindex);
        assert_eq!(decode(&stream, expected.len()).unwrap(), expected);
    }

    #[test]
    fn compressed_block_with_fancy_mtf_and_bwt_round_trips() {
        let sorted = b"aaabbbcccaaabbbccc".to_vec();
        let firstindex = 5usize;
        let stream = single_compressed_block_stream(false, true, firstindex, &sorted);
        let expected = unsort_bwt(&sorted, firstindex);
        assert_eq!(decode(&stream, expected.len()).unwrap(), expected);
    }

    #[test]
    fn compressed_block_with_st4_dispatch_round_trips() {
        // Same hand-traced vector bwt.rs's own ST4 test pins (a repeated byte
        // that forces the `ST4_INDIRECT` branch), driven here through the full
        // model + block-framing pipeline rather than calling `unsort_st4` bare.
        let sorted = vec![1u8, 1, 2, 1];
        let firstindex = 0usize;
        let stream = single_compressed_block_stream(true, false, firstindex, &sorted);
        let expected = unsort_st4(&sorted, firstindex);
        assert_eq!(decode(&stream, expected.len()).unwrap(), expected);
    }

    #[test]
    fn escape_encoded_values_round_trip() {
        // Many distinct byte values in a short span force `symbol==3` escapes
        // (only 3 bytes get a "direct" MTF rank at a time), covering several
        // different `bits_final` lengths as ranks grow.
        let sorted: Vec<u8> = (0u8..40).chain((0u8..40).rev()).collect();
        let firstindex = 7usize;
        let stream = single_compressed_block_stream(false, false, firstindex, &sorted);
        let expected = unsort_bwt(&sorted, firstindex);
        assert_eq!(decode(&stream, expected.len()).unwrap(), expected);
    }

    #[test]
    fn escape_encoded_values_round_trip_with_fancy_mtf() {
        let sorted: Vec<u8> = (0u8..40).chain((0u8..40).rev()).collect();
        let firstindex = 11usize;
        let stream = single_compressed_block_stream(false, true, firstindex, &sorted);
        let expected = unsort_bwt(&sorted, firstindex);
        assert_eq!(decode(&stream, expected.len()).unwrap(), expected);
    }

    #[test]
    fn long_run_needs_a_multi_bit_count_round_trips() {
        // A run of 300 copies needs `count_bits>=8`, well past the single-bit
        // cases the other tests exercise.
        let mut sorted = vec![b'x'; 300];
        sorted.extend_from_slice(b"trailer");
        let firstindex = 42usize;
        let stream = single_compressed_block_stream(false, false, firstindex, &sorted);
        let expected = unsort_bwt(&sorted, firstindex);
        assert_eq!(decode(&stream, expected.len()).unwrap(), expected);
    }

    #[test]
    fn single_byte_block_round_trips() {
        let sorted = vec![42u8];
        let stream = single_compressed_block_stream(false, false, 0, &sorted);
        let expected = unsort_bwt(&sorted, 0);
        assert_eq!(decode(&stream, expected.len()).unwrap(), expected);
    }
}
