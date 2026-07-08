//! Codec detection and decoding for NSIS payload streams.
//!
//! NSIS sniffs the compression method from the first bytes of the data area
//! (`XADNSISParser.m` `LooksLike*` and the format constants `:9-15,:51-69`).
//! For task 20a we decode **LZMA** (raw LZMA1, five property bytes, no size
//! field — via the mature `lzma-rs` crate) and **NSIS-deflate** (via
//! `newtua-common::deflate::inflate_nsis`). The filtered-LZMA (BCJ+LZMA) and
//! custom NSIS-bzip2 branches are recognised but deferred to task 20b, and the
//! legacy zlib branch is out of scope; all three surface as `Unsupported`.

use std::io::{self, Cursor};

use newtua_common::deflate;

use crate::{invalid, unsupported};

/// The compression method backing an NSIS archive's data area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Codec {
    /// Raw LZMA1: five property bytes, an end-of-stream marker, no size field.
    Lzma,
    /// NSIS's modified deflate (`XADNSISDeflateVariant`).
    NsisDeflate,
}

/// `LooksLikeLZMA` (`XADNSISParser.m:51-54`): the raw-LZMA property bytes always
/// begin `5D 00 00 xx xx 00`.
fn looks_like_lzma(sig: &[u8]) -> bool {
    sig.len() >= 6 && sig[0] == 0x5d && sig[1] == 0 && sig[2] == 0 && sig[5] == 0
}

/// `LooksLikeFilteredLZMA` (`:56-59`): a leading filter byte (0 or 1), then LZMA.
fn looks_like_filtered_lzma(sig: &[u8]) -> bool {
    sig.len() >= 7 && (sig[0] == 0 || sig[0] == 1) && looks_like_lzma(&sig[1..])
}

/// `LooksLikeNSISBzip2` (`:61-64`): `'1'` then a 24-bit block size below 900000.
fn looks_like_nsis_bzip2(sig: &[u8]) -> bool {
    sig.len() >= 4
        && sig[0] == b'1'
        && ((u32::from(sig[1]) << 16) + (u32::from(sig[2]) << 8) + u32::from(sig[3])) < 900_000
}

/// `LooksLikeZlib` (`:66-69`): a zlib header with best-compression flags.
fn looks_like_zlib(sig: &[u8]) -> bool {
    sig.len() >= 2 && sig[0] == 0x78 && sig[1] == 0xda
}

/// Sniff the codec from the first bytes of a stream, mirroring the reference's
/// probe order. `Lzma` and `NsisDeflate` are decodable in 20a; the deferred and
/// out-of-scope methods return `Unsupported` rather than silently mis-decoding.
pub fn sniff(sig: &[u8]) -> io::Result<Codec> {
    if looks_like_lzma(sig) {
        Ok(Codec::Lzma)
    } else if looks_like_filtered_lzma(sig) {
        Err(unsupported(
            "nsis: filtered LZMA (BCJ+LZMA) is deferred to task 20b",
        ))
    } else if looks_like_nsis_bzip2(sig) {
        Err(unsupported(
            "nsis: custom NSIS bzip2 is deferred to task 20b",
        ))
    } else if looks_like_zlib(sig) {
        Err(unsupported("nsis: legacy zlib format is out of scope"))
    } else {
        // No recognised signature: NSIS-deflate is the fallback (`:96,:329`).
        Ok(Codec::NsisDeflate)
    }
}

/// Decode a whole codec stream to the end (LZMA end-marker or deflate stream
/// end). `data` starts at the codec payload — for LZMA, the five property bytes.
pub fn decode(codec: Codec, data: &[u8]) -> io::Result<Vec<u8>> {
    match codec {
        Codec::Lzma => decode_lzma_raw(data),
        Codec::NsisDeflate => deflate::inflate_nsis(data),
    }
}

/// Decode raw LZMA1 as NSIS stores it: five property bytes, then the LZMA
/// stream terminated by an end-of-stream marker, with **no** eight-byte size
/// field (`XADLZMAHandle.m`, `XADNSISParser.m:1181-1188`).
///
/// `lzma-rs`'s `UnpackedSize::UseProvided(None)` reads exactly the five-byte
/// property header, skips the (absent) size field, and decodes until the end
/// marker — precisely NSIS's on-disk layout, so no synthetic 13-byte header is
/// needed.
fn decode_lzma_raw(data: &[u8]) -> io::Result<Vec<u8>> {
    let options = lzma_rs::decompress::Options {
        unpacked_size: lzma_rs::decompress::UnpackedSize::UseProvided(None),
        ..Default::default()
    };
    let mut out = Vec::new();
    let mut input = Cursor::new(data);
    lzma_rs::lzma_decompress_with_options(&mut input, &mut out, &options)
        .map_err(|e| invalid(format!("nsis: lzma decode failed: {e}")))?;
    Ok(out)
}

#[cfg(test)]
pub(crate) mod test_support {
    //! LZMA encoder used by tests to build fixtures in NSIS's raw layout.
    use std::io::Cursor;

    /// Compress `data` to NSIS raw LZMA: five property bytes + stream + end
    /// marker, no size field — the inverse of [`super::decode_lzma_raw`].
    ///
    /// `lzma-rs` only writes an end-of-stream marker together with the eight-byte
    /// size field (`WriteToHeader(None)`); its `SkipWritingToHeader` mode omits
    /// both. NSIS wants the marker but *not* the size, so we compress with
    /// `WriteToHeader(None)` and then drop the size field (bytes 5..13), leaving
    /// exactly NSIS's on-disk layout.
    pub fn lzma_encode_raw(data: &[u8]) -> Vec<u8> {
        let options = lzma_rs::compress::Options {
            unpacked_size: lzma_rs::compress::UnpackedSize::WriteToHeader(None),
        };
        let mut out = Vec::new();
        let mut input = Cursor::new(data);
        lzma_rs::lzma_compress_with_options(&mut input, &mut out, &options).unwrap();
        out.drain(5..13); // remove the eight-byte uncompressed-size field
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_support::lzma_encode_raw;

    #[test]
    fn lzma_round_trips_raw_stream() {
        let data = b"raw LZMA1 with an end marker and no size field. ".repeat(30);
        let comp = lzma_encode_raw(&data);
        // A genuine raw stream starts with the 0x5D property byte.
        assert_eq!(comp[0], 0x5d);
        assert_eq!(decode(Codec::Lzma, &comp).unwrap(), data);
    }

    #[test]
    fn lzma_round_trips_empty_and_small() {
        for data in [b"".to_vec(), b"x".to_vec(), vec![0u8; 1000]] {
            let comp = lzma_encode_raw(&data);
            assert_eq!(decode(Codec::Lzma, &comp).unwrap(), data);
        }
    }

    #[test]
    fn nsis_deflate_round_trips() {
        let data = b"nsis deflate payload payload payload. ".repeat(20);
        let comp = deflate::deflate_dynamic(&data, &deflate::ZIP_ORDER);
        assert_eq!(decode(Codec::NsisDeflate, &comp).unwrap(), data);
    }

    #[test]
    fn sniff_detects_lzma() {
        assert_eq!(sniff(&[0x5d, 0, 0, 0x00, 0x10, 0, 0]).unwrap(), Codec::Lzma);
    }

    #[test]
    fn sniff_defaults_to_deflate() {
        // A deflate stream begins with arbitrary bits, not any known signature.
        assert_eq!(
            sniff(&[0x78, 0x01, 0, 0, 0, 0, 0]).unwrap(),
            Codec::NsisDeflate
        );
    }

    #[test]
    fn sniff_filtered_lzma_is_unsupported() {
        let e = sniff(&[0x00, 0x5d, 0, 0, 0x00, 0x10, 0]).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn sniff_nsis_bzip2_is_unsupported() {
        // '1' followed by a 24-bit block size < 900000.
        let e = sniff(&[b'1', 0x00, 0x00, 0x10, 0, 0, 0]).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn sniff_zlib_is_unsupported() {
        let e = sniff(&[0x78, 0xda, 0, 0, 0, 0, 0]).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
    }
}
