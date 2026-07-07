//! Shared StuffIt fork codec dispatch, used by both the classic `.sit` container
//! ([`crate::stuffit`]) and StuffIt 5 ([`crate::sit5`]).
//!
//! Both formats carry the *same* compression methods in a fork's method byte
//! (low nibble): 0 store, 1 RLE90, 2 Unix `compress`/LZW, 3 StuffIt-Huffman,
//! 5 LZAH, 13 LZ+Huffman, 15 Arsenic. Keeping the mapping here avoids duplicating
//! it in each container parser.

use std::io::{self, Read};

use newtua_common::compress::CompressReader;
use newtua_common::crc16::crc16_arc;
use newtua_common::rle90::Rle90Reader;
use newtua_common::stuffit_huffman::StuffItHuffman;

use crate::stuffit13;
use crate::stuffit15;
use crate::stuffit5;

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn unexpected_eof() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "stuffit: unexpected end of data",
    )
}

/// Read exactly `n` bytes from `r`.
fn read_n(mut r: impl Read, n: usize) -> io::Result<Vec<u8>> {
    let mut v = vec![0u8; n];
    r.read_exact(&mut v)?;
    Ok(v)
}

/// Decode one fork's `raw` compressed bytes to `size` bytes using compression
/// `method` (only the low nibble selects the codec). Returns
/// [`io::ErrorKind::Unsupported`] for methods 6/8/14, which are not implemented.
pub(crate) fn decode_fork(method: u8, raw: &[u8], size: usize) -> io::Result<Vec<u8>> {
    Ok(match method & 0x0f {
        0 => raw.get(..size).ok_or_else(unexpected_eof)?.to_vec(),
        1 => read_n(Rle90Reader::new(raw), size)?,
        2 => read_n(CompressReader::new(raw, 14, true), size)?,
        3 => StuffItHuffman::new(raw)?.read_exact(size)?,
        5 => stuffit5::decode(raw, size)?,
        13 => stuffit13::decode(raw, size)?,
        15 => stuffit15::decode(raw, size)?,
        m => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("stuffit: compression method {m} is not supported"),
            ))
        }
    })
}

/// Verify a decoded fork against its stored CRC-16/ARC. Method 15 (Arsenic)
/// carries its own internal CRC-32 and is *not* checked here — faithful to
/// XADMaster (`if((compressionmethod&0x0f)==15) return handle;`).
pub(crate) fn verify_content_crc(method: u8, decoded: &[u8], crc: u16) -> io::Result<()> {
    if method & 0x0f == 15 {
        return Ok(());
    }
    if crc16_arc(decoded) != crc {
        return Err(invalid("stuffit: fork CRC mismatch"));
    }
    Ok(())
}
