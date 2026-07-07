//! Shared low-level primitives for the `newtua-formats` family of legacy
//! archive-format decoders.
//!
//! These are the building blocks reused across the format crates (`newtua-dos`,
//! `newtua-mac`, `newtua-stuffit`, `newtua-amiga`, …): bit readers, prefix/Huffman
//! code tables, the LZSS sliding window, RLE90, and CRC variants.
//!
//! Modules are grown test-first as the format crates need them.

#![forbid(unsafe_code)]

use std::io::{self, Read};

pub mod bitreader;
pub mod bytes;
pub mod compress;
pub mod crc16;
pub mod crc32;
pub mod lzss;
pub mod lzw;
pub mod md5;
pub mod prefixcode;
pub mod rc4;
pub mod rle90;
pub mod stuffit_huffman;

/// Read one byte from `r`, retrying on `Interrupted`; `None` at end of input.
///
/// Shared by the byte-at-a-time decoders ([`rle90`], [`bitreader`]) so the
/// read/EOF/retry handling lives in one place.
pub(crate) fn read_one_byte<R: Read>(r: &mut R) -> io::Result<Option<u8>> {
    let mut b = [0u8; 1];
    loop {
        match r.read(&mut b) {
            Ok(0) => return Ok(None),
            Ok(_) => return Ok(Some(b[0])),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}
