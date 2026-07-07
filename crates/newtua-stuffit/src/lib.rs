//! Decoders for the StuffIt family of classic Macintosh archives.
//!
//! Pure-Rust ports of the StuffIt formats (LGPL-2.1), built on the shared
//! primitives in [`newtua_common`]. This crate covers the **classic** StuffIt
//! container ([`stuffit`], signature `SIT!` + `rLau`) and the **StuffIt 5**
//! container ([`sit5`], the 1997 banner format, including its self-extracting
//! `.exe` variant); StuffItX is still planned.
//!
//! Both containers share the same compression methods (store, RLE90, Unix
//! `compress` / LZW, StuffIt-Huffman, LZAH (method 5), LZ + Huffman (method 13),
//! and Arsenic (method 15)), dispatched through the shared [`methods`] module.
//! StuffIt 5 encryption (RC4 + MD5) is parsed but not yet decoded.

#![forbid(unsafe_code)]

mod methods;
pub mod sit5;
pub mod stuffit;
mod stuffit13;
mod stuffit15;
mod stuffit5;
