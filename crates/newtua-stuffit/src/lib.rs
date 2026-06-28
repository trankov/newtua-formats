//! Decoders for the StuffIt family of classic Macintosh archives.
//!
//! Pure-Rust ports of the StuffIt formats (LGPL-2.1), built on the shared
//! primitives in [`newtua_common`]. This crate currently covers the **classic**
//! StuffIt container (`.sit`, signature `SIT!` + `rLau`); StuffIt 5 and StuffItX
//! are planned.
//!
//! See [`stuffit`] for the classic container and the compression methods it
//! supports so far (store, RLE90, Unix `compress` / LZW, and StuffIt-Huffman).

#![forbid(unsafe_code)]

pub mod stuffit;
mod stuffit13;
