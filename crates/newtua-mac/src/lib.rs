//! Decoders for classic Macintosh archive / encoding formats.
//!
//! Pure-Rust ports of legacy Mac formats (LGPL-2.1). Each format is a container
//! parser plus its codec, built on the shared primitives in [`newtua_common`].
//!
//! Formats: BinHex 4.0 (`.hqx`), MacBinary I/II/III, and AppleSingle /
//! AppleDouble.

#![forbid(unsafe_code)]

pub mod applesingle;
pub mod binhex;
pub mod macbinary;
