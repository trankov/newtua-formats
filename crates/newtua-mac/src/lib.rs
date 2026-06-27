//! Decoders for classic Macintosh archive / encoding formats.
//!
//! Pure-Rust ports of legacy Mac formats (LGPL-2.1). Each format is a container
//! parser plus its codec, built on the shared primitives in [`newtua_common`].
//!
//! First format: BinHex 4.0 (`.hqx`).

#![forbid(unsafe_code)]

pub mod binhex;
