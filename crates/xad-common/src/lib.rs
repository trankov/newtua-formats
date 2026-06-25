//! Shared low-level primitives for the `xad-rs` family of legacy
//! archive-format decoders.
//!
//! These are the building blocks reused across the format crates (`xad-dos`,
//! `xad-mac`, `xad-stuffit`, `xad-amiga`, …): bit readers, prefix/Huffman code
//! tables, the LZSS sliding window, RLE90, and CRC variants. They are ported
//! from the corresponding pieces of The Unarchiver's XADMaster (LGPL-2.1).
//!
//! Modules are grown test-first as the format crates need them.

#![forbid(unsafe_code)]
