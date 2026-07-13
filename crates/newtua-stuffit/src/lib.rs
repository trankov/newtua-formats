// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Decoders for the StuffIt family of classic Macintosh archives.
//!
//! Pure-Rust ports of the StuffIt formats (LGPL-3.0-or-later), built on the shared
//! primitives in [`newtua_common`]. This crate covers the **classic** StuffIt
//! container ([`stuffit`], signature `SIT!` + `rLau`), the **StuffIt 5**
//! container ([`sit5`], the 1997 banner format, including its self-extracting
//! `.exe` variant), and **StuffItX** ([`sitx`], the post-2002 `.sitx` format:
//! container plus the None / Deflate / RC4 codecs and the x86 preprocessor).
//!
//! Both containers share the same compression methods (store, RLE90, Unix
//! `compress` / LZW, StuffIt-Huffman, LZAH (method 5), LZ + Huffman (method 13),
//! and Arsenic (method 15)), dispatched through the shared [`methods`] module.
//! StuffIt 5 encrypted members (RC4 + MD5 password) decode via
//! [`sit5::StuffIt5Archive::open_with_password`].

#![forbid(unsafe_code)]

mod methods;
pub mod sit5;
pub mod sitx;
pub mod stuffit;
mod stuffit13;
mod stuffit15;
mod stuffit5;
