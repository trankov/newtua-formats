//! Decoders for DOS / CP-M era archive formats.
//!
//! Pure-Rust ports of legacy formats (LGPL-2.1). Each format is a
//! container parser plus its compression methods, built on the shared
//! primitives in [`newtua_common`].
//!
//! Planned formats (easiest first): Squeeze (`.SQ`), ARC, LBR, Crunch, Zoo, ARJ.
//! Modules are added one format at a time, test-first.

#![forbid(unsafe_code)]

pub mod squeeze;
