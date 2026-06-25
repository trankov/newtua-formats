//! Decoders for Amiga compression formats.
//!
//! Pure-Rust ports from The Unarchiver's XADMaster (LGPL-2.1). Modules are added
//! one format at a time, test-first.
//!
//! Planned (easiest first): PowerPacker, Amiga LZX, DMS (+ libxad bridge).

#![forbid(unsafe_code)]

pub mod powerpacker;
