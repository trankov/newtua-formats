// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Decoders for Amiga compression formats.
//!
//! Pure-Rust ports of legacy Amiga formats (LGPL-3.0-or-later). Modules are added
//! one format at a time, test-first.
//!
//! Formats: PowerPacker, Amiga LZX (container + LZX codec), DMS (disk images —
//! all seven methods NOCOMP/SIMPLE/QUICK/MEDIUM/DEEP/HEAVY1/HEAVY2, plus
//! encryption — and FMS file archives).

#![forbid(unsafe_code)]

pub mod dms;
pub mod lzx;
pub mod powerpacker;
