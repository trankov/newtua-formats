//! Decoders for DOS / CP-M era archive formats.
//!
//! Pure-Rust ports of legacy formats (LGPL-2.1). Each format is a
//! container parser plus its compression methods, built on the shared
//! primitives in [`newtua_common`].
//!
//! Planned formats (easiest first): Squeeze (`.SQ`), ARC, LBR, Crunch, Zoo, ARJ.
//! Modules are added one format at a time, test-first.

#![forbid(unsafe_code)]

pub mod arc;
pub mod crunch;
pub mod crush;
pub mod squeeze;

/// Shared test helpers.
#[cfg(test)]
pub(crate) mod testhex {
    /// Decode an ASCII-hex string into bytes.
    pub fn hex(s: &[u8]) -> Vec<u8> {
        fn nib(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => panic!("bad hex"),
            }
        }
        s.chunks(2).map(|p| nib(p[0]) << 4 | nib(p[1])).collect()
    }
}
