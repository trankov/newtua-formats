// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Generic LZW decoder — a prefix tree of `code → (parent code, byte)`.
//!
//! Faithful port of XADMaster's `LZW.c`. This is the generic engine that Zoo's
//! method 1 drives; it is distinct from the Unix-`compress` LZW in
//! [`crate::compress`] and from ARC's crunch. The caller reads variable-width
//! symbols from the stream (the width is [`Lzw::suggested_symbol_size`], read
//! LSB-first) and feeds each in with [`Lzw::next_symbol`]; after an accepted
//! symbol [`Lzw::reverse_output_to_buffer`] yields its decoded string — built
//! leaf-first, so the caller reads it back-to-front.

/// Outcome of feeding a symbol the tree cannot turn into output.
#[derive(Debug, PartialEq, Eq)]
pub enum LzwError {
    /// The symbol is out of range (past the next assignable code).
    InvalidCode,
    /// The code table is full, so no new entry was added. Decoding may still
    /// continue — the symbol's output was produced as usual.
    TooManyCodes,
}

/// One tree node: a byte plus the code of its prefix (`-1` for a root leaf).
#[derive(Clone, Copy)]
struct Node {
    chr: u8,
    parent: i32,
}

/// A generic LZW code tree.
pub struct Lzw {
    nodes: Vec<Node>,
    numsymbols: i32,
    maxsymbols: i32,
    reservedsymbols: i32,
    prevsymbol: i32,
    symbolsize: u32,
}

impl Lzw {
    /// Create a tree holding up to `maxsymbols` codes, reserving
    /// `reservedsymbols` slots above the 256 single-byte roots (e.g. clear and
    /// end markers). The table starts cleared.
    pub fn new(maxsymbols: i32, reservedsymbols: i32) -> Self {
        let mut nodes = vec![Node { chr: 0, parent: -1 }; maxsymbols as usize];
        for (i, node) in nodes.iter_mut().enumerate().take(256) {
            node.chr = i as u8;
        }
        let mut lzw = Self {
            nodes,
            numsymbols: 0,
            maxsymbols,
            reservedsymbols,
            prevsymbol: -1,
            symbolsize: 9,
        };
        lzw.clear_table();
        lzw
    }

    /// Reset to the initial alphabet: the 256 roots plus the reserved codes,
    /// 9-bit symbols, no previous symbol.
    pub fn clear_table(&mut self) {
        self.numsymbols = 256 + self.reservedsymbols;
        self.prevsymbol = -1;
        self.symbolsize = 9;
    }

    /// The current symbol width in bits.
    pub fn suggested_symbol_size(&self) -> u32 {
        self.symbolsize
    }

    /// Whether the code table has reached `maxsymbols`.
    pub fn is_full(&self) -> bool {
        self.numsymbols == self.maxsymbols
    }

    /// The first byte of `symbol`'s string (walk to the root of its chain).
    fn find_first_byte(&self, mut symbol: i32) -> u8 {
        while self.nodes[symbol as usize].parent >= 0 {
            symbol = self.nodes[symbol as usize].parent;
        }
        self.nodes[symbol as usize].chr
    }

    /// Feed the next code. On the first call it just records the symbol; after
    /// that it adds a new code `prevsymbol + first-byte-of(symbol)` and advances.
    /// Returns [`LzwError::InvalidCode`] for an out-of-range code and
    /// [`LzwError::TooManyCodes`] when the table is full (caller continues).
    pub fn next_symbol(&mut self, symbol: i32) -> Result<(), LzwError> {
        if self.prevsymbol < 0 {
            if symbol >= self.numsymbols {
                return Err(LzwError::InvalidCode);
            }
            self.prevsymbol = symbol;
            return Ok(());
        }

        let postfixbyte = if symbol < self.numsymbols {
            self.find_first_byte(symbol)
        } else if symbol == self.numsymbols {
            // KwKwK: the code being decoded is the one we are about to define,
            // so its first byte is the first byte of the previous string.
            self.find_first_byte(self.prevsymbol)
        } else {
            return Err(LzwError::InvalidCode);
        };

        let parent = self.prevsymbol;
        self.prevsymbol = symbol;

        if self.is_full() {
            return Err(LzwError::TooManyCodes);
        }
        self.nodes[self.numsymbols as usize] = Node {
            chr: postfixbyte,
            parent,
        };
        self.numsymbols += 1;
        if !self.is_full() && (self.numsymbols & (self.numsymbols - 1)) == 0 {
            self.symbolsize += 1;
        }
        Ok(())
    }

    /// Write the current symbol's string into `buffer`, leaf byte first, and
    /// return its length. The caller reads `buffer` back-to-front to recover the
    /// forward byte order.
    pub fn reverse_output_to_buffer(&self, buffer: &mut Vec<u8>) -> usize {
        buffer.clear();
        let mut symbol = self.prevsymbol;
        while symbol >= 0 {
            buffer.push(self.nodes[symbol as usize].chr);
            symbol = self.nodes[symbol as usize].parent;
        }
        buffer.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed a symbol, then read its decoded string in forward order.
    fn decode(lzw: &mut Lzw, symbol: i32) -> Vec<u8> {
        lzw.next_symbol(symbol).unwrap();
        let mut buf = Vec::new();
        lzw.reverse_output_to_buffer(&mut buf);
        buf.reverse();
        buf
    }

    #[test]
    fn fresh_table_starts_at_nine_bits_and_reserved_count() {
        let lzw = Lzw::new(8192, 2);
        assert_eq!(lzw.suggested_symbol_size(), 9);
        assert!(!lzw.is_full());
    }

    #[test]
    fn literals_decode_to_themselves() {
        let mut lzw = Lzw::new(8192, 2);
        assert_eq!(decode(&mut lzw, b'A' as i32), b"A");
        assert_eq!(decode(&mut lzw, b'B' as i32), b"B");
        assert_eq!(decode(&mut lzw, b'C' as i32), b"C");
    }

    #[test]
    fn back_reference_decodes_the_built_string() {
        // 'A','B' build code 258 = "AB"; referencing 258 yields "AB".
        let mut lzw = Lzw::new(8192, 2);
        assert_eq!(decode(&mut lzw, b'A' as i32), b"A");
        assert_eq!(decode(&mut lzw, b'B' as i32), b"B");
        assert_eq!(decode(&mut lzw, 258), b"AB");
    }

    #[test]
    fn kwkwk_uses_first_byte_of_previous_string() {
        // 'A' then code 258 (== numsymbols) is the classic KwKwK case: the new
        // code is "A"+first-byte("A") = "AA", giving the run "A","AA" = "AAA".
        let mut lzw = Lzw::new(8192, 2);
        assert_eq!(decode(&mut lzw, b'A' as i32), b"A");
        assert_eq!(decode(&mut lzw, 258), b"AA");
    }

    #[test]
    fn symbol_size_grows_at_power_of_two_boundary() {
        // Start at numsymbols 258; the first symbol adds no code, each later one
        // adds exactly one. numsymbols hits 512 after 254 added codes, bumping
        // the width to 10 bits.
        let mut lzw = Lzw::new(8192, 2);
        lzw.next_symbol(b'A' as i32).unwrap();
        for _ in 0..253 {
            lzw.next_symbol(b'A' as i32).unwrap();
            assert_eq!(lzw.suggested_symbol_size(), 9);
        }
        lzw.next_symbol(b'A' as i32).unwrap(); // numsymbols -> 512
        assert_eq!(lzw.suggested_symbol_size(), 10);
    }

    #[test]
    fn out_of_range_first_symbol_is_invalid() {
        let mut lzw = Lzw::new(8192, 2);
        // numsymbols is 258; code 258 is not yet defined on the first symbol.
        assert_eq!(lzw.next_symbol(258), Err(LzwError::InvalidCode));
    }

    #[test]
    fn out_of_range_later_symbol_is_invalid() {
        let mut lzw = Lzw::new(8192, 2);
        lzw.next_symbol(b'A' as i32).unwrap();
        // Next assignable code is 258; 259 skips past it.
        assert_eq!(lzw.next_symbol(259), Err(LzwError::InvalidCode));
    }

    #[test]
    fn full_table_reports_too_many_codes_but_still_outputs() {
        // Room for exactly one added code (max 259, starts at 258).
        let mut lzw = Lzw::new(259, 2);
        lzw.next_symbol(b'A' as i32).unwrap();
        lzw.next_symbol(b'B' as i32).unwrap(); // adds code 258, now full
        assert!(lzw.is_full());
        // Further symbols add nothing but still decode normally.
        assert_eq!(lzw.next_symbol(b'C' as i32), Err(LzwError::TooManyCodes));
        let mut buf = Vec::new();
        lzw.reverse_output_to_buffer(&mut buf);
        buf.reverse();
        assert_eq!(buf, b"C");
    }

    #[test]
    fn clear_table_resets_alphabet_and_width() {
        let mut lzw = Lzw::new(8192, 2);
        lzw.next_symbol(b'A' as i32).unwrap();
        for _ in 0..254 {
            lzw.next_symbol(b'A' as i32).unwrap();
        }
        assert_eq!(lzw.suggested_symbol_size(), 10);
        lzw.clear_table();
        assert_eq!(lzw.suggested_symbol_size(), 9);
        // After a clear, the first symbol again just seeds prevsymbol.
        assert_eq!(decode(&mut lzw, b'X' as i32), b"X");
    }
}
