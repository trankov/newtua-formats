//! LZSS sliding window.
//!
//! A power-of-two ring buffer that reconstructs LZSS output: literals are
//! written straight through, matches copy a run of earlier bytes given a
//! backward `distance` and a `length`. The copy is byte-by-byte so an
//! overlapping match (`distance < length`, the run-length case) reads bytes it
//! has just written.
//!
//! Ported from XADMaster's `LZSS.c` (`EmitLZSSLiteral` / `EmitLZSSMatch`); the
//! streaming flush machinery of `XADFastLZSSHandle` is dropped because decoders
//! here reconstruct the whole output in memory.

/// A sliding-window LZSS decoder buffer.
pub struct LzssWindow {
    /// Ring buffer of the last `mask + 1` emitted bytes.
    buffer: Vec<u8>,
    /// `window_size - 1`, used to wrap absolute positions into the ring.
    mask: usize,
    /// Total bytes emitted so far (the absolute output position).
    position: u64,
}

impl LzssWindow {
    /// Create a window of `window_size` bytes. `window_size` must be a power of
    /// two (the ring is indexed by masking).
    pub fn new(window_size: usize) -> Self {
        assert!(
            window_size.is_power_of_two(),
            "LZSS window size must be a power of two"
        );
        Self {
            buffer: vec![0u8; window_size],
            mask: window_size - 1,
            position: 0,
        }
    }

    /// Total number of bytes emitted so far.
    pub fn position(&self) -> u64 {
        self.position
    }

    /// Store `byte` at the current ring position and advance.
    fn push(&mut self, byte: u8, out: &mut Vec<u8>) {
        self.buffer[self.position as usize & self.mask] = byte;
        self.position += 1;
        out.push(byte);
    }

    /// Emit one literal byte: store it in the window and append it to `out`.
    pub fn emit_literal(&mut self, byte: u8, out: &mut Vec<u8>) {
        self.push(byte, out);
    }

    /// Emit a back-reference: copy `length` bytes starting `distance` bytes
    /// before the current position, appending each to `out`. Overlapping copies
    /// (`distance < length`) are well-defined and replicate the run.
    pub fn emit_match(&mut self, distance: usize, length: usize, out: &mut Vec<u8>) {
        for _ in 0..length {
            let src = (self.position as usize).wrapping_sub(distance) & self.mask;
            self.push(self.buffer[src], out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapping_match_replicates_run() {
        let mut w = LzssWindow::new(8);
        let mut out = Vec::new();
        w.emit_literal(b'a', &mut out);
        w.emit_match(1, 3, &mut out); // distance 1, length 3 -> "aaa"
        assert_eq!(out, b"aaaa");
        assert_eq!(w.position(), 4);
    }

    #[test]
    fn non_overlapping_match_copies_earlier_run() {
        let mut w = LzssWindow::new(8);
        let mut out = Vec::new();
        for &b in b"abc" {
            w.emit_literal(b, &mut out);
        }
        w.emit_match(3, 3, &mut out); // copy the "abc" three bytes back
        assert_eq!(out, b"abcabc");
        assert_eq!(w.position(), 6);
    }

    #[test]
    fn match_reads_across_ring_wrap() {
        // Window of 4: after "abcde", 'a' has been overwritten and the window
        // holds the last four bytes b,c,d,e. A distance-4 match copies them.
        let mut w = LzssWindow::new(4);
        let mut out = Vec::new();
        for &b in b"abcde" {
            w.emit_literal(b, &mut out);
        }
        w.emit_match(4, 4, &mut out);
        assert_eq!(out, b"abcdebcde");
        assert_eq!(w.position(), 9);
    }

    #[test]
    #[should_panic(expected = "power of two")]
    fn rejects_non_power_of_two_window() {
        LzssWindow::new(1000);
    }
}
