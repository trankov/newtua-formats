//! RLE90 run-length decoding.
//!
//! The `0x90` byte is a repeat marker: `b 0x90 n` expands to `b` repeated `n`
//! times total. `0x90 0x00` is a literal `0x90`. A count of `1` is invalid.
//! Ported from XADMaster's `XADRLE90Handle`.

use std::io::{self, Read};

/// A [`Read`] adapter that RLE90-decodes the bytes of an inner reader.
pub struct Rle90Reader<R> {
    inner: R,
    repeated: u8,
    count: usize,
}

impl<R: Read> Rle90Reader<R> {
    /// Wrap `inner`, decoding its bytes as an RLE90 stream.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            repeated: 0,
            count: 0,
        }
    }
}

impl<R: Read> Read for Rle90Reader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut n = 0;
        while n < out.len() {
            match self.produce_byte()? {
                Some(b) => {
                    out[n] = b;
                    n += 1;
                }
                None => break,
            }
        }
        Ok(n)
    }
}

impl<R: Read> Rle90Reader<R> {
    /// Produce the next decoded byte, or `None` at end of stream.
    fn produce_byte(&mut self) -> io::Result<Option<u8>> {
        if self.count > 0 {
            self.count -= 1;
            return Ok(Some(self.repeated));
        }

        let b = match crate::read_one_byte(&mut self.inner)? {
            Some(b) => b,
            None => return Ok(None),
        };

        if b != 0x90 {
            self.repeated = b;
            return Ok(Some(b));
        }

        // 0x90 is the repeat marker; the next byte is the count.
        let count = crate::read_one_byte(&mut self.inner)?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "truncated RLE90 repeat marker")
        })?;

        match count {
            // 0x90 0x00 is a literal 0x90.
            0 => {
                self.repeated = 0x90;
                Ok(Some(0x90))
            }
            1 => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid RLE90 repeat count of 1",
            )),
            // The previous byte was already emitted once, so emit `count - 1`
            // more: one now, `count - 2` queued.
            _ => {
                self.count = (count as usize) - 2;
                Ok(Some(self.repeated))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn decode(input: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        Rle90Reader::new(Cursor::new(input.to_vec())).read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn passes_plain_bytes_through() {
        assert_eq!(decode(b"ABC").unwrap(), b"ABC");
    }

    #[test]
    fn empty_input_yields_empty_output() {
        assert_eq!(decode(b"").unwrap(), b"");
    }

    #[test]
    fn escaped_marker_is_literal_0x90() {
        assert_eq!(decode(&[0x90, 0x00]).unwrap(), vec![0x90]);
    }

    #[test]
    fn run_repeats_previous_byte_to_total_count() {
        // 'A', then 0x90 0x04 → 'A' appears 4 times total.
        assert_eq!(decode(&[0x41, 0x90, 0x04]).unwrap(), vec![0x41; 4]);
    }

    #[test]
    fn run_after_escaped_marker_repeats_0x90() {
        // 0x90 0x00 (literal 0x90), then 0x90 0x03 → three 0x90 total.
        assert_eq!(decode(&[0x90, 0x00, 0x90, 0x03]).unwrap(), vec![0x90; 3]);
    }

    #[test]
    fn count_of_one_is_invalid() {
        assert!(decode(&[0x41, 0x90, 0x01]).is_err());
    }

    #[test]
    fn run_at_start_repeats_initial_zero() {
        // No preceding literal, so the run emits count-1 copies of the default
        // repeated byte (0x00) — the marker's implied "first copy" is the
        // absent literal. Matches XADMaster's XADRLE90Handle.
        assert_eq!(decode(&[0x90, 0x03]).unwrap(), vec![0x00; 2]);
    }
}
