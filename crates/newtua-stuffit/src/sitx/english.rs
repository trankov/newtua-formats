//! StuffItX English preprocessor (`XADStuffItXEnglishHandle`), applied last in
//! the chain after the compression codec runs (`preprocessalgorithm == 0`,
//! `XADStuffItXParser.m:179-181`). It is a word-substitution de-escaper for
//! English text: short escape codes stand in for whole dictionary words, and a
//! small case-tracking state machine restores capitalization.
//!
//! The whole module lives behind the `english-dict` cargo feature (see
//! `sitx::mod`), because it embeds a 100366-word, ~414 KB dictionary asset that
//! real-world `.sitx` archives rarely need.
//!
//! ## Dictionary asset provenance
//!
//! The reference implementation stores the dictionary compressed with PPMd
//! **variant I** (`XADPPMdVariantIHandle`, `maxOrder:16`, `subAllocSize:16MB`,
//! `modelRestorationMethod:0`, `.m:26-27`) and decompresses it on first use,
//! gating on CRC32 `0xfb1dcfd5` (`.m:33-34`). Variant I is a different PPMd
//! model than the variant G this project already ports (Brimstone, 19g); since
//! porting it just for one static dictionary isn't worthwhile, the asset
//! embedded here (`english_dict.deflate`) was produced once, offline: the raw
//! PPMd-I stream from `StuffItXEnglishDictionary.c` (325602 bytes) was wrapped
//! in a ZIP entry using method 98 (ZIP-PPMd, which is variant I) with the
//! 2-byte parameter word `0x00FF` (order 16, 16 MB memory, restoration method
//! 0), inflated with `7zz` (7-Zip supports ZIP-PPMd variant I), the result
//! verified against CRC32 `0xfb1dcfd5`, and re-compressed with raw deflate
//! (RFC 1951, no zlib wrapper) for compact, dependency-free embedding. This
//! module inflates it back with [`newtua_common::deflate`] and re-checks the
//! CRC before trusting it (`dictionary_bytes`, below).
//!
//! ## Dictionary layout (`.m:36-44`)
//!
//! The inflated 881863 bytes are 100366 `\n`-separated words. [`build_pointers`]
//! walks the buffer once to build an offset table; word `i` spans
//! `pointers[i]..pointers[i+1]-1` (the `-1` drops the trailing `\n`).
//!
//! ## Automaton (`.m:51-144`)
//!
//! [`decode_with_dictionary`] is a byte-for-byte port of `resetByteStream` /
//! `produceByteAtOffset:`, factored so unit tests can drive it against a tiny
//! mock [`Dictionary`] instead of the real asset.

use std::io;
use std::sync::OnceLock;

use newtua_common::{crc32, deflate};

use super::invalid;

const WORD_COUNT: usize = 100_366;
const DICT_DEFLATE: &[u8] = include_bytes!("english_dict.deflate");
const DICT_LEN: usize = 881_863;
const DICT_CRC: u32 = 0xfb1d_cfd5;

/// A `\n`-separated word list plus its offset table (`XADStuffItXEnglishHandle
/// dictionaryPointers`, `.m:20-49`). Borrowed, so tests can build a small mock
/// dictionary without touching the embedded asset.
struct Dictionary<'a> {
    bytes: &'a [u8],
    pointers: &'a [u32],
}

impl<'a> Dictionary<'a> {
    fn new(bytes: &'a [u8], pointers: &'a [u32]) -> Self {
        Dictionary { bytes, pointers }
    }

    fn len(&self) -> usize {
        self.pointers.len().saturating_sub(1)
    }

    /// Word `index`, without its trailing `\n` (`.m:94`). Caller must have
    /// already checked `index < self.len()`.
    fn word(&self, index: usize) -> &'a [u8] {
        let start = self.pointers[index] as usize;
        let end = self.pointers[index + 1] as usize - 1;
        &self.bytes[start..end]
    }
}

/// Build the offset table for a `\n`-separated word list of `word_count`
/// words (`dictionaryPointers`, `.m:36-44`).
fn build_pointers(bytes: &[u8], word_count: usize) -> io::Result<Vec<u32>> {
    let mut pointers = Vec::with_capacity(word_count + 1);
    pointers.push(0u32);
    let mut pos = 0usize;
    for _ in 0..word_count {
        let rest = bytes
            .get(pos..)
            .ok_or_else(|| invalid("sitx: english dictionary truncated"))?;
        let newline = rest
            .iter()
            .position(|&b| b == b'\n')
            .ok_or_else(|| invalid("sitx: english dictionary truncated"))?;
        pos += newline + 1;
        pointers
            .push(u32::try_from(pos).map_err(|_| invalid("sitx: english dictionary too large"))?);
    }
    Ok(pointers)
}

/// Re-borrow a `OnceLock`-cached `io::Result<Vec<T>>` as `io::Result<&[T]>`,
/// rebuilding the error shell on the error path (`io::Error` isn't `Clone`).
fn reborrow<T>(cached: &io::Result<Vec<T>>) -> io::Result<&[T]> {
    match cached {
        Ok(v) => Ok(v.as_slice()),
        Err(e) => Err(io::Error::new(e.kind(), e.to_string())),
    }
}

/// Inflate and CRC-gate the embedded dictionary asset once, caching the
/// result (`dictionaryPointers`'s `static pointers` guard, `.m:22-46`).
fn dictionary_bytes() -> io::Result<&'static [u8]> {
    static DICT: OnceLock<io::Result<Vec<u8>>> = OnceLock::new();
    reborrow(DICT.get_or_init(|| {
        let dict = deflate::inflate(DICT_DEFLATE, DICT_LEN, &deflate::ZIP_ORDER)?;
        if crc32::crc32_ieee(&dict) != DICT_CRC {
            return Err(invalid("sitx: english dictionary CRC mismatch"));
        }
        Ok(dict)
    }))
}

/// Build (once) and cache the pointer table for the embedded dictionary.
fn dictionary_pointers() -> io::Result<&'static [u32]> {
    static POINTERS: OnceLock<io::Result<Vec<u32>>> = OnceLock::new();
    reborrow(POINTERS.get_or_init(|| build_pointers(dictionary_bytes()?, WORD_COUNT)))
}

fn next_byte(input: &[u8], pos: &mut usize) -> Option<u8> {
    let b = *input.get(*pos)?;
    *pos += 1;
    Some(b)
}

/// Like [`next_byte`], but a stream that runs out here is truncated/invalid
/// rather than legitimately finished (used for header bytes, the byte
/// following an escape, and the byte re-read when a word's terminator is
/// itself the escape code).
fn read_required(input: &[u8], pos: &mut usize) -> io::Result<u8> {
    next_byte(input, pos).ok_or_else(|| invalid("sitx: english stream truncated"))
}

fn is_dict_letter(b: u8) -> bool {
    b.is_ascii_alphabetic()
}

/// Base-52 digit value of a dictionary-index letter (`.m:85-87`): `A`..`Z` are
/// 27..52, `a`..`z` are 1..26 (index 0 is encoded by *no* letters at all).
fn letter_value(b: u8) -> usize {
    if b.is_ascii_uppercase() {
        (b - b'A') as usize + 27
    } else {
        (b - b'a') as usize + 1
    }
}

/// The automaton (`produceByteAtOffset:`, `.m:62-144`), decoupled from the
/// dictionary asset so it can be unit-tested against a small mock table.
/// Produces up to `size` bytes, stopping early if `input` runs out at a word
/// boundary (mirrors `CSByteStreamEOF`, `.m:66`).
fn decode_with_dictionary(input: &[u8], size: usize, dict: &Dictionary) -> io::Result<Vec<u8>> {
    let mut pos = 0usize;

    let esccode = read_required(input, &mut pos)?;
    let wordcode = read_required(input, &mut pos)?;
    let firstcode = read_required(input, &mut pos)?;
    let uppercode = read_required(input, &mut pos)?;

    let mut caseflag = true;
    let mut wordbuf: Vec<u8> = Vec::new();
    let mut wordoffs = 0usize;

    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        if wordoffs < wordbuf.len() {
            out.push(wordbuf[wordoffs]);
            wordoffs += 1;
            continue;
        }

        let Some(c) = next_byte(input, &mut pos) else {
            break;
        };

        if c == esccode {
            caseflag = false;
            out.push(read_required(input, &mut pos)?);
        } else if c == wordcode || c == firstcode || c == uppercode {
            let mut index: usize = 0;
            let mut terminator: Option<u8> = None;
            loop {
                match next_byte(input, &mut pos) {
                    None => break,
                    Some(b) if is_dict_letter(b) => {
                        index = index * 52 + letter_value(b);
                    }
                    Some(b) => {
                        terminator = Some(b);
                        break;
                    }
                }
            }

            if index >= dict.len() {
                return Err(invalid("sitx: english dictionary index out of range"));
            }

            wordbuf.clear();
            wordbuf.extend_from_slice(dict.word(index));

            if c == uppercode {
                for b in wordbuf.iter_mut() {
                    *b = b.wrapping_sub(32);
                }
            } else if c == firstcode {
                if let Some(first) = wordbuf.first_mut() {
                    *first = first.wrapping_sub(32);
                }
            }

            if caseflag {
                if let Some(first) = wordbuf.first_mut() {
                    if first.is_ascii_uppercase() {
                        *first += 32;
                    } else if first.is_ascii_lowercase() {
                        *first -= 32;
                    }
                }
            }

            if terminator == Some(esccode) {
                terminator = Some(read_required(input, &mut pos)?);
            }

            if let Some(tail) = terminator {
                wordbuf.push(tail);
            }

            caseflag = matches!(terminator, Some(b'.') | Some(b'?') | Some(b'!'));

            let Some(&first) = wordbuf.first() else {
                return Err(invalid("sitx: english word decoded to empty buffer"));
            };
            out.push(first);
            wordoffs = 1;
        } else {
            let mut b = c;
            if caseflag {
                if b.is_ascii_uppercase() {
                    b += 32;
                    caseflag = false;
                } else if b.is_ascii_lowercase() {
                    b -= 32;
                    caseflag = false;
                } else {
                    caseflag = true; // "useless" branch, kept for fidelity with the reference
                }
            }
            if b == b'.' || b == b'?' || b == b'!' {
                caseflag = true;
            } else if b != b' ' && b != b'\n' && b != b'\r' && b != b'\t' {
                caseflag = false;
            }
            out.push(b);
        }
    }

    Ok(out)
}

/// Decode a stream through the English preprocessor, using the embedded
/// dictionary (`XADStuffItXParser.m:179-181` dispatch target).
pub(crate) fn decode(input: &[u8], size: usize) -> io::Result<Vec<u8>> {
    let bytes = dictionary_bytes()?;
    let pointers = dictionary_pointers()?;
    let dict = Dictionary::new(bytes, pointers);
    decode_with_dictionary(input, size, &dict)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ESC: u8 = 0xF0;
    const WORD: u8 = 0xF1;
    const FIRST: u8 = 0xF2;
    const UPPER: u8 = 0xF3;

    fn mock_dictionary(words: &[&str]) -> (Vec<u8>, Vec<u32>) {
        let mut bytes = Vec::new();
        for w in words {
            bytes.extend_from_slice(w.as_bytes());
            bytes.push(b'\n');
        }
        let pointers = build_pointers(&bytes, words.len()).unwrap();
        (bytes, pointers)
    }

    fn header() -> Vec<u8> {
        vec![ESC, WORD, FIRST, UPPER]
    }

    #[test]
    fn escape_code_emits_raw_byte_and_clears_caseflag() {
        let (bytes, pointers) = mock_dictionary(&["alpha", "beta", "gamma"]);
        let dict = Dictionary::new(&bytes, &pointers);

        let mut input = header();
        input.extend_from_slice(&[ESC, b'X', b'y']);

        let out = decode_with_dictionary(&input, 2, &dict).unwrap();
        assert_eq!(out, b"Xy");
    }

    #[test]
    fn word_code_decodes_plain_word() {
        let (bytes, pointers) = mock_dictionary(&["alpha", "beta", "gamma"]);
        let dict = Dictionary::new(&bytes, &pointers);

        let mut input = header();
        input.extend_from_slice(&[ESC, b' ', WORD, b'a', b' ']);

        let out = decode_with_dictionary(&input, 6, &dict).unwrap();
        assert_eq!(out, b" beta ");
    }

    #[test]
    fn first_code_capitalizes_first_letter() {
        let (bytes, pointers) = mock_dictionary(&["alpha", "beta", "gamma"]);
        let dict = Dictionary::new(&bytes, &pointers);

        let mut input = header();
        input.extend_from_slice(&[ESC, b' ', FIRST, b'a', b' ']);

        let out = decode_with_dictionary(&input, 6, &dict).unwrap();
        assert_eq!(out, b" Beta ");
    }

    #[test]
    fn upper_code_uppercases_whole_word() {
        let (bytes, pointers) = mock_dictionary(&["alpha", "beta", "gamma"]);
        let dict = Dictionary::new(&bytes, &pointers);

        let mut input = header();
        input.extend_from_slice(&[ESC, b' ', UPPER, b'a', b' ']);

        let out = decode_with_dictionary(&input, 6, &dict).unwrap();
        assert_eq!(out, b" BETA ");
    }

    #[test]
    fn caseflag_recovers_after_sentence_end() {
        let (bytes, pointers) = mock_dictionary(&["alpha", "beta", "gamma"]);
        let dict = Dictionary::new(&bytes, &pointers);

        let mut input = header();
        input.extend_from_slice(&[ESC, b' ', WORD, b'a', b'.', WORD, b'a', b' ']);

        let out = decode_with_dictionary(&input, 11, &dict).unwrap();
        assert_eq!(out, b" beta.Beta ");
    }

    #[test]
    fn multi_letter_index_uses_base_52() {
        let words: Vec<String> = (0..150).map(|i| format!("w{i}")).collect();
        let word_refs: Vec<&str> = words.iter().map(String::as_str).collect();
        let (bytes, pointers) = mock_dictionary(&word_refs);
        let dict = Dictionary::new(&bytes, &pointers);
        // "ba" -> index 2*52+1 = 105 (letter values: 'b'=2, 'a'=1).
        assert_eq!(dict.word(105), b"w105");

        let mut input = header();
        input.extend_from_slice(&[ESC, b' ', WORD, b'b', b'a', b' ']);

        let out = decode_with_dictionary(&input, 6, &dict).unwrap();
        assert_eq!(out, b" w105 ");
    }

    #[test]
    fn terminator_equal_to_esc_code_is_reread() {
        let (bytes, pointers) = mock_dictionary(&["alpha", "beta", "gamma"]);
        let dict = Dictionary::new(&bytes, &pointers);

        let mut input = header();
        input.extend_from_slice(&[ESC, b' ', WORD, b'a', ESC, b'Z']);

        let out = decode_with_dictionary(&input, 6, &dict).unwrap();
        assert_eq!(out, b" betaZ");
    }

    #[test]
    fn index_out_of_range_is_an_error() {
        let (bytes, pointers) = mock_dictionary(&["alpha", "beta", "gamma"]);
        let dict = Dictionary::new(&bytes, &pointers);

        let mut input = header();
        input.extend_from_slice(&[ESC, b' ', WORD, b'c', b' ']);

        assert!(decode_with_dictionary(&input, 10, &dict).is_err());
    }

    #[test]
    fn truncated_header_is_an_error() {
        let (bytes, pointers) = mock_dictionary(&["alpha"]);
        let dict = Dictionary::new(&bytes, &pointers);
        assert!(decode_with_dictionary(&[ESC, WORD], 1, &dict).is_err());
    }

    #[test]
    fn stops_early_when_input_is_exhausted_at_a_boundary() {
        let (bytes, pointers) = mock_dictionary(&["alpha", "beta", "gamma"]);
        let dict = Dictionary::new(&bytes, &pointers);

        let mut input = header();
        input.extend_from_slice(&[ESC, b' ']);

        // Requesting more output than the input can produce: the loop breaks
        // at the top-level "at EOF" checkpoint instead of erroring.
        let out = decode_with_dictionary(&input, 10, &dict).unwrap();
        assert_eq!(out, b" ");
    }

    #[test]
    fn dictionary_asset_inflates_and_passes_crc_gate() {
        let bytes = dictionary_bytes().expect("embedded dictionary should inflate and CRC-check");
        assert_eq!(bytes.len(), DICT_LEN);
        assert_eq!(crc32::crc32_ieee(bytes), DICT_CRC);

        let pointers = dictionary_pointers().expect("pointer table should build");
        assert_eq!(pointers.len(), WORD_COUNT + 1);
    }
}
