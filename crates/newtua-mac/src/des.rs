// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! DES (Data Encryption Standard) in ECB mode — the cipher PackIt's `PMa6`
//! records are encrypted with.
//!
//! A self-contained, safe-Rust port of the textbook DES algorithm, equivalent to
//! XADMaster's `Crypto/des.c` (`DES_set_key` + `DES_encrypt`). That reference is a
//! table-accelerated implementation; DES is a fixed standard, so this plain
//! version produces byte-identical output (pinned by the standard test vector in
//! the tests, and cross-checked against the real libdes through the `unar`
//! oracle). Only what PackIt needs is exposed: a key schedule and single-block
//! encrypt/decrypt.
//!
//! Bit numbering follows the standard (NBS) convention: bit 1 is the most
//! significant bit of byte 0, so a 64-bit block maps to a `u64` big-endian.

/// Initial permutation.
#[rustfmt::skip]
const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
];

/// Final permutation (inverse of `IP`).
#[rustfmt::skip]
const FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
];

/// Expansion function (32 -> 48 bits).
#[rustfmt::skip]
const E: [u8; 48] = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
];

/// Permutation applied to the S-box output.
#[rustfmt::skip]
const P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25,
];

/// Permuted choice 1 (key 64 -> 56 bits).
#[rustfmt::skip]
const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

/// Permuted choice 2 (56 -> 48 bits per round subkey).
#[rustfmt::skip]
const PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
];

/// Per-round left-rotation counts for the C/D key halves.
const SHIFTS: [u32; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

/// The eight S-boxes, each 4 rows × 16 columns, flattened row-major.
#[rustfmt::skip]
const S: [[u8; 64]; 8] = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
];

/// Select `table.len()` bits from the low `in_bits` of `input`, where table
/// entries are 1-based bit positions counted from the most-significant bit.
fn permute(input: u64, table: &[u8], in_bits: u32) -> u64 {
    let mut out = 0u64;
    for &p in table {
        out = (out << 1) | ((input >> (in_bits - u32::from(p))) & 1);
    }
    out
}

/// A 28-bit left rotation (for the C and D key halves).
fn rotl28(value: u32, count: u32) -> u32 {
    ((value << count) | (value >> (28 - count))) & 0x0fff_ffff
}

/// A DES key schedule: the sixteen 48-bit round subkeys.
pub(crate) struct DesKeySchedule {
    subkeys: [u64; 16],
}

/// Build the key schedule from an 8-byte key. Port of `DES_set_key`.
pub(crate) fn set_key(key: &[u8; 8]) -> DesKeySchedule {
    let k = u64::from_be_bytes(*key);
    let permuted = permute(k, &PC1, 64); // 56 bits
    let mut c = (permuted >> 28) as u32 & 0x0fff_ffff;
    let mut d = permuted as u32 & 0x0fff_ffff;

    let mut subkeys = [0u64; 16];
    for (round, key) in subkeys.iter_mut().enumerate() {
        c = rotl28(c, SHIFTS[round]);
        d = rotl28(d, SHIFTS[round]);
        let cd = (u64::from(c) << 28) | u64::from(d);
        *key = permute(cd, &PC2, 56); // 48 bits
    }
    DesKeySchedule { subkeys }
}

/// The Feistel function: expand `r` to 48 bits, mix in `subkey`, substitute
/// through the S-boxes, and permute the 32-bit result.
fn feistel(r: u32, subkey: u64) -> u32 {
    let expanded = permute(u64::from(r), &E, 32) ^ subkey; // 48 bits
    let mut sout = 0u32;
    for (i, sbox) in S.iter().enumerate() {
        let six = ((expanded >> (42 - 6 * i)) & 0x3f) as usize;
        let row = ((six & 0x20) >> 4) | (six & 1);
        let col = (six >> 1) & 0x0f;
        sout = (sout << 4) | u32::from(sbox[row * 16 + col]);
    }
    permute(u64::from(sout), &P, 32) as u32
}

/// Encrypt (or, with `decrypt`, decrypt) one 8-byte block in place. Port of
/// `DES_encrypt(block, decrypt, ks)`: decryption simply applies the round
/// subkeys in reverse order.
pub(crate) fn encrypt_block(block: &mut [u8; 8], decrypt: bool, ks: &DesKeySchedule) {
    let permuted = permute(u64::from_be_bytes(*block), &IP, 64);
    let mut l = (permuted >> 32) as u32;
    let mut r = permuted as u32;

    for round in 0..16 {
        let subkey = if decrypt {
            ks.subkeys[15 - round]
        } else {
            ks.subkeys[round]
        };
        let next = l ^ feistel(r, subkey);
        l = r;
        r = next;
    }

    // Pre-output swaps the halves: R is placed before L.
    let preoutput = (u64::from(r) << 32) | u64::from(l);
    let out = permute(preoutput, &FP, 64);
    *block = out.to_be_bytes();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical DES test vector (FIPS / libdes): key 0123456789ABCDEF,
    /// plaintext 4E6F772069732074 -> ciphertext 3FA40E8A984D4815.
    const KEY: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
    const PLAIN: [u8; 8] = [0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74];
    const CIPHER: [u8; 8] = [0x3F, 0xA4, 0x0E, 0x8A, 0x98, 0x4D, 0x48, 0x15];

    #[test]
    fn encrypt_matches_test_vector() {
        let ks = set_key(&KEY);
        let mut block = PLAIN;
        encrypt_block(&mut block, false, &ks);
        assert_eq!(block, CIPHER);
    }

    #[test]
    fn decrypt_inverts_test_vector() {
        let ks = set_key(&KEY);
        let mut block = CIPHER;
        encrypt_block(&mut block, true, &ks);
        assert_eq!(block, PLAIN);
    }

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let ks = set_key(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let original = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33];
        let mut block = original;
        encrypt_block(&mut block, false, &ks);
        assert_ne!(block, original);
        encrypt_block(&mut block, true, &ks);
        assert_eq!(block, original);
    }

    #[test]
    fn all_zero_key_and_block_known_vector() {
        // DES with an all-zero key and all-zero block -> 8CA64DE9C1B123A7.
        let ks = set_key(&[0u8; 8]);
        let mut block = [0u8; 8];
        encrypt_block(&mut block, false, &ks);
        assert_eq!(block, [0x8C, 0xA6, 0x4D, 0xE9, 0xC1, 0xB1, 0x23, 0xA7]);
    }
}
