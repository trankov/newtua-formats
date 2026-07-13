// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Traditional PKWARE ZipCrypto stream cipher.
//!
//! The classic ZIP encryption, reused by ALZip for its encrypted members. Three
//! 32-bit keys are seeded from fixed constants, mixed with the password, and
//! then advanced by each *plaintext* byte; a keystream byte derived from `key2`
//! is XORed with the ciphertext. The stream is prefixed by a 12-byte header
//! whose last decrypted byte must equal a known check byte (the top byte of the
//! member's CRC), which is how a wrong password is detected.
//!
//! A faithful port of XADMaster's `XADZipCryptHandle` (`UpdateKeys` /
//! `DecryptByte` / `resetByteStream` / `produceByteAtOffset`).

use std::io;

use crate::crc32::crc32_step;

/// The ZipCrypto keystream engine: three keys advanced by each plaintext byte.
pub struct ZipCrypt {
    key0: u32,
    key1: u32,
    key2: u32,
}

impl ZipCrypt {
    /// Seed the keys from the fixed constants and mix in `password` (raw bytes).
    pub fn new(password: &[u8]) -> Self {
        let mut c = Self {
            key0: 305_419_896,
            key1: 591_751_049,
            key2: 878_082_192,
        };
        for &b in password {
            c.update(b);
        }
        c
    }

    /// Advance the keys by one plaintext byte (`UpdateKeys`).
    pub fn update(&mut self, plain: u8) {
        self.key0 = crc32_step(self.key0, plain);
        self.key1 = self
            .key1
            .wrapping_add(self.key0 & 0xff)
            .wrapping_mul(134_775_813)
            .wrapping_add(1);
        self.key2 = crc32_step(self.key2, (self.key1 >> 24) as u8);
    }

    /// The next keystream byte (`DecryptByte`), XORed with cipher/plaintext.
    pub fn keystream_byte(&self) -> u8 {
        let t = (self.key2 | 2) & 0xffff;
        (t.wrapping_mul(t ^ 1) >> 8) as u8
    }
}

/// Decrypt a ZipCrypto stream: the 12-byte check header plus the payload. On
/// success returns the `cipher.len() - 12` payload bytes; a header shorter than
/// 12 bytes or a check byte (index 11) that does not match `test_byte` (a wrong
/// password) is [`io::ErrorKind::InvalidInput`].
pub fn decrypt(cipher: &[u8], password: &[u8], test_byte: u8) -> io::Result<Vec<u8>> {
    if cipher.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zipcrypt: stream shorter than the 12-byte header",
        ));
    }

    let mut c = ZipCrypt::new(password);
    for (i, &cb) in cipher[..12].iter().enumerate() {
        let b = cb ^ c.keystream_byte();
        c.update(b);
        if i == 11 && b != test_byte {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zipcrypt: incorrect password",
            ));
        }
    }

    let mut out = Vec::with_capacity(cipher.len() - 12);
    for &cb in &cipher[12..] {
        let b = cb ^ c.keystream_byte();
        c.update(b);
        out.push(b);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirror encoder: encrypt `payload` behind a 12-byte header whose last byte
    /// is `test_byte` (the ZipCrypto check byte). Inverse of [`decrypt`].
    fn encrypt(payload: &[u8], password: &[u8], test_byte: u8) -> Vec<u8> {
        let mut c = ZipCrypt::new(password);
        let mut out = Vec::with_capacity(12 + payload.len());
        for i in 0..12 {
            let p = if i == 11 {
                test_byte
            } else {
                (i as u8).wrapping_mul(37)
            };
            out.push(p ^ c.keystream_byte());
            c.update(p);
        }
        for &p in payload {
            out.push(p ^ c.keystream_byte());
            c.update(p);
        }
        out
    }

    #[test]
    fn round_trip_recovers_payload() {
        let payload = b"secret ALZip payload, encrypted with ZipCrypto";
        let cipher = encrypt(payload, b"opensesame", 0x9a);
        let out = decrypt(&cipher, b"opensesame", 0x9a).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn round_trip_various_passwords_and_sizes() {
        for pw in [&b""[..], b"a", b"correct horse battery staple"] {
            for len in [0usize, 1, 7, 300] {
                let payload: Vec<u8> = (0..len).map(|i| (i * 91 + 7) as u8).collect();
                let cipher = encrypt(&payload, pw, 0x42);
                assert_eq!(decrypt(&cipher, pw, 0x42).unwrap(), payload);
                assert_eq!(cipher.len(), payload.len() + 12);
            }
        }
    }

    #[test]
    fn wrong_password_fails_check_byte() {
        let cipher = encrypt(b"payload", b"rightpass", 0x9a);
        let err = decrypt(&cipher, b"wrongpass", 0x9a).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn wrong_test_byte_fails() {
        let cipher = encrypt(b"payload", b"pw", 0x9a);
        assert!(decrypt(&cipher, b"pw", 0x9b).is_err());
    }

    #[test]
    fn stream_shorter_than_header_errors() {
        assert!(decrypt(&[0u8; 11], b"pw", 0).is_err());
    }

    #[test]
    fn empty_password_is_accepted() {
        // A degenerate but valid case: no `update` runs from the password.
        let cipher = encrypt(b"data", b"", 0x00);
        assert_eq!(decrypt(&cipher, b"", 0x00).unwrap(), b"data");
    }
}
