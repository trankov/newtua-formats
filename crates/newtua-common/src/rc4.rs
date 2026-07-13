// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! RC4 stream cipher (Rivest Cipher 4).
//!
//! A tiny symmetric stream cipher: a 256-byte permutation state keyed by the
//! password (KSA), then a keystream (PRGA) XORed over the data. Encryption and
//! decryption are the same operation. Used by StuffIt 5 (and later StuffItX).
//!
//! Faithful port of XADMaster's `XADRC4Engine`.

/// An RC4 keystream generator over a keyed 256-byte permutation.
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Key the cipher (the KSA). `key` must be non-empty — an empty key is a
    /// programming error (the KSA indexes `key[i % key.len()]`) and panics.
    pub fn new(key: &[u8]) -> Self {
        assert!(!key.is_empty(), "rc4: key must not be empty");
        let mut s = [0u8; 256];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    /// XOR the RC4 keystream over `buf` in place (the PRGA). Applying the same
    /// key twice restores the original bytes.
    pub fn apply(&mut self, buf: &mut [u8]) {
        for byte in buf {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k = self.s[self.i as usize].wrapping_add(self.s[self.j as usize]);
            *byte ^= self.s[k as usize];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keystream_xor(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut buf = plaintext.to_vec();
        Rc4::new(key).apply(&mut buf);
        buf
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn wikipedia_test_vectors() {
        assert_eq!(
            hex(&keystream_xor(b"Key", b"Plaintext")),
            "bbf316e8d940af0ad3"
        );
        assert_eq!(hex(&keystream_xor(b"Wiki", b"pedia")), "1021bf0420");
        assert_eq!(
            hex(&keystream_xor(b"Secret", b"Attack at dawn")),
            "45a01f645fc35b383552544b9bf5"
        );
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = b"a longer key for round-trip";
        let plain = b"the quick brown fox jumps over the lazy dog, twice over now";
        let mut buf = plain.to_vec();
        Rc4::new(key).apply(&mut buf);
        assert_ne!(&buf, plain);
        Rc4::new(key).apply(&mut buf);
        assert_eq!(&buf, plain);
    }

    #[test]
    #[should_panic(expected = "key must not be empty")]
    fn empty_key_panics() {
        Rc4::new(&[]);
    }
}
