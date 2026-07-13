// SPDX-FileCopyrightText: 2026 Aleksei Trankov and contributors
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Independent cross-check of [`newtua_common::zipcrypt`] against Info-ZIP's
//! `zip`, a real third-party implementation of traditional PKWARE ZipCrypto.
//!
//! We cannot use `unar` here: XADMaster's ALZip parser leaves encryption
//! unimplemented (`raiseNotSupportedException`, the `XADZipCryptHandle` wiring is
//! commented out), so `unar` refuses encrypted `.alz`. Info-ZIP `zip -e` writes
//! the same cipher, though, so encrypting a file with it and decrypting with our
//! `zipcrypt` (matching the byte for byte payload) validates our keys and
//! 12-byte check header against an independent encoder. Skipped when `zip` is
//! absent.

use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use newtua_common::deflate::{self, ZIP_ORDER};
use newtua_common::zipcrypt;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn zip_installed() -> bool {
    Command::new("zip")
        .arg("-v")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn rd_u16(d: &[u8], p: usize) -> u16 {
    u16::from_le_bytes([d[p], d[p + 1]])
}
fn rd_u32(d: &[u8], p: usize) -> u32 {
    u32::from_le_bytes([d[p], d[p + 1], d[p + 2], d[p + 3]])
}

/// Run `zip` with `level` (`"-0"` stored / `"-9"` deflate) and password `pw`
/// over `content`, then return `(method, uncompressed_size, encrypted_stream,
/// test_byte)` parsed from the single local file header.
fn zip_encrypt(content: &[u8], level: &str, pw: &str) -> (u16, usize, Vec<u8>, u8) {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("newtua_zipcrypt_{}_{}", std::process::id(), n));
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("payload.bin");
    let zip = dir.join("out.zip");
    std::fs::write(&input, content).unwrap();

    let status = Command::new("zip")
        .args(["-q", "-j", level, "-P", pw])
        .arg(&zip)
        .arg(&input)
        .status()
        .expect("run zip");
    assert!(status.success(), "zip failed");

    let d = std::fs::read(&zip).unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(&d[0..4], b"PK\x03\x04", "not a local file header");
    let flags = rd_u16(&d, 6);
    let method = rd_u16(&d, 8);
    let modtime = rd_u16(&d, 10);
    let crc = rd_u32(&d, 14);
    let comp = rd_u32(&d, 18) as usize;
    let unc = rd_u32(&d, 22) as usize;
    let namelen = rd_u16(&d, 26) as usize;
    let extralen = rd_u16(&d, 28) as usize;
    assert_eq!(flags & 0x01, 1, "zip did not encrypt");

    let data_off = 30 + namelen + extralen;
    let stream = d[data_off..data_off + comp].to_vec();

    // ZipCrypto check byte: high byte of the mod time when the streaming bit
    // (bit 3) is set (the CRC is not yet known when encrypting a stream),
    // otherwise the high byte of the CRC.
    let test_byte = if flags & 0x08 != 0 {
        (modtime >> 8) as u8
    } else {
        (crc >> 24) as u8
    };

    (method, unc, stream, test_byte)
}

#[test]
fn decrypts_infozip_stored() {
    if !zip_installed() {
        eprintln!("skipping: `zip` not installed");
        return;
    }
    let content = b"traditional ZipCrypto, stored, decrypted by our port.";
    let (method, _unc, stream, test_byte) = zip_encrypt(content, "-0", "secretpw");
    assert_eq!(method, 0, "expected a stored entry");
    let payload = zipcrypt::decrypt(&stream, b"secretpw", test_byte).unwrap();
    assert_eq!(payload, content);
}

#[test]
fn decrypts_infozip_deflate() {
    if !zip_installed() {
        eprintln!("skipping: `zip` not installed");
        return;
    }
    // A compressible payload so `zip -9` picks deflate; our zipcrypt decrypts,
    // then our own inflate recovers it — cipher and codec chained.
    let content = b"deflate then encrypt, repeated so it compresses well. ".repeat(20);
    let (method, unc, stream, test_byte) = zip_encrypt(&content, "-9", "hunter2");
    assert_eq!(method, 8, "expected a deflate entry");
    let payload = zipcrypt::decrypt(&stream, b"hunter2", test_byte).unwrap();
    let out = deflate::inflate(&payload, unc, &ZIP_ORDER).unwrap();
    assert_eq!(out, content);
}

#[test]
fn wrong_password_rejected() {
    if !zip_installed() {
        eprintln!("skipping: `zip` not installed");
        return;
    }
    let content = b"check byte guards the password";
    let (_method, _unc, stream, test_byte) = zip_encrypt(content, "-0", "rightpw");
    assert!(zipcrypt::decrypt(&stream, b"wrongpw", test_byte).is_err());
}
