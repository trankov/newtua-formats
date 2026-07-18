# newtua-formats

> Pure-Rust decoders for the legacy archive formats the modern ecosystem forgot.

[![License: LGPL v3](https://img.shields.io/badge/License-LGPLv3-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/rustc-1.74+-orange.svg)](#requirements)
[![Made for retro & preservation](https://img.shields.io/badge/for-digital%20preservation-8a2be2.svg)](#why-this-exists)

**English** · [Русский](README_ru.md)

---

Somewhere on an old hard drive there is a `.sit` from a 1996 Mac, a `.dms` disk image from an Amiga, a `.arj` off a DOS BBS, or a `.zoo` from a Usenet post. The programs that made them are long gone, and today's Rust crates don't read them.

`newtua-formats` does. It is a family of small, self-contained crates that decode **exactly the formats missing from the Rust ecosystem** — no more, no less — with the decompression algorithms carefully ported from [The Unarchiver](https://theunarchiver.com/)'s battle-tested **XADMaster** engine and cross-checked against it for correctness.

It's built as the archive backend for a larger project, **New The Unarchiver**, but every crate stands on its own and is offered as a gift to the wider Rust and digital-preservation communities.

## Why this exists

- **The ecosystem has gaps.** Mainstream formats are well covered in Rust (zip, 7z, tar, RAR, gzip, bzip2, xz, zstd, LHA via `delharc`, `.Z`). The *old* stuff — Mac classic, Amiga, DOS/CP-M-era archivers — mostly is not. This project fills those gaps and *only* those gaps.
- **Old data deserves to be readable.** These formats matter for retrocomputing, museum and archive work, and anyone rescuing files from obsolete media.
- **No FFI, no shelling out.** Everything is pure Rust. You don't need a copy of `unar`, `7z`, or any C library at runtime.

## How it came to be

We set out to carry [The Unarchiver](https://theunarchiver.com/) forward — to give that venerable Mac tool a modern, **cross-platform life in Rust**. As we rebuilt it, we kept hitting the same wall: for the mainstream formats there were good Rust crates, but for the *legacy* ones — the old Mac, Amiga and DOS archivers The Unarchiver was famous for handling — there was simply nothing.

So we went to the source. The Unarchiver's engine, **XADMaster**, was written in Objective-C and its code was public. (The Unarchiver was eventually sold on, but that Objective-C source had long been available under the LGPL.) Rather than reverse-engineer each format from scratch, we ported the decoders from that reference implementation — reading the proven ObjC, re-expressing it as idiomatic, dependency-free Rust, and verifying the result against the original.

`newtua-formats` is the result: the legacy-format layer, pulled out into standalone crates so the whole community can use it, not just our own extractor.

## Part of New The Unarchiver

These crates are one layer of **[New The Unarchiver](https://github.com/new-the-unarchiver)** — a ground-up, cross-platform Rust reincarnation of The Unarchiver. Where the original was a macOS app, New The Unarchiver aims to run everywhere and adds a cross-platform command line, an inline terminal UI, fully in-process extraction (no bundled `unrar`/`7z`/`tar` binaries to shell out to), selective extraction by glob, and localizable messages — all while reading the same archive formats users relied on the original for. `newtua-formats` is the piece of that engine responsible for the *legacy* formats. We carved it out and published it on its own because a good pure-Rust decoder for a forgotten format is useful far beyond one app — and giving it back is the point.

## Supported formats

Grouped by the world they came from. The **Notes & limitations** column flags where a decoder intentionally stops — ⚠️ marks a corner that is *not* supported.

### Classic Macintosh — `newtua-mac`, `newtua-stuffit`

| Format | Ext. | Notes & limitations |
|--------|------|---------------------|
| StuffIt (classic) | `.sit` | The dominant Mac archiver; methods 0/1/2/3/5/13/15. ⚠️ Methods 6/8/14 not implemented |
| StuffIt 5 | `.sit` | Later container, incl. RC4/MD5 encryption |
| StuffItX | `.sitx` | Range-coded successor, incl. the Brimstone codec. ⚠️ Encrypted streams and recovery/redundancy records unsupported (the reference tool can't do them either); the English dictionary preprocessor is behind the `english-dict` feature, off by default |
| BinHex 4.0 | `.hqx` | 7-bit ASCII transport encoding with resource forks |
| MacBinary I/II/III | `.bin` | Resource-fork container |
| AppleSingle / AppleDouble | — | Fork-preserving encodings |
| Compact Pro | `.cpt` | Popular early-90s shareware archiver |
| PackIt | `.pit` | Early Mac archiver |

### Commodore Amiga — `newtua-amiga`

| Format | Ext. | Notes & limitations |
|--------|------|---------------------|
| Amiga LZX | `.lzx` | The Amiga archiver (distinct from LHA's LZX). ⚠️ Block type 1 not supported |
| PowerPacker | `.pp` | Single-file cruncher |
| DMS | `.dms` | Disk Masher System floppy images, **including encryption and FMS files — which `unar` itself cannot do**. ⚠️ Self-extracting wrappers (DMSSFX/SDSSFX) not ported |

### DOS / CP/M era — `newtua-dos`

| Format | Ext. | Notes & limitations |
|--------|------|---------------------|
| ARJ | `.arj` | Robert Jung's archiver. ⚠️ Encrypted archives not supported |
| Zoo | `.zoo` | Rahul Dhesi's cross-platform archiver. ⚠️ Method 1 (LZW) not supported |
| ARC | `.arc` | SEA's original PC archiver. ⚠️ A few rare methods unsupported |
| Squeeze | `.sq`, `.qqq` | Huffman-coded CP/M & DOS files |
| Crunch | — | LZW cruncher (DOS and CP/M variants) |
| LBR | `.lbr` | CP/M library container |

### Other

| Format | Ext. | Crate | Notes & limitations |
|--------|------|-------|---------------------|
| ALZip | `.alz` | `newtua-alz` | ESTsoft's Korean archiver; methods 0/1/2/3, ZipCrypto encryption, multi-volume sets |
| NSIS | `.exe` | `newtua-nsis` | Contents of Nullsoft installer executables. ⚠️ NSIS 2.0+/3.x only; pre-2.0 heuristics and legacy zlib unsupported |

Shared low-level machinery (bit readers, prefix/Huffman codes, LZSS/LZW windows, deflate, RLE90, CRC-16/32, MD5, RC4, ZipCrypto) lives in **`newtua-common`**.

## What we didn't port — and why

Two kinds of things are deliberately absent, so you know the boundaries up front.

**Mainstream formats are out of scope** — Rust already handles them well, and we have no interest in duplicating that work: zip, 7z, tar, RAR, gzip, bzip2, xz, zstd, LHA/LZH (via `delharc`), `.Z`. `newtua-formats` fills the gaps; it doesn't reinvent what already exists.

**A few legacy formats are deferred** — genuinely rare today, to be revisited on demand:

| Format | Why not (yet) |
|--------|---------------|
| DiskDoubler (`.dd`) | Early-90s classic Mac, deep-retro only. Many methods (several untested even upstream) plus Stac LZS compression |
| NowCompress | Even more niche classic Mac; relies on fragile offset heuristics that need a real corpus to validate first |
| Assorted rare libxad formats | Seldom seen in the wild today |

**On encryption and edge cases:** where the original XADMaster / `unar` cannot decrypt or extract something, neither do we — we return a clean `Unsupported` error instead of guessing. The happy exceptions are **ALZip** and **DMS**, where we go *further* than the reference and do decrypt/extract, verified against independent tools.

## Usage

Add the crate for the family you need:

```sh
cargo add newtua-dos
```

Almost every format shares the same small, uniform API — `recognize` to sniff,
`open` to parse, `entries` to list, `read_entry` to extract:

```rust
use std::io::Cursor;
use newtua_dos::zoo::ZooArchive;

fn main() -> std::io::Result<()> {
    let bytes = std::fs::read("classic.zoo")?;

    // Optional: cheaply confirm the format before committing to a parser.
    if !ZooArchive::recognize(&bytes) {
        eprintln!("not a Zoo archive");
        return Ok(());
    }

    let archive = ZooArchive::open(Cursor::new(bytes))?;
    for (i, entry) in archive.entries().iter().enumerate() {
        if entry.is_dir() {
            continue;
        }
        let name = String::from_utf8_lossy(entry.name());
        let mut out = Vec::new();
        archive.read_entry(i, &mut out)?;
        println!("{name} — {} bytes", out.len());
    }
    Ok(())
}
```
The same shape works for `newtua_mac::binhex::BinHexArchive`, `newtua_stuffit::stuffit::StuffItArchive`, `newtua_alz::AlzArchive`, `newtua_nsis::NsisArchive`, and the rest.

**Filenames are bytes.** `entry.name()` returns `&[u8]`, not `String`: these archives predate UTF-8 and carry names in Mac Roman, Shift-JIS, Amiga Latin-1 and more. Decoding the charset is left to the caller, who knows the provenance — a deliberate choice for faithful preservation.

**A few streaming formats differ.** The Amiga trio is shaped around what it actually holds: `PowerPacker` decodes one stream (`open(..).decode()`), and `DMS` is a floppy image you read whole (`read_disk_image()`) or per-file (`read_file(..)`). See the per-crate docs on docs.rs.

## Correctness

Most of these formats have **no surviving compressor**, so we can't just round-trip against a reference tool. Instead each decoder is validated three ways:

1. **Mirror encoder** — an exact inverse of the decoder, used to synthesise fixtures for an always-on round-trip test.
2. **`unar` oracle** — output is cross-checked byte-for-byte against The Unarchiver's reference decompressor.
3. **Independent encoders** — where one exists (e.g. `binhex`, `macbinary`, Info-ZIP `zip`), fixtures are produced by third-party tools too.

The whole project is test-driven, so every format ships with the tests that prove it.

## Crates

| Crate | What it decodes |
|-------|-----------------|
| [`newtua-common`](crates/newtua-common) | Shared primitives (bit readers, Huffman/LZW, deflate, CRC, MD5, RC4, ZipCrypto) |
| [`newtua-dos`](crates/newtua-dos) | Squeeze, ARC, LBR, Crunch, Zoo, ARJ |
| [`newtua-mac`](crates/newtua-mac) | BinHex, MacBinary/AppleSingle/AppleDouble, Compact Pro, PackIt |
| [`newtua-stuffit`](crates/newtua-stuffit) | StuffIt classic, StuffIt 5, StuffItX |
| [`newtua-amiga`](crates/newtua-amiga) | PowerPacker, Amiga LZX, DMS |
| [`newtua-alz`](crates/newtua-alz) | ALZip |
| [`newtua-nsis`](crates/newtua-nsis) | NSIS installers |

## Requirements

- **Rust 1.74+** (edition 2021).
- No system dependencies. A couple of crates lean on mature pure-Rust codecs that are explicitly out of scope to re-implement (`bzip2-rs` for ALZip, `lzma-rs` for NSIS); both are permissively licensed and fully LGPL-compatible.

## Provenance & license

**Licensed under LGPL-3.0-or-later** — and, to be honest, this wasn't a free choice; it's the only honest one.

The decompression algorithms are ported from **XADMaster** (The Unarchiver), by Dag Ågren and contributors. Dag built the whole engine under the **LGPL** from the start, and parts of it descend from even older LGPL code that can never be relicensed. A faithful port of that work is a derivative work, so it inherits the license — there's no legitimate way to slip it under MIT or Apache. We don't fight that; we embrace it. Keeping these decoders under the LGPL is also what keeps them *free software for good*, which is exactly the spirit of the original.

- Full text: [`LICENSE`](LICENSE) (the GNU LGPL v3), which incorporates the GNU GPL v3 provided in [`GPL-3.0.txt`](GPL-3.0.txt).
- Copyright and provenance: [`NOTICE`](NOTICE).

In plain terms: the library stays free software forever, but — thanks to the *Lesser* GPL — you can still use it inside a program under a license of your own choosing.

## Status

The formats above are implemented and tested. A handful of rarer variants remain on the backlog; implementation order is tracked in the companion New The Unarchiver project. Contributions and bug reports for the supported formats are welcome.
