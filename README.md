# newtua-formats

Pure-Rust decoders for legacy archive formats that have no mature Rust crate yet.
Built to plug into the [`newtua`](../newtheunarchiver) archive extractor, but each
crate is usable standalone.

## Scope

This project only implements formats that are **missing** from the Rust
ecosystem. Mainstream and already-covered formats (zip, 7z, tar, RAR, cab, gzip,
bzip2, xz, zstd, LHA/LZH via `delharc`, `.Z`) are out of scope.

Each format is a **self-contained** crate: its own container parser plus its own
ported codecs, with no runtime dependency on third-party codec libraries. A
reference `unar` build serves only as a test oracle for cross-checking
correctness.

## Crates

Done formats are listed plainly; still-queued ones are marked *(planned)*.

| Crate | Formats |
|-------|---------|
| `newtua-common` | shared primitives: LSB/MSB bit readers, Huffman/prefix codes, LZSS window, generic LZW, Unix-compress LZW, StuffIt Huffman, deflate, RLE90, CRC-16 (ARC + CCITT), CRC-32, MD5, RC4, ZipCrypto |
| `newtua-dos` | Squeeze, ARC, LBR, Crunch, Zoo, ARJ |
| `newtua-mac` | BinHex, MacBinary/AppleSingle/AppleDouble, Compact Pro, PackIt *(DiskDoubler, NowCompress planned)* |
| `newtua-stuffit` | StuffIt classic, StuffIt 5, StuffItX |
| `newtua-amiga` | PowerPacker, Amiga LZX, DMS |
| `newtua-alz` | ALZip |
| `newtua-nsis` | NSIS |
| `newtua-testutil` | shared test helpers (not published) |

Implementation order and status are tracked in
[`newtheunarchiver/docs/legacy-formats-roadmap.md`](../newtheunarchiver/docs/legacy-formats-roadmap.md).

## License & provenance

Licensed under **LGPL-2.1-or-later**, matching XADMaster, from which the
algorithms are ported. XADMaster is © Dag Ågren and contributors. This is a
derivative work; see `LICENSE`.

## Methodology

Test-driven. Because most of these legacy formats have no surviving compressor,
fixtures are usually synthesised by a **mirror encoder** (the exact inverse of the
decoder) for an always-on round-trip, then cross-checked against the reference
`unar` decompressor — and, where the system provides one, an independent
third-party encoder (e.g. `binhex`, `macbinary`, Info-ZIP `zip`).
