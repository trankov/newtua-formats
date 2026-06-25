# newtua-formats

Pure-Rust decoders for legacy archive formats that have no mature Rust crate yet.
Built to plug into the [`newtua`](../newtheunarchiver) archive extractor, but each
crate is usable standalone.

## Scope

This project only implements formats that are **missing** from the Rust
ecosystem. Mainstream and already-covered formats (zip, 7z, tar, RAR, cab, gzip,
bzip2, xz, zstd, LHA/LZH via `delharc`, `.Z`) are out of scope.

Each format is a **self-contained** crate: its own container parser plus its own
ported codecs, with no runtime dependency on third-party codec libraries. The
`compcol` crate and a reference `unar` build serve only as test oracles for
cross-checking correctness.

## Crates

| Crate | Formats |
|-------|---------|
| `newtua-common` | shared primitives: bit readers, Huffman/prefix codes, LZSS window, RLE90, CRC |
| `newtua-dos` | Squeeze, ARC, LBR, Crunch, Zoo, ARJ |
| `newtua-mac` *(planned)* | BinHex, MacBinary/AppleSingle/AppleDouble, Compact Pro, PackIt, DiskDoubler, NowCompress |
| `newtua-stuffit` *(planned)* | StuffIt classic, StuffIt 5, StuffItX |
| `newtua-amiga` | PowerPacker (Amiga LZX, DMS planned) |
| `newtua-alz` *(planned)* | ALZip |
| `newtua-nsis` *(planned)* | NSIS |

Implementation order and status are tracked in
[`newtheunarchiver/docs/legacy-formats-roadmap.md`](../newtheunarchiver/docs/legacy-formats-roadmap.md).

## License & provenance

Licensed under **LGPL-2.1-or-later**, matching XADMaster, from which the
algorithms are ported. XADMaster is © Dag Ågren and contributors. This is a
derivative work; see `LICENSE`.

## Methodology

Test-driven, with golden tests built from real archives and verified against the
reference `unar` decompressor (and `compcol` where it covers the format).
