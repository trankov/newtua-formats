# xad-rs

Pure-Rust decoders for legacy archive formats that have no mature Rust crate yet
— ported from [The Unarchiver](https://theunarchiver.com/)'s **XADMaster**
engine (LGPL-2.1). Built to plug into the [`newtua`](../newtheunarchiver) archive
extractor, but usable standalone.

> Working name. The crate/repo names may change before the first crates.io
> publish.

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
| `xad-common` | shared primitives: bit readers, Huffman/prefix codes, LZSS window, RLE90, CRC |
| `xad-dos` | Squeeze, ARC, LBR, Crunch, Zoo, ARJ |
| `xad-mac` *(planned)* | BinHex, MacBinary/AppleSingle/AppleDouble, Compact Pro, PackIt, DiskDoubler, NowCompress |
| `xad-stuffit` *(planned)* | StuffIt classic, StuffIt 5, StuffItX |
| `xad-amiga` *(planned)* | PowerPacker, Amiga LZX, DMS, libxad bridge |
| `xad-alz` *(planned)* | ALZip |
| `xad-nsis` *(planned)* | NSIS |

Implementation order and status are tracked in
[`newtheunarchiver/docs/legacy-formats-roadmap.md`](../newtheunarchiver/docs/legacy-formats-roadmap.md).

## License & provenance

Licensed under **LGPL-2.1-or-later**, matching XADMaster, from which the
algorithms are ported. XADMaster is © Dag Ågren and contributors. This is a
derivative work; see `LICENSE`.

## Methodology

Test-driven, with golden tests built from real archives and verified against the
reference `unar` decompressor (and `compcol` where it covers the format).
