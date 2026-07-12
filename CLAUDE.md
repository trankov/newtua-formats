# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`newtua-formats` — pure-Rust decoders for **legacy archive formats that have no mature
Rust crate yet**, ported from The Unarchiver's **XADMaster** engine (LGPL-2.1).
Built to plug into the `newtua` extractor (`../newtheunarchiver`), but each crate
is usable standalone by the wider community.

- Only formats **missing** from the Rust ecosystem are in scope. Already-covered
  formats (zip, 7z, tar, RAR, cab, gzip/bzip2/xz/zstd, LHA via `delharc`, `.Z`)
  are out of scope.
- Each format is **self-contained**: its own container parser plus its own ported
  codecs, with **no runtime dependency** on third-party codec libraries. A
  reference `unar` build (from XADMaster) is used **only as a test oracle** for
  cross-checking correctness, never as a dependency.
- License is **LGPL-2.1-or-later**, matching XADMaster — so code may be ported
  directly (1:1) from XADMaster.

## Architecture

- `crates/newtua-common` — shared primitives reused by every family crate, grown
  **test-first** as formats need them. Currently: `bitreader` (LSB- and MSB-first
  bit readers), `prefixcode` (Huffman/prefix tree, incremental or table build),
  `lzss` (`LzssWindow` sliding window), `lzw` (generic LZW code tree, distinct from
  Unix-compress), `compress` (Unix-`compress` LZW), `stuffit_huffman` (StuffIt's
  bitstream-embedded Huffman tree), `deflate` (RFC 1951 inflate with a
  parameterisable code-length meta-order), `rle90` (RLE90 run expansion), `crc16`
  (CRC-16/ARC and CRC-16/CCITT-XMODEM), `crc32` (CRC-32/IEEE conditioned, plus the
  raw `crc32_step`), `md5` (RFC 1321), `rc4` (RC4 stream cipher), `zipcrypt`
  (traditional PKWARE ZipCrypto), `bytes` (little-endian helpers). Reuse these
  before writing a new codec.
- Family crates — one per **family**, each format inside being a container parser
  plus its compression methods: `newtua-dos` (Squeeze, ARC, LBR, Crunch, Zoo, ARJ),
  `newtua-mac` (BinHex, MacBinary/AppleSingle/AppleDouble, Compact Pro, PackIt),
  `newtua-stuffit` (StuffIt classic + StuffIt 5 + StuffItX), `newtua-amiga`
  (PowerPacker, Amiga LZX, DMS), `newtua-nsis` (NSIS installer), `newtua-alz` (ALZip).
  `newtua-testutil` holds shared test helpers. Some family crates still have
  queued formats (see the roadmap). Add a new family crate to the workspace
  `members` when its first
  format lands.
- Each crate exposes a **newtua-agnostic** API (its own `Entry`/`Error` types,
  raw filename bytes — never decode charsets here; newtua does that centrally).
  newtua wraps it in a thin `format/<fmt>.rs` `FormatHandler` + `ArchiveReader`.
- Decoders are modelled as `std::io::Read` adapters that chain (e.g.
  `Huffman → RLE90`), mirroring XADMaster's `CSHandle` chains.

Implementation order and status: `../newtheunarchiver/docs/legacy-formats-roadmap.md`.
Algorithm deep-dives per family: `../unarch39/docs/porting-to-rust/`.
XADMaster source to port from: `../unarch39/The Unarchiver/XADMaster/`.

## Scope boundary (do not cross)

Work happens **only in this repo (`newtua-formats`)**, plus read-only analysis under
`../unarch39`. **Do NOT modify anything in `../newtheunarchiver` (newtua) except
the formats table `docs/legacy-formats-roadmap.md`** — its `CLAUDE.md`, source,
and handlers are owned by the newtua maintainers. Writing the newtua-side
`format/<fmt>.rs` handler that wraps our crates is **their** job, not ours; we
deliver the crates and keep the formats table updated. If a task seems to require
editing newtua, stop and flag it.

## Commands

Tests run through **cargo-nextest**. Per-package aliases (in `.cargo/config.toml`)
scope the TDD loop to just the crate under work — no whole-workspace rebuild:

```bash
cargo tc                # newtua-common only      \
cargo td                # newtua-dos only          |
cargo tm                # newtua-mac only          | nextest, one package
cargo ts                # newtua-stuffit only      |
cargo ta                # newtua-amiga only        |
cargo tz                # newtua-alz only          |
cargo tu                # newtua-testutil only    /
cargo tw                # whole workspace — the final Definition-of-Done sweep

cargo td decode_one     # filter: any nextest args append to an alias

cargo kc                # clippy newtua-common   \  check-only: type-check,
cargo kd                # clippy newtua-dos       | NO codegen or linking
cargo km                # clippy newtua-mac       | (one per family crate:
cargo ks                # clippy newtua-stuffit   |  kc/kd/km/ks/ka/kz)
cargo ka                # clippy newtua-amiga     |
cargo kz                # clippy newtua-alz      /

cargo build --workspace
cargo clippy --workspace --all-targets   # must be warning-free
cargo fmt --all --check
```

While building a format, run its own test alias (e.g. `cargo td`); run `cargo tw`
only for step 4 of the Definition of Done.

### Keep the inner loop fast (compilation, not just tests)

The crates have **no external dependencies**, so dependency compilation is free
and the cost of each rebuild is dominated by **linking the test binary** (and,
on macOS, `dsymutil`). Two rules keep that cost down:

- **`cargo k*` while chasing compile errors.** When you are only fixing things
  that don't compile yet — not ready to *run* a test — use the check-only alias
  (`cargo kd`, etc.). It type-checks and skips codegen + linking, finishing far
  faster than building a test binary. Switch to `cargo td` only when you actually
  need to watch a test go red/green.
- **Link settings are already tuned** in `[profile.dev]` (`Cargo.toml`):
  `debug = "line-tables-only"` (keep line numbers in panics, drop the rest) and
  `split-debuginfo = "unpacked"` (skip the macOS `dsymutil` step on every link).
  Don't add a debugger-grade `debug = 2` or a packed dSYM to the dev profile.

## Definition of Done (per roadmap item — ALWAYS follow)

Each format/primitive is **not done** until every step below is complete:

1. **TDD** — red → green → refactor for the core behavior. No production code
   without a failing test first.
2. **Unit / edge tests** — after TDD, add thorough boundary, error, and
   malformed-input tests (truncated streams, invalid markers, empty input,
   max sizes).
3. **Integration / end-to-end tests** *(when applicable)* — full-archive decode
   through the crate's own public API, cross-checked by an **oracle**:
   - a **mirror encoder** (the inverse of your decoder) for an always-on
     round-trip — most legacy formats have no system compressor, so fixtures are
     synthesised this way;
   - the reference **`unar`** decoding those fixtures byte-for-byte (gate on
     `newtua_testutil::unar_installed()`; it must actually run — report "0 skipped");
   - an **independent third-party encoder** as a third check when the system has
     one (e.g. `/usr/bin/binhex`, `/usr/bin/macbinary`).

   (newtua-side handler wiring is out of scope — see Scope boundary.)
4. **Run the whole suite and fix** — `cargo tw` (whole workspace) fully green,
   `clippy`/`fmt` clean. Fix the code, not the tests.
5. **`/simplify`** — run the `simplify` skill on the just-written code and apply
   its cleanups (reuse, simplification, efficiency, altitude), keeping all tests
   green. This is the final step.

Only after step 5 is the item done: commit and flip its status to ✅ in the
roadmap.

## Conventions

- `#![forbid(unsafe_code)]` in every crate.
- Stable Rust, edition 2021. Keep crates publishable (no nightly-only features).
- Filename bytes stay raw (`Vec<u8>`); charset handling is the consumer's job.
- Match XADMaster's behavior **byte-for-byte**, including its quirks — correctness
  means "matches the reference `unar` output", not "looks cleaner".
