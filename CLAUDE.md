# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`xad-rs` — pure-Rust decoders for **legacy archive formats that have no mature
Rust crate yet**, ported from The Unarchiver's **XADMaster** engine (LGPL-2.1).
Built to plug into the `newtua` extractor (`../newtheunarchiver`), but each crate
is usable standalone by the wider community.

- Only formats **missing** from the Rust ecosystem are in scope. Already-covered
  formats (zip, 7z, tar, RAR, cab, gzip/bzip2/xz/zstd, LHA via `delharc`, `.Z`)
  are out of scope.
- Each format is **self-contained**: its own container parser plus its own ported
  codecs, with **no runtime dependency** on third-party codec libraries. The
  `compcol` crate and a reference `unar` build (from XADMaster) are used **only as
  test oracles** for cross-checking correctness, never as dependencies.
- License is **LGPL-2.1-or-later**, matching XADMaster — so code may be ported
  directly (1:1) from XADMaster.

## Architecture

- `crates/xad-common` — shared primitives reused by every family crate: bit
  readers, prefix/Huffman codes, LZSS sliding window, range coder, CRC, RLE90.
  Grown **test-first**, one primitive at a time, as formats need them.
- `crates/xad-dos` (and future `xad-mac`, `xad-stuffit`, `xad-amiga`, `xad-alz`,
  `xad-nsis`) — one crate per **family**; each format inside is a container parser
  + its compression methods.
- Each crate exposes a **newtua-agnostic** API (its own `Entry`/`Error` types,
  raw filename bytes — never decode charsets here; newtua does that centrally).
  newtua wraps it in a thin `format/<fmt>.rs` `FormatHandler` + `ArchiveReader`.
- Decoders are modelled as `std::io::Read` adapters that chain (e.g.
  `Huffman → RLE90`), mirroring XADMaster's `CSHandle` chains.

Implementation order and status: `../newtheunarchiver/docs/legacy-formats-roadmap.md`.
Algorithm deep-dives per family: `../unarch39/docs/porting-to-rust/`.
XADMaster source to port from: `../unarch39/The Unarchiver/XADMaster/`.

## Scope boundary (do not cross)

Work happens **only in this repo (`xad-rs`)**, plus read-only analysis under
`../unarch39`. **Do NOT modify anything in `../newtheunarchiver` (newtua) except
the formats table `docs/legacy-formats-roadmap.md`** — its `CLAUDE.md`, source,
and handlers are owned by the newtua maintainers. Writing the newtua-side
`format/<fmt>.rs` handler that wraps our crates is **their** job, not ours; we
deliver the crates and keep the formats table updated. If a task seems to require
editing newtua, stop and flag it.

## Commands

```bash
cargo build --workspace
cargo test  --workspace                  # must be green before done
cargo clippy --workspace --all-targets   # must be warning-free
cargo fmt --all --check

cargo test -p xad-common rle90           # single module
```

## Definition of Done (per roadmap item — ALWAYS follow)

Each format/primitive is **not done** until every step below is complete:

1. **TDD** — red → green → refactor for the core behavior. No production code
   without a failing test first.
2. **Unit / edge tests** — after TDD, add thorough boundary, error, and
   malformed-input tests (truncated streams, invalid markers, empty input,
   max sizes).
3. **Integration / end-to-end tests** *(when applicable)* — full-archive decode
   through the crate's own public API, with **golden tests** comparing output
   byte-for-byte against the `unar` oracle (and `compcol` where it covers the
   format). (newtua-side handler wiring is out of scope — see Scope boundary.)
4. **Run the whole suite and fix** — `cargo test --workspace` fully green,
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
