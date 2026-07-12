# rust-UAPKI

Rust wrapper for digital-signature verification (CMS/CAdES, `.p7s`) on top of
[UAPKI](https://github.com/specinfo-ua/UAPKI) — **without the `process()`
JSON interface**. It calls UAPKI's internal `Doc::Verify::VerifySignedDoc`
classes directly.

| Crate | Role |
|---|---|
| `uapki` (root) | safe Rust API (`add_trusted_certs`, `verify`, `verify_file`) |
| `uapki-sys` | raw FFI bindings + `build.rs` that statically links UAPKI |

The UAPKI C code is wired in as a **git submodule** `uapki-sys/uapki` — a fork
of [SunRiseGG/UAPKI](https://github.com/SunRiseGG/UAPKI) (branch `uapki-up`).
UAPKI's own CMake compiles verify-direct.cpp into `libuapki.a` via `aux_source_directory`.

## Build

```sh
git submodule update --init --recursive
cargo build --release
cargo test --release
```

`uapki-sys/build.rs` builds UAPKI with cmake as **static** libraries
(`libuapki.a` + `libuapkic.a` + `libuapkif.a`) using `-DUAPKI_LIBS_TYPE=STATIC`
and links them directly together with `curl` and the C++ runtime.
Requires: `git`, `cmake`, a C++ toolchain, and the
`libcurl` dev package (on Linux — `libcurl4-openssl-dev`).

Override for local development without the submodule:
`UAPKI_SRC_DIR=/path/to/UAPKI cargo build`.

## Usage

```rust
use uapki::{add_trusted_certs, verify, verify_file, Validation};

// trusted CA root certificates (DER), once
add_trusted_certs(&[ca_der])?;

// attached envelope
let v = verify(&p7s, None, Validation::Chain)?;        // v.signer_count

// detached with data in memory
verify(&p7s, Some(&data), Validation::Chain)?;

// detached, data hashed from a file
verify_file(&p7s, "/path/to/doc.pdf", Validation::Chain)?;
```

`Validation::Struct` — signature + CMS structure only; `Validation::Chain`
(offline) — plus building the chain to trusted CAs (no OCSP/CRL).

## Updating the UAPKI fork

C++ changes (including `verify-direct.cpp`) are committed to the
[SunRiseGG/UAPKI](https://github.com/SunRiseGG/UAPKI) fork on branch `uapki-up`,
then the submodule pointer is updated here:

```sh
cd uapki-sys/uapki && git checkout uapki-up && git pull
cd ../.. && git add uapki-sys/uapki
```
