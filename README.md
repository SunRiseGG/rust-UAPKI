# rust-UAPKI

Rust wrapper for digital-signature verification (CMS/CAdES, p7s) on top of
[UAPKI](https://github.com/specinfo-ua/UAPKI), through a direct C interface:
bytes in, verdict out, with the same crypto core as upstream.

| Crate | Role |
|---|---|
| `uapki` (root) | safe Rust API (`init`, `add_trusted_certs`, `verify`, `verify_file`) |
| `uapki-sys` | raw FFI bindings + `build.rs` that builds and links UAPKI |

The UAPKI C code is wired in as a **git submodule** `uapki-sys/uapki` — a fork
of [SunRiseGG/UAPKI](https://github.com/SunRiseGG/UAPKI) (branch `uapki-up`),
whose CMake compiles `verify-direct.cpp` into `libuapki.a`.

## Build

```sh
git submodule update --init --recursive
cargo build --release
cargo test --release
```

`uapki-sys/build.rs` builds UAPKI with cmake (`libuapki.a` + `libuapkic.a` +
`libuapkif.a`) and links them together with `curl` and the C++ runtime.
Requires: `git`, `cmake`, a C++ toolchain, and the `libcurl` dev package
(on Linux — `libcurl4-openssl-dev`).

Override for local development without the submodule:
`UAPKI_SRC_DIR=/path/to/UAPKI cargo build`.

## Usage

```rust
use uapki::{init, verify, verify_file, Error, Network, Validation};

// Configuration and the trusted set, in one call. Calling it again states the
// set afresh, so trust can be withdrawn as well as granted.
init(Network::default(), &[ca_der])?;                  // offline by default

// attached envelope
let v = verify(&p7s, None, Validation::Chain)?;        // v.signer_count

// detached, data in memory or hashed straight from a file
verify(&p7s, Some(&data), Validation::Chain)?;
verify_file(&p7s, "/path/to/doc.pdf", Validation::Chain)?;
```

### Validation levels

| Level | Checks | Needs |
|---|---|---|
| `Struct` | signature and content digest | nothing |
| `Envelope` | plus the envelope's timestamps and references | the TSA's certificate |
| `Chain` | plus the chain to trusted CAs | the signer's CA |
| `Full` | plus revocation status (OCSP/CRL) | an online `Network` |

`Envelope` builds no chain, so it accepts an envelope whose signer's CA is
absent.

### Three outcomes

`Ok(Verified)` and `Err(Error::Invalid)` are the definite answers. Between them
sits `Err(Error::Indeterminate)`: the check could not be completed — revocation
data was unreachable, or nothing places the signature before a revocation. It is
not a failure, and the same envelope may verify once the missing evidence is
available. Whether it should block an operation is a policy question for the
caller. Tampering is always `Invalid`, never `Indeterminate`.

## Thread safety

`verify` and `verify_file` run concurrently with each other. `init` and
`add_trusted_certs` are exclusive against them: a verification borrows
certificates from the process-global store, and `init` is free to replace it.
An internal `RwLock` enforces this — the C interface leaves it to its caller.

## Updating the UAPKI fork

C++ changes (including `verify-direct.cpp`) are committed to the
[SunRiseGG/UAPKI](https://github.com/SunRiseGG/UAPKI) fork on branch `uapki-up`,
then the submodule pointer is updated here:

```sh
cd uapki-sys/uapki && git checkout uapki-up && git pull
cd ../.. && git add uapki-sys/uapki
```
