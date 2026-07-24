//! In a file of its own because each test file is a separate process, and this
//! one calls `init` — which states the trusted set for the whole of it.

use std::fs;
use std::path::{Path, PathBuf};

use uapki::{init, verify, Error, Network, Validation};

fn fx(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

fn trusted() -> Vec<Vec<u8>> {
    fs::read_dir(fx("certs"))
        .expect("certs dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .map(|p| fs::read(p).expect("read cert"))
        .collect()
}

// Offline, so revocation cannot be established at all: Indeterminate, not a
// failure. The same envelope at CHAIN, which claims nothing about revocation,
// verifies — that contrast is the level.
#[test]
fn full_offline_cannot_establish_revocation() {
    let certs = trusted();
    let refs: Vec<&[u8]> = certs.iter().map(|c| c.as_slice()).collect();
    init(Network { offline: true, ..Network::default() }, &refs).expect("init offline");

    let sign = fs::read(fx("cades-t.p7s")).expect("read fixture");

    assert_eq!(verify(&sign, None, Validation::Full), Err(Error::Indeterminate));
    assert!(verify(&sign, None, Validation::Chain).is_ok());
}
