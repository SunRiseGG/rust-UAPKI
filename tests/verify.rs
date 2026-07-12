//! Integration tests on real DSTU CAdES signatures (Diia test data).
//! Trusted certificates are added once; tests run sequentially because
//! UAPKI's certificate cache is global.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Once;

use uapki::{add_trusted_certs, verify, verify_file, Error, Validation};

fn fx(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

fn read(name: &str) -> Vec<u8> {
    fs::read(fx(name)).expect("read fixture")
}

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        let dir = fx("certs");
        let certs: Vec<Vec<u8>> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .map(|p| fs::read(p).unwrap())
            .collect();
        let refs: Vec<&[u8]> = certs.iter().map(|c| c.as_slice()).collect();
        add_trusted_certs(&refs).expect("add trusted certs");
    });
}

#[test]
fn attached_cades_bes() {
    setup();
    let v = verify(&read("attached-bes.p7s"), None, Validation::Chain).unwrap();
    assert_eq!(v.signer_count, 1);
}

#[test]
fn attached_cades_t() {
    setup();
    let v = verify(&read("cades-t.p7s"), None, Validation::Chain).unwrap();
    assert_eq!(v.signer_count, 1);
}

#[test]
fn detached_memory() {
    setup();
    let v = verify(&read("detached.p7s"), Some(&read("content.dat")), Validation::Chain).unwrap();
    assert_eq!(v.signer_count, 1);
}

#[test]
fn detached_file() {
    setup();
    let data_path = fx("content.dat");
    let v = verify_file(&read("detached.p7s"), data_path.to_str().unwrap(), Validation::Chain).unwrap();
    assert_eq!(v.signer_count, 1);
}

#[test]
fn tampered_data_is_invalid() {
    setup();
    let mut data = read("content.dat");
    data.push(b'x');
    assert_eq!(verify(&read("detached.p7s"), Some(&data), Validation::Chain), Err(Error::Invalid));
}

#[test]
fn garbage_is_error() {
    setup();
    let r = verify(&[0, 1, 2, 3], None, Validation::Chain);
    assert!(matches!(r, Err(Error::Verify(_)) | Err(Error::Invalid)));
}
