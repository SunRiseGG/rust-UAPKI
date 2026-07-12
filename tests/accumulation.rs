//! TEMP diagnostic test: proves whether verify() leaves the envelope's
//! non-trusted certificates in the process-global store after returning.
//!
//! Setup seeds ONLY the CA/root certs as trusted (NOT the leaf signer/TSP),
//! so any growth we observe is the envelope's certs being added and not purged.

use std::fs;
use std::path::{Path, PathBuf};

use uapki::{add_trusted_certs, verify, Validation};

fn fx(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}
fn read(name: &str) -> Vec<u8> {
    fs::read(fx(name)).expect("read fixture")
}

fn count() -> (usize, usize) {
    let (mut total, mut trusted) = (0usize, 0usize);
    let ret = unsafe { uapki_sys::uapki_direct_cert_count(&mut total, &mut trusted) };
    assert_eq!(ret, 0, "cert_count failed");
    (total, trusted)
}

#[test]
fn envelope_certs_accumulate() {
    let roots = ["diia-CA-05E19E2CD92EA2990100000001000000E1000000.cer",
                 "CAO-05E19E2CD92EA2990100000001000000C1000000.cer"];
    let bufs: Vec<Vec<u8>> = roots.iter().map(|n| read(&format!("certs/{n}"))).collect();
    let refs: Vec<&[u8]> = bufs.iter().map(|b| b.as_slice()).collect();
    add_trusted_certs(&refs).expect("seed trusted roots");

    let (t0, tr0) = count();
    println!("after seeding roots:      total={t0} trusted={tr0}");

    // Verify the same signer several times.
    let sig = read("detached.p7s");
    let dat = read("content.dat");
    for i in 1..=3 {
        let v = verify(&sig, Some(&dat), Validation::Chain).unwrap();
        assert_eq!(v.signer_count, 1);
        let (t, tr) = count();
        println!("after verify #{i} (detached): total={t} trusted={tr}");
    }

    // A CAdES-T envelope carries extra TSP certs — verify it too.
    let cades_t = read("cades-t.p7s");
    let _ = verify(&cades_t, None, Validation::Chain);
    let (t1, tr1) = count();
    println!("after verify cades-t:     total={t1} trusted={tr1}");

    let (t_final, _) = count();
    println!("\nSUMMARY: seeded {t0} trusted certs, global store now holds {t_final} total \
              ({} non-trusted certs left behind by verify)", t_final - t0);
    // Envelope certs go into a per-verify local store and are freed
    // with it, so the global store stays exactly the seeded trusted set.
    assert_eq!(t_final, t0, "global store must NOT accumulate envelope certs");
}
