//! Safe Rust wrapper for digital-signature verification (CMS/CAdES, p7s)
//! on top of UAPKI.
//!
//! Works through the direct C interface (`uapki-sys`) implemented in the UAPKI
//! fork (`verify-direct.cpp`) — without the `process()` JSON layer. The crypto
//! core is the same as in upstream UAPKI; the internal `Doc::Verify::VerifySignedDoc`
//! classes are called directly.
//!
//! # Example
//! ```no_run
//! use uapki::{add_trusted_certs, verify, Validation};
//!
//! let ca_der: &[u8] = b"";   // DER of the CA root certificate
//! add_trusted_certs(&[ca_der]).unwrap();
//!
//! let p7s: &[u8] = b"";      // .p7s envelope
//! let data: &[u8] = b"";     // signed data (detached)
//! let _ok = verify(p7s, Some(data), Validation::Chain).is_ok();
//! ```
//!
//! Validation levels — [`Validation::Struct`] (signature + structure only) and
//! [`Validation::Chain`] (plus the chain to trusted CAs, offline, no OCSP/CRL).

use std::ffi::CString;
use std::os::raw::c_int;

/// Validation level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validation {
    /// Cryptographic signature and CMS structure check only.
    Struct,
    /// Plus building and checking the chain to trusted CAs (offline).
    Chain,
}

impl Validation {
    fn code(self) -> c_int {
        match self {
            Validation::Struct => 0,
            Validation::Chain => 1,
        }
    }
}

/// Verification error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Failed to add trusted certificates; UAPKI error code.
    AddTrusted(i32),
    /// Error during verification; UAPKI error code.
    Verify(i32),
    /// Signature is invalid (not all signers verified).
    Invalid,
    /// Invalid data-file path (contains NUL).
    BadPath,
}

/// Result of a successful verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    /// Number of verified signers.
    pub signer_count: u32,
}

/// Adds trusted CA root certificates (DER) to the library cache.
/// Call once before verifying; can be appended to.
pub fn add_trusted_certs(certs: &[&[u8]]) -> Result<(), Error> {
    let ptrs: Vec<*const u8> = certs.iter().map(|c| c.as_ptr()).collect();
    let lens: Vec<usize> = certs.iter().map(|c| c.len()).collect();
    let ret = unsafe {
        uapki_sys::uapki_direct_add_trusted(ptrs.as_ptr(), lens.as_ptr(), ptrs.len())
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(Error::AddTrusted(ret))
    }
}

fn interpret(ret: c_int, count: c_int, all_valid: c_int) -> Result<Verified, Error> {
    if ret != 0 {
        return Err(Error::Verify(ret));
    }
    if all_valid == 1 && count > 0 {
        Ok(Verified { signer_count: count as u32 })
    } else {
        Err(Error::Invalid)
    }
}

/// In-memory CMS/CAdES verification.
/// `data == None` — attached envelope; `Some(bytes)` — detached with data.
pub fn verify(sign: &[u8], data: Option<&[u8]>, validation: Validation) -> Result<Verified, Error> {
    let (data_ptr, data_len) = match data {
        Some(d) => (d.as_ptr(), d.len()),
        None => (std::ptr::null(), 0),
    };
    let mut count: c_int = 0;
    let mut all_valid: c_int = 0;
    let ret = unsafe {
        uapki_sys::uapki_direct_verify(
            sign.as_ptr(),
            sign.len(),
            data_ptr,
            data_len,
            validation.code(),
            &mut count,
            &mut all_valid,
        )
    };
    interpret(ret, count, all_valid)
}

/// Detached verification where the library hashes the data straight from the
/// file.
pub fn verify_file(sign: &[u8], data_path: &str, validation: Validation) -> Result<Verified, Error> {
    let c_path = CString::new(data_path).map_err(|_| Error::BadPath)?;
    let mut count: c_int = 0;
    let mut all_valid: c_int = 0;
    let ret = unsafe {
        uapki_sys::uapki_direct_verify_file(
            sign.as_ptr(),
            sign.len(),
            c_path.as_ptr(),
            validation.code(),
            &mut count,
            &mut all_valid,
        )
    };
    interpret(ret, count, all_valid)
}
