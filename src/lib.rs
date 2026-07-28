//! Safe Rust wrapper for digital-signature verification (CMS/CAdES, p7s)
//! on top of UAPKI.
//!
//! Through the direct C interface (`verify-direct.cpp` in the UAPKI fork).
//!
//! # Example
//! ```no_run
//! use uapki::{init, verify, Network, Validation};
//!
//! let ca_der: &[u8] = b"";   // DER of the CA root certificate
//! init(Network::default(), &[ca_der]).unwrap();
//!
//! let p7s: &[u8] = b"";      // .p7s envelope
//! let data: &[u8] = b"";     // signed data (detached)
//! let _ok = verify(p7s, Some(data), Validation::Chain).is_ok();
//! ```
//!
//! [`verify`] and [`verify_file`] run concurrently; [`init`] and
//! [`add_trusted_certs`] are exclusive against them.

use std::ffi::CString;
use std::marker::PhantomData;
use std::os::raw::c_int;
use std::sync::RwLock;

// A verification borrows certificates from the process-global store rather than
// copying them, and `init` is free to free that set. The C interface leaves the
// ordering to its caller; this lock is where that duty is met.
static STORE_LOCK: RwLock<()> = RwLock::new(());

fn read_lock() -> std::sync::RwLockReadGuard<'static, ()> {
    STORE_LOCK.read().unwrap_or_else(|e| e.into_inner())
}

fn write_lock() -> std::sync::RwLockWriteGuard<'static, ()> {
    STORE_LOCK.write().unwrap_or_else(|e| e.into_inner())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validation {
    /// Cryptographic signature and CMS structure check only.
    Struct,
    /// Plus the timestamps and references the envelope carries. Builds no chain,
    /// so it accepts without the signer's CA — but a timestamp is signed too, and
    /// verifying it needs the TSA's certificate.
    Envelope,
    /// Plus building and checking the chain to trusted CAs (offline).
    Chain,
    /// Plus revocation status (OCSP/CRL); needs an online [`Network`].
    Full,
}

impl Validation {
    fn to_code(self) -> c_int {
        match self {
            Validation::Struct => 0,
            Validation::Envelope => 1,
            Validation::Chain => 2,
            Validation::Full => 3,
        }
    }
}

/// The other half of the wire contract [`Validation::to_code`] starts. Nothing
/// links these numbers to verify-direct.cpp; unknown fails closed.
enum Verdict {
    Failed,
    Valid,
    Indeterminate,
}

impl Verdict {
    fn from_code(code: c_int) -> Self {
        match code {
            1 => Verdict::Valid,
            2 => Verdict::Indeterminate,
            _ => Verdict::Failed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// UAPKI error code from adding trusted certificates.
    AddTrusted(i32),
    /// UAPKI error code raised during verification.
    Verify(i32),
    /// Signature is invalid (not all signers verified).
    Invalid,
    /// Not enough evidence to decide — unreachable revocation data, or nothing
    /// placing the signature before a revocation. The caller's policy reads it.
    Indeterminate,
    /// Invalid data-file path (contains NUL).
    BadPath,
    /// UAPKI error code from configuring the library or HTTP layer.
    Configure(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    pub signer_count: u32,
}

/// How the library talks to the network while verifying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network<'a> {
    /// Offline keeps the library off the network; online enables the OCSP/CRL
    /// fetching [`Validation::Full`] needs.
    pub offline: bool,
    pub proxy: Option<(&'a str, &'a str)>,
    /// Milliseconds to reach the host; 0 keeps the current value. The C `int`
    /// type, so it is passed to the library without a lossy conversion.
    pub connect_timeout_ms: c_int,
    /// Milliseconds for the whole exchange; 0 keeps the current value.
    pub total_timeout_ms: c_int,
    /// Revocation status from CRLs alone, never OCSP.
    pub only_crl: bool,
}

impl Default for Network<'_> {
    fn default() -> Self {
        Self {
            offline: true,
            proxy: None,
            connect_timeout_ms: 0,
            total_timeout_ms: 0,
            only_crl: false,
        }
    }
}

/// DER blobs as C wants them: pointers plus lengths. Holding both makes them the
/// same length; the lifetime stops the list outliving what it points into.
struct DerList<'a> {
    ptrs: Vec<*const u8>,
    lens: Vec<usize>,
    _borrow: PhantomData<&'a [u8]>,
}

impl<'a> DerList<'a> {
    fn new(items: &[&'a [u8]]) -> Self {
        Self {
            ptrs: items.iter().map(|i| i.as_ptr()).collect(),
            lens: items.iter().map(|i| i.len()).collect(),
            _borrow: PhantomData,
        }
    }

    fn as_parts(&self) -> (*const *const u8, *const usize, usize) {
        (self.ptrs.as_ptr(), self.lens.as_ptr(), self.ptrs.len())
    }
}

/// Network mode, timeouts and the trusted CA certificates (DER). Calling it again
/// states the set afresh, so trust can be withdrawn — [`add_trusted_certs`] only
/// extends it.
pub fn init(network: Network<'_>, trusted_certs: &[&[u8]]) -> Result<(), Error> {
    let (url, credentials) = match network.proxy {
        Some((u, c)) => (
            Some(CString::new(u).map_err(|_| Error::BadPath)?),
            Some(CString::new(c).map_err(|_| Error::BadPath)?),
        ),
        None => (None, None),
    };
    let as_ptr = |s: &Option<CString>| s.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());

    let certs = DerList::new(trusted_certs);

    let _guard = write_lock();  // covers the clear too, not just the init

    let ret = unsafe { uapki_sys::uapki_direct_clear_trusted() };
    if ret != 0 {
        return Err(Error::Configure(ret));
    }

    let (ptrs, lens, count) = certs.as_parts();
    let ret = unsafe {
        uapki_sys::uapki_direct_init(
            if network.offline { 1 } else { 0 },
            as_ptr(&url),
            as_ptr(&credentials),
            network.connect_timeout_ms,
            network.total_timeout_ms,
            if network.only_crl { 1 } else { 0 },
            ptrs,
            lens,
            count,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(Error::Configure(ret))
    }
}

/// Extends the trusted set, leaving the rest of the configuration alone.
pub fn add_trusted_certs(certs: &[&[u8]]) -> Result<(), Error> {
    let list = DerList::new(certs);
    let (ptrs, lens, count) = list.as_parts();

    let _guard = write_lock(); // exclusive: no verification may read the store
    let ret = unsafe { uapki_sys::uapki_direct_add_trusted(ptrs, lens, count) };
    if ret == 0 {
        Ok(())
    } else {
        Err(Error::AddTrusted(ret))
    }
}

fn interpret(ret: c_int, count: u32, verdict: c_int) -> Result<Verified, Error> {
    if ret != 0 {
        return Err(Error::Verify(ret));
    }
    if count == 0 {
        return Err(Error::Invalid);
    }
    match Verdict::from_code(verdict) {
        Verdict::Valid => Ok(Verified { signer_count: count }),
        Verdict::Indeterminate => Err(Error::Indeterminate),
        Verdict::Failed => Err(Error::Invalid),
    }
}

/// `data == None` — attached envelope; `Some(bytes)` — detached.
pub fn verify(sign: &[u8], data: Option<&[u8]>, validation: Validation) -> Result<Verified, Error> {
    let _guard = read_lock(); // shared: concurrent with other verifications
    let (data_ptr, data_len) = match data {
        Some(d) => (d.as_ptr(), d.len()),
        None => (std::ptr::null(), 0),
    };
    let mut count: u32 = 0;
    let mut verdict: c_int = 0;
    let ret = unsafe {
        uapki_sys::uapki_direct_verify(
            sign.as_ptr(),
            sign.len(),
            data_ptr,
            data_len,
            validation.to_code(),
            &mut count,
            &mut verdict,
        )
    };
    interpret(ret, count, verdict)
}

/// Detached, with the library hashing the file itself.
pub fn verify_file(sign: &[u8], data_path: &str, validation: Validation) -> Result<Verified, Error> {
    let c_path = CString::new(data_path).map_err(|_| Error::BadPath)?;
    let _guard = read_lock(); // shared: concurrent with other verifications
    let mut count: u32 = 0;
    let mut verdict: c_int = 0;
    let ret = unsafe {
        uapki_sys::uapki_direct_verify_file(
            sign.as_ptr(),
            sign.len(),
            c_path.as_ptr(),
            validation.to_code(),
            &mut count,
            &mut verdict,
        )
    };
    interpret(ret, count, verdict)
}
