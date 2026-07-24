//! Raw FFI bindings to UAPKI's direct verification interface.

#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_int};

unsafe extern "C" {
    /// Adds to the trusted set, never removes; proxy may be null, timeouts are
    /// milliseconds with 0 meaning "keep". Fully documented in verify-direct.cpp.
    pub fn uapki_direct_init(
        offline: c_int,
        proxy_url: *const c_char,
        proxy_credentials: *const c_char,
        connect_timeout_ms: c_int,
        total_timeout_ms: c_int,
        only_crl: c_int,
        certs: *const *const u8,
        lens: *const usize,
        count: usize,
    ) -> c_int;

    /// `certs` — buffer pointers, `lens` — their lengths. Returns 0 or a UAPKI code.
    pub fn uapki_direct_add_trusted(
        certs: *const *const u8,
        lens: *const usize,
        count: usize,
    ) -> c_int;

    /// `data == null` → attached. validation_type: 0 STRUCT, 1 ENVELOPE, 2 CHAIN,
    /// 3 FULL. out_verdict: 0 failed, 1 valid, 2 indeterminate.
    pub fn uapki_direct_verify(
        sig: *const u8,
        sig_len: usize,
        data: *const u8,
        data_len: usize,
        validation_type: c_int,
        out_signer_count: *mut c_int,
        out_verdict: *mut c_int,
    ) -> c_int;

    /// Detached, with the library hashing `data_path` itself.
    pub fn uapki_direct_verify_file(
        sig: *const u8,
        sig_len: usize,
        data_path: *const c_char,
        validation_type: c_int,
        out_signer_count: *mut c_int,
        out_verdict: *mut c_int,
    ) -> c_int;

    /// Must not run concurrently with a verification — it frees what one borrows.
    pub fn uapki_direct_clear_trusted() -> c_int;

    pub fn uapki_direct_cert_count(
        out_total: *mut usize,
        out_trusted: *mut usize,
    ) -> c_int;
}
