//! Raw FFI bindings to UAPKI's direct verification interface.

#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_int};

unsafe extern "C" {
    /// Adds trusted certificates (DER) to the global get_cerstore() cache.
    /// `certs` — array of buffer pointers, `lens` — their lengths, `count` — number.
    /// Returns 0 (RET_OK) or a UAPKI error code.
    pub fn uapki_direct_add_trusted(
        certs: *const *const u8,
        lens: *const usize,
        count: usize,
    ) -> c_int;

    /// In-memory CMS/CAdES verification.
    /// `data == null` → attached envelope; `validation_type`: 0=STRUCT, 1=CHAIN.
    /// `out_signer_count` — number of signers; `out_all_valid` — 1 if all valid.
    pub fn uapki_direct_verify(
        sig: *const u8,
        sig_len: usize,
        data: *const u8,
        data_len: usize,
        validation_type: c_int,
        out_signer_count: *mut c_int,
        out_all_valid: *mut c_int,
    ) -> c_int;

    /// Like `uapki_direct_verify`, but for detached data the library hashes it
    /// from the file at `data_path` itself.
    pub fn uapki_direct_verify_file(
        sig: *const u8,
        sig_len: usize,
        data_path: *const c_char,
        validation_type: c_int,
        out_signer_count: *mut c_int,
        out_all_valid: *mut c_int,
    ) -> c_int;

    /// Total / trusted certificate count in the global store.
    pub fn uapki_direct_cert_count(
        out_total: *mut usize,
        out_trusted: *mut usize,
    ) -> c_int;
}
