// VÄRN-60 (Anu) — FFI bindings to liboqs (Open Quantum Safe), ML-KEM only.

use std::ffi::{c_char, CStr};
use std::sync::Once;

#[repr(C)]
pub struct OQS_KEM {
    _private: [u8; 0],
}

/// Leading fields of liboqs' `OQS_KEM` struct (kem.h). Only these fields are
/// read; they come before the function pointers and have kept this order.
#[repr(C)]
struct OqsKemHeader {
    method_name: *const c_char,
    alg_version: *const c_char,
    claimed_nist_level: u8,
    ind_cca: u8,
    length_public_key: usize,
    length_secret_key: usize,
    length_ciphertext: usize,
    length_shared_secret: usize,
}

pub type OqsStatus = i32;
pub const OQS_SUCCESS: OqsStatus = 0;

extern "C" {
    pub fn OQS_init();
    pub fn OQS_version() -> *const c_char;
    pub fn OQS_KEM_new(method_name: *const c_char) -> *mut OQS_KEM;
    pub fn OQS_KEM_keypair(kem: *const OQS_KEM, public_key: *mut u8, secret_key: *mut u8) -> OqsStatus;
    pub fn OQS_KEM_encaps(
        kem: *const OQS_KEM,
        ciphertext: *mut u8,
        shared_secret: *mut u8,
        public_key: *const u8,
    ) -> OqsStatus;
    pub fn OQS_KEM_decaps(
        kem: *const OQS_KEM,
        shared_secret: *mut u8,
        ciphertext: *const u8,
        secret_key: *const u8,
    ) -> OqsStatus;
    pub fn OQS_KEM_free(kem: *mut OQS_KEM);
}

static INIT: Once = Once::new();

/// Initialise liboqs once (CPU feature detection).
pub fn init() {
    INIT.call_once(|| unsafe { OQS_init() });
}

/// liboqs version string as reported by the linked library.
pub fn liboqs_version() -> String {
    unsafe {
        let p = OQS_version();
        if p.is_null() {
            return "unknown".into();
        }
        CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KemLengths {
    pub public_key: usize,
    pub secret_key: usize,
    pub ciphertext: usize,
    pub shared_secret: usize,
}

/// Buffer lengths reported by liboqs for this KEM.
///
/// # Safety
/// `kem` must be a non-null pointer returned by `OQS_KEM_new`.
pub unsafe fn kem_lengths(kem: *const OQS_KEM) -> KemLengths {
    let h = &*(kem as *const OqsKemHeader);
    KemLengths {
        public_key: h.length_public_key,
        secret_key: h.length_secret_key,
        ciphertext: h.length_ciphertext,
        shared_secret: h.length_shared_secret,
    }
}
