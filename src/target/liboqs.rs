// VÄRN-60 (Anu) — liboqs Target
//
// FFI bindings to Open Quantum Safe's liboqs C library.
// This is the library that Cloudflare, AWS, and Signal use.
// Compiled by Apple Clang on M4 Pro — different compiler,
// different optimizations, potentially different timing behavior.
//
// Nobody has tested this on Apple Silicon with real timing measurements.
// Until now.

use std::ffi::CString;

use std::time::Instant;
use serde::Serialize;
use crate::analysis::Statistics;

// ═══════════════════════════════════════════════════════
// FFI declarations — raw C bindings to liboqs
// ═══════════════════════════════════════════════════════

#[repr(C)]
pub struct OQS_KEM {
    _private: [u8; 0],
}

#[repr(C)]
pub struct OQS_SIG {
    _private: [u8; 0],
}

type OqsStatus = i32;
const OQS_SUCCESS: OqsStatus = 0;

extern "C" {
    pub fn OQS_KEM_new(method_name: *const i8) -> *mut OQS_KEM;
    pub fn OQS_KEM_keypair(kem: *const OQS_KEM, public_key: *mut u8, secret_key: *mut u8) -> OqsStatus;
    pub fn OQS_KEM_encaps(kem: *const OQS_KEM, ciphertext: *mut u8, shared_secret: *mut u8, public_key: *const u8) -> OqsStatus;
    pub fn OQS_KEM_decaps(kem: *const OQS_KEM, shared_secret: *mut u8, ciphertext: *const u8, secret_key: *const u8) -> OqsStatus;
    pub fn OQS_KEM_free(kem: *mut OQS_KEM);

    pub fn OQS_SIG_new(method_name: *const i8) -> *mut OQS_SIG;
    pub fn OQS_SIG_keypair(sig: *const OQS_SIG, public_key: *mut u8, secret_key: *mut u8) -> OqsStatus;
    pub fn OQS_SIG_sign(sig: *const OQS_SIG, signature: *mut u8, signature_len: *mut usize,
                    message: *const u8, message_len: usize, secret_key: *const u8) -> OqsStatus;
    #[allow(dead_code)]
    pub fn OQS_SIG_verify(sig: *const OQS_SIG, message: *const u8, message_len: usize,
                      signature: *const u8, signature_len: usize, public_key: *const u8) -> OqsStatus;
    pub fn OQS_SIG_free(sig: *mut OQS_SIG);
}

// ═══════════════════════════════════════════════════════
// KEM sizes (from headers)
// ═══════════════════════════════════════════════════════

struct KemSizes {
    pk: usize,
    sk: usize,
    ct: usize,
    ss: usize,
}

fn kem_sizes(level: &str) -> KemSizes {
    match level {
        "ML-KEM-512" => KemSizes { pk: 800, sk: 1632, ct: 768, ss: 32 },
        "ML-KEM-768" => KemSizes { pk: 1184, sk: 2400, ct: 1088, ss: 32 },
        "ML-KEM-1024" => KemSizes { pk: 1568, sk: 3168, ct: 1568, ss: 32 },
        _ => panic!("Unknown KEM level: {}", level),
    }
}

struct SigSizes {
    pk: usize,
    sk: usize,
    sig: usize,
}

fn sig_sizes(level: &str) -> SigSizes {
    match level {
        "ML-DSA-44" => SigSizes { pk: 1312, sk: 2560, sig: 2420 },
        "ML-DSA-65" => SigSizes { pk: 1952, sk: 4032, sig: 3309 },
        "ML-DSA-87" => SigSizes { pk: 2592, sk: 4896, sig: 4627 },
        _ => panic!("Unknown SIG level: {}", level),
    }
}

// ═══════════════════════════════════════════════════════
// Safe wrappers
// ═══════════════════════════════════════════════════════

struct OqsKem {
    ptr: *mut OQS_KEM,
    sizes: KemSizes,
}

impl OqsKem {
    fn new(name: &str) -> Option<Self> {
        let cname = CString::new(name).ok()?;
        let ptr = unsafe { OQS_KEM_new(cname.as_ptr()) };
        if ptr.is_null() { return None; }
        Some(OqsKem { ptr, sizes: kem_sizes(name) })
    }

    fn keypair(&self) -> (Vec<u8>, Vec<u8>) {
        let mut pk = vec![0u8; self.sizes.pk];
        let mut sk = vec![0u8; self.sizes.sk];
        let rc = unsafe { OQS_KEM_keypair(self.ptr, pk.as_mut_ptr(), sk.as_mut_ptr()) };
        assert_eq!(rc, OQS_SUCCESS, "OQS_KEM_keypair failed");
        (pk, sk)
    }

    fn encaps(&self, pk: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut ct = vec![0u8; self.sizes.ct];
        let mut ss = vec![0u8; self.sizes.ss];
        let rc = unsafe { OQS_KEM_encaps(self.ptr, ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr()) };
        assert_eq!(rc, OQS_SUCCESS, "OQS_KEM_encaps failed");
        (ct, ss)
    }

    fn decaps(&self, ct: &[u8], sk: &[u8]) -> Vec<u8> {
        let mut ss = vec![0u8; self.sizes.ss];
        let rc = unsafe { OQS_KEM_decaps(self.ptr, ss.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()) };
        assert_eq!(rc, OQS_SUCCESS, "OQS_KEM_decaps failed");
        ss
    }

    fn timed_decaps(&self, ct: &[u8], sk: &[u8]) -> (Vec<u8>, u64) {
        let mut ss = vec![0u8; self.sizes.ss];
        let start = Instant::now();
        unsafe { OQS_KEM_decaps(self.ptr, ss.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()) };
        let elapsed = start.elapsed().as_nanos() as u64;
        (ss, elapsed)
    }
}

impl Drop for OqsKem {
    fn drop(&mut self) {
        unsafe { OQS_KEM_free(self.ptr); }
    }
}

struct OqsSig {
    ptr: *mut OQS_SIG,
    sizes: SigSizes,
}

impl OqsSig {
    fn new(name: &str) -> Option<Self> {
        let cname = CString::new(name).ok()?;
        let ptr = unsafe { OQS_SIG_new(cname.as_ptr()) };
        if ptr.is_null() { return None; }
        Some(OqsSig { ptr, sizes: sig_sizes(name) })
    }

    fn keypair(&self) -> (Vec<u8>, Vec<u8>) {
        let mut pk = vec![0u8; self.sizes.pk];
        let mut sk = vec![0u8; self.sizes.sk];
        let rc = unsafe { OQS_SIG_keypair(self.ptr, pk.as_mut_ptr(), sk.as_mut_ptr()) };
        assert_eq!(rc, OQS_SUCCESS, "OQS_SIG_keypair failed");
        (pk, sk)
    }

    fn timed_sign(&self, msg: &[u8], sk: &[u8]) -> (Vec<u8>, u64) {
        let mut sig = vec![0u8; self.sizes.sig];
        let mut sig_len: usize = 0;
        let start = Instant::now();
        unsafe {
            OQS_SIG_sign(self.ptr, sig.as_mut_ptr(), &mut sig_len,
                         msg.as_ptr(), msg.len(), sk.as_ptr());
        }
        let elapsed = start.elapsed().as_nanos() as u64;
        sig.truncate(sig_len);
        (sig, elapsed)
    }

    #[allow(dead_code)]
    fn timed_verify(&self, msg: &[u8], sig: &[u8], pk: &[u8]) -> (bool, u64) {
        let start = Instant::now();
        let rc = unsafe {
            OQS_SIG_verify(self.ptr, msg.as_ptr(), msg.len(),
                           sig.as_ptr(), sig.len(), pk.as_ptr())
        };
        let elapsed = start.elapsed().as_nanos() as u64;
        (rc == OQS_SUCCESS, elapsed)
    }
}

impl Drop for OqsSig {
    fn drop(&mut self) {
        unsafe { OQS_SIG_free(self.ptr); }
    }
}

// ═══════════════════════════════════════════════════════
// SCAN MODULE — Test all three standards via liboqs
// ═══════════════════════════════════════════════════════

#[derive(Debug, Serialize)]
pub struct LiboqsScanResult {
    pub library: String,
    pub version: String,
    pub platform: String,

    // ML-KEM results
    pub kem_level: String,
    pub kem_valid_mean_ns: f64,
    pub kem_invalid_mean_ns: f64,
    pub kem_delta_ns: f64,
    pub kem_cohens_d: f64,
    pub kem_verdict: String,

    // ML-DSA results
    pub dsa_level: String,
    pub dsa_sign_cv: f64,
    pub dsa_key_cv: f64,
    pub dsa_verdict: String,

    // SLH-DSA results
    pub slh_variant: String,
    pub slh_sign_cv: f64,
    pub slh_msg_cv: f64,
    pub slh_verdict: String,
}

pub fn run_liboqs_scan(samples: usize) -> LiboqsScanResult {
    let info = crate::platform::PlatformInfo::detect();

    println!();
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║     VÄRN-60 (Anu) — liboqs Scan                       ║");
    println!("  ║     Open Quantum Safe · Apple Clang · M4 Pro           ║");
    println!("  ║     The library Cloudflare and AWS use                 ║");
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Platform:  {}", info.chip);
    println!("  Library:   liboqs 0.15.0 (Homebrew, Apple Clang)");
    println!("  Samples:   {} per test", samples);
    println!();

    // ═══ ML-KEM-768 ═══
    println!("  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓");
    println!("  ┃  FIPS 203: ML-KEM-768 via liboqs                     ┃");
    println!("  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛");
    println!();

    let kem = OqsKem::new("ML-KEM-768").expect("liboqs ML-KEM-768 not available");
    let (pk, sk) = kem.keypair();
    let (valid_ct, _valid_ss) = kem.encaps(&pk);

    // Invalid ciphertext — different key's encapsulation
    let (pk2, _sk2) = kem.keypair();
    let (invalid_ct, _) = kem.encaps(&pk2);

    // Warmup
    println!("  Warmup...");
    for _ in 0..2000 { kem.decaps(&valid_ct, &sk); }

    // Interleaved measurement
    println!("  Measuring (interleaved valid/invalid)...");
    let mut valid_times = Vec::with_capacity(samples);
    let mut invalid_times = Vec::with_capacity(samples);

    for _ in 0..samples {
        let (_, vt) = kem.timed_decaps(&valid_ct, &sk);
        valid_times.push(vt);
        let (_, it) = kem.timed_decaps(&invalid_ct, &sk);
        invalid_times.push(it);
    }

    let vs = Statistics::from_samples(&valid_times);
    let is = Statistics::from_samples(&invalid_times);
    let delta = vs.mean - is.mean;
    let pooled = ((vs.variance + is.variance) / 2.0).sqrt();
    let kem_d = if pooled > 0.0 { delta.abs() / pooled } else { 0.0 };

    println!("    Valid:   {:.0} ± {:.0} ns", vs.mean, vs.stddev);
    println!("    Invalid: {:.0} ± {:.0} ns", is.mean, is.stddev);
    println!("    Δ = {:.1} ns, Cohen's d = {:.4}", delta, kem_d);

    let kem_tag = if kem_d > 0.5 { "██ SIGNIFICANT LEAK" }
        else if kem_d > 0.2 { "▓▓ SMALL LEAK" }
        else if kem_d > 0.05 { "░░ DETECTABLE" }
        else { "   CONSTANT-TIME ✓" };
    println!("    {}", kem_tag);
    println!();

    let kem_verdict = if kem_d > 0.2 {
        format!("LEAK DETECTED (d={:.4})", kem_d)
    } else {
        format!("CONSTANT-TIME ✓ (d={:.4})", kem_d)
    };

    // ═══ ML-DSA-65 ═══
    println!("  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓");
    println!("  ┃  FIPS 204: ML-DSA-65 via liboqs                      ┃");
    println!("  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛");
    println!();

    let sig = OqsSig::new("ML-DSA-65").expect("liboqs ML-DSA-65 not available");
    let msg = b"VARN-60 Anu liboqs timing test - sectio-aurea-q";

    // Single-key signing variance
    println!("  Single-key signing variance...");
    let (_pk_sig, sk_sig) = sig.keypair();
    let mut sign_times = Vec::with_capacity(samples);

    for _ in 0..5 { sig.timed_sign(msg, &sk_sig); } // warmup
    for _ in 0..samples {
        let (_, t) = sig.timed_sign(msg, &sk_sig);
        sign_times.push(t);
    }

    let ss = Statistics::from_samples(&sign_times);
    let sign_cv = ss.stddev / ss.mean;
    println!("    Signing: {:.0} ± {:.0} ns (CV={:.4})", ss.mean, ss.stddev, sign_cv);

    // Key-dependent variance
    println!("  Key-dependent signing (20 keys)...");
    let num_keys = 20;
    let key_samples = (samples / 10).max(100);
    let mut key_means: Vec<f64> = Vec::new();

    for k in 0..num_keys {
        let (_, sk_k) = sig.keypair();
        let mut times = Vec::with_capacity(key_samples);
        for _ in 0..3 { sig.timed_sign(msg, &sk_k); }
        for _ in 0..key_samples {
            let (_, t) = sig.timed_sign(msg, &sk_k);
            times.push(t);
        }
        let mean = times.iter().sum::<u64>() as f64 / times.len() as f64;
        key_means.push(mean);
        if k < 10 { println!("    Key {:>2}: {:.0} ns", k + 1, mean); }
    }

    let km_mean: f64 = key_means.iter().sum::<f64>() / key_means.len() as f64;
    let km_var: f64 = key_means.iter().map(|m| (m - km_mean).powi(2)).sum::<f64>()
        / (key_means.len() - 1) as f64;
    let key_cv = km_var.sqrt() / km_mean;
    println!("    Key CV: {:.4} ({:.2}%)", key_cv, key_cv * 100.0);
    println!();

    let dsa_verdict = if sign_cv > 0.05 {
        format!("VARIABLE-TIME SIGNING (CV={:.2}%)", sign_cv * 100.0)
    } else {
        format!("CONSTANT-TIME ✓ (CV={:.4})", sign_cv)
    };

    // ═══ SLH-DSA ═══
    println!("  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓");
    println!("  ┃  FIPS 205: SLH-DSA-SHA2-128s via liboqs              ┃");
    println!("  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛");
    println!();

    let slh = OqsSig::new("SLH-DSA-SHA2-128s").expect("liboqs SLH-DSA not available");
    let slh_samples = (samples / 20).max(50);

    println!("  Single-key signing ({} samples)...", slh_samples);
    let (_pk_slh, sk_slh) = slh.keypair();
    let mut slh_sign_times = Vec::with_capacity(slh_samples);

    for _ in 0..3 { slh.timed_sign(msg, &sk_slh); }
    for _ in 0..slh_samples {
        let (_, t) = slh.timed_sign(msg, &sk_slh);
        slh_sign_times.push(t);
    }

    let slh_ss = Statistics::from_samples(&slh_sign_times);
    let slh_cv = slh_ss.stddev / slh_ss.mean;
    println!("    Signing: {:.0} ± {:.0} ns (CV={:.4})", slh_ss.mean, slh_ss.stddev, slh_cv);

    // Message-dependent
    println!("  Message-dependent (20 messages)...");
    let mut msg_means: Vec<f64> = Vec::new();
    let msg_samples = (slh_samples / 4).max(10);

    for m in 0..20 {
        let test_msg = format!("Anu liboqs SLH-DSA message {}", m);
        let mut times = Vec::with_capacity(msg_samples);
        for _ in 0..msg_samples {
            let (_, t) = slh.timed_sign(test_msg.as_bytes(), &sk_slh);
            times.push(t);
        }
        let mean = times.iter().sum::<u64>() as f64 / times.len() as f64;
        msg_means.push(mean);
        if m < 10 { println!("    Msg {:>2}: {:.0} ns", m + 1, mean); }
    }

    let mm_mean: f64 = msg_means.iter().sum::<f64>() / msg_means.len() as f64;
    let mm_var: f64 = msg_means.iter().map(|m| (m - mm_mean).powi(2)).sum::<f64>()
        / (msg_means.len() - 1) as f64;
    let msg_cv = mm_var.sqrt() / mm_mean;
    println!("    Msg CV: {:.4} ({:.2}%)", msg_cv, msg_cv * 100.0);
    println!();

    let slh_verdict = if slh_cv > 0.05 {
        format!("VARIABLE-TIME (CV={:.2}%)", slh_cv * 100.0)
    } else {
        format!("CONSTANT-TIME ✓ (CV={:.4})", slh_cv)
    };

    // ═══ SUMMARY ═══
    println!("  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓");
    println!("  ┃  liboqs SCAN SUMMARY                                 ┃");
    println!("  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛");
    println!();
    println!("  ML-KEM-768:  d={:.4} — {}", kem_d, kem_verdict);
    println!("  ML-DSA-65:   CV={:.2}% — {}", sign_cv * 100.0, dsa_verdict);
    println!("  SLH-DSA:     CV={:.4} — {}", slh_cv, slh_verdict);
    println!();

    LiboqsScanResult {
        library: "liboqs".into(),
        version: "0.15.0".into(),
        platform: info.chip,
        kem_level: "ML-KEM-768".into(),
        kem_valid_mean_ns: vs.mean, kem_invalid_mean_ns: is.mean,
        kem_delta_ns: delta, kem_cohens_d: kem_d,
        kem_verdict,
        dsa_level: "ML-DSA-65".into(),
        dsa_sign_cv: sign_cv, dsa_key_cv: key_cv,
        dsa_verdict,
        slh_variant: "SLH-DSA-SHA2-128s".into(),
        slh_sign_cv: slh_cv, slh_msg_cv: msg_cv,
        slh_verdict,
    }
}
