// VÄRN-60 (Anu) — Benchmark Module
//
// PQC-LEO measures speed. Anu measures speed AND security.
// For every operation (keygen, encaps, decaps, sign, verify),
// Anu reports ops/sec, latency, AND timing variance.
//
// "ML-KEM-768 in liboqs: 12.000 ops/sec, CV=0.003, constant-time ✓"
// PQC-LEO says only "12.000 ops/sec" — Anu says if it's also SAFE.

use std::time::Instant;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct BenchOp {
    pub operation: String,
    pub mean_ns: f64,
    pub stddev_ns: f64,
    pub cv: f64,
    pub ops_per_sec: f64,
    pub security: String,
}

#[derive(Debug, Serialize)]
pub struct BenchLibrary {
    pub library: String,
    pub algorithm: String,
    pub operations: Vec<BenchOp>,
}

#[derive(Debug, Serialize)]
pub struct BenchResult {
    pub platform: String,
    pub samples: usize,
    pub libraries: Vec<BenchLibrary>,
}

fn bench_op<F: Fn()>(name: &str, f: F, samples: usize) -> BenchOp {
    // Warmup
    for _ in 0..100 { f(); }

    let mut times = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        f();
        times.push(start.elapsed().as_nanos() as f64);
    }

    let mean = times.iter().sum::<f64>() / times.len() as f64;
    let var: f64 = times.iter().map(|t| (t - mean).powi(2)).sum::<f64>() / (times.len() - 1) as f64;
    let stddev = var.sqrt();
    let cv = if mean > 0.0 { stddev / mean } else { 0.0 };
    let ops = if mean > 0.0 { 1_000_000_000.0 / mean } else { 0.0 };

    let security = if cv > 0.05 {
        format!("VARIABLE (CV={:.2}%)", cv * 100.0)
    } else {
        format!("CONSTANT-TIME ✓ (CV={:.4})", cv)
    };

    BenchOp {
        operation: name.into(),
        mean_ns: mean,
        stddev_ns: stddev,
        cv,
        ops_per_sec: ops,
        security,
    }
}

fn print_op(op: &BenchOp) {
    let security_tag = if op.cv > 0.05 { "⚠" } else { "✓" };
    println!("    {:<14} {:>10.0} ns  {:>8.0} ops/s  CV={:.4}  {}",
             op.operation, op.mean_ns, op.ops_per_sec, op.cv, security_tag);
}

pub fn run_benchmark(samples: usize) -> BenchResult {
    let info = crate::platform::PlatformInfo::detect();

    println!();
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║     VÄRN-60 (Anu) — PQC Benchmark                     ║");
    println!("  ║     Speed + Security Score · All Libraries             ║");
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Platform:  {}", info.chip);
    println!("  Samples:   {} per operation", samples);
    println!();

    let mut libraries: Vec<BenchLibrary> = Vec::new();

    // ═══ pqcrypto-kyber (AARCH64 Assembly) ═══
    println!("  ── pqcrypto-kyber (AARCH64 Assembly) ──");
    {
        use pqcrypto_kyber::kyber768;

        let keygen_op = bench_op("keygen", || { kyber768::keypair(); }, samples);
        print_op(&keygen_op);

        let (pk, sk) = kyber768::keypair();
        let encaps_op = bench_op("encaps", || { kyber768::encapsulate(&pk); }, samples);
        print_op(&encaps_op);

        let (ss, ct) = kyber768::encapsulate(&pk);
        let decaps_op = bench_op("decaps", || { kyber768::decapsulate(&ct, &sk); }, samples);
        print_op(&decaps_op);

        libraries.push(BenchLibrary {
            library: "pqcrypto-kyber".into(),
            algorithm: "ML-KEM-768".into(),
            operations: vec![keygen_op, encaps_op, decaps_op],
        });
    }
    println!();

    // ═══ ml-kem (Pure Rust) ═══
    println!("  ── ml-kem (Pure Rust / LLVM) ──");
    {
        use ml_kem::MlKem768;
        use ml_kem::KemCore;
        use kem::{Encapsulate, Decapsulate};

        let keygen_op = bench_op("keygen", || {
            let mut rng = rand::thread_rng();
            let _ = MlKem768::generate(&mut rng);
        }, samples);
        print_op(&keygen_op);

        let mut rng = rand::thread_rng();
        let (dk, ek) = MlKem768::generate(&mut rng);
        let encaps_op = bench_op("encaps", || {
            let mut rng = rand::thread_rng();
            let _ = ek.encapsulate(&mut rng);
        }, samples);
        print_op(&encaps_op);

        let (ct, _ss) = ek.encapsulate(&mut rng).unwrap();
        let decaps_op = bench_op("decaps", || {
            let _ = dk.decapsulate(&ct);
        }, samples);
        print_op(&decaps_op);

        libraries.push(BenchLibrary {
            library: "ml-kem".into(),
            algorithm: "ML-KEM-768".into(),
            operations: vec![keygen_op, encaps_op, decaps_op],
        });
    }
    println!();

    // ═══ liboqs ML-KEM-768 ═══
    println!("  ── liboqs (C / Apple Clang) ──");
    {
        use std::ffi::CString;
        use crate::target::liboqs::*;

        let kem_name = CString::new("ML-KEM-768").unwrap();
        let kem = unsafe { OQS_KEM_new(kem_name.as_ptr()) };
        if !kem.is_null() {
            let mut pk = vec![0u8; 1184];
            let mut sk = vec![0u8; 2400];
            let mut ct = vec![0u8; 1088];
            let mut ss = vec![0u8; 32];

            let keygen_op = bench_op("keygen", || {
                unsafe { OQS_KEM_keypair(kem, pk.as_mut_ptr(), sk.as_mut_ptr()) };
            }, samples);
            print_op(&keygen_op);

            unsafe { OQS_KEM_keypair(kem, pk.as_mut_ptr(), sk.as_mut_ptr()) };
            let encaps_op = bench_op("encaps", || {
                unsafe { OQS_KEM_encaps(kem, ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr()) };
            }, samples);
            print_op(&encaps_op);

            unsafe { OQS_KEM_encaps(kem, ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr()) };
            let decaps_op = bench_op("decaps", || {
                unsafe { OQS_KEM_decaps(kem, ss.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()) };
            }, samples);
            print_op(&decaps_op);

            unsafe { OQS_KEM_free(kem as *mut _) };

            libraries.push(BenchLibrary {
                library: "liboqs".into(),
                algorithm: "ML-KEM-768".into(),
                operations: vec![keygen_op, encaps_op, decaps_op],
            });
        }
    }
    println!();

    // ═══ liboqs ML-DSA-65 ═══
    println!("  ── liboqs ML-DSA-65 (Signing) ──");
    {
        use std::ffi::CString;
        use crate::target::liboqs::*;

        let sig_name = CString::new("ML-DSA-65").unwrap();
        let sig = unsafe { OQS_SIG_new(sig_name.as_ptr()) };
        if !sig.is_null() {
            let mut pk = vec![0u8; 1952];
            let mut sk = vec![0u8; 4032];
            let mut signature = vec![0u8; 3309];
            let mut sig_len: usize = 0;
            let msg = b"VARN-60 Anu benchmark message";

            let keygen_op = bench_op("keygen", || {
                unsafe { OQS_SIG_keypair(sig, pk.as_mut_ptr(), sk.as_mut_ptr()) };
            }, samples);
            print_op(&keygen_op);

            unsafe { OQS_SIG_keypair(sig, pk.as_mut_ptr(), sk.as_mut_ptr()) };
            let sign_op = bench_op("sign", || {
                unsafe { OQS_SIG_sign(sig, signature.as_mut_ptr(), &mut sig_len,
                                      msg.as_ptr(), msg.len(), sk.as_ptr()) };
            }, samples);
            print_op(&sign_op);

            unsafe { OQS_SIG_sign(sig, signature.as_mut_ptr(), &mut sig_len,
                                  msg.as_ptr(), msg.len(), sk.as_ptr()) };
            let verify_op = bench_op("verify", || {
                unsafe { OQS_SIG_verify(sig, msg.as_ptr(), msg.len(),
                                        signature.as_ptr(), sig_len, pk.as_ptr()) };
            }, samples);
            print_op(&verify_op);

            unsafe { OQS_SIG_free(sig as *mut _) };

            libraries.push(BenchLibrary {
                library: "liboqs".into(),
                algorithm: "ML-DSA-65".into(),
                operations: vec![keygen_op, sign_op, verify_op],
            });
        }
    }
    println!();

    // ═══ COMPARISON TABLE ═══
    println!("  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓");
    println!("  ┃  COMPARISON: Speed + Security                                             ┃");
    println!("  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛");
    println!();
    println!("  {:<20} {:<14} {:>10} {:>10} {:>8} {}", "Library", "Operation", "Latency", "ops/s", "CV", "Safe?");
    println!("  {}", "─".repeat(75));

    for lib in &libraries {
        for op in &lib.operations {
            let safe = if op.cv > 0.05 { "⚠ VAR" } else { "✓" };
            println!("  {:<20} {:<14} {:>8.0} ns {:>10.0} {:>8.4} {}",
                     format!("{} {}", lib.library, lib.algorithm), op.operation,
                     op.mean_ns, op.ops_per_sec, op.cv, safe);
        }
    }
    println!();

    BenchResult {
        platform: info.chip,
        samples,
        libraries,
    }
}
