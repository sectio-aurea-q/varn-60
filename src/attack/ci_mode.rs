// VÄRN-60 (Anu) — CI/CD Mode
//
// anu ci — runs in a GitHub Actions pipeline.
// Tests PQC implementations for timing side-channels.
// Returns exit code 0 (pass) or 1 (fail).
//
// Usage in GitHub Actions:
//   - name: PQC Side-Channel Check
//     run: ANU_LICENSE=${{ secrets.ANU_LICENSE }} anu ci --threshold 0.2
//
// Every PQC project needs this. One line in your CI pipeline
// and every commit is automatically checked for timing leaks.

use std::process;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct CiResult {
    pub passed: bool,
    pub threshold: f64,
    pub max_cohens_d: f64,
    pub tests_run: usize,
    pub tests_passed: usize,
    pub tests_failed: usize,
    pub failures: Vec<CiFailure>,
}

#[derive(Debug, Serialize)]
pub struct CiFailure {
    pub test: String,
    pub cohens_d: f64,
    pub threshold: f64,
}

pub fn run_ci_mode(threshold: f64, samples: usize) -> CiResult {
    println!();
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║     VÄRN-60 (Anu) — CI/CD Mode                        ║");
    println!("  ║     Automated PQC Side-Channel Gate                    ║");
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Threshold: d > {:.2} = FAIL", threshold);
    println!("  Samples:   {}", samples);
    println!();

    let mut tests_run = 0;
    let mut tests_passed = 0;
    let mut tests_failed = 0;
    let mut failures: Vec<CiFailure> = Vec::new();
    let mut max_d: f64 = 0.0;

    // ═══ Test 1: ML-KEM-768 pqcrypto-kyber FO-Transform ═══
    println!("  [1/4] ML-KEM-768 (pqcrypto-kyber) FO-Transform...");
    {
        use pqcrypto_kyber::kyber768;
        use pqcrypto_traits::kem::{Ciphertext as CiphertextTrait, SharedSecret};
        use std::time::Instant;

        let (pk, sk) = kyber768::keypair();
        let (ss, ct) = kyber768::encapsulate(&pk);

        // Invalid ciphertext
        let (pk2, _) = kyber768::keypair();
        let (_, ct_inv) = kyber768::encapsulate(&pk2);

        // Warmup
        for _ in 0..1000 { kyber768::decapsulate(&ct, &sk); }

        // Interleaved measurement
        let mut valid_times = Vec::with_capacity(samples);
        let mut invalid_times = Vec::with_capacity(samples);

        for _ in 0..samples {
            let start = Instant::now();
            kyber768::decapsulate(&ct, &sk);
            valid_times.push(start.elapsed().as_nanos() as f64);

            let start = Instant::now();
            kyber768::decapsulate(&ct_inv, &sk);
            invalid_times.push(start.elapsed().as_nanos() as f64);
        }

        let v_mean: f64 = valid_times.iter().sum::<f64>() / valid_times.len() as f64;
        let i_mean: f64 = invalid_times.iter().sum::<f64>() / invalid_times.len() as f64;
        let v_var: f64 = valid_times.iter().map(|t| (t - v_mean).powi(2)).sum::<f64>() / (valid_times.len() - 1) as f64;
        let i_var: f64 = invalid_times.iter().map(|t| (t - i_mean).powi(2)).sum::<f64>() / (invalid_times.len() - 1) as f64;
        let pooled = ((v_var + i_var) / 2.0).sqrt();
        let d = if pooled > 0.0 { (v_mean - i_mean).abs() / pooled } else { 0.0 };

        tests_run += 1;
        if d > max_d { max_d = d; }

        if d > threshold {
            tests_failed += 1;
            println!("    FAIL  d={:.4} (threshold={:.2})", d, threshold);
            failures.push(CiFailure {
                test: "ML-KEM-768 pqcrypto-kyber FO-Transform".into(),
                cohens_d: d, threshold,
            });
        } else {
            tests_passed += 1;
            println!("    PASS  d={:.4}", d);
        }
    }

    // ═══ Test 2: ML-KEM-768 liboqs FO-Transform ═══
    println!("  [2/4] ML-KEM-768 (liboqs) FO-Transform...");
    {
        use std::ffi::CString;
        use std::time::Instant;
        use crate::target::liboqs::*;

        let kem_name = CString::new("ML-KEM-768").unwrap();
        let kem = unsafe { OQS_KEM_new(kem_name.as_ptr()) };

        if !kem.is_null() {
            let mut pk = vec![0u8; 1184];
            let mut sk = vec![0u8; 2400];
            let mut ct = vec![0u8; 1088];
            let mut ss = vec![0u8; 32];
            let mut ss2 = vec![0u8; 32];

            unsafe { OQS_KEM_keypair(kem, pk.as_mut_ptr(), sk.as_mut_ptr()) };
            unsafe { OQS_KEM_encaps(kem, ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr()) };

            let mut pk2 = vec![0u8; 1184];
            let mut sk2 = vec![0u8; 2400];
            unsafe { OQS_KEM_keypair(kem, pk2.as_mut_ptr(), sk2.as_mut_ptr()) };
            let mut ct_inv = vec![0u8; 1088];
            let mut ss_d = vec![0u8; 32];
            unsafe { OQS_KEM_encaps(kem, ct_inv.as_mut_ptr(), ss_d.as_mut_ptr(), pk2.as_ptr()) };

            for _ in 0..1000 {
                unsafe { OQS_KEM_decaps(kem, ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()) };
            }

            let mut valid_times = Vec::with_capacity(samples);
            let mut invalid_times = Vec::with_capacity(samples);

            for _ in 0..samples {
                let start = Instant::now();
                unsafe { OQS_KEM_decaps(kem, ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()) };
                valid_times.push(start.elapsed().as_nanos() as f64);

                let start = Instant::now();
                unsafe { OQS_KEM_decaps(kem, ss2.as_mut_ptr(), ct_inv.as_ptr(), sk.as_ptr()) };
                invalid_times.push(start.elapsed().as_nanos() as f64);
            }

            unsafe { OQS_KEM_free(kem as *mut _) };

            let v_mean: f64 = valid_times.iter().sum::<f64>() / valid_times.len() as f64;
            let i_mean: f64 = invalid_times.iter().sum::<f64>() / invalid_times.len() as f64;
            let v_var: f64 = valid_times.iter().map(|t| (t - v_mean).powi(2)).sum::<f64>() / (valid_times.len() - 1) as f64;
            let i_var: f64 = invalid_times.iter().map(|t| (t - i_mean).powi(2)).sum::<f64>() / (invalid_times.len() - 1) as f64;
            let pooled = ((v_var + i_var) / 2.0).sqrt();
            let d = if pooled > 0.0 { (v_mean - i_mean).abs() / pooled } else { 0.0 };

            tests_run += 1;
            if d > max_d { max_d = d; }

            if d > threshold {
                tests_failed += 1;
                println!("    FAIL  d={:.4} (threshold={:.2})", d, threshold);
                failures.push(CiFailure {
                    test: "ML-KEM-768 liboqs FO-Transform".into(),
                    cohens_d: d, threshold,
                });
            } else {
                tests_passed += 1;
                println!("    PASS  d={:.4}", d);
            }
        }
    }

    // ═══ Test 3: ML-KEM-768 ml-kem (pure Rust) ═══
    println!("  [3/4] ML-KEM-768 (ml-kem pure Rust) FO-Transform...");
    {
        use ml_kem::MlKem768;
        use ml_kem::KemCore;
        use kem::{Encapsulate, Decapsulate};
        use std::time::Instant;

        let mut rng = rand::thread_rng();
        let (dk, ek) = MlKem768::generate(&mut rng);
        let (ct, _ss) = ek.encapsulate(&mut rng).unwrap();

        let (dk2, ek2) = MlKem768::generate(&mut rng);
        let (ct_inv, _) = ek2.encapsulate(&mut rng).unwrap();

        for _ in 0..1000 { dk.decapsulate(&ct).ok(); }

        let mut valid_times = Vec::with_capacity(samples);
        let mut invalid_times = Vec::with_capacity(samples);

        for _ in 0..samples {
            let start = Instant::now();
            dk.decapsulate(&ct).ok();
            valid_times.push(start.elapsed().as_nanos() as f64);

            let start = Instant::now();
            dk.decapsulate(&ct_inv).ok();
            invalid_times.push(start.elapsed().as_nanos() as f64);
        }

        let v_mean: f64 = valid_times.iter().sum::<f64>() / valid_times.len() as f64;
        let i_mean: f64 = invalid_times.iter().sum::<f64>() / invalid_times.len() as f64;
        let v_var: f64 = valid_times.iter().map(|t| (t - v_mean).powi(2)).sum::<f64>() / (valid_times.len() - 1) as f64;
        let i_var: f64 = invalid_times.iter().map(|t| (t - i_mean).powi(2)).sum::<f64>() / (invalid_times.len() - 1) as f64;
        let pooled = ((v_var + i_var) / 2.0).sqrt();
        let d = if pooled > 0.0 { (v_mean - i_mean).abs() / pooled } else { 0.0 };

        tests_run += 1;
        if d > max_d { max_d = d; }

        if d > threshold {
            tests_failed += 1;
            println!("    FAIL  d={:.4} (threshold={:.2})", d, threshold);
            failures.push(CiFailure {
                test: "ML-KEM-768 ml-kem FO-Transform".into(),
                cohens_d: d, threshold,
            });
        } else {
            tests_passed += 1;
            println!("    PASS  d={:.4}", d);
        }
    }

    // ═══ Test 4: SLH-DSA signing CV ═══
    println!("  [4/4] SLH-DSA (liboqs) signing variance...");
    {
        use std::ffi::CString;
        use std::time::Instant;
        use crate::target::liboqs::*;

        let sig_name = CString::new("SLH_DSA_PURE_SHA2_128S").unwrap();
        let sig = unsafe { OQS_SIG_new(sig_name.as_ptr()) };

        if !sig.is_null() {
            let mut pk = vec![0u8; 32];
            let mut sk = vec![0u8; 64];
            let mut signature = vec![0u8; 7856];
            let mut sig_len: usize = 0;
            let msg = b"Anu CI test";

            unsafe { OQS_SIG_keypair(sig, pk.as_mut_ptr(), sk.as_mut_ptr()) };

            let slh_samples = (samples / 50).max(20);
            let mut times = Vec::with_capacity(slh_samples);

            for _ in 0..3 {
                unsafe { OQS_SIG_sign(sig, signature.as_mut_ptr(), &mut sig_len,
                                      msg.as_ptr(), msg.len(), sk.as_ptr()) };
            }
            for _ in 0..slh_samples {
                let start = Instant::now();
                unsafe { OQS_SIG_sign(sig, signature.as_mut_ptr(), &mut sig_len,
                                      msg.as_ptr(), msg.len(), sk.as_ptr()) };
                times.push(start.elapsed().as_nanos() as f64);
            }

            unsafe { OQS_SIG_free(sig as *mut _) };

            let mean: f64 = times.iter().sum::<f64>() / times.len() as f64;
            let var: f64 = times.iter().map(|t| (t - mean).powi(2)).sum::<f64>() / (times.len() - 1) as f64;
            let cv = if mean > 0.0 { var.sqrt() / mean } else { 0.0 };

            tests_run += 1;

            // SLH-DSA: CV > 5% = fail
            if cv > 0.05 {
                tests_failed += 1;
                println!("    FAIL  CV={:.4} (threshold=0.05)", cv);
                failures.push(CiFailure {
                    test: "SLH-DSA signing variance".into(),
                    cohens_d: cv, threshold: 0.05,
                });
            } else {
                tests_passed += 1;
                println!("    PASS  CV={:.4}", cv);
            }
        }
    }

    // ═══ SUMMARY ═══
    println!();
    let passed = tests_failed == 0;

    if passed {
        println!("  ════════════════════════════════════════════════════════");
        println!("  ✓ ALL TESTS PASSED ({}/{})", tests_passed, tests_run);
        println!("  ✓ Max Cohen's d: {:.4} (threshold: {:.2})", max_d, threshold);
        println!("  ════════════════════════════════════════════════════════");
    } else {
        println!("  ════════════════════════════════════════════════════════");
        println!("  ✗ TESTS FAILED: {}/{}", tests_failed, tests_run);
        println!("  ✗ Max Cohen's d: {:.4} (threshold: {:.2})", max_d, threshold);
        for f in &failures {
            println!("  ✗ {} — d={:.4}", f.test, f.cohens_d);
        }
        println!("  ════════════════════════════════════════════════════════");
    }
    println!();

    CiResult {
        passed,
        threshold,
        max_cohens_d: max_d,
        tests_run,
        tests_passed,
        tests_failed,
        failures,
    }
}
