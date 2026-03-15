// VÄRN-60 (Anu) — Pure Rust ML-KEM Target
//
// RustCrypto `ml-kem` crate. Pure Rust. No assembly.
// API: KemCore::generate, Encapsulate::encapsulate, Decapsulate::decapsulate
// Types: DecapsulationKey<P>, EncapsulationKey<P>, EncodedCiphertext<P>, SharedKey

use crate::target::SecurityLevel;
use crate::analysis::Statistics;
use serde::Serialize;
use std::time::Instant;

use ml_kem::KemCore;
use ml_kem::{MlKem512, MlKem768, MlKem1024};
// These traits provide encapsulate/decapsulate methods
use kem::{Encapsulate, Decapsulate};

#[derive(Debug, Serialize)]
pub struct PureRustKemResult {
    pub level: String,
    pub implementation: String,
    pub samples: usize,
    pub valid_mean_ns: f64,
    pub valid_stddev_ns: f64,
    pub invalid_mean_ns: f64,
    pub invalid_stddev_ns: f64,
    pub delta_ns: f64,
    pub cohens_d: f64,
    pub key_cv: f64,
    pub key_means: Vec<f64>,
    pub pqcrypto_mean_ns: f64,
    pub pure_rust_mean_ns: f64,
    pub speed_ratio: f64,
    pub verdict: String,
}

pub fn run_pure_rust_kem_test(level: SecurityLevel, samples: usize) -> PureRustKemResult {
    println!();
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║     VÄRN-60 (Anu) — Pure Rust ML-KEM Analysis          ║");
    println!("  ║     RustCrypto ml-kem crate (no assembly)              ║");
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Level: {}  Samples: {}", level, samples);
    println!();

    println!("  [1/4] FO-Transform timing (interleaved valid/invalid)...");

    let (valid_times, invalid_times, pure_mean) = match level {
        SecurityLevel::MlKem512 => measure_512(samples),
        SecurityLevel::MlKem768 => measure_768(samples),
        SecurityLevel::MlKem1024 => measure_1024(samples),
    };

    let vs = Statistics::from_samples(&valid_times);
    let is = Statistics::from_samples(&invalid_times);
    let delta = vs.mean - is.mean;
    let pooled = ((vs.variance + is.variance) / 2.0).sqrt();
    let d = if pooled > 0.0 { delta.abs() / pooled } else { 0.0 };

    println!("    Valid:   {:.0} ± {:.0} ns", vs.mean, vs.stddev);
    println!("    Invalid: {:.0} ± {:.0} ns", is.mean, is.stddev);
    println!("    Δ = {:.1} ns, Cohen's d = {:.4}", delta, d);

    let fo_tag = if d > 0.5 { "██ SIGNIFICANT LEAK" }
        else if d > 0.2 { "▓▓ SMALL LEAK" }
        else if d > 0.05 { "░░ DETECTABLE" }
        else { "   noise" };
    println!("    {}", fo_tag);
    println!();

    println!("  [2/4] Key-dependent timing (20 keys)...");
    let num_keys = 20;
    let key_samples = samples / 5;
    let mut key_means: Vec<f64> = Vec::new();

    for k in 0..num_keys {
        let m = measure_key_mean(level, key_samples);
        key_means.push(m);
        if k < 10 { println!("    Key {:>2}: {:.0} ns", k + 1, m); }
    }

    let km_mean: f64 = key_means.iter().sum::<f64>() / key_means.len() as f64;
    let km_var: f64 = key_means.iter().map(|m| (m - km_mean).powi(2)).sum::<f64>()
        / (key_means.len() - 1) as f64;
    let key_cv = km_var.sqrt() / km_mean;
    println!("    Key CV: {:.4}", key_cv);
    println!();

    println!("  [3/4] Comparison with pqcrypto-kyber (assembly)...");
    let pq_mean = measure_pqcrypto_mean(level, key_samples);
    let ratio = pure_mean / pq_mean;
    println!("    pqcrypto (asm): {:.0} ns", pq_mean);
    println!("    ml-kem (Rust):  {:.0} ns", pure_mean);
    println!("    Ratio:          {:.2}x", ratio);
    println!();

    println!("  [4/4] Analysis...");
    let verdict = if d > 0.5 {
        format!("CRITICAL — Pure Rust ML-KEM timing leak! d={:.3}, Δ={:.0}ns. \
                LLVM generated non-constant-time code.", d, delta)
    } else if d > 0.2 {
        format!("HIGH — Measurable timing difference d={:.3}", d)
    } else if d > 0.05 {
        format!("DETECTABLE — Small signal d={:.4}", d)
    } else {
        format!("CLEAN — Pure Rust appears constant-time (d={:.4})", d)
    };

    println!();
    println!("  ════════════════════════════════════════════════════════");
    println!("  {}", verdict);
    println!("  ════════════════════════════════════════════════════════");
    println!();

    PureRustKemResult {
        level: level.to_string(),
        implementation: "ml-kem 0.2 (RustCrypto, pure Rust)".into(),
        samples,
        valid_mean_ns: vs.mean, valid_stddev_ns: vs.stddev,
        invalid_mean_ns: is.mean, invalid_stddev_ns: is.stddev,
        delta_ns: delta, cohens_d: d,
        key_cv, key_means,
        pqcrypto_mean_ns: pq_mean, pure_rust_mean_ns: pure_mean,
        speed_ratio: ratio, verdict,
    }
}

// ── ML-KEM-768 ──

fn measure_768(samples: usize) -> (Vec<u64>, Vec<u64>, f64) {
    let mut rng = rand::thread_rng();

    // Generate keypair
    let (dk, ek) = MlKem768::generate(&mut rng);

    // Valid ciphertext for this key
    let (ct_valid, _ss) = ek.encapsulate(&mut rng).unwrap();

    // Invalid ciphertext: encapsulate with a DIFFERENT key
    let (_dk2, ek2) = MlKem768::generate(&mut rng);
    let (ct_invalid, _) = ek2.encapsulate(&mut rng).unwrap();

    // Warmup
    for _ in 0..2000 {
        let _r: Result<_, _> = dk.decapsulate(&ct_valid);
    }

    let mut vt = Vec::with_capacity(samples);
    let mut it = Vec::with_capacity(samples);

    for _ in 0..samples {
        let start = Instant::now();
        let _r: Result<_, _> = dk.decapsulate(&ct_valid);
        vt.push(start.elapsed().as_nanos() as u64);

        let start = Instant::now();
        let _r: Result<_, _> = dk.decapsulate(&ct_invalid);
        it.push(start.elapsed().as_nanos() as u64);
    }

    let mean = vt.iter().sum::<u64>() as f64 / vt.len() as f64;
    (vt, it, mean)
}

// ── ML-KEM-512 ──

fn measure_512(samples: usize) -> (Vec<u64>, Vec<u64>, f64) {
    let mut rng = rand::thread_rng();

    let (dk, ek) = MlKem512::generate(&mut rng);
    let (ct_valid, _ss) = ek.encapsulate(&mut rng).unwrap();

    let (_dk2, ek2) = MlKem512::generate(&mut rng);
    let (ct_invalid, _) = ek2.encapsulate(&mut rng).unwrap();

    for _ in 0..2000 { let _r: Result<_, _> = dk.decapsulate(&ct_valid); }

    let mut vt = Vec::with_capacity(samples);
    let mut it = Vec::with_capacity(samples);

    for _ in 0..samples {
        let start = Instant::now();
        let _r: Result<_, _> = dk.decapsulate(&ct_valid);
        vt.push(start.elapsed().as_nanos() as u64);

        let start = Instant::now();
        let _r: Result<_, _> = dk.decapsulate(&ct_invalid);
        it.push(start.elapsed().as_nanos() as u64);
    }

    let mean = vt.iter().sum::<u64>() as f64 / vt.len() as f64;
    (vt, it, mean)
}

// ── ML-KEM-1024 ──

fn measure_1024(samples: usize) -> (Vec<u64>, Vec<u64>, f64) {
    let mut rng = rand::thread_rng();

    let (dk, ek) = MlKem1024::generate(&mut rng);
    let (ct_valid, _ss) = ek.encapsulate(&mut rng).unwrap();

    let (_dk2, ek2) = MlKem1024::generate(&mut rng);
    let (ct_invalid, _) = ek2.encapsulate(&mut rng).unwrap();

    for _ in 0..2000 { let _r: Result<_, _> = dk.decapsulate(&ct_valid); }

    let mut vt = Vec::with_capacity(samples);
    let mut it = Vec::with_capacity(samples);

    for _ in 0..samples {
        let start = Instant::now();
        let _r: Result<_, _> = dk.decapsulate(&ct_valid);
        vt.push(start.elapsed().as_nanos() as u64);

        let start = Instant::now();
        let _r: Result<_, _> = dk.decapsulate(&ct_invalid);
        it.push(start.elapsed().as_nanos() as u64);
    }

    let mean = vt.iter().sum::<u64>() as f64 / vt.len() as f64;
    (vt, it, mean)
}

// ── Key-dependent timing ──

fn measure_key_mean(level: SecurityLevel, samples: usize) -> f64 {
    let mut rng = rand::thread_rng();
    match level {
        SecurityLevel::MlKem768 => {
            let (dk, ek) = MlKem768::generate(&mut rng);
            let (ct, _) = ek.encapsulate(&mut rng).unwrap();
            for _ in 0..100 { let _r: Result<_, _> = dk.decapsulate(&ct); }
            let mut times = Vec::with_capacity(samples);
            for _ in 0..samples {
                let start = Instant::now();
                let _r: Result<_, _> = dk.decapsulate(&ct);
                times.push(start.elapsed().as_nanos() as u64);
            }
            times.iter().sum::<u64>() as f64 / times.len() as f64
        }
        SecurityLevel::MlKem512 => {
            let (dk, ek) = MlKem512::generate(&mut rng);
            let (ct, _) = ek.encapsulate(&mut rng).unwrap();
            for _ in 0..100 { let _r: Result<_, _> = dk.decapsulate(&ct); }
            let mut times = Vec::with_capacity(samples);
            for _ in 0..samples {
                let start = Instant::now();
                let _r: Result<_, _> = dk.decapsulate(&ct);
                times.push(start.elapsed().as_nanos() as u64);
            }
            times.iter().sum::<u64>() as f64 / times.len() as f64
        }
        SecurityLevel::MlKem1024 => {
            let (dk, ek) = MlKem1024::generate(&mut rng);
            let (ct, _) = ek.encapsulate(&mut rng).unwrap();
            for _ in 0..100 { let _r: Result<_, _> = dk.decapsulate(&ct); }
            let mut times = Vec::with_capacity(samples);
            for _ in 0..samples {
                let start = Instant::now();
                let _r: Result<_, _> = dk.decapsulate(&ct);
                times.push(start.elapsed().as_nanos() as u64);
            }
            times.iter().sum::<u64>() as f64 / times.len() as f64
        }
    }
}

// ── pqcrypto comparison ──

fn measure_pqcrypto_mean(level: SecurityLevel, samples: usize) -> f64 {
    let target = crate::target::MlKemTarget::new(level);
    let (ct, _) = target.encapsulate();
    for _ in 0..100 { let _ = target.timed_decapsulate(&ct); }
    let mut times = Vec::with_capacity(samples);
    for _ in 0..samples {
        let (_, t) = target.timed_decapsulate(&ct);
        times.push(t);
    }
    times.iter().sum::<u64>() as f64 / times.len() as f64
}
