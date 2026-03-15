// VÄRN-60 (Anu) — SLH-DSA (SPHINCS+) Timing Analysis
//
// The THIRD NIST Post-Quantum Standard. FIPS 205.
// Hash-based signatures — completely different from lattice crypto.
//
// SPHINCS+ uses Merkle trees with WOTS+ one-time signatures.
// The signing process traverses a hypertree, which involves:
//   - FORS (Forest of Random Subsets) — few-time signature
//   - WOTS+ chain computations — hash chains of variable length
//   - Merkle tree authentication paths
//
// Potential timing leaks:
//   1. WOTS+ chain length depends on the message digest
//      (each chain has length 0 to w-1, determined by message bits)
//   2. FORS leaf selection depends on the message
//   3. Hypertree traversal pattern depends on the signing index
//
// SPHINCS+ has two modes:
//   - "f" (fast): faster signing, larger signatures
//   - "s" (small): slower signing, smaller signatures
//
// Nobody has tested software implementations for timing side-channels.
// Anu will be the first.

use crate::analysis::Statistics;
use serde::Serialize;
use std::time::Instant;

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub enum SlhDsaVariant {
    Shake128f,  // NIST Level 1, fast
    Shake128s,  // NIST Level 1, small
    Shake256f,  // NIST Level 5, fast (FIPS 205 SLH-DSA-256f)
    Shake256s,  // NIST Level 5, small
    Shake192f,  // NIST Level 3, fast
    Shake192s,  // NIST Level 3, small
}

impl std::fmt::Display for SlhDsaVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlhDsaVariant::Shake128f => write!(f, "SLH-DSA-SHAKE-128f"),
            SlhDsaVariant::Shake128s => write!(f, "SLH-DSA-SHAKE-128s"),
            SlhDsaVariant::Shake256f => write!(f, "SLH-DSA-SHAKE-256f"),
            SlhDsaVariant::Shake256s => write!(f, "SLH-DSA-SHAKE-256s"),
            SlhDsaVariant::Shake192f => write!(f, "SLH-DSA-SHAKE-192f"),
            SlhDsaVariant::Shake192s => write!(f, "SLH-DSA-SHAKE-192s"),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SlhDsaTimingResult {
    pub variant: String,
    pub platform: String,

    // Signing timing
    pub sign_samples: usize,
    pub sign_mean_ns: f64,
    pub sign_stddev_ns: f64,
    pub sign_cv: f64,
    pub sign_min_ns: u64,
    pub sign_max_ns: u64,
    pub sign_range_ratio: f64,

    // Verify timing
    pub verify_mean_ns: f64,
    pub verify_stddev_ns: f64,
    pub verify_cv: f64,

    // Key-dependent signing
    pub key_count: usize,
    pub key_cv: f64,
    pub key_means: Vec<f64>,

    // Message-dependent signing
    pub msg_count: usize,
    pub msg_cv: f64,
    pub msg_means: Vec<f64>,

    pub verdict: String,
}

pub fn run_slhdsa_timing(variant: SlhDsaVariant, samples: usize) -> SlhDsaTimingResult {
    let platform = crate::platform::PlatformInfo::detect();

    println!();
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║     VÄRN-60 (Anu) — SLH-DSA (SPHINCS+) Analysis       ║");
    println!("  ║     FIPS 205 — Hash-Based Signature Timing             ║");
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Variant:  {}", variant);
    println!("  Samples:  {}", samples);
    println!();

    // ── Step 1: Single-key signing/verify variance ──
    println!("  [1/3] Single-key signing variance...");

    let (sign_times, verify_times) = measure_sign_verify(variant, samples);

    let ss = Statistics::from_samples(&sign_times);
    let vs = Statistics::from_samples(&verify_times);
    let sign_cv = ss.stddev / ss.mean;
    let verify_cv = vs.stddev / vs.mean;
    let range_ratio = ss.max as f64 / ss.min.max(1) as f64;

    println!("    Signing:  {:.0} ± {:.0} ns (CV={:.4}, range={:.2}x)",
        ss.mean, ss.stddev, sign_cv, range_ratio);
    println!("    Verify:   {:.0} ± {:.0} ns (CV={:.4})",
        vs.mean, vs.stddev, verify_cv);
    println!("    Sign/Verify ratio: {:.1}x", ss.mean / vs.mean.max(1.0));
    println!();

    // ── Step 2: Key-dependent variance ──
    println!("  [2/3] Key-dependent signing (20 keys, same message)...");

    let num_keys = 20;
    let key_samples = (samples / 10).max(50);
    let mut key_means: Vec<f64> = Vec::new();

    for k in 0..num_keys {
        let times = measure_sign_only(variant, key_samples);
        let mean = times.iter().sum::<u64>() as f64 / times.len() as f64;
        key_means.push(mean);
        if k < 10 {
            println!("    Key {:>2}: {:.0} ns", k + 1, mean);
        }
    }

    let km_mean: f64 = key_means.iter().sum::<f64>() / key_means.len() as f64;
    let km_var: f64 = key_means.iter().map(|m| (m - km_mean).powi(2)).sum::<f64>()
        / (key_means.len() - 1) as f64;
    let key_cv = km_var.sqrt() / km_mean;
    println!("    Key CV: {:.4} ({:.2}%)", key_cv, key_cv * 100.0);
    println!();

    // ── Step 3: Message-dependent variance ──
    println!("  [3/3] Message-dependent signing (20 messages, same key)...");

    let msg_count = 20;
    let msg_samples = (samples / 10).max(50);
    let mut msg_means: Vec<f64> = Vec::new();

    for m in 0..msg_count {
        let msg = format!("VARN-60 SLH-DSA test message number {} - sectio-aurea-q", m);
        let times = measure_sign_with_msg(variant, msg.as_bytes(), msg_samples);
        let mean = times.iter().sum::<u64>() as f64 / times.len() as f64;
        msg_means.push(mean);
        if m < 10 {
            println!("    Msg {:>2}: {:.0} ns", m + 1, mean);
        }
    }

    let mm_mean: f64 = msg_means.iter().sum::<f64>() / msg_means.len() as f64;
    let mm_var: f64 = msg_means.iter().map(|m| (m - mm_mean).powi(2)).sum::<f64>()
        / (msg_means.len() - 1) as f64;
    let msg_cv = mm_var.sqrt() / mm_mean;
    println!("    Msg CV: {:.4} ({:.2}%)", msg_cv, msg_cv * 100.0);
    println!();

    let verdict = if sign_cv > 0.1 {
        format!("CRITICAL — SLH-DSA signing time varies by {:.0}x (CV={:.2}%). \
                WOTS+ chain length or FORS selection leaks message-dependent timing.",
                range_ratio, sign_cv * 100.0)
    } else if sign_cv > 0.01 {
        format!("HIGH — Measurable signing variance (CV={:.2}%). \
                Hash-tree traversal may be message-dependent.", sign_cv * 100.0)
    } else if msg_cv > 0.01 {
        format!("DETECTABLE — Message-dependent variance (msg CV={:.2}%). \
                Different messages produce different timing.", msg_cv * 100.0)
    } else {
        format!("CLEAN — SLH-DSA signing appears constant-time (CV={:.4})", sign_cv)
    };

    println!("  ════════════════════════════════════════════════════════");
    println!("  {}", verdict);
    println!("  ════════════════════════════════════════════════════════");
    println!();

    SlhDsaTimingResult {
        variant: variant.to_string(),
        platform: platform.chip,
        sign_samples: samples,
        sign_mean_ns: ss.mean, sign_stddev_ns: ss.stddev, sign_cv,
        sign_min_ns: ss.min, sign_max_ns: ss.max, sign_range_ratio: range_ratio,
        verify_mean_ns: vs.mean, verify_stddev_ns: vs.stddev, verify_cv,
        key_count: num_keys, key_cv, key_means,
        msg_count, msg_cv, msg_means,
        verdict,
    }
}

// ── Measurement helpers ──

fn measure_sign_verify(variant: SlhDsaVariant, samples: usize) -> (Vec<u64>, Vec<u64>) {
    let msg = b"VARN-60 SLH-DSA timing analysis - sectio-aurea-q";
    let mut sign_times = Vec::with_capacity(samples);
    let mut verify_times = Vec::with_capacity(samples);

    macro_rules! measure_variant {
        ($mod:path) => {{
            use $mod::{keypair, sign, open};
            let (pk, sk) = keypair();
            // Warmup
            for _ in 0..10 {
                let sm = sign(msg, &sk);
                let _ = open(&sm, &pk);
            }
            for _ in 0..samples {
                let start = Instant::now();
                let sm = sign(msg, &sk);
                sign_times.push(start.elapsed().as_nanos() as u64);
                let start = Instant::now();
                let _ = open(&sm, &pk);
                verify_times.push(start.elapsed().as_nanos() as u64);
            }
        }};
    }

    match variant {
        SlhDsaVariant::Shake128f => measure_variant!(pqcrypto_sphincsplus::sphincsshake128fsimple),
        SlhDsaVariant::Shake128s => measure_variant!(pqcrypto_sphincsplus::sphincsshake128ssimple),
        SlhDsaVariant::Shake192f => measure_variant!(pqcrypto_sphincsplus::sphincsshake192fsimple),
        SlhDsaVariant::Shake192s => measure_variant!(pqcrypto_sphincsplus::sphincsshake192ssimple),
        SlhDsaVariant::Shake256f => measure_variant!(pqcrypto_sphincsplus::sphincsshake256fsimple),
        SlhDsaVariant::Shake256s => measure_variant!(pqcrypto_sphincsplus::sphincsshake256ssimple),
    }

    (sign_times, verify_times)
}

fn measure_sign_only(variant: SlhDsaVariant, samples: usize) -> Vec<u64> {
    let msg = b"VARN-60 SLH-DSA key-dependent test";
    let mut times = Vec::with_capacity(samples);

    macro_rules! measure_variant {
        ($mod:path) => {{
            use $mod::{keypair, sign};
            let (_pk, sk) = keypair();
            for _ in 0..5 { let _ = sign(msg, &sk); }
            for _ in 0..samples {
                let start = Instant::now();
                let _ = sign(msg, &sk);
                times.push(start.elapsed().as_nanos() as u64);
            }
        }};
    }

    match variant {
        SlhDsaVariant::Shake128f => measure_variant!(pqcrypto_sphincsplus::sphincsshake128fsimple),
        SlhDsaVariant::Shake128s => measure_variant!(pqcrypto_sphincsplus::sphincsshake128ssimple),
        SlhDsaVariant::Shake192f => measure_variant!(pqcrypto_sphincsplus::sphincsshake192fsimple),
        SlhDsaVariant::Shake192s => measure_variant!(pqcrypto_sphincsplus::sphincsshake192ssimple),
        SlhDsaVariant::Shake256f => measure_variant!(pqcrypto_sphincsplus::sphincsshake256fsimple),
        SlhDsaVariant::Shake256s => measure_variant!(pqcrypto_sphincsplus::sphincsshake256ssimple),
    }

    times
}

fn measure_sign_with_msg(variant: SlhDsaVariant, msg: &[u8], samples: usize) -> Vec<u64> {
    let mut times = Vec::with_capacity(samples);

    macro_rules! measure_variant {
        ($mod:path, $msg:expr) => {{
            use $mod::{keypair, sign};
            let (_pk, sk) = keypair();
            for _ in 0..5 { let _ = sign($msg, &sk); }
            for _ in 0..samples {
                let start = Instant::now();
                let _ = sign($msg, &sk);
                times.push(start.elapsed().as_nanos() as u64);
            }
        }};
    }

    match variant {
        SlhDsaVariant::Shake128f => measure_variant!(pqcrypto_sphincsplus::sphincsshake128fsimple, msg),
        SlhDsaVariant::Shake128s => measure_variant!(pqcrypto_sphincsplus::sphincsshake128ssimple, msg),
        SlhDsaVariant::Shake192f => measure_variant!(pqcrypto_sphincsplus::sphincsshake192fsimple, msg),
        SlhDsaVariant::Shake192s => measure_variant!(pqcrypto_sphincsplus::sphincsshake192ssimple, msg),
        SlhDsaVariant::Shake256f => measure_variant!(pqcrypto_sphincsplus::sphincsshake256fsimple, msg),
        SlhDsaVariant::Shake256s => measure_variant!(pqcrypto_sphincsplus::sphincsshake256ssimple, msg),
    }

    times
}
