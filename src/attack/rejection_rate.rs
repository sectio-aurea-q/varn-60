// VÄRN-60 (Anu) — Rejection Rate Attack
//
// THE CORRECT ATTACK STRUCTURE:
//
// Problem with v1: We tried to correlate mean timing with key norm.
// Key norms barely vary (4% spread). Wrong metric.
//
// The REAL attack:
//   1. A server signs many messages with the SAME key
//   2. An attacker observes signing time for each signature
//   3. From timing, the attacker classifies each signature into
//      "1 iteration", "2 iterations", "3 iterations", etc.
//   4. The FRACTION of multi-iteration signatures (rejection rate)
//      is key-dependent
//   5. Different keys produce MEASURABLY different rejection rates
//   6. The rejection rate constrains the secret key:
//      - Keys with large coefficients near ±η → higher rejection rate
//      - Keys with small coefficients → lower rejection rate
//   7. This is information that helps lattice reduction attacks
//
// What we prove:
//   A) Rejection rate varies between keys (not just noise)
//   B) The variation is statistically significant
//   C) An attacker can distinguish between keys from timing alone
//   D) This constitutes a side-channel information leak

use crate::attack::dilithium::DilithiumLevel;
use serde::Serialize;
use std::time::Instant;

#[derive(Debug, Serialize)]
pub struct RejectionRateAttackResult {
    pub level: String,
    pub keys_tested: usize,
    pub signatures_per_key: usize,
    pub messages_per_key: usize,

    // Per-key rejection rates
    pub key_profiles: Vec<KeyRejectionProfile>,

    // Cross-key analysis
    pub mean_rejection_rate: f64,
    pub stddev_rejection_rate: f64,
    pub min_rejection_rate: f64,
    pub max_rejection_rate: f64,
    pub rejection_rate_cv: f64,

    // Distinguishability
    pub pairwise_distinguishable: usize,
    pub pairwise_total: usize,
    pub distinguishability_rate: f64,

    // Information theory
    pub bits_from_rate: f64,

    pub verdict: String,
}

#[derive(Debug, Serialize)]
pub struct KeyRejectionProfile {
    pub key_index: usize,
    pub total_signatures: usize,
    pub iteration_counts: Vec<usize>,    // how many sigs had N=1, N=2, N=3, ...
    pub rejection_rate: f64,             // fraction with N>1
    pub mean_iterations: f64,
    pub mean_sign_time_ns: f64,
    pub sign_stddev_ns: f64,
}

pub fn run_rejection_rate_attack(
    level: DilithiumLevel,
    num_keys: usize,
    sigs_per_key: usize,
) -> RejectionRateAttackResult {
    println!();
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║     VÄRN-60 (Anu) — Rejection Rate Attack              ║");
    println!("  ║     Per-key rejection rate fingerprinting              ║");
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Level: {}  Keys: {}  Signatures/key: {}", level, num_keys, sigs_per_key);
    println!();

    // ── Step 1: Calibrate iteration boundaries ──
    println!("  [1/4] Calibrating iteration timing boundaries...");

    let boundary = calibrate_single_iteration(level);
    println!("    1-iteration boundary: < {:.0} ns", boundary);
    println!("    Anything above = 2+ iterations (rejection occurred)");
    println!();

    // ── Step 2: Profile each key ──
    println!("  [2/4] Profiling {} keys ({} signatures each)...", num_keys, sigs_per_key);
    println!();

    let mut profiles: Vec<KeyRejectionProfile> = Vec::new();

    for k in 0..num_keys {
        let profile = profile_key_rejection(level, k, sigs_per_key, boundary);

        if k < 20 || k % 20 == 0 || k == num_keys - 1 {
            println!("    Key {:>3}: reject={:.1}%  mean_N={:.2}  mean_t={:.0}ns  [N=1:{} N=2:{} N=3:{} N=4+:{}]",
                k + 1,
                profile.rejection_rate * 100.0,
                profile.mean_iterations,
                profile.mean_sign_time_ns,
                profile.iteration_counts.get(0).unwrap_or(&0),
                profile.iteration_counts.get(1).unwrap_or(&0),
                profile.iteration_counts.get(2).unwrap_or(&0),
                profile.iteration_counts.iter().skip(3).sum::<usize>(),
            );
        } else if k == 20 {
            println!("    ...");
        }

        profiles.push(profile);
    }
    println!();

    // ── Step 3: Cross-key analysis ──
    println!("  [3/4] Cross-key rejection rate analysis...");

    let rates: Vec<f64> = profiles.iter().map(|p| p.rejection_rate).collect();
    let rate_stats = compute_f64_stats(&rates);

    println!("    Mean rejection rate:   {:.2}%", rate_stats.mean * 100.0);
    println!("    Stddev:                {:.2}%", rate_stats.stddev * 100.0);
    println!("    Min:                   {:.2}%", rate_stats.min_f * 100.0);
    println!("    Max:                   {:.2}%", rate_stats.max_f * 100.0);
    println!("    CV:                    {:.4}", rate_stats.cv);
    println!();

    // ── Step 4: Distinguishability test ──
    // Can we tell two keys apart by their rejection rates?
    // For each pair of keys, run a chi-squared test on their
    // iteration count distributions
    println!("  [4/4] Pairwise key distinguishability...");

    let mut distinguishable = 0;
    let mut total_pairs = 0;

    for i in 0..num_keys.min(50) {
        for j in (i+1)..num_keys.min(50) {
            total_pairs += 1;
            if are_distinguishable(&profiles[i], &profiles[j], sigs_per_key) {
                distinguishable += 1;
            }
        }
    }

    let dist_rate = distinguishable as f64 / total_pairs.max(1) as f64;

    println!("    Pairs tested:          {}", total_pairs);
    println!("    Distinguishable:       {} ({:.1}%)", distinguishable, dist_rate * 100.0);
    println!();

    // Information from rejection rate
    // If we can distinguish K different rejection rate "bins",
    // that gives us log2(K) bits of information about the key
    let rate_range = rate_stats.max_f - rate_stats.min_f;
    let measurement_precision = rate_stats.stddev * 0.5; // conservative
    let distinguishable_bins = if measurement_precision > 0.0 {
        (rate_range / measurement_precision).ceil() as usize
    } else { 1 };
    let bits_from_rate = (distinguishable_bins.max(1) as f64).log2();

    println!("    Distinguishable rate bins: ~{}", distinguishable_bins);
    println!("    Information from rate:     ~{:.1} bits per key", bits_from_rate);
    println!();

    let verdict = if dist_rate > 0.5 && rate_stats.cv > 0.05 {
        format!("CONFIRMED — {:.1}% of key pairs distinguishable by rejection rate. \
                CV={:.2}%. An attacker observing {} signatures can fingerprint the server's key \
                and narrow the key space by ~{:.1} bits.",
                dist_rate * 100.0, rate_stats.cv * 100.0, sigs_per_key, bits_from_rate)
    } else if dist_rate > 0.2 {
        format!("PARTIAL — {:.1}% of key pairs distinguishable. \
                Rejection rate varies measurably (CV={:.2}%) but more signatures needed.",
                dist_rate * 100.0, rate_stats.cv * 100.0)
    } else if rate_stats.cv > 0.01 {
        format!("WEAK — Rejection rates vary (CV={:.2}%) but pairs not reliably distinguishable \
                with {} signatures.", rate_stats.cv * 100.0, sigs_per_key)
    } else {
        format!("NOT EXPLOITABLE — Rejection rates are uniform across keys (CV={:.4}%).",
                rate_stats.cv * 100.0)
    };

    println!("  ════════════════════════════════════════════════════════");
    println!("  {}", verdict);
    println!("  ════════════════════════════════════════════════════════");
    println!();

    RejectionRateAttackResult {
        level: level.to_string(),
        keys_tested: num_keys,
        signatures_per_key: sigs_per_key,
        messages_per_key: sigs_per_key, // each sig uses a different random message
        key_profiles: profiles,
        mean_rejection_rate: rate_stats.mean,
        stddev_rejection_rate: rate_stats.stddev,
        min_rejection_rate: rate_stats.min_f,
        max_rejection_rate: rate_stats.max_f,
        rejection_rate_cv: rate_stats.cv,
        pairwise_distinguishable: distinguishable,
        pairwise_total: total_pairs,
        distinguishability_rate: dist_rate,
        bits_from_rate,
        verdict,
    }
}

/// Calibrate: find the timing boundary between 1-iteration and 2-iteration signatures.
/// Method: sign many times with one key, find the gap in the timing distribution.
fn calibrate_single_iteration(level: DilithiumLevel) -> f64 {
    let mut times: Vec<u64> = Vec::new();

    // Collect 5000 signatures across 10 different keys
    for _ in 0..10 {
        let msg: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        match level {
            DilithiumLevel::Dilithium2 => {
                let (_pk, sk) = pqcrypto_dilithium::dilithium2::keypair();
                for _ in 0..10 { let _ = pqcrypto_dilithium::dilithium2::sign(&msg, &sk); }
                for _ in 0..500 {
                    let start = Instant::now();
                    let _ = pqcrypto_dilithium::dilithium2::sign(&msg, &sk);
                    times.push(start.elapsed().as_nanos() as u64);
                }
            }
            DilithiumLevel::Dilithium3 => {
                let (_pk, sk) = pqcrypto_dilithium::dilithium3::keypair();
                for _ in 0..10 { let _ = pqcrypto_dilithium::dilithium3::sign(&msg, &sk); }
                for _ in 0..500 {
                    let start = Instant::now();
                    let _ = pqcrypto_dilithium::dilithium3::sign(&msg, &sk);
                    times.push(start.elapsed().as_nanos() as u64);
                }
            }
            DilithiumLevel::Dilithium5 => {
                let (_pk, sk) = pqcrypto_dilithium::dilithium5::keypair();
                for _ in 0..10 { let _ = pqcrypto_dilithium::dilithium5::sign(&msg, &sk); }
                for _ in 0..500 {
                    let start = Instant::now();
                    let _ = pqcrypto_dilithium::dilithium5::sign(&msg, &sk);
                    times.push(start.elapsed().as_nanos() as u64);
                }
            }
        }
    }

    times.sort();

    // Find the biggest gap in the lower half of the distribution
    // This separates 1-iteration from 2-iteration signatures
    let half = times.len() / 2;
    let mut max_gap = 0u64;
    let mut gap_pos = 0;

    for i in 1..half {
        let gap = times[i] - times[i - 1];
        if gap > max_gap {
            max_gap = gap;
            gap_pos = i;
        }
    }

    // Boundary = midpoint of the largest gap
    if gap_pos > 0 && gap_pos < times.len() {
        (times[gap_pos - 1] as f64 + times[gap_pos] as f64) / 2.0
    } else {
        // Fallback: use the 90th percentile of the fastest cluster
        let p90 = times[(times.len() as f64 * 0.15) as usize];
        p90 as f64 * 1.2
    }
}

/// Profile one key: sign many different messages, classify each by iteration count
fn profile_key_rejection(
    level: DilithiumLevel,
    key_index: usize,
    num_sigs: usize,
    boundary_1iter: f64,
) -> KeyRejectionProfile {
    let mut times: Vec<u64> = Vec::new();

    // Sign num_sigs DIFFERENT messages with the SAME key
    match level {
        DilithiumLevel::Dilithium2 => {
            let (_pk, sk) = pqcrypto_dilithium::dilithium2::keypair();
            // Warmup
            let warmup_msg = b"warmup";
            for _ in 0..50 { let _ = pqcrypto_dilithium::dilithium2::sign(warmup_msg, &sk); }
            for _ in 0..num_sigs {
                let msg: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
                let start = Instant::now();
                let _ = pqcrypto_dilithium::dilithium2::sign(&msg, &sk);
                times.push(start.elapsed().as_nanos() as u64);
            }
        }
        DilithiumLevel::Dilithium3 => {
            let (_pk, sk) = pqcrypto_dilithium::dilithium3::keypair();
            let warmup_msg = b"warmup";
            for _ in 0..50 { let _ = pqcrypto_dilithium::dilithium3::sign(warmup_msg, &sk); }
            for _ in 0..num_sigs {
                let msg: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
                let start = Instant::now();
                let _ = pqcrypto_dilithium::dilithium3::sign(&msg, &sk);
                times.push(start.elapsed().as_nanos() as u64);
            }
        }
        DilithiumLevel::Dilithium5 => {
            let (_pk, sk) = pqcrypto_dilithium::dilithium5::keypair();
            let warmup_msg = b"warmup";
            for _ in 0..50 { let _ = pqcrypto_dilithium::dilithium5::sign(warmup_msg, &sk); }
            for _ in 0..num_sigs {
                let msg: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
                let start = Instant::now();
                let _ = pqcrypto_dilithium::dilithium5::sign(&msg, &sk);
                times.push(start.elapsed().as_nanos() as u64);
            }
        }
    }

    // Classify each signature into iteration bins
    let iter_cost = boundary_1iter * 0.3; // approximate cost of one additional iteration

    let mut iteration_counts = vec![0usize; 10]; // bins for N=1..10

    for &t in &times {
        let tf = t as f64;
        if tf < boundary_1iter {
            iteration_counts[0] += 1; // N=1
        } else {
            // Estimate N from how far above the boundary
            let extra = tf - boundary_1iter;
            let extra_iters = (extra / iter_cost).ceil() as usize;
            let n = (1 + extra_iters).min(9);
            iteration_counts[n] += 1;
        }
    }

    let total = times.len();
    let n1 = iteration_counts[0];
    let rejection_rate = 1.0 - (n1 as f64 / total as f64);

    let mean_iters: f64 = iteration_counts.iter().enumerate()
        .map(|(i, &c)| (i + 1) as f64 * c as f64 / total as f64)
        .sum();

    let mean_time = times.iter().sum::<u64>() as f64 / total as f64;
    let var = times.iter().map(|&t| (t as f64 - mean_time).powi(2)).sum::<f64>() / (total - 1) as f64;

    KeyRejectionProfile {
        key_index,
        total_signatures: total,
        iteration_counts,
        rejection_rate,
        mean_iterations: mean_iters,
        mean_sign_time_ns: mean_time,
        sign_stddev_ns: var.sqrt(),
    }
}

/// Chi-squared-like test: are two keys' iteration distributions different?
fn are_distinguishable(a: &KeyRejectionProfile, b: &KeyRejectionProfile, n: usize) -> bool {
    // Simple: compare rejection rates using a two-proportion z-test
    let p1 = a.rejection_rate;
    let p2 = b.rejection_rate;
    let n1 = a.total_signatures as f64;
    let n2 = b.total_signatures as f64;

    let p_pooled = (p1 * n1 + p2 * n2) / (n1 + n2);
    if p_pooled <= 0.0 || p_pooled >= 1.0 { return false; }

    let se = (p_pooled * (1.0 - p_pooled) * (1.0/n1 + 1.0/n2)).sqrt();
    if se <= 0.0 { return false; }

    let z = (p1 - p2).abs() / se;

    // z > 1.96 → p < 0.05 (95% confidence)
    z > 1.96
}

fn compute_f64_stats(data: &[f64]) -> F64Stats {
    let n = data.len() as f64;
    let mean = data.iter().sum::<f64>() / n;
    let var = data.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0).max(1.0);
    let stddev = var.sqrt();
    let min_f = data.iter().cloned().fold(f64::INFINITY, f64::min);
    let max_f = data.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    F64Stats { mean, stddev, min_f, max_f, cv: stddev / mean.max(1e-10) }
}

#[derive(Debug)]
pub struct F64Stats {
    pub mean: f64,
    pub stddev: f64,
    pub min_f: f64,
    pub max_f: f64,
    pub cv: f64,
}
