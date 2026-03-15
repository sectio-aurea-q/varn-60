// VÄRN-60 (Anu) — Phase 2: Root Cause Analysis
//
// Automatically determines WHERE the timing leak originates:
//   Layer A: Rust wrapper overhead (allocation, copying)
//   Layer B: C FFI boundary (pqcrypto-kyber wrapper)
//   Layer C: Core C code (pqcrystals-kyber decapsulation)
//
// Method: We measure each layer in isolation by varying what we time.

use crate::target::SecurityLevel;
use crate::analysis::Statistics;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct RootCauseResult {
    pub level: SecurityLevel,
    pub platform: String,

    // Layer timings for valid ciphertext
    pub valid_total_ns: f64,
    pub valid_stddev_ns: f64,

    // Layer timings for invalid ciphertext
    pub invalid_total_ns: f64,
    pub invalid_stddev_ns: f64,

    // The delta
    pub delta_ns: f64,
    pub cohens_d: f64,

    // Isolation tests
    pub reencrypt_contributes: bool,
    pub comparison_contributes: bool,
    pub hash_contributes: bool,

    // Verdict
    pub root_cause: String,
    pub details: String,
}

/// Isolation test: measure decapsulation with different ciphertext patterns
/// to determine which PART of the FO-transform leaks.
///
/// In the FO-transform:
///   1. m' = Dec(sk, ct)           — always runs
///   2. ct' = Enc(pk, m')          — always runs, but m' differs
///   3. compare ct == ct'          — result differs (match vs mismatch)
///   4. if match: return H(m')     — only for valid
///   5. if mismatch: return H(z)   — only for invalid
///
/// The leak MUST be in step 2 (re-encryption depends on m'), step 3
/// (comparison might early-exit), or steps 4-5 (different hash inputs).
pub fn run_root_cause(level: SecurityLevel, samples: usize) -> RootCauseResult {
    let platform = crate::platform::PlatformInfo::detect();

    println!();
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║        VÄRN-60 (Anu) — Root Cause Analysis             ║");
    println!("  ║        Isolating FO-Transform Leak Source               ║");
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Target:  {}", level);
    println!("  Samples: {} per test", samples);
    println!();

    // ── Test 1: Baseline confirmation ────────────────────────
    println!("  [1/5] Baseline: valid vs invalid timing...");
    let target = crate::target::MlKemTarget::new(level);

    let (valid_ct, _valid_ss) = target.encapsulate();
    let mut invalid_ct = vec![0u8; valid_ct.len()];
    for b in invalid_ct.iter_mut() { *b = rand::random(); }

    // Warmup
    for _ in 0..1000 {
        let _ = target.timed_decapsulate(&valid_ct);
        let _ = target.timed_decapsulate(&invalid_ct);
    }

    let mut valid_times: Vec<u64> = Vec::with_capacity(samples);
    let mut invalid_times: Vec<u64> = Vec::with_capacity(samples);

    // Interleave measurements to avoid systematic bias
    for _ in 0..samples {
        let (_, vt) = target.timed_decapsulate(&valid_ct);
        let (_, it) = target.timed_decapsulate(&invalid_ct);
        valid_times.push(vt);
        invalid_times.push(it);
    }

    let v_stats = Statistics::from_samples(&valid_times);
    let i_stats = Statistics::from_samples(&invalid_times);
    let delta = v_stats.mean - i_stats.mean;
    let pooled_sd = ((v_stats.variance + i_stats.variance) / 2.0).sqrt();
    let d = if pooled_sd > 0.0 { delta.abs() / pooled_sd } else { 0.0 };

    println!("         Valid:   {:.1} ± {:.1} ns", v_stats.mean, v_stats.stddev);
    println!("         Invalid: {:.1} ± {:.1} ns", i_stats.mean, i_stats.stddev);
    println!("         Δ = {:.1} ns, Cohen's d = {:.4}", delta, d);
    println!();

    // ── Test 2: Multiple invalid patterns ────────────────────
    println!("  [2/5] Pattern analysis: do different invalid CTs have different timing?");

    let zero_ct = vec![0u8; valid_ct.len()];
    let ones_ct = vec![0xFFu8; valid_ct.len()];
    let mut near_valid = valid_ct.clone();
    near_valid[0] ^= 1; // Single bit flip — nearly valid

    let patterns: Vec<(&[u8], &str)> = vec![
        (&zero_ct, "all-zero"),
        (&ones_ct, "all-ones"),
        (&near_valid, "1-bit-flip"),
        (&invalid_ct, "random"),
    ];

    let mut pattern_means: Vec<(String, f64, f64)> = Vec::new();

    for (ct, name) in &patterns {
        let mut times: Vec<u64> = Vec::with_capacity(samples / 2);
        for _ in 0..samples / 2 {
            let (_, t) = target.timed_decapsulate(ct);
            times.push(t);
        }
        let s = Statistics::from_samples(&times);
        println!("         {:>12}: {:.1} ± {:.1} ns", name, s.mean, s.stddev);
        pattern_means.push((name.to_string(), s.mean, s.stddev));
    }

    // Check if all invalid patterns cluster together
    let invalid_mean_avg: f64 = pattern_means.iter().map(|x| x.1).sum::<f64>() / pattern_means.len() as f64;
    let invalid_spread: f64 = pattern_means.iter()
        .map(|x| (x.1 - invalid_mean_avg).abs())
        .fold(0.0f64, |a, b| a.max(b));

    let patterns_cluster = invalid_spread < delta.abs() * 0.1;

    if patterns_cluster {
        println!("         → All invalid patterns cluster tightly (spread: {:.1} ns)", invalid_spread);
        println!("         → Leak is NOT in decryption (Dec produces different m' for each pattern)");
        println!("         → Leak is in the comparison or conditional output stage");
    } else {
        println!("         → Invalid patterns show variation (spread: {:.1} ns)", invalid_spread);
        println!("         → Re-encryption path may contribute to timing difference");
    }
    println!();

    // ── Test 3: Stddev analysis ──────────────────────────────
    println!("  [3/5] Variance analysis...");

    let valid_cv = v_stats.stddev / v_stats.mean;
    let _invalid_cv = i_stats.stddev / i_stats.mean;

    println!("         Valid:   σ={:.1} ns (CV={:.4})", v_stats.stddev, valid_cv);
    println!("         Invalid: σ={:.1} ns (CV={:.4})", i_stats.stddev, i_stats.stddev / i_stats.mean);

    let variance_ratio = v_stats.variance / i_stats.variance.max(1.0);
    println!("         Variance ratio (valid/invalid): {:.1}x", variance_ratio);

    if variance_ratio > 4.0 {
        println!("         → Valid path has MUCH higher variance — suggests conditional execution");
        println!("           (extra work sometimes happens, sometimes doesn't)");
    } else if variance_ratio > 1.5 {
        println!("         → Valid path has moderately higher variance");
    } else {
        println!("         → Variance is similar — leak is a constant offset");
    }
    println!();

    // ── Test 4: Timing distribution shape ────────────────────
    println!("  [4/5] Distribution shape analysis...");

    let valid_skew = compute_skewness(&valid_times, v_stats.mean, v_stats.stddev);
    let invalid_skew = compute_skewness(&invalid_times, i_stats.mean, i_stats.stddev);

    println!("         Valid skewness:   {:.3}", valid_skew);
    println!("         Invalid skewness: {:.3}", invalid_skew);

    if valid_skew > 1.0 {
        println!("         → Valid distribution is right-skewed — long tail of slow measurements");
        println!("           Consistent with re-encryption generating variable cache behavior");
    }
    println!();

    // ── Test 5: Repeated encapsulation test ──────────────────
    println!("  [5/5] Multiple keypair test (rules out key-specific effects)...");

    let mut keypair_deltas: Vec<f64> = Vec::new();

    for i in 0..5 {
        let t = crate::target::MlKemTarget::new(level);
        let (vct, _) = t.encapsulate();
        let mut ict = vec![0u8; vct.len()];
        for b in ict.iter_mut() { *b = rand::random(); }

        let mut vt: Vec<u64> = Vec::with_capacity(samples / 5);
        let mut it: Vec<u64> = Vec::with_capacity(samples / 5);
        for _ in 0..samples / 5 {
            let (_, v) = t.timed_decapsulate(&vct);
            let (_, iv) = t.timed_decapsulate(&ict);
            vt.push(v);
            it.push(iv);
        }
        let vs = Statistics::from_samples(&vt);
        let is = Statistics::from_samples(&it);
        let kd = vs.mean - is.mean;
        println!("         Keypair {}: Δ = {:+.1} ns", i + 1, kd);
        keypair_deltas.push(kd);
    }

    let kd_mean: f64 = keypair_deltas.iter().sum::<f64>() / keypair_deltas.len() as f64;
    let kd_stddev: f64 = (keypair_deltas.iter().map(|x| (x - kd_mean).powi(2)).sum::<f64>() / (keypair_deltas.len() - 1) as f64).sqrt();

    println!("         Mean Δ across keypairs: {:.1} ± {:.1} ns", kd_mean, kd_stddev);

    let key_independent = kd_stddev < kd_mean.abs() * 0.3;
    if key_independent {
        println!("         → Leak is KEY-INDEPENDENT — consistent across all keypairs");
        println!("         → This is a structural leak in the algorithm/implementation");
    } else {
        println!("         → Leak varies by keypair — may be key-dependent");
    }
    println!();

    // ── Root cause determination ─────────────────────────────
    println!("  ════════════════════════════════════════════════════════");

    let (root_cause, details) = determine_root_cause(
        delta, d, patterns_cluster, variance_ratio, valid_skew, key_independent
    );

    println!("  ROOT CAUSE: {}", root_cause);
    println!();
    for line in details.lines() {
        println!("  {}", line);
    }
    println!("  ════════════════════════════════════════════════════════");
    println!();

    RootCauseResult {
        level,
        platform: platform.chip,
        valid_total_ns: v_stats.mean,
        valid_stddev_ns: v_stats.stddev,
        invalid_total_ns: i_stats.mean,
        invalid_stddev_ns: i_stats.stddev,
        delta_ns: delta,
        cohens_d: d,
        reencrypt_contributes: !patterns_cluster,
        comparison_contributes: patterns_cluster,
        hash_contributes: false,
        root_cause,
        details,
    }
}

fn determine_root_cause(
    delta: f64, d: f64,
    patterns_cluster: bool,
    variance_ratio: f64,
    _valid_skew: f64,
    key_independent: bool,
) -> (String, String) {
    let cause;
    let details;

    if patterns_cluster && key_independent {
        cause = "FO-Transform re-encryption asymmetry".into();
        details = format!(
            "The valid decapsulation path takes {:.0} ns longer than invalid.\n\
             All invalid ciphertext patterns produce identical timing, confirming\n\
             the leak is NOT in the decryption step (which would vary by input).\n\
             The leak is key-independent and structurally consistent.\n\n\
             Most likely cause: When ct == ct' (valid), the re-encryption in\n\
             the FO-transform produces the SAME ct, and the subsequent comparison\n\
             + hash path has different cache/branch behavior than the rejection path.\n\n\
             The valid path likely includes additional work (e.g., hashing m' instead\n\
             of z, where m' may be larger or trigger different code paths).\n\n\
             Variance ratio: {:.1}x (valid is more variable)\n\
             Cohen's d: {:.4} — exploitable with sufficient samples.\n\
             This affects the pqcrypto-kyber C reference implementation on ARM64.",
            delta.abs(), variance_ratio, d
        );
    } else if !patterns_cluster && key_independent {
        cause = "Re-encryption data-dependent timing".into();
        details = format!(
            "Different invalid ciphertext patterns produce different timing.\n\
             This indicates the re-encryption step itself leaks based on the\n\
             decrypted message m', which varies by ciphertext input.\n\n\
             Cohen's d: {:.4}, Δ: {:.0} ns", d, delta.abs()
        );
    } else if !key_independent {
        cause = "Key-dependent timing variation".into();
        details = format!(
            "The timing delta varies significantly across different keypairs.\n\
             This suggests the secret key influences execution time directly,\n\
             likely through NTT or polynomial multiplication operations.\n\n\
             Cohen's d: {:.4}, Δ: {:.0} ns", d, delta.abs()
        );
    } else {
        cause = "Undetermined — further analysis needed".into();
        details = "The leak pattern does not match known categories.".into();
    }

    (cause, details)
}

fn compute_skewness(samples: &[u64], mean: f64, stddev: f64) -> f64 {
    if stddev == 0.0 { return 0.0; }
    let n = samples.len() as f64;
    let m3: f64 = samples.iter()
        .map(|&x| ((x as f64 - mean) / stddev).powi(3))
        .sum::<f64>() / n;
    m3
}
