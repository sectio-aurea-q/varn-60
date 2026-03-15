// VÄRN-60 (Anu) — Module: Microarchitectural Fingerprinting
//
// Instead of raw timing, analyze the SHAPE of timing distributions.
// Different execution paths produce different distribution signatures:
//   - Bimodal = two code paths (branch)
//   - Heavy right tail = variable iteration count (rejection sampling)
//   - High kurtosis = occasional cache misses
//   - Multimodal = multiple distinct execution patterns
//
// This is more powerful than simple mean comparison because it detects
// leaks that average out to zero but are still exploitable.

use crate::target::{MlKemTarget, SecurityLevel};
use crate::analysis::Statistics;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct FingerprintResult {
    pub level: String,
    pub tests: Vec<DistributionTest>,
    pub verdict: String,
}

#[derive(Debug, Serialize)]
pub struct DistributionTest {
    pub name: String,
    pub sample_count: usize,
    pub mean: f64,
    pub stddev: f64,
    pub skewness: f64,
    pub kurtosis: f64,
    pub bimodality_coeff: f64,
    pub histogram: Vec<u64>,
    pub histogram_bin_ns: f64,
    pub is_bimodal: bool,
    pub notes: Vec<String>,
}

pub fn run_fingerprinting(level: SecurityLevel, samples: usize) -> FingerprintResult {
    println!();
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║     VÄRN-60 (Anu) — Microarchitectural Fingerprinting  ║");
    println!("  ║     Distribution shape analysis for timing leaks        ║");
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Level: {}  Samples: {}", level, samples);
    println!();

    let target = MlKemTarget::new(level);

    // Warmup
    let (warmup_ct, _) = target.encapsulate();
    for _ in 0..2000 {
        let _ = target.timed_decapsulate(&warmup_ct);
    }

    let mut tests = Vec::new();

    // Test 1: Valid ciphertext distribution
    println!("  [1/4] Valid ciphertext distribution...");
    {
        let (valid_ct, _) = target.encapsulate();
        let mut times: Vec<u64> = Vec::with_capacity(samples);
        for _ in 0..samples {
            let (_, t) = target.timed_decapsulate(&valid_ct);
            times.push(t);
        }
        tests.push(analyze_distribution("valid ciphertext", &times));
    }

    // Test 2: Invalid ciphertext distribution
    println!("  [2/4] Invalid (random) ciphertext distribution...");
    {
        let mut invalid_ct = vec![0u8; target.ciphertext_size()];
        for b in invalid_ct.iter_mut() { *b = rand::random(); }
        let mut times: Vec<u64> = Vec::with_capacity(samples);
        for _ in 0..samples {
            let (_, t) = target.timed_decapsulate(&invalid_ct);
            times.push(t);
        }
        tests.push(analyze_distribution("invalid ciphertext", &times));
    }

    // Test 3: Multiple different valid ciphertexts (tests message-dependent paths)
    println!("  [3/4] Varying valid ciphertexts (tests message-dependent paths)...");
    {
        let mut times: Vec<u64> = Vec::with_capacity(samples);
        for _ in 0..samples {
            let (ct, _) = target.encapsulate();
            let (_, t) = target.timed_decapsulate(&ct);
            times.push(t);
        }
        tests.push(analyze_distribution("varying valid CTs", &times));
    }

    // Test 4: Interleaved valid/invalid (natural pattern)
    println!("  [4/4] Interleaved valid/invalid...");
    {
        let (valid_ct, _) = target.encapsulate();
        let mut invalid_ct = vec![0u8; target.ciphertext_size()];
        for b in invalid_ct.iter_mut() { *b = rand::random(); }

        let mut all_times: Vec<u64> = Vec::with_capacity(samples);
        for i in 0..samples {
            let ct = if i % 2 == 0 { &valid_ct } else { &invalid_ct };
            let (_, t) = target.timed_decapsulate(ct);
            all_times.push(t);
        }
        tests.push(analyze_distribution("interleaved valid/invalid", &all_times));
    }

    // Print results
    println!();
    for test in &tests {
        println!("  {:>30}:", test.name);
        println!("    Mean: {:.0} ns  σ: {:.0} ns", test.mean, test.stddev);
        println!("    Skewness: {:.3}  Kurtosis: {:.3}", test.skewness, test.kurtosis);
        println!("    Bimodality: {:.3} (>0.555 = bimodal)", test.bimodality_coeff);
        if test.is_bimodal {
            println!("    ██ BIMODAL DISTRIBUTION DETECTED");
        }

        // Print histogram
        let max_count = test.histogram.iter().cloned().max().unwrap_or(1);
        let bar_width = 40;
        println!("    Histogram ({:.0}ns bins):", test.histogram_bin_ns);
        for (i, &count) in test.histogram.iter().enumerate() {
            if count > 0 {
                let bar_len = (count as f64 / max_count as f64 * bar_width as f64) as usize;
                let bar: String = "█".repeat(bar_len);
                let start_ns = test.mean - test.stddev * 3.0 + i as f64 * test.histogram_bin_ns;
                println!("      {:>8.0}ns |{:<40} {}", start_ns, bar, count);
            }
        }

        for note in &test.notes {
            println!("    → {}", note);
        }
        println!();
    }

    // Overall verdict
    let any_bimodal = tests.iter().any(|t| t.is_bimodal);
    let high_kurtosis = tests.iter().any(|t| t.kurtosis > 5.0);
    let high_skew = tests.iter().any(|t| t.skewness.abs() > 2.0);

    let verdict = if any_bimodal {
        "BIMODAL distribution detected — indicates two distinct execution paths (potential branch on secret)"
    } else if high_kurtosis && high_skew {
        "Heavy-tailed distribution — variable execution (potential rejection sampling or cache effects)"
    } else if high_skew {
        "Skewed distribution — occasional slow outliers (likely system noise, not crypto leak)"
    } else {
        "Distributions appear unimodal and symmetric — consistent with constant-time execution"
    };

    println!("  ════════════════════════════════════════════════════════");
    println!("  VERDICT: {}", verdict);
    println!("  ════════════════════════════════════════════════════════");
    println!();

    FingerprintResult {
        level: level.to_string(),
        tests,
        verdict: verdict.into(),
    }
}

fn analyze_distribution(name: &str, times: &[u64]) -> DistributionTest {
    let stats = Statistics::from_samples(times);
    let n = times.len() as f64;

    // Skewness
    let skewness: f64 = times.iter()
        .map(|&x| ((x as f64 - stats.mean) / stats.stddev.max(1.0)).powi(3))
        .sum::<f64>() / n;

    // Kurtosis (excess)
    let kurtosis: f64 = times.iter()
        .map(|&x| ((x as f64 - stats.mean) / stats.stddev.max(1.0)).powi(4))
        .sum::<f64>() / n - 3.0;

    // Bimodality coefficient: BC = (skew^2 + 1) / (kurtosis + 3*(n-1)^2/((n-2)*(n-3)))
    // BC > 0.555 suggests bimodality
    let bc = (skewness.powi(2) + 1.0) / (kurtosis + 3.0 * (n - 1.0).powi(2) / ((n - 2.0) * (n - 3.0)));

    // Build histogram (20 bins covering mean ± 3σ)
    let num_bins = 20;
    let hist_min = stats.mean - stats.stddev * 3.0;
    let hist_max = stats.mean + stats.stddev * 3.0;
    let bin_width = (hist_max - hist_min) / num_bins as f64;
    let mut histogram = vec![0u64; num_bins];

    for &t in times {
        let val = t as f64;
        if val >= hist_min && val < hist_max {
            let bin = ((val - hist_min) / bin_width) as usize;
            if bin < num_bins {
                histogram[bin] += 1;
            }
        }
    }

    // Detect bimodality from histogram: look for valley between two peaks
    let is_bimodal = detect_bimodal(&histogram);

    let mut notes = Vec::new();
    if skewness > 2.0 {
        notes.push("Right-skewed: occasional slow outliers".into());
    }
    if kurtosis > 5.0 {
        notes.push("Heavy tails: high variance in execution time".into());
    }
    if is_bimodal {
        notes.push("TWO PEAKS DETECTED: distinct fast and slow execution paths".into());
    }
    if stats.stddev / stats.mean < 0.01 {
        notes.push("Very tight distribution (CV < 1%): consistent with constant-time".into());
    }

    DistributionTest {
        name: name.into(),
        sample_count: times.len(),
        mean: stats.mean,
        stddev: stats.stddev,
        skewness,
        kurtosis,
        bimodality_coeff: bc,
        histogram,
        histogram_bin_ns: bin_width,
        is_bimodal,
        notes,
    }
}

fn detect_bimodal(histogram: &[u64]) -> bool {
    if histogram.len() < 5 { return false; }

    // Find two highest peaks
    let mut peaks: Vec<(usize, u64)> = Vec::new();

    for i in 1..histogram.len() - 1 {
        if histogram[i] > histogram[i-1] && histogram[i] > histogram[i+1] && histogram[i] > 0 {
            peaks.push((i, histogram[i]));
        }
    }

    if peaks.len() < 2 { return false; }

    peaks.sort_by(|a, b| b.1.cmp(&a.1));
    let peak1 = peaks[0];
    let peak2 = peaks[1];

    // Check that peaks are separated and have a valley between them
    let (left, right) = if peak1.0 < peak2.0 { (peak1.0, peak2.0) } else { (peak2.0, peak1.0) };

    if right - left < 3 { return false; } // Peaks must be at least 3 bins apart

    // Find minimum between peaks
    let valley = histogram[left..=right].iter().cloned().min().unwrap_or(0);
    let lower_peak = peak1.1.min(peak2.1);

    // Valley must be less than 60% of the lower peak
    valley < (lower_peak * 6 / 10)
}
