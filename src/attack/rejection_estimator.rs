// VÄRN-60 (Anu) — Rejection Count Estimator v2
//
// CLEAN REWRITE. No hacks.
//
// Core method:
//   1. Generate 200 fresh (key, message) pairs
//   2. For each pair, measure signing time 50x → stable mean
//   3. Each pair has a FIXED iteration count N (determined by key+msg+randomness)
//   4. Sort the 200 means, find natural clusters
//   5. Clusters correspond to N=1, N=2, N=3, ...
//   6. The spacing between clusters = cost of one iteration

use crate::attack::dilithium::DilithiumLevel;
use serde::Serialize;
use std::time::Instant;

#[derive(Debug, Clone, Serialize)]
pub struct CalibrationProfile {
    pub level: String,
    pub iteration_cost_ns: f64,
    pub base_cost_ns: f64,
    pub cluster_centers: Vec<f64>,
    pub cluster_counts: Vec<usize>,
    pub cluster_boundaries: Vec<f64>,
    pub max_iterations_seen: usize,
    pub r_squared: f64,
    pub total_pairs: usize,
}

#[derive(Debug, Serialize)]
pub struct EstimatorResult {
    pub calibration: CalibrationProfile,
    pub entropy_bits: f64,
    pub mean_iterations: f64,
    pub rejection_probability: f64,
    pub validation_accuracy: f64,
    pub validation_samples: usize,
    pub verdict: String,
}

pub fn run_rejection_estimator(level: DilithiumLevel, total_samples: usize) -> EstimatorResult {
    println!();
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║     VÄRN-60 (Anu) — Rejection Count Estimator v2       ║");
    println!("  ║     Clean calibration from timing clusters             ║");
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!();

    let num_pairs = 500;
    let samples_per_pair = (total_samples / num_pairs).max(30);

    println!("  Level: {}  Pairs: {}  Samples/pair: {}", level, num_pairs, samples_per_pair);
    println!();

    // ── Collect pair means ──
    println!("  [1/4] Measuring {} (key,msg) pairs...", num_pairs);

    let mut pair_means: Vec<f64> = Vec::with_capacity(num_pairs);

    for p in 0..num_pairs {
        let mean = measure_pair_mean(level, samples_per_pair);
        pair_means.push(mean);

        if p < 5 || (p + 1) == num_pairs {
            println!("    Pair {:>3}: {:.0} ns", p + 1, mean);
        } else if p == 5 {
            println!("    ...");
        }
    }
    println!();

    // ── Find clusters ──
    println!("  [2/4] Finding iteration clusters...");

    let calibration = find_clusters(&mut pair_means, level);

    println!("    Iteration cost:  {:.0} ns", calibration.iteration_cost_ns);
    println!("    Base cost:       {:.0} ns", calibration.base_cost_ns);
    println!("    Clusters:        {}", calibration.cluster_centers.len());
    println!("    R²:              {:.4}", calibration.r_squared);
    println!();

    let total_in_clusters: usize = calibration.cluster_counts.iter().sum();
    for (i, (center, count)) in calibration.cluster_centers.iter()
        .zip(calibration.cluster_counts.iter()).enumerate()
    {
        let pct = *count as f64 / total_in_clusters.max(1) as f64 * 100.0;
        let bar_len = (pct * 0.5) as usize;
        let bar: String = "█".repeat(bar_len.max(1));
        println!("      N={}: {:>8.0} ns  ({:>3} pairs, {:>5.1}%)  {}",
            i + 1, center, count, pct, bar);
    }
    println!();

    // ── Statistics ──
    println!("  [3/4] Information metrics...");

    let probs: Vec<f64> = calibration.cluster_counts.iter()
        .map(|&c| c as f64 / total_in_clusters.max(1) as f64)
        .collect();

    let entropy: f64 = probs.iter()
        .filter(|&&p| p > 0.0)
        .map(|p| -p * p.log2())
        .sum();

    let mean_iters: f64 = probs.iter().enumerate()
        .map(|(i, p)| (i + 1) as f64 * p)
        .sum();

    let p_reject = 1.0 - probs.first().copied().unwrap_or(1.0);

    println!("    P(reject):       {:.1}%", p_reject * 100.0);
    println!("    Mean iterations: {:.2}", mean_iters);
    println!("    Entropy:         {:.3} bits/signature", entropy);
    println!();

    // ── Validate ──
    println!("  [4/4] Validation...");

    let val_pairs = 100;
    let mut correct = 0;
    for _ in 0..val_pairs {
        let mean = measure_pair_mean(level, samples_per_pair);
        let predicted = classify_iteration(&calibration, mean);
        let idx = predicted.max(1) - 1;
        if idx < calibration.cluster_centers.len() {
            let center = calibration.cluster_centers[idx];
            if (mean - center).abs() < calibration.iteration_cost_ns * 0.4 {
                correct += 1;
            }
        }
    }
    let accuracy = correct as f64 / val_pairs as f64;
    println!("    Validation:  {}/{} = {:.1}%", correct, val_pairs, accuracy * 100.0);
    println!();

    let verdict = if entropy > 1.0 && accuracy > 0.7 {
        format!("CRITICAL — {:.2} bits/sig, {:.0}% accuracy", entropy, accuracy * 100.0)
    } else if entropy > 0.3 {
        format!("HIGH — {:.2} bits/sig, rejection sampling detectable", entropy)
    } else {
        format!("LOW — {:.3} bits/sig", entropy)
    };

    println!("  ════════════════════════════════════════════════════════");
    println!("  {}", verdict);
    println!("  ════════════════════════════════════════════════════════");
    println!();

    EstimatorResult {
        calibration, entropy_bits: entropy, mean_iterations: mean_iters,
        rejection_probability: p_reject, validation_accuracy: accuracy,
        validation_samples: val_pairs, verdict,
    }
}

pub fn classify_iteration(cal: &CalibrationProfile, time_ns: f64) -> usize {
    for (i, &boundary) in cal.cluster_boundaries.iter().enumerate() {
        if time_ns < boundary { return i + 1; }
    }
    cal.cluster_centers.len()
}

fn measure_pair_mean(level: DilithiumLevel, samples: usize) -> f64 {
    let msg: Vec<u8> = (0..64).map(|_| rand::random::<u8>()).collect();
    let mut times = Vec::with_capacity(samples);

    match level {
        DilithiumLevel::Dilithium2 => {
            let (_pk, sk) = pqcrypto_dilithium::dilithium2::keypair();
            for _ in 0..10 { let _ = pqcrypto_dilithium::dilithium2::sign(&msg, &sk); }
            for _ in 0..samples {
                let start = Instant::now();
                let _ = pqcrypto_dilithium::dilithium2::sign(&msg, &sk);
                times.push(start.elapsed().as_nanos() as u64);
            }
        }
        DilithiumLevel::Dilithium3 => {
            let (_pk, sk) = pqcrypto_dilithium::dilithium3::keypair();
            for _ in 0..10 { let _ = pqcrypto_dilithium::dilithium3::sign(&msg, &sk); }
            for _ in 0..samples {
                let start = Instant::now();
                let _ = pqcrypto_dilithium::dilithium3::sign(&msg, &sk);
                times.push(start.elapsed().as_nanos() as u64);
            }
        }
        DilithiumLevel::Dilithium5 => {
            let (_pk, sk) = pqcrypto_dilithium::dilithium5::keypair();
            for _ in 0..10 { let _ = pqcrypto_dilithium::dilithium5::sign(&msg, &sk); }
            for _ in 0..samples {
                let start = Instant::now();
                let _ = pqcrypto_dilithium::dilithium5::sign(&msg, &sk);
                times.push(start.elapsed().as_nanos() as u64);
            }
        }
    }

    times.iter().sum::<u64>() as f64 / times.len() as f64
}

fn find_clusters(means: &mut Vec<f64>, level: DilithiumLevel) -> CalibrationProfile {
    means.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = means.len();

    if n < 10 {
        return CalibrationProfile {
            level: level.to_string(), iteration_cost_ns: 0.0, base_cost_ns: 0.0,
            cluster_centers: vec![], cluster_counts: vec![],
            cluster_boundaries: vec![], max_iterations_seen: 0,
            r_squared: 0.0, total_pairs: n,
        };
    }

    // Find gaps between consecutive sorted values
    let mut gaps: Vec<(usize, f64)> = Vec::new();
    for i in 1..n {
        gaps.push((i, means[i] - means[i - 1]));
    }

    // Compute median gap
    let mut gap_vals: Vec<f64> = gaps.iter().map(|g| g.1).collect();
    gap_vals.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median_gap = gap_vals[gap_vals.len() / 2];
    let threshold = (median_gap * 5.0).max(500.0);

    // Find significant gaps (cluster boundaries)
    let mut split_points: Vec<usize> = vec![0];
    for (i, gap) in &gaps {
        if *gap > threshold {
            split_points.push(*i);
        }
    }
    split_points.push(n);

    // Build clusters
    let mut centers: Vec<f64> = Vec::new();
    let mut counts: Vec<usize> = Vec::new();

    for w in split_points.windows(2) {
        let slice = &means[w[0]..w[1]];
        if !slice.is_empty() {
            let mean = slice.iter().sum::<f64>() / slice.len() as f64;
            centers.push(mean);
            counts.push(slice.len());
        }
    }

    // Iteration cost = average gap between cluster centers
    let iter_cost = if centers.len() >= 2 {
        let diffs: Vec<f64> = centers.windows(2).map(|w| w[1] - w[0]).collect();
        diffs.iter().sum::<f64>() / diffs.len() as f64
    } else {
        // Estimate from the spread within the single cluster
        (means.last().unwrap() - means.first().unwrap()).max(1000.0)
    };

    let base_cost = (centers.first().copied().unwrap_or(0.0) - iter_cost).max(0.0);

    // Boundaries = midpoints
    let mut boundaries: Vec<f64> = Vec::new();
    for w in centers.windows(2) {
        boundaries.push((w[0] + w[1]) / 2.0);
    }

    // R²
    let r_squared = if centers.len() >= 2 {
        let points: Vec<(f64, f64)> = centers.iter().enumerate()
            .map(|(i, &c)| ((i + 1) as f64, c))
            .collect();
        compute_r_squared(&points)
    } else { 0.0 };

    CalibrationProfile {
        level: level.to_string(), iteration_cost_ns: iter_cost,
        base_cost_ns: base_cost, cluster_centers: centers,
        cluster_counts: counts, cluster_boundaries: boundaries,
        max_iterations_seen: split_points.len() - 1,
        r_squared, total_pairs: n,
    }
}

fn compute_r_squared(points: &[(f64, f64)]) -> f64 {
    let n = points.len() as f64;
    if n < 2.0 { return 0.0; }
    let sx: f64 = points.iter().map(|(x, _)| x).sum();
    let sy: f64 = points.iter().map(|(_, y)| y).sum();
    let sxy: f64 = points.iter().map(|(x, y)| x * y).sum();
    let sx2: f64 = points.iter().map(|(x, _)| x * x).sum();
    let my = sy / n;
    let d = n * sx2 - sx * sx;
    if d.abs() < 1e-10 { return 0.0; }
    let slope = (n * sxy - sx * sy) / d;
    let intercept = (sy - slope * sx) / n;
    let ss_res: f64 = points.iter().map(|(x, y)| (y - (slope * x + intercept)).powi(2)).sum();
    let ss_tot: f64 = points.iter().map(|(_, y)| (y - my).powi(2)).sum();
    if ss_tot > 0.0 { 1.0 - ss_res / ss_tot } else { 0.0 }
}
