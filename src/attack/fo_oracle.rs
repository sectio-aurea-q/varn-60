use crate::target::{MlKemTarget, SecurityLevel};
use crate::analysis::{Statistics, normal_cdf};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct AttackConfig {
    pub samples_per_variant: usize,
    pub warmup_rounds: usize,
    pub level: SecurityLevel,
}

impl Default for AttackConfig {
    fn default() -> Self {
        AttackConfig {
            samples_per_variant: 10_000,
            warmup_rounds: 1_000,
            level: SecurityLevel::MlKem768,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AttackResult {
    pub config: AttackConfig,
    pub platform: crate::platform::PlatformInfo,
    pub variants: Vec<VariantResult>,
    pub fo_timing_delta_ns: f64,
    pub fo_cohens_d: f64,
    pub fo_t_statistic: f64,
    pub fo_p_value: f64,
    pub vulnerable: bool,
    pub timestamp: String,
}

#[derive(Debug, Serialize)]
pub struct VariantResult {
    pub name: String,
    pub sample_count: usize,
    pub mean_ns: f64,
    pub median_ns: f64,
    pub stddev_ns: f64,
    pub min_ns: u64,
    pub max_ns: u64,
}

pub fn run_fo_oracle(config: &AttackConfig) -> AttackResult {
    let platform = crate::platform::PlatformInfo::detect();

    println!();
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║           VÄRN-60 (Anu) — FO-Transform Oracle          ║");
    println!("  ║       Side-Channel Analysis: ML-KEM Decapsulation      ║");
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Target:    {}", config.level);
    println!("  Platform:  {}", platform.chip);
    println!("  Samples:   {} per variant", config.samples_per_variant);
    println!("  Timer res: {:.1} ns", platform.timer_resolution_ns);
    println!();

    println!("  [1/4] Generating {} keypair...", config.level);
    let target = MlKemTarget::new(config.level);

    println!("  [2/4] Crafting ciphertexts...");
    let variants = target.generate_attack_ciphertexts(8);
    println!("         {} variants prepared", variants.len());

    println!("  [3/4] Warmup ({} rounds)...", config.warmup_rounds);
    let (warmup_ct, _) = target.encapsulate();
    for _ in 0..config.warmup_rounds {
        let _ = target.timed_decapsulate(&warmup_ct);
    }

    println!("  [4/4] Measuring...");
    println!();

    let mut all_results: Vec<VariantResult> = Vec::new();
    let mut all_measurements: Vec<Vec<u64>> = Vec::new();

    for (ct_bytes, variant_name) in &variants {
        let mut measurements: Vec<u64> = Vec::with_capacity(config.samples_per_variant);

        for _ in 0..config.samples_per_variant {
            let (_, ns) = target.timed_decapsulate(ct_bytes);
            measurements.push(ns);
        }

        let stats = Statistics::from_samples(&measurements);

        let delta_str = if !all_results.is_empty() {
            let baseline = all_results[0].mean_ns;
            let d = stats.mean - baseline;
            if d.abs() > stats.stddev * 0.1 {
                format!("  Δ = {:+.1} ns", d)
            } else {
                "  Δ ≈ 0".into()
            }
        } else {
            "  (baseline)".into()
        };

        println!(
            "    {:>12} | mean: {:>10.1} ns | σ: {:>8.1} | med: {:>10.1} {}",
            variant_name, stats.mean, stats.stddev, stats.median, delta_str
        );

        all_results.push(VariantResult {
            name: variant_name.clone(),
            sample_count: measurements.len(),
            mean_ns: stats.mean,
            median_ns: stats.median,
            stddev_ns: stats.stddev,
            min_ns: stats.min,
            max_ns: stats.max,
        });

        all_measurements.push(measurements);
    }

    // Critical analysis: compare valid vs invalid
    println!();
    println!("  ────────────────────────────────────────────────────────");
    println!("  FO-Transform Oracle Analysis:");
    println!();

    let valid_mean = all_results[0].mean_ns;
    let valid_stddev = all_results[0].stddev_ns;
    let mut max_d: f64 = 0.0;
    let mut max_t: f64 = 0.0;
    let mut best_delta: f64 = 0.0;
    let mut min_p: f64 = 1.0;

    for (i, result) in all_results[1..].iter().enumerate() {
        let delta = result.mean_ns - valid_mean;
        let pooled_sd = ((valid_stddev.powi(2) + result.stddev_ns.powi(2)) / 2.0).sqrt();
        let d = if pooled_sd > 0.0 { delta.abs() / pooled_sd } else { 0.0 };

        let n = config.samples_per_variant as f64;
        let se = ((valid_stddev.powi(2) / n) + (result.stddev_ns.powi(2) / n)).sqrt();
        let t = if se > 0.0 { delta / se } else { 0.0 };
        let p = 2.0 * (1.0 - normal_cdf(t.abs()));

        let tag = if d > 0.5 {
            "██ SIGNIFICANT"
        } else if d > 0.2 {
            "▓▓ SMALL LEAK"
        } else if p < 0.001 {
            "░░ DETECTABLE"
        } else {
            "   noise"
        };

        println!("    {} vs valid: Δ={:+.1}ns d={:.4} t={:.2} p={:.2e}  {}", result.name, delta, d, t, p, tag);

        if d > max_d { max_d = d; best_delta = delta; }
        if t.abs() > max_t.abs() { max_t = t; }
        if p < min_p { min_p = p; }
    }

    let vulnerable = max_d > 0.2 || (min_p < 0.001 && max_d > 0.05);

    println!();
    println!("  ════════════════════════════════════════════════════════");
    if vulnerable {
        println!("  ██ VERDICT: TIMING LEAK DETECTED");
        println!("  ██ Max Cohen's d: {:.4}", max_d);
        println!("  ██ Max Δ: {:.1} ns", best_delta);
        println!("  ██ Min p-value: {:.2e}", min_p);
    } else {
        println!("  ○ VERDICT: No significant timing leak detected");
        println!("  ○ Max Cohen's d: {:.4} (threshold: 0.20)", max_d);
        println!("  ○ Min p-value: {:.2e}", min_p);
    }
    println!("  ════════════════════════════════════════════════════════");
    println!();

    AttackResult {
        config: config.clone(),
        platform,
        variants: all_results,
        fo_timing_delta_ns: best_delta,
        fo_cohens_d: max_d,
        fo_t_statistic: max_t,
        fo_p_value: min_p,
        vulnerable,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }
}
