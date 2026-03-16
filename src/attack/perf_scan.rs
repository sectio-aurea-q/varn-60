// VÄRN-60 (Anu) — Performance Counter Crypto Scanner
//
// Uses hardware PMCs to detect side-channels at the hardware level.
// Works in two modes:
// - FULL MODE (SIP disabled): Cache misses, branch mispredictions, instructions
// - FIXED MODE (SIP enabled): CPU cycles + instructions per operation
//
// Even in Fixed Mode, cycle count differences between valid/invalid
// decapsulations reveal microarchitectural behavior that pure timing
// measurement (which includes OS overhead) cannot isolate.

use serde::Serialize;
use crate::platform::perf_counters::PerformanceCounters;

#[derive(Debug, Serialize)]
pub struct PmcCounterResult {
    pub name: String,
    pub valid_mean: f64,
    pub invalid_mean: f64,
    pub delta: f64,
    pub cohens_d: f64,
    pub verdict: String,
}

#[derive(Debug, Serialize)]
pub struct PmcScanResult {
    pub target: String,
    pub platform: String,
    pub mode: String,
    pub samples: usize,
    pub counters: Vec<PmcCounterResult>,
    pub verdict: String,
}

pub fn run_pmc_kem_scan(samples: usize) -> Option<PmcScanResult> {
    let info = crate::platform::PlatformInfo::detect();

    println!();
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║     VÄRN-60 (Anu) — Performance Counter Scanner        ║");
    println!("  ║     Hardware-Level Side-Channel Detection               ║");
    println!("  ║     Apple M4 Pro · PMC · Microarchitectural Analysis    ║");
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Platform:  {}", info.chip);
    println!("  Samples:   {} per variant", samples);
    println!();

    // Initialize PMC
    println!("  [1/5] Initializing Performance Counters...");
    let mut pmc = match PerformanceCounters::new() {
        Some(p) => p,
        None => {
            println!("  ERROR: Cannot access performance counters.");
            return None;
        }
    };

    if !pmc.configure_crypto_events() {
        println!("  ERROR: No readable counters available.");
        return None;
    }

    let mode = if pmc.full_mode { "FULL" } else { "FIXED" };

    // Setup liboqs ML-KEM-768
    println!();
    println!("  [2/5] Setting up ML-KEM-768 via liboqs...");
    use std::ffi::CString;
    use crate::target::liboqs::*;

    let kem_name = CString::new("ML-KEM-768").unwrap();
    let kem = unsafe { OQS_KEM_new(kem_name.as_ptr()) };
    if kem.is_null() {
        println!("  ERROR: ML-KEM-768 not available in liboqs");
        return None;
    }

    let mut pk = vec![0u8; 1184];
    let mut sk = vec![0u8; 2400];
    let mut valid_ct = vec![0u8; 1088];
    let mut ss = vec![0u8; 32];
    let mut ss2 = vec![0u8; 32];

    unsafe { OQS_KEM_keypair(kem, pk.as_mut_ptr(), sk.as_mut_ptr()) };
    unsafe { OQS_KEM_encaps(kem, valid_ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr()) };

    // Invalid ciphertext
    let mut pk2 = vec![0u8; 1184];
    let mut sk2 = vec![0u8; 2400];
    unsafe { OQS_KEM_keypair(kem, pk2.as_mut_ptr(), sk2.as_mut_ptr()) };
    let mut invalid_ct = vec![0u8; 1088];
    let mut ss_dummy = vec![0u8; 32];
    unsafe { OQS_KEM_encaps(kem, invalid_ct.as_mut_ptr(), ss_dummy.as_mut_ptr(), pk2.as_ptr()) };

    // Warmup
    println!("  [3/5] Warmup (1000 rounds)...");
    for _ in 0..1000 {
        unsafe { OQS_KEM_decaps(kem, ss2.as_mut_ptr(), valid_ct.as_ptr(), sk.as_ptr()) };
    }

    // Measure — collect raw counter snapshots
    println!("  [4/5] Measuring with Performance Counters (interleaved)...");

    let num_counters = pmc.snapshot().counters.len();
    let mut valid_counters: Vec<Vec<i64>> = vec![Vec::with_capacity(samples); num_counters];
    let mut invalid_counters: Vec<Vec<i64>> = vec![Vec::with_capacity(samples); num_counters];

    for _ in 0..samples {
        // Valid decapsulation
        let before = pmc.snapshot();
        unsafe { OQS_KEM_decaps(kem, ss2.as_mut_ptr(), valid_ct.as_ptr(), sk.as_ptr()) };
        let after = pmc.snapshot();
        for i in 0..num_counters {
            let delta = after.counters[i] as i64 - before.counters[i] as i64;
            valid_counters[i].push(delta);
        }

        // Invalid decapsulation
        let before = pmc.snapshot();
        unsafe { OQS_KEM_decaps(kem, ss2.as_mut_ptr(), invalid_ct.as_ptr(), sk.as_ptr()) };
        let after = pmc.snapshot();
        for i in 0..num_counters {
            let delta = after.counters[i] as i64 - before.counters[i] as i64;
            invalid_counters[i].push(delta);
        }
    }

    unsafe { OQS_KEM_free(kem as *mut _) };

    // Analysis
    println!("  [5/5] Analysis...");
    println!();

    let counter_names: Vec<String> = if pmc.full_mode {
        vec![
            "Fixed 0 (Cycles)".into(), "Fixed 1 (Instructions)".into(),
            "L1 Cache Miss".into(), "Branch Mispredict".into(),
            "Instructions".into(), "L1 Cache Access".into(),
            "Branch Retired".into(),
        ]
    } else {
        (0..num_counters).map(|i| format!("Counter {}", i)).collect()
    };

    let mut results: Vec<PmcCounterResult> = Vec::new();
    let mut max_d: f64 = 0.0;

    for i in 0..num_counters {
        let v = &valid_counters[i];
        let inv = &invalid_counters[i];

        // Skip counters that are all zeros
        let v_sum: i64 = v.iter().sum();
        let i_sum: i64 = inv.iter().sum();
        if v_sum == 0 && i_sum == 0 { continue; }

        let v_mean = v.iter().sum::<i64>() as f64 / v.len() as f64;
        let i_mean = inv.iter().sum::<i64>() as f64 / inv.len() as f64;
        let v_var: f64 = v.iter().map(|&x| (x as f64 - v_mean).powi(2)).sum::<f64>() / (v.len() - 1) as f64;
        let i_var: f64 = inv.iter().map(|&x| (x as f64 - i_mean).powi(2)).sum::<f64>() / (inv.len() - 1) as f64;
        let pooled = ((v_var + i_var) / 2.0).sqrt();
        let delta = v_mean - i_mean;
        let d = if pooled > 0.0 { delta.abs() / pooled } else { 0.0 };

        let name = counter_names.get(i).cloned().unwrap_or(format!("Counter {}", i));

        let tag = if d > 0.5 { "██ SIGNIFICANT" }
            else if d > 0.2 { "▓▓ SMALL" }
            else if d > 0.05 { "░░ DETECTABLE" }
            else { "   noise" };

        println!("  {}:", name);
        println!("    Valid:   {:.1} ± {:.1}", v_mean, v_var.sqrt());
        println!("    Invalid: {:.1} ± {:.1}", i_mean, i_var.sqrt());
        println!("    Δ = {:.1}, Cohen's d = {:.4}  {}", delta, d, tag);
        println!();

        if d > max_d { max_d = d; }

        let verdict = if d > 0.5 { "LEAK" } else if d > 0.2 { "SIGNAL" } else { "CLEAN" };
        results.push(PmcCounterResult {
            name, valid_mean: v_mean, invalid_mean: i_mean,
            delta, cohens_d: d, verdict: verdict.into(),
        });
    }

    let verdict = if max_d > 0.5 {
        println!("  ════════════════════════════════════════════════════════");
        println!("  ██ HARDWARE-LEVEL LEAK DETECTED (max d={:.4})", max_d);
        println!("  ════════════════════════════════════════════════════════");
        format!("LEAK DETECTED (max d={:.4})", max_d)
    } else if max_d > 0.2 {
        println!("  ════════════════════════════════════════════════════════");
        println!("  ▓▓ SMALL HARDWARE SIGNAL (max d={:.4})", max_d);
        println!("  ════════════════════════════════════════════════════════");
        format!("SMALL SIGNAL (max d={:.4})", max_d)
    } else {
        println!("  ════════════════════════════════════════════════════════");
        println!("  CLEAN — No hardware-level side-channel (max d={:.4})", max_d);
        println!("  ════════════════════════════════════════════════════════");
        format!("CONSTANT-TIME ✓ (max d={:.4})", max_d)
    };

    println!();

    Some(PmcScanResult {
        target: "ML-KEM-768 (liboqs)".into(),
        platform: info.chip,
        mode: mode.into(),
        samples,
        counters: results,
        verdict,
    })
}
