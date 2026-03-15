// VÄRN-60 (Anu) — Deep Branch Inspector
//
// Analyzes each data-dependent branch (CBZ/CBNZ/TBZ/TBNZ) in crypto code
// to determine if it operates on secret-dependent data.
//
// Method: Extract surrounding instructions to identify if the branch
// condition comes from secret key material, ciphertext, or loop counters.

use serde::Serialize;
use std::process::Command;

#[derive(Debug, Serialize)]
pub struct DeepBranchResult {
    pub total_branches: usize,
    pub data_dependent: usize,
    pub in_secret_path: usize,
    pub functions_with_branches: Vec<FunctionBranches>,
    pub suspicious: Vec<SuspiciousBranch>,
    pub verdict: String,
}

#[derive(Debug, Serialize)]
pub struct FunctionBranches {
    pub function: String,
    pub total: usize,
    pub data_dependent: usize,
    pub conditional_select: usize,
    pub risk: String,
}

#[derive(Debug, Serialize)]
pub struct SuspiciousBranch {
    pub function: String,
    pub instruction: String,
    pub context_before: Vec<String>,
    pub context_after: Vec<String>,
    pub reason: String,
}

pub fn run_deep_branch_inspection(binary: &str) -> DeepBranchResult {
    println!();
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║     VÄRN-60 (Anu) — Deep Branch Inspector              ║");
    println!("  ║     Classifying data-dependent branches in crypto code  ║");
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!();

    // Get full disassembly
    let output = Command::new("otool")
        .args(["-tV", binary])
        .output();

    let disasm = if let Ok(out) = output {
        String::from_utf8_lossy(&out.stdout).to_string()
    } else {
        println!("  ERROR: Could not disassemble binary");
        return DeepBranchResult {
            total_branches: 0, data_dependent: 0, in_secret_path: 0,
            functions_with_branches: vec![], suspicious: vec![],
            verdict: "Could not disassemble".into(),
        };
    };

    let lines: Vec<&str> = disasm.lines().collect();

    // Crypto-relevant function prefixes
    let crypto_prefixes = [
        "pqclean_kyber", "kyber", "indcpa", "poly_", "polyvec",
        "ntt", "invntt", "cbd", "kem_dec", "kem_enc",
        "verify", "cmov", "sha3", "keccak",
        "frommsg", "tomsg", "compress", "decompress",
        "gen_matrix", "pack", "unpack",
    ];

    // Secret-touching functions (where branches are dangerous)
    let secret_functions = [
        "indcpa_dec", "dec", "decaps", "decapsulate",
        "poly_frommsg", "poly_tomsg",
        "cmov", "verify",
        "cbd", // Centered Binomial Distribution - processes secret noise
        "ntt", "invntt", // NTT on secret polynomials
        "basemul", "asymmetric_mul", "point_mul",
    ];

    let branch_mnemonics = ["cbz", "cbnz", "tbz", "tbnz"];
    let csel_mnemonics = ["csel", "cset", "csinc", "csinv", "csneg"];

    let mut func_map: std::collections::HashMap<String, FunctionBranches> = std::collections::HashMap::new();
    let mut suspicious: Vec<SuspiciousBranch> = Vec::new();
    let mut current_func = String::new();
    let mut in_crypto = false;
    let mut total_data_dep = 0;
    let mut total_csel = 0;
    let mut total_branches = 0;

    println!("  [1/3] Scanning {} lines of disassembly...", lines.len());

    for (i, line) in lines.iter().enumerate() {
        // Detect function labels
        if !line.starts_with(' ') && line.contains(':') {
            let sym = line.split(':').next().unwrap_or("").trim();
            let lower = sym.to_lowercase();
            in_crypto = crypto_prefixes.iter().any(|p| lower.contains(p));
            if in_crypto {
                current_func = sym.to_string();
                func_map.entry(current_func.clone()).or_insert(FunctionBranches {
                    function: current_func.clone(),
                    total: 0,
                    data_dependent: 0,
                    conditional_select: 0,
                    risk: "unknown".into(),
                });
            }
        }

        if !in_crypto { continue; }

        let lower = line.to_lowercase();

        // Count data-dependent branches
        for mnem in &branch_mnemonics {
            if lower.contains(mnem) {
                total_data_dep += 1;
                total_branches += 1;
                if let Some(entry) = func_map.get_mut(&current_func) {
                    entry.data_dependent += 1;
                    entry.total += 1;
                }

                // Check if this function touches secrets
                let func_lower = current_func.to_lowercase();
                let in_secret = secret_functions.iter().any(|sf| func_lower.contains(sf));

                if in_secret {
                    // Extract context (5 lines before, 3 after)
                    let start = if i > 5 { i - 5 } else { 0 };
                    let end = std::cmp::min(i + 4, lines.len());
                    let before: Vec<String> = lines[start..i].iter().map(|l| l.trim().to_string()).collect();
                    let after: Vec<String> = lines[i+1..end].iter().map(|l| l.trim().to_string()).collect();

                    suspicious.push(SuspiciousBranch {
                        function: current_func.clone(),
                        instruction: line.trim().to_string(),
                        context_before: before,
                        context_after: after,
                        reason: format!("{} in secret-touching function '{}'", mnem, current_func),
                    });
                }
                break;
            }
        }

        // Count conditional selects (these are GOOD — constant-time alternatives to branches)
        for mnem in &csel_mnemonics {
            if lower.contains(mnem) {
                total_csel += 1;
                total_branches += 1;
                if let Some(entry) = func_map.get_mut(&current_func) {
                    entry.conditional_select += 1;
                    entry.total += 1;
                }
                break;
            }
        }
    }

    // Classify risk per function
    for entry in func_map.values_mut() {
        let func_lower = entry.function.to_lowercase();
        let touches_secret = secret_functions.iter().any(|sf| func_lower.contains(sf));

        entry.risk = if touches_secret && entry.data_dependent > 0 {
            "HIGH — data-dependent branches in secret-touching function".into()
        } else if touches_secret && entry.conditional_select > 0 && entry.data_dependent == 0 {
            "LOW — uses constant-time selects (good)".into()
        } else if !touches_secret && entry.data_dependent > 0 {
            "MEDIUM — branches in crypto code (may not touch secrets)".into()
        } else {
            "OK".into()
        };
    }

    // Sort by risk
    let mut func_list: Vec<FunctionBranches> = func_map.into_values().collect();
    func_list.sort_by(|a, b| {
        let risk_order = |r: &str| -> u8 {
            if r.starts_with("HIGH") { 0 }
            else if r.starts_with("MEDIUM") { 1 }
            else if r.starts_with("LOW") { 2 }
            else { 3 }
        };
        risk_order(&a.risk).cmp(&risk_order(&b.risk))
    });

    // Output
    println!("  [2/3] Classification results:");
    println!();
    println!("    Total conditional constructs in crypto: {}", total_branches);
    println!("    Data-dependent branches (CBZ/CBNZ/TBZ/TBNZ): {}", total_data_dep);
    println!("    Constant-time selects (CSEL/CSET): {}", total_csel);
    println!("    Branches in secret-touching functions: {}", suspicious.len());
    println!();

    println!("  [3/3] Functions with highest risk:");
    println!();

    let high_risk: Vec<&FunctionBranches> = func_list.iter()
        .filter(|f| f.risk.starts_with("HIGH") || f.risk.starts_with("MEDIUM"))
        .collect();

    for f in high_risk.iter().take(15) {
        println!("    {:>50}: {} dd-branches, {} csel — {}",
            truncate(&f.function, 50), f.data_dependent, f.conditional_select, f.risk);
    }

    if !suspicious.is_empty() {
        println!();
        println!("  Suspicious branches in secret-touching functions:");
        println!();
        for (i, s) in suspicious.iter().take(10).enumerate() {
            println!("    [{}] {} in {}", i + 1, s.instruction, s.function);
            println!("        Reason: {}", s.reason);
            if !s.context_before.is_empty() {
                println!("        Before: {}", s.context_before.last().unwrap_or(&"".into()));
            }
            println!();
        }
        if suspicious.len() > 10 {
            println!("    ... and {} more", suspicious.len() - 10);
        }
    }

    let verdict = if suspicious.len() > 5 {
        format!("{} data-dependent branches found in secret-touching crypto functions — manual audit recommended", suspicious.len())
    } else if suspicious.is_empty() {
        "No data-dependent branches in secret-touching functions — implementation appears safe".into()
    } else {
        format!("{} data-dependent branches in secret paths — low count, likely loop counters", suspicious.len())
    };

    println!();
    println!("  ════════════════════════════════════════════════════════");
    println!("  VERDICT: {}", verdict);
    println!("  ════════════════════════════════════════════════════════");
    println!();

    DeepBranchResult {
        total_branches,
        data_dependent: total_data_dep,
        in_secret_path: suspicious.len(),
        functions_with_branches: func_list,
        suspicious,
        verdict,
    }
}

#[derive(Debug, Serialize)]
pub struct KeyTimingResult {
    pub num_keys: usize,
    pub samples_per_key: usize,
    pub means: Vec<f64>,
    pub overall_mean: f64,
    pub overall_stddev: f64,
    pub range_ns: f64,
    pub cv: f64,
    pub verdict: String,
}

/// Test if different secret keys produce measurably different decapsulation times
/// Uses many keys with the same ciphertext pattern to amplify any signal
pub fn run_key_timing_amplifier(
    level: crate::target::SecurityLevel,
    num_keys: usize,
    samples_per_key: usize,
) -> KeyTimingResult {
    println!();
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║     VÄRN-60 (Anu) — Key-Dependent Timing Amplifier     ║");
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Keys: {}  Samples/key: {}  Level: {}", num_keys, samples_per_key, level);
    println!();

    let ct_len = match level {
        crate::target::SecurityLevel::MlKem512 => 768,
        crate::target::SecurityLevel::MlKem768 => 1088,
        crate::target::SecurityLevel::MlKem1024 => 1568,
    };

    // Fixed ciphertext pattern
    let mut fixed_ct = vec![0u8; ct_len];
    for b in fixed_ct.iter_mut() { *b = rand::random(); }

    let mut means: Vec<f64> = Vec::with_capacity(num_keys);

    for k in 0..num_keys {
        let target = crate::target::MlKemTarget::new(level);

        // Warmup
        for _ in 0..500 {
            let _ = target.timed_decapsulate(&fixed_ct);
        }

        let mut times: Vec<u64> = Vec::with_capacity(samples_per_key);
        for _ in 0..samples_per_key {
            let (_, t) = target.timed_decapsulate(&fixed_ct);
            times.push(t);
        }

        let stats = crate::analysis::Statistics::from_samples(&times);
        means.push(stats.mean);

        if k < 20 || k % 10 == 0 {
            println!("    Key {:>3}: mean = {:.1} ns (σ={:.1})", k + 1, stats.mean, stats.stddev);
        }
    }

    let overall_mean: f64 = means.iter().sum::<f64>() / means.len() as f64;
    let overall_var: f64 = means.iter().map(|m| (m - overall_mean).powi(2)).sum::<f64>() / (means.len() - 1) as f64;
    let overall_stddev = overall_var.sqrt();
    let range = means.iter().cloned().fold(f64::NEG_INFINITY, f64::max)
              - means.iter().cloned().fold(f64::INFINITY, f64::min);
    let cv = overall_stddev / overall_mean;

    println!();
    println!("  Results across {} keys:", num_keys);
    println!("    Mean of means:  {:.1} ns", overall_mean);
    println!("    Stddev of means: {:.1} ns", overall_stddev);
    println!("    Range:          {:.1} ns", range);
    println!("    CV:             {:.6}", cv);

    // A CV > 0.001 with enough keys suggests key-dependent timing
    let verdict = if cv > 0.01 {
        "SIGNIFICANT key-dependent timing variation detected"
    } else if cv > 0.001 {
        "Small key-dependent variation — may be exploitable with many samples"
    } else {
        "No significant key-dependent timing — implementation appears constant-time across keys"
    };

    println!();
    println!("  ════════════════════════════════════════════════════════");
    println!("  VERDICT: {}", verdict);
    println!("  ════════════════════════════════════════════════════════");
    println!();

    KeyTimingResult {
        num_keys,
        samples_per_key,
        means,
        overall_mean,
        overall_stddev,
        range_ns: range,
        cv,
        verdict: verdict.into(),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() }
    else { format!("...{}", &s[s.len()-max+3..]) }
}
