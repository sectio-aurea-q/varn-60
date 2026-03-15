// VÄRN-60 (Anu) — Attack Vector 3: Binary Branch Analysis
//
// KyberSlash was found because the Clang compiler inserted a
// secret-dependent branch that the developer never wrote.
//
// This module:
//   1. Locates the pqcrypto-kyber compiled C code in the binary
//   2. Disassembles it looking for conditional branches
//   3. Times individual operations with controlled inputs
//      to detect data-dependent execution paths
//
// On ARM64 (Apple Silicon), we look for:
//   - CBZ/CBNZ (Compare and Branch on Zero/Non-Zero)
//   - TBZ/TBNZ (Test Bit and Branch)
//   - B.cond (Conditional Branch)
//   near crypto-relevant functions

use crate::target::{MlKemTarget, SecurityLevel};
use crate::analysis::Statistics;
use serde::Serialize;
use std::process::Command;

#[derive(Debug, Serialize)]
pub struct BinaryAnalysisResult {
    pub level: SecurityLevel,
    pub platform: String,
    pub binary_path: String,
    pub crypto_symbols: Vec<String>,
    pub conditional_branches: Vec<BranchInfo>,
    pub timing_tests: Vec<BranchTimingTest>,
    pub verdict: String,
}

#[derive(Debug, Serialize)]
pub struct BranchInfo {
    pub symbol: String,
    pub instruction: String,
    pub offset: String,
    pub branch_type: String,
}

#[derive(Debug, Serialize)]
pub struct BranchTimingTest {
    pub test_name: String,
    pub input_a_desc: String,
    pub input_b_desc: String,
    pub mean_a_ns: f64,
    pub mean_b_ns: f64,
    pub delta_ns: f64,
    pub cohens_d: f64,
    pub verdict: String,
}

pub fn run_binary_analysis(level: SecurityLevel, samples: usize) -> BinaryAnalysisResult {
    let platform = crate::platform::PlatformInfo::detect();

    println!();
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║     VÄRN-60 (Anu) — Binary Branch Analysis             ║");
    println!("  ║     Searching for compiler-induced timing leaks         ║");
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!();

    // ── Step 1: Find crypto symbols in binary ────────────────
    println!("  [1/4] Scanning binary for crypto symbols...");

    let binary_path = "target/release/anu".to_string();
    let symbols = find_crypto_symbols(&binary_path);

    println!("         Found {} crypto-relevant symbols", symbols.len());
    for s in symbols.iter().take(10) {
        println!("           {}", s);
    }
    if symbols.len() > 10 {
        println!("           ... and {} more", symbols.len() - 10);
    }
    println!();

    // ── Step 2: Disassemble and find conditional branches ────
    println!("  [2/4] Disassembling crypto functions for conditional branches...");

    let branches = find_conditional_branches(&binary_path, &symbols);

    let mut branch_categories: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for b in &branches {
        *branch_categories.entry(b.branch_type.clone()).or_insert(0) += 1;
    }

    println!("         Found {} conditional branches in crypto code:", branches.len());
    for (btype, count) in &branch_categories {
        println!("           {}: {}", btype, count);
    }
    println!();

    // ── Step 3: Interleaved timing tests ─────────────────────
    println!("  [3/4] Timing tests (interleaved, artifact-free)...");
    println!();

    let timing_tests = run_timing_tests(level, samples);

    for test in &timing_tests {
        let tag = if test.cohens_d > 0.5 {
            "██ SIGNIFICANT"
        } else if test.cohens_d > 0.2 {
            "▓▓ SMALL"
        } else if test.cohens_d > 0.05 {
            "░░ DETECTABLE"
        } else {
            "   noise"
        };

        println!(
            "    {:>30}: Δ={:+.1}ns d={:.4}  {}",
            test.test_name, test.delta_ns, test.cohens_d, tag
        );
    }
    println!();

    // ── Step 4: Verdict ──────────────────────────────────────
    println!("  [4/4] Analysis...");

    let max_d = timing_tests.iter()
        .map(|t| t.cohens_d)
        .fold(0.0f64, |a, b| a.max(b));

    let verdict = if max_d > 0.5 {
        "SIGNIFICANT timing leak detected in compiled binary"
    } else if max_d > 0.2 {
        "Small but measurable timing variation — investigate further"
    } else if max_d > 0.05 {
        "Marginal timing differences — likely not exploitable"
    } else {
        "Binary appears constant-time for tested operations"
    };

    println!();
    println!("  ════════════════════════════════════════════════════════");
    println!("  BINARY ANALYSIS: {}", verdict);
    println!("  Max Cohen's d: {:.4}", max_d);
    println!("  Conditional branches in crypto: {}", branches.len());
    println!("  ════════════════════════════════════════════════════════");
    println!();

    BinaryAnalysisResult {
        level,
        platform: platform.chip,
        binary_path,
        crypto_symbols: symbols,
        conditional_branches: branches,
        timing_tests,
        verdict: verdict.into(),
    }
}

fn find_crypto_symbols(binary: &str) -> Vec<String> {
    let output = Command::new("nm")
        .args(["-g", binary])
        .output();

    let mut symbols = Vec::new();

    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        let crypto_patterns = [
            "kyber", "indcpa", "poly_", "ntt", "invntt",
            "cbd", "kem_dec", "kem_enc", "verify",
            "cmov", "cmp", "sha3", "keccak",
            "frommsg", "tomsg", "compress", "decompress",
        ];

        for line in text.lines() {
            let lower = line.to_lowercase();
            if crypto_patterns.iter().any(|p| lower.contains(p)) {
                // Extract just the symbol name (last field)
                if let Some(sym) = line.split_whitespace().last() {
                    symbols.push(sym.to_string());
                }
            }
        }
    }

    symbols.sort();
    symbols.dedup();
    symbols
}

fn find_conditional_branches(binary: &str, symbols: &[String]) -> Vec<BranchInfo> {
    let mut branches = Vec::new();

    // Try otool (macOS) first, then objdump
    let output = Command::new("otool")
        .args(["-tV", binary])
        .output();

    let disasm = if let Ok(out) = output {
        String::from_utf8_lossy(&out.stdout).to_string()
    } else if let Ok(out) = Command::new("objdump").args(["-d", binary]).output() {
        String::from_utf8_lossy(&out.stdout).to_string()
    } else {
        return branches;
    };

    // ARM64 conditional branch mnemonics
    let branch_mnemonics = [
        "cbz", "cbnz", "tbz", "tbnz",
        "b.eq", "b.ne", "b.lt", "b.gt", "b.le", "b.ge",
        "b.lo", "b.hi", "b.ls", "b.hs",
        "b.mi", "b.pl", "b.vs", "b.vc",
        "csel", "cset", "csinc",
    ];

    let mut current_symbol = String::new();
    let mut in_crypto = false;

    for line in disasm.lines() {
        // Detect symbol labels
        if line.ends_with(':') && !line.starts_with(' ') {
            let sym = line.trim_end_matches(':');
            let lower_sym = sym.to_lowercase();
            in_crypto = symbols.iter().any(|s| lower_sym.contains(&s.to_lowercase()))
                || ["kyber", "indcpa", "poly", "ntt", "cbd", "verify", "cmov"]
                    .iter().any(|p| lower_sym.contains(p));
            if in_crypto {
                current_symbol = sym.to_string();
            }
        }

        if !in_crypto { continue; }

        let lower_line = line.to_lowercase();

        for mnemonic in &branch_mnemonics {
            if lower_line.contains(mnemonic) {
                let offset = line.split_whitespace().next().unwrap_or("?").to_string();
                let btype = if mnemonic.starts_with("cb") || mnemonic.starts_with("tb") {
                    "data-dependent branch"
                } else if mnemonic.starts_with("b.") {
                    "conditional branch"
                } else {
                    "conditional select"
                };

                branches.push(BranchInfo {
                    symbol: current_symbol.clone(),
                    instruction: mnemonic.to_string(),
                    offset,
                    branch_type: btype.into(),
                });
                break;
            }
        }
    }

    branches
}

/// Interleaved timing tests — the RIGHT way to measure
/// Each measurement alternates between input A and input B
/// to eliminate cache warming artifacts
fn run_timing_tests(level: SecurityLevel, samples: usize) -> Vec<BranchTimingTest> {
    let mut tests = Vec::new();
    let target = MlKemTarget::new(level);

    // Warmup
    let (warmup_ct, _) = target.encapsulate();
    for _ in 0..2000 {
        let _ = target.timed_decapsulate(&warmup_ct);
    }

    // Test 1: Valid vs Random (interleaved)
    {
        let (valid_ct, _) = target.encapsulate();
        let mut random_ct = vec![0u8; valid_ct.len()];
        for b in random_ct.iter_mut() { *b = rand::random(); }

        let mut valid_times: Vec<u64> = Vec::with_capacity(samples);
        let mut invalid_times: Vec<u64> = Vec::with_capacity(samples);

        for _ in 0..samples {
            let (_, vt) = target.timed_decapsulate(&valid_ct);
            let (_, it) = target.timed_decapsulate(&random_ct);
            valid_times.push(vt);
            invalid_times.push(it);
        }

        let vs = Statistics::from_samples(&valid_times);
        let is = Statistics::from_samples(&invalid_times);
        let delta = vs.mean - is.mean;
        let pooled = ((vs.variance + is.variance) / 2.0).sqrt();
        let d = if pooled > 0.0 { delta.abs() / pooled } else { 0.0 };

        tests.push(BranchTimingTest {
            test_name: "valid vs random (interleaved)".into(),
            input_a_desc: "valid ciphertext".into(),
            input_b_desc: "random ciphertext".into(),
            mean_a_ns: vs.mean,
            mean_b_ns: is.mean,
            delta_ns: delta,
            cohens_d: d,
            verdict: if d > 0.2 { "LEAK" } else { "OK" }.into(),
        });
    }

    // Test 2: All-zero vs All-ones (both invalid, interleaved)
    {
        let ct_len = target.ciphertext_size();
        let zero_ct = vec![0u8; ct_len];
        let ones_ct = vec![0xFFu8; ct_len];

        let mut zero_times: Vec<u64> = Vec::with_capacity(samples);
        let mut ones_times: Vec<u64> = Vec::with_capacity(samples);

        for _ in 0..samples {
            let (_, zt) = target.timed_decapsulate(&zero_ct);
            let (_, ot) = target.timed_decapsulate(&ones_ct);
            zero_times.push(zt);
            ones_times.push(ot);
        }

        let zs = Statistics::from_samples(&zero_times);
        let os = Statistics::from_samples(&ones_times);
        let delta = zs.mean - os.mean;
        let pooled = ((zs.variance + os.variance) / 2.0).sqrt();
        let d = if pooled > 0.0 { delta.abs() / pooled } else { 0.0 };

        tests.push(BranchTimingTest {
            test_name: "all-zero vs all-ones (interleaved)".into(),
            input_a_desc: "zero ciphertext".into(),
            input_b_desc: "ones ciphertext".into(),
            mean_a_ns: zs.mean,
            mean_b_ns: os.mean,
            delta_ns: delta,
            cohens_d: d,
            verdict: if d > 0.2 { "LEAK" } else { "OK" }.into(),
        });
    }

    // Test 3: Near-valid (1 bit flip) vs far-invalid (random)
    {
        let (valid_ct, _) = target.encapsulate();
        let mut near_ct = valid_ct.clone();
        near_ct[0] ^= 1;
        let mut far_ct = vec![0u8; valid_ct.len()];
        for b in far_ct.iter_mut() { *b = rand::random(); }

        let mut near_times: Vec<u64> = Vec::with_capacity(samples);
        let mut far_times: Vec<u64> = Vec::with_capacity(samples);

        for _ in 0..samples {
            let (_, nt) = target.timed_decapsulate(&near_ct);
            let (_, ft) = target.timed_decapsulate(&far_ct);
            near_times.push(nt);
            far_times.push(ft);
        }

        let ns = Statistics::from_samples(&near_times);
        let fs = Statistics::from_samples(&far_times);
        let delta = ns.mean - fs.mean;
        let pooled = ((ns.variance + fs.variance) / 2.0).sqrt();
        let d = if pooled > 0.0 { delta.abs() / pooled } else { 0.0 };

        tests.push(BranchTimingTest {
            test_name: "near-valid vs far-invalid (interleaved)".into(),
            input_a_desc: "1-bit-flip from valid".into(),
            input_b_desc: "random ciphertext".into(),
            mean_a_ns: ns.mean,
            mean_b_ns: fs.mean,
            delta_ns: delta,
            cohens_d: d,
            verdict: if d > 0.2 { "LEAK" } else { "OK" }.into(),
        });
    }

    // Test 4: Decapsulation with different secret keys (same ciphertext)
    // This tests if the SECRET KEY affects timing
    {
        let target_a = MlKemTarget::new(level);
        let target_b = MlKemTarget::new(level);
        // Use a random CT — will be invalid for both, but decoded differently
        let ct_len = match level {
            SecurityLevel::MlKem512 => 768,
            SecurityLevel::MlKem768 => 1088,
            SecurityLevel::MlKem1024 => 1568,
        };
        let mut shared_ct = vec![0u8; ct_len];
        for b in shared_ct.iter_mut() { *b = rand::random(); }

        let mut times_a: Vec<u64> = Vec::with_capacity(samples);
        let mut times_b: Vec<u64> = Vec::with_capacity(samples);

        for _ in 0..samples {
            let (_, ta) = target_a.timed_decapsulate(&shared_ct);
            let (_, tb) = target_b.timed_decapsulate(&shared_ct);
            times_a.push(ta);
            times_b.push(tb);
        }

        let sa = Statistics::from_samples(&times_a);
        let sb = Statistics::from_samples(&times_b);
        let delta = sa.mean - sb.mean;
        let pooled = ((sa.variance + sb.variance) / 2.0).sqrt();
        let d = if pooled > 0.0 { delta.abs() / pooled } else { 0.0 };

        tests.push(BranchTimingTest {
            test_name: "key A vs key B (same CT, interleaved)".into(),
            input_a_desc: "keypair A decapsulates CT".into(),
            input_b_desc: "keypair B decapsulates same CT".into(),
            mean_a_ns: sa.mean,
            mean_b_ns: sb.mean,
            delta_ns: delta,
            cohens_d: d,
            verdict: if d > 0.2 { "KEY-DEPENDENT LEAK" } else { "OK" }.into(),
        });
    }

    // Test 5: Multiple encapsulations of same key (cache pattern test)
    {
        let (valid_ct_1, _) = target.encapsulate();
        let (valid_ct_2, _) = target.encapsulate();

        let mut times_1: Vec<u64> = Vec::with_capacity(samples);
        let mut times_2: Vec<u64> = Vec::with_capacity(samples);

        for _ in 0..samples {
            let (_, t1) = target.timed_decapsulate(&valid_ct_1);
            let (_, t2) = target.timed_decapsulate(&valid_ct_2);
            times_1.push(t1);
            times_2.push(t2);
        }

        let s1 = Statistics::from_samples(&times_1);
        let s2 = Statistics::from_samples(&times_2);
        let delta = s1.mean - s2.mean;
        let pooled = ((s1.variance + s2.variance) / 2.0).sqrt();
        let d = if pooled > 0.0 { delta.abs() / pooled } else { 0.0 };

        tests.push(BranchTimingTest {
            test_name: "valid CT1 vs valid CT2 (interleaved)".into(),
            input_a_desc: "valid ciphertext 1".into(),
            input_b_desc: "valid ciphertext 2".into(),
            mean_a_ns: s1.mean,
            mean_b_ns: s2.mean,
            delta_ns: delta,
            cohens_d: d,
            verdict: if d > 0.2 { "MESSAGE-DEPENDENT LEAK" } else { "OK" }.into(),
        });
    }

    tests
}
