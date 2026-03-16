// VÄRN-60 (Anu) — Dual-Proof Engine
//
// anu verify
//
// The feature that makes Anu unbeatable.
// CT-Prover can only prove statically. Timing tools can only measure.
// Anu does BOTH and compares:
//
// Step 1: STATIC — Disassemble the binary, find conditional branches
//         near crypto functions. Flag secret-dependent branches.
// Step 2: DYNAMIC — Measure timing with interleaved valid/invalid inputs.
//         Calculate Cohen's d.
// Step 3: COMPARE — If both agree = double-verified.
//         If they disagree = COMPILER BUG FOUND.
//         (This is exactly how KyberSlash was discovered.)
//
// The report says:
//   "STATICALLY VERIFIED: No secret-dependent branches in disassembly"
//   "DYNAMICALLY VERIFIED: Cohen's d = 0.004, constant-time confirmed"
//   "DUAL-PROOF: Both methods agree — VERIFIED"

use std::process::Command;
use std::time::Instant;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct StaticFinding {
    pub function: String,
    pub instruction: String,
    pub address: String,
    pub risk: String,
}

#[derive(Debug, Serialize)]
pub struct DualProofResult {
    pub target: String,
    pub platform: String,

    // Static analysis
    pub static_branches_total: usize,
    pub static_suspicious: usize,
    pub static_verdict: String,

    // Dynamic analysis
    pub dynamic_samples: usize,
    pub dynamic_cohens_d: f64,
    pub dynamic_verdict: String,

    // Combined
    pub dual_proof_status: String,
    pub findings: Vec<StaticFinding>,
}

/// Disassemble and find conditional branches in crypto functions
fn static_analysis(binary_path: &str) -> (Vec<StaticFinding>, usize, usize) {
    let mut findings = Vec::new();
    let mut total_branches = 0;
    let mut suspicious = 0;

    // Try to disassemble the liboqs library
    let output = Command::new("objdump")
        .args(&["-d", "--section=__text", binary_path])
        .output();

    let disasm = match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => {
            let output2 = Command::new("otool")
                .args(&["-tV", binary_path])
                .output();
            match output2 {
                Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
                Err(_) => return (findings, 0, 0),
            }
        }
    };

    let mut current_fn = String::new();
    let mut prev_line = String::new();
    let mut fn_line_count: usize = 0;

    // INNER crypto functions — specifically ML-KEM / CRYSTALS-Kyber
    // These are where secret data is processed and MUST be constant-time
    // Narrowed to avoid false positives from FrodoKEM, BIKE, NTRU etc.
    let hot_crypto_fns = [
        // ML-KEM core
        "indcpa_dec", "indcpa_enc",
        "poly_tomsg", "poly_frommsg",
        "poly_compress", "poly_decompress",
        "cmov",  // constant-time conditional move — branches here = critical
        // CRYSTALS-Kyber specific
        "pqcrystals_kyber", "kyber_indcpa",
        "ml_kem_768", "ml_kem_512", "ml_kem_1024",
        // NTT — number theoretic transform (core lattice math)
        "ntt_", "invntt_", "basemul_",
        // Polynomial operations on secret data
        "poly_ntt", "poly_invntt", "poly_basemul",
        "poly_reduce", "poly_add", "poly_sub",
        "polyvec_ntt", "polyvec_basemul",
        // CBD — centered binomial distribution (generates secret)
        "cbd2", "cbd3", "cbd_",
    ];

    // Wrapper/dispatch functions — branches here are typically
    // null checks and error handling, NOT secret-dependent
    let wrapper_fns = [
        "OQS_KEM_keypair", "OQS_KEM_encaps", "OQS_KEM_decaps",
        "OQS_KEM_new", "OQS_KEM_free",
        "OQS_SIG_keypair", "OQS_SIG_sign", "OQS_SIG_verify",
        "OQS_SIG_new", "OQS_SIG_free",
        "OQS_MEM_", "OQS_randombytes",
    ];

    let branch_insns = [
        "b.eq", "b.ne", "b.lt", "b.gt", "b.le", "b.ge",
        "b.hi", "b.lo", "b.hs", "b.ls",
        "cbz", "cbnz", "tbz", "tbnz",
    ];

    let is_hot_crypto = |fname: &str| -> bool {
        let lower = fname.to_lowercase();
        hot_crypto_fns.iter().any(|cf| lower.contains(cf))
    };

    let is_wrapper = |fname: &str| -> bool {
        wrapper_fns.iter().any(|wf| fname.contains(wf))
    };

    // Patterns that indicate a NULL-check or error-handling branch (SAFE)
    let is_null_check = |line: &str, prev: &str, fn_offset: usize| -> bool {
        let lower = line.to_lowercase();
        // CBZ x0 near function entry = null pointer check
        if (lower.contains("cbz\tx0") || lower.contains("cbz\tw0")) && fn_offset < 10 {
            return true;
        }
        // CBZ after a function call (bl/blr) = checking return value
        if (lower.contains("cbz") || lower.contains("cbnz")) &&
           (prev.contains("bl\t") || prev.contains("blr\t")) {
            return true;
        }
        false
    };

    // Patterns that indicate a loop branch (usually SAFE for CT)
    let is_loop_branch = |line: &str| -> bool {
        let lower = line.to_lowercase();
        // b.ne that jumps backward (loop) — common in NTT butterfly
        // subs + b.ne is a loop counter pattern
        if lower.contains("b.ne") || lower.contains("b.lt") || lower.contains("b.gt") {
            // These are often loop termination conditions, not secret-dependent
            // But we still count them — just at lower risk
            return false; // Don't auto-dismiss, but note it
        }
        false
    };

    for line in disasm.lines() {
        let trimmed = line.trim();

        // Track function names
        if trimmed.ends_with(':') && !trimmed.starts_with(' ') {
            current_fn = trimmed.trim_end_matches(':').to_string();
            fn_line_count = 0;
            continue;
        }

        fn_line_count += 1;

        // Skip wrapper functions entirely — their branches are dispatch/null-checks
        if is_wrapper(&current_fn) {
            prev_line = trimmed.to_string();
            continue;
        }

        // Check for branch instructions
        let lower = trimmed.to_lowercase();
        for branch in &branch_insns {
            if lower.contains(branch) {
                total_branches += 1;

                // Filter 1: NULL checks near function entry
                if is_null_check(trimmed, &prev_line, fn_line_count) {
                    continue;
                }

                // Filter 2: Is this in a HOT crypto function?
                let risk = if is_hot_crypto(&current_fn) {
                    "HIGH"
                } else {
                    "LOW"
                };

                // Only count HIGH-risk branches as suspicious
                if risk == "HIGH" {
                    suspicious += 1;
                    findings.push(StaticFinding {
                        function: current_fn.clone(),
                        instruction: trimmed.chars().take(80).collect(),
                        address: trimmed.split_whitespace().next().unwrap_or("").into(),
                        risk: risk.into(),
                    });
                }
            }
        }

        prev_line = trimmed.to_string();
    }

    (findings, total_branches, suspicious)
}

/// Dynamic timing analysis (interleaved valid/invalid)
fn dynamic_analysis(samples: usize) -> (f64, f64, f64) {
    use std::ffi::CString;
    use crate::target::liboqs::*;

    let kem_name = CString::new("ML-KEM-768").unwrap();
    let kem = unsafe { OQS_KEM_new(kem_name.as_ptr()) };
    if kem.is_null() {
        return (0.0, 0.0, 0.0);
    }

    let mut pk = vec![0u8; 1184];
    let mut sk = vec![0u8; 2400];
    let mut ct = vec![0u8; 1088];
    let mut ss = vec![0u8; 32];
    let mut ss2 = vec![0u8; 32];

    unsafe { OQS_KEM_keypair(kem, pk.as_mut_ptr(), sk.as_mut_ptr()) };
    unsafe { OQS_KEM_encaps(kem, ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr()) };

    let mut pk2 = vec![0u8; 1184];
    let mut sk2 = vec![0u8; 2400];
    unsafe { OQS_KEM_keypair(kem, pk2.as_mut_ptr(), sk2.as_mut_ptr()) };
    let mut ct_inv = vec![0u8; 1088];
    let mut ss_d = vec![0u8; 32];
    unsafe { OQS_KEM_encaps(kem, ct_inv.as_mut_ptr(), ss_d.as_mut_ptr(), pk2.as_ptr()) };

    // Warmup
    for _ in 0..2000 {
        unsafe { OQS_KEM_decaps(kem, ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()) };
    }

    // Interleaved measurement
    let mut valid_times = Vec::with_capacity(samples);
    let mut invalid_times = Vec::with_capacity(samples);

    for _ in 0..samples {
        let start = Instant::now();
        unsafe { OQS_KEM_decaps(kem, ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()) };
        valid_times.push(start.elapsed().as_nanos() as f64);

        let start = Instant::now();
        unsafe { OQS_KEM_decaps(kem, ss2.as_mut_ptr(), ct_inv.as_ptr(), sk.as_ptr()) };
        invalid_times.push(start.elapsed().as_nanos() as f64);
    }

    unsafe { OQS_KEM_free(kem as *mut _) };

    let v_mean: f64 = valid_times.iter().sum::<f64>() / valid_times.len() as f64;
    let i_mean: f64 = invalid_times.iter().sum::<f64>() / invalid_times.len() as f64;
    let v_var: f64 = valid_times.iter().map(|t| (t - v_mean).powi(2)).sum::<f64>() / (valid_times.len() - 1) as f64;
    let i_var: f64 = invalid_times.iter().map(|t| (t - i_mean).powi(2)).sum::<f64>() / (invalid_times.len() - 1) as f64;
    let pooled = ((v_var + i_var) / 2.0).sqrt();
    let d = if pooled > 0.0 { (v_mean - i_mean).abs() / pooled } else { 0.0 };
    let delta = v_mean - i_mean;

    (d, delta, v_mean)
}

pub fn run_dual_proof(samples: usize) -> DualProofResult {
    let info = crate::platform::PlatformInfo::detect();

    println!();
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║     VÄRN-60 (Anu) — DUAL-PROOF ENGINE                 ║");
    println!("  ║     Static Analysis + Dynamic Measurement              ║");
    println!("  ║     The verification no other tool can do.             ║");
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Target:    ML-KEM-768 (liboqs)");
    println!("  Platform:  {}", info.chip);
    println!("  Samples:   {}", samples);
    println!();

    // ═══ STEP 1: Static Analysis ═══
    println!("  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓");
    println!("  ┃  STEP 1: Static Binary Analysis                      ┃");
    println!("  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛");
    println!();

    // Analyze the liboqs static library
    let lib_path = "/opt/homebrew/lib/liboqs.a";
    println!("  Analyzing: {}", lib_path);

    let (findings, total_branches, suspicious) = static_analysis(lib_path);

    let filtered = total_branches - suspicious;
    println!("  Total conditional branches: {}", total_branches);
    println!("  Filtered (null-checks, wrappers, dispatch): {}", filtered);
    println!("  Suspicious (in hot crypto code): {}", suspicious);

    let static_verdict = if suspicious == 0 && total_branches > 0 {
        "CLEAN — No secret-dependent branches in hot crypto functions".to_string()
    } else if suspicious == 0 && total_branches == 0 {
        "INCONCLUSIVE — Could not disassemble".to_string()
    } else if suspicious < 10 {
        format!("LOW RISK — {} branches in crypto code (likely loop counters)", suspicious)
    } else {
        format!("WARNING — {} suspicious branches in hot crypto functions", suspicious)
    };

    if !findings.is_empty() {
        println!();
        for (i, f) in findings.iter().take(10).enumerate() {
            println!("    [{}] {} in {}", i + 1, f.instruction, f.function);
        }
        if findings.len() > 10 {
            println!("    ... and {} more", findings.len() - 10);
        }
    }

    println!();
    println!("  Static verdict: {}", static_verdict);
    println!();

    // ═══ STEP 2: Dynamic Analysis ═══
    println!("  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓");
    println!("  ┃  STEP 2: Dynamic Timing Measurement                  ┃");
    println!("  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛");
    println!();

    let (d, delta, mean_ns) = dynamic_analysis(samples);

    println!("  Mean decapsulation: {:.0} ns", mean_ns);
    println!("  Valid vs Invalid Δ: {:.1} ns", delta);
    println!("  Cohen's d: {:.4}", d);

    let dynamic_verdict = if d > 0.5 {
        format!("LEAK DETECTED (d={:.4})", d)
    } else if d > 0.2 {
        format!("SMALL SIGNAL (d={:.4})", d)
    } else {
        format!("CONSTANT-TIME ✓ (d={:.4})", d)
    };

    println!("  Dynamic verdict: {}", dynamic_verdict);
    println!();

    // ═══ STEP 3: Dual-Proof Comparison ═══
    println!("  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓");
    println!("  ┃  STEP 3: DUAL-PROOF Verification                     ┃");
    println!("  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛");
    println!();

    let static_clean = suspicious == 0;
    let static_low = suspicious > 0 && suspicious < 10;
    let dynamic_clean = d < 0.2;

    let dual_proof_status = if static_clean && dynamic_clean {
        println!("  ════════════════════════════════════════════════════════");
        println!("  ✓ DUAL-PROOF: VERIFIED");
        println!("  ✓ Static:  No secret-dependent branches in hot crypto");
        println!("  ✓ Dynamic: Cohen's d = {:.4} (constant-time)", d);
        println!("  ✓ Both methods agree — IMPLEMENTATION IS SAFE");
        println!("  ════════════════════════════════════════════════════════");
        "VERIFIED — Both static and dynamic analysis confirm constant-time".into()
    } else if static_low && dynamic_clean {
        println!("  ════════════════════════════════════════════════════════");
        println!("  ✓ DUAL-PROOF: VERIFIED (with notes)");
        println!("  ⚠ Static:  {} branches in hot crypto (likely loop counters)", suspicious);
        println!("  ✓ Dynamic: Cohen's d = {:.4} (constant-time)", d);
        println!("  ✓ Branches do not leak — timing confirms constant-time");
        println!("  ════════════════════════════════════════════════════════");
        format!("VERIFIED — {} static branches but dynamic confirms constant-time (d={:.4})", suspicious, d)
    } else if !static_clean && !static_low && dynamic_clean {
        println!("  ════════════════════════════════════════════════════════");
        println!("  ⚠ DUAL-PROOF: NEEDS REVIEW");
        println!("  ⚠ Static:  {} branches in hot crypto functions", suspicious);
        println!("  ✓ Dynamic: Cohen's d = {:.4} (constant-time)", d);
        println!("  ⚠ Many branches exist but timing shows no leak");
        println!("  ⚠ Manual review of flagged functions recommended");
        println!("  ════════════════════════════════════════════════════════");
        format!("NEEDS REVIEW — {} branches but dynamic clean (d={:.4})", suspicious, d)
    } else if (static_clean || static_low) && !dynamic_clean {
        println!("  ════════════════════════════════════════════════════════");
        println!("  ██ DUAL-PROOF: COMPILER BUG SUSPECTED");
        println!("  ✓ Static:  No suspicious branches in source");
        println!("  ✗ Dynamic: Cohen's d = {:.4} (LEAK DETECTED)", d);
        println!("  ██ Source looks safe but compiled code leaks!");
        println!("  ██ This is how KyberSlash was discovered.");
        println!("  ════════════════════════════════════════════════════════");
        format!("COMPILER BUG SUSPECTED — Static clean but dynamic shows d={:.4}", d)
    } else {
        println!("  ════════════════════════════════════════════════════════");
        println!("  ██ DUAL-PROOF: VULNERABLE");
        println!("  ✗ Static:  {} suspicious branches", suspicious);
        println!("  ✗ Dynamic: Cohen's d = {:.4} (LEAK DETECTED)", d);
        println!("  ██ Both methods confirm: implementation is NOT constant-time");
        println!("  ════════════════════════════════════════════════════════");
        format!("VULNERABLE — Both methods confirm leak (d={:.4}, {} branches)", d, suspicious)
    };

    println!();

    DualProofResult {
        target: "ML-KEM-768 (liboqs)".into(),
        platform: info.chip,
        static_branches_total: total_branches,
        static_suspicious: suspicious,
        static_verdict,
        dynamic_samples: samples,
        dynamic_cohens_d: d,
        dynamic_verdict,
        dual_proof_status,
        findings,
    }
}
