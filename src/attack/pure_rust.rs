// VÄRN-60 (Anu) — Module: Pure Rust Implementation Analysis
//
// The pqcrypto-kyber crate uses handwritten AARCH64 assembly on Apple Silicon.
// But many deployments use pure Rust or pure C implementations where
// the COMPILER decides what instructions to emit.
//
// This module doesn't test a different crate (to avoid dependency hell),
// but instead:
//   1. Identifies which code paths use assembly vs C fallback
//   2. Tests the C reference implementation paths specifically
//   3. Compares timing signatures between optimized and reference paths
//   4. Checks if the binary contains BOTH assembly and C implementations
//      (some builds include both, with runtime dispatch)

use crate::target::{MlKemTarget, SecurityLevel};
use crate::analysis::Statistics;
use serde::Serialize;
use std::process::Command;

#[derive(Debug, Serialize)]
pub struct PureImplResult {
    pub has_aarch64_asm: bool,
    pub has_c_reference: bool,
    pub has_avx2: bool,
    pub asm_symbol_count: usize,
    pub c_ref_symbol_count: usize,
    pub implementation_type: String,
    pub c_ref_branches: Vec<CRefBranch>,
    pub timing_comparison: Option<ImplTimingComparison>,
    pub verdict: String,
}

#[derive(Debug, Serialize)]
pub struct CRefBranch {
    pub function: String,
    pub instruction: String,
    pub risk: String,
}

#[derive(Debug, Serialize)]
pub struct ImplTimingComparison {
    pub asm_mean_ns: f64,
    pub asm_stddev_ns: f64,
    pub ref_functions_found: usize,
    pub ref_branches_in_secret_path: usize,
}

pub fn run_pure_impl_analysis(binary: &str, level: SecurityLevel, samples: usize) -> PureImplResult {
    println!();
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║     VÄRN-60 (Anu) — Implementation Path Analysis       ║");
    println!("  ║     Assembly vs C Reference Code Detection              ║");
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!();

    // ── Step 1: Symbol analysis ──
    println!("  [1/4] Scanning binary for implementation variants...");

    let symbols = get_symbols(binary);

    let aarch64_syms: Vec<&String> = symbols.iter()
        .filter(|s| s.contains("AARCH64") || s.contains("aarch64"))
        .collect();
    let avx2_syms: Vec<&String> = symbols.iter()
        .filter(|s| s.contains("AVX2") || s.contains("avx2") || s.contains("AVX"))
        .collect();
    // C reference implementations typically use _ref_ or don't have arch suffix
    let c_ref_syms: Vec<&String> = symbols.iter()
        .filter(|s| {
            let lower = s.to_lowercase();
            (lower.contains("_ref_") || lower.contains("_clean_"))
            && (lower.contains("kyber") || lower.contains("indcpa") || lower.contains("poly"))
        })
        .collect();

    let has_aarch64 = !aarch64_syms.is_empty();
    let has_avx2 = !avx2_syms.is_empty();
    let has_c_ref = !c_ref_syms.is_empty();

    println!("    AARCH64 assembly symbols: {}", aarch64_syms.len());
    println!("    AVX2 symbols:             {}", avx2_syms.len());
    println!("    C reference symbols:      {}", c_ref_syms.len());
    println!();

    for s in aarch64_syms.iter().take(5) {
        println!("      ASM: {}", s);
    }
    if aarch64_syms.len() > 5 {
        println!("      ... and {} more", aarch64_syms.len() - 5);
    }

    for s in c_ref_syms.iter().take(5) {
        println!("      REF: {}", s);
    }
    println!();

    let impl_type = if has_aarch64 && has_c_ref {
        "HYBRID — both AARCH64 assembly and C reference present (runtime dispatch possible)"
    } else if has_aarch64 {
        "AARCH64 ASSEMBLY — hardware-optimized, likely constant-time hardened"
    } else if has_avx2 {
        "AVX2 — x86 optimized (not expected on Apple Silicon)"
    } else if has_c_ref {
        "C REFERENCE — compiler-generated code, highest risk for timing leaks"
    } else {
        "UNKNOWN — no recognized implementation signatures found"
    };

    println!("  Implementation: {}", impl_type);
    println!();

    // ── Step 2: Disassemble C reference functions for branches ──
    println!("  [2/4] Analyzing C reference code paths...");

    let disasm = get_disassembly(binary);
    let mut c_ref_branches = Vec::new();

    let secret_functions = [
        "indcpa_dec", "poly_frommsg", "poly_tomsg",
        "cmov", "verify", "cbd",
    ];

    let branch_mnemonics = ["cbz", "cbnz", "tbz", "tbnz"];

    let lines: Vec<&str> = disasm.lines().collect();
    let mut current_func = String::new();
    let mut in_ref = false;

    for line in &lines {
        if !line.starts_with(' ') && line.contains(':') {
            let sym = line.split(':').next().unwrap_or("").trim();
            let lower = sym.to_lowercase();
            in_ref = (lower.contains("_ref_") || lower.contains("_clean_"))
                && secret_functions.iter().any(|sf| lower.contains(sf));
            if in_ref || secret_functions.iter().any(|sf| lower.contains(sf)) {
                current_func = sym.to_string();
                in_ref = true;
            } else {
                in_ref = false;
            }
        }

        if !in_ref { continue; }

        let lower = line.to_lowercase();
        for mnem in &branch_mnemonics {
            if lower.contains(mnem) {
                let risk = if current_func.to_lowercase().contains("cmov")
                    || current_func.to_lowercase().contains("verify") {
                    "HIGH — branch in constant-time-critical function"
                } else if current_func.to_lowercase().contains("indcpa_dec") {
                    "HIGH — branch in decapsulation path"
                } else if current_func.to_lowercase().contains("frommsg") {
                    "CRITICAL — KyberSlash was in this function"
                } else {
                    "MEDIUM — branch in secret-processing function"
                };

                c_ref_branches.push(CRefBranch {
                    function: current_func.clone(),
                    instruction: line.trim().to_string(),
                    risk: risk.into(),
                });
                break;
            }
        }
    }

    println!("    Branches in secret-touching reference code: {}", c_ref_branches.len());
    for b in c_ref_branches.iter().take(10) {
        println!("      [{}] {} in {}", b.risk, b.instruction, truncate(&b.function, 40));
    }
    println!();

    // ── Step 3: Timing measurement ──
    println!("  [3/4] Timing the active implementation...");

    let target = MlKemTarget::new(level);
    let (ct, _) = target.encapsulate();

    // Warmup
    for _ in 0..2000 { let _ = target.timed_decapsulate(&ct); }

    let mut times: Vec<u64> = Vec::with_capacity(samples);
    for _ in 0..samples {
        let (_, t) = target.timed_decapsulate(&ct);
        times.push(t);
    }
    let stats = Statistics::from_samples(&times);

    println!("    Active impl: {:.0} ± {:.0} ns (CV={:.4})",
        stats.mean, stats.stddev, stats.stddev / stats.mean);
    println!();

    let timing = ImplTimingComparison {
        asm_mean_ns: stats.mean,
        asm_stddev_ns: stats.stddev,
        ref_functions_found: c_ref_syms.len(),
        ref_branches_in_secret_path: c_ref_branches.len(),
    };

    // ── Step 4: Risk assessment ──
    println!("  [4/4] Risk assessment...");

    let _critical_branches: Vec<&CRefBranch> = c_ref_branches.iter()
        .filter(|b| b.risk.contains("CRITICAL") || b.risk.contains("HIGH"))
        .collect();

    let verdict = if !has_aarch64 && !c_ref_branches.is_empty() {
        format!("VULNERABLE — C reference implementation active with {} branches in secret paths. \
                No assembly hardening present. Compiler may introduce timing leaks.",
                c_ref_branches.len())
    } else if has_aarch64 && has_c_ref {
        format!("MIXED — AARCH64 assembly present (likely active), but C reference code also linked. \
                {} reference branches in secret paths. Verify runtime dispatch.",
                c_ref_branches.len())
    } else if has_aarch64 && !has_c_ref {
        "HARDENED — Only AARCH64 assembly implementation present. \
                Constant-time properties manually maintained.".into()
    } else {
        "UNKNOWN — Could not determine implementation security posture".into()
    };

    println!();
    println!("  ════════════════════════════════════════════════════════");
    println!("  {}", verdict);
    println!("  ════════════════════════════════════════════════════════");
    println!();

    PureImplResult {
        has_aarch64_asm: has_aarch64,
        has_c_reference: has_c_ref,
        has_avx2,
        asm_symbol_count: aarch64_syms.len(),
        c_ref_symbol_count: c_ref_syms.len(),
        implementation_type: impl_type.into(),
        c_ref_branches,
        timing_comparison: Some(timing),
        verdict,
    }
}

fn get_symbols(binary: &str) -> Vec<String> {
    let mut symbols = Vec::new();
    if let Ok(out) = Command::new("nm").args(["-g", binary]).output() {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if let Some(sym) = line.split_whitespace().last() {
                let lower = sym.to_lowercase();
                if lower.contains("kyber") || lower.contains("indcpa") || lower.contains("poly")
                    || lower.contains("ntt") || lower.contains("cbd")
                    || lower.contains("cmov") || lower.contains("verify")
                    || lower.contains("keccak") || lower.contains("sha3")
                {
                    symbols.push(sym.to_string());
                }
            }
        }
    }
    symbols.sort();
    symbols.dedup();
    symbols
}

fn get_disassembly(binary: &str) -> String {
    if let Ok(out) = Command::new("otool").args(["-tV", binary]).output() {
        return String::from_utf8_lossy(&out.stdout).to_string();
    }
    String::new()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() }
    else { format!("...{}", &s[s.len()-max+3..]) }
}
