// VÄRN-60 (Anu) — Module: Compiler Flag Analysis
//
// KyberSlash was caused by Clang optimizing constant-time code into
// branching code. This module:
//   1. Detects which compiler/flags were used
//   2. Examines critical functions for optimization-dependent patterns
//   3. Counts constant-time vs branching implementations
//   4. Generates a security score per function

use serde::Serialize;
use std::process::Command;

#[derive(Debug, Serialize)]
pub struct CompilerAnalysisResult {
    pub compiler: String,
    pub arch: String,
    pub binary_path: String,
    pub functions_analyzed: usize,
    pub functions: Vec<FunctionSecurityProfile>,
    pub overall_score: f64,
    pub verdict: String,
}

#[derive(Debug, Serialize)]
pub struct FunctionSecurityProfile {
    pub name: String,
    pub size_bytes: usize,
    pub instruction_count: usize,
    pub branch_count: usize,
    pub csel_count: usize,
    pub has_cmov_pattern: bool,
    pub has_lookup_table: bool,
    pub security_score: f64,
    pub notes: Vec<String>,
}

pub fn run_compiler_analysis(binary: &str) -> CompilerAnalysisResult {
    println!();
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║     VÄRN-60 (Anu) — Compiler Security Analysis         ║");
    println!("  ║     Detecting optimization-induced timing leaks         ║");
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!();

    // Detect compiler
    let compiler = detect_compiler(binary);
    let arch = detect_arch(binary);
    println!("  Compiler: {}", compiler);
    println!("  Arch:     {}", arch);
    println!();

    // Get full disassembly
    let disasm = get_disassembly(binary);

    // Critical functions to analyze
    let targets = [
        "cmov", "verify", "indcpa_dec", "indcpa_enc",
        "poly_frommsg", "poly_tomsg",
        "ntt", "invntt", "basemul",
        "cbd", "poly_compress", "poly_decompress",
        "kem_dec", "kem_enc", "keypair",
    ];

    println!("  Analyzing {} critical function patterns...", targets.len());
    println!();

    let mut functions = Vec::new();

    for target in &targets {
        let profiles = analyze_function(&disasm, target);
        for p in profiles {
            let tag = if p.security_score >= 0.9 { "✓ SAFE" }
                else if p.security_score >= 0.7 { "~ OK" }
                else if p.security_score >= 0.5 { "? REVIEW" }
                else { "✗ RISK" };

            println!("    {:>50}: score={:.2} ({}) branches={} csel={}",
                truncate(&p.name, 50), p.security_score, tag, p.branch_count, p.csel_count);

            for note in &p.notes {
                println!("      → {}", note);
            }
            functions.push(p);
        }
    }

    let overall_score = if functions.is_empty() {
        0.0
    } else {
        functions.iter().map(|f| f.security_score).sum::<f64>() / functions.len() as f64
    };

    let risky: Vec<&FunctionSecurityProfile> = functions.iter()
        .filter(|f| f.security_score < 0.7)
        .collect();

    let verdict = if risky.is_empty() {
        "All analyzed crypto functions appear constant-time safe"
    } else {
        "Some functions have potential timing vulnerabilities — see details"
    };

    println!();
    println!("  ════════════════════════════════════════════════════════");
    println!("  Overall security score: {:.2}/1.00", overall_score);
    println!("  Functions at risk: {}/{}", risky.len(), functions.len());
    println!("  VERDICT: {}", verdict);
    println!("  ════════════════════════════════════════════════════════");
    println!();

    CompilerAnalysisResult {
        compiler, arch,
        binary_path: binary.into(),
        functions_analyzed: functions.len(),
        functions,
        overall_score,
        verdict: verdict.into(),
    }
}

fn analyze_function(disasm: &str, pattern: &str) -> Vec<FunctionSecurityProfile> {
    let mut results = Vec::new();
    let lines: Vec<&str> = disasm.lines().collect();

    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];

        // Find function starts matching pattern
        if !line.starts_with(' ') && line.contains(':') {
            let lower = line.to_lowercase();
            if lower.contains(&pattern.to_lowercase()) && lower.contains("kyber") {
                let func_name = line.split(':').next().unwrap_or("").trim().to_string();

                // Collect all instructions until next function
                let mut instr_count = 0;
                let mut branch_count = 0;
                let mut csel_count = 0;
                let mut has_cmov = false;
                let mut has_lut = false;
                let mut notes: Vec<String> = Vec::new();
                let start = i;

                i += 1;
                while i < lines.len() {
                    let l = lines[i];
                    if !l.starts_with(' ') && l.contains(':') && !l.contains("0x") {
                        break;
                    }

                    let lower_l = l.to_lowercase();
                    instr_count += 1;

                    // Count branches
                    if ["cbz", "cbnz", "tbz", "tbnz"].iter().any(|m| lower_l.contains(m)) {
                        branch_count += 1;
                    }
                    if ["b.eq", "b.ne", "b.lt", "b.gt", "b.lo", "b.hi", "b.le", "b.ge"]
                        .iter().any(|m| lower_l.contains(m)) {
                        branch_count += 1;
                    }

                    // Count constant-time selects (good)
                    if ["csel", "cset", "csinc"].iter().any(|m| lower_l.contains(m)) {
                        csel_count += 1;
                    }

                    // Detect BIC/AND/ORR pattern (cmov-safe)
                    if lower_l.contains("bic") && lower_l.contains("w") {
                        has_cmov = true;
                    }

                    // Detect table lookups (potential cache timing)
                    if lower_l.contains("ldr") && lower_l.contains("[x") && lower_l.contains(",") {
                        has_lut = true;
                    }

                    i += 1;
                }

                let size = i - start;

                // Calculate security score
                let mut score: f64 = 1.0;

                // Penalize branches in small functions (more likely secret-dependent)
                if branch_count > 0 && instr_count < 50 {
                    score -= 0.3;
                    notes.push(format!("{} branches in small function ({} instrs)", branch_count, instr_count));
                } else if branch_count > 0 {
                    score -= 0.1; // Larger functions may have legit loop branches
                }

                // Reward CSEL usage
                if csel_count > 0 {
                    score += 0.1;
                    notes.push(format!("Uses {} constant-time selects", csel_count));
                }

                // Reward BIC/AND/ORR cmov pattern
                if has_cmov {
                    score += 0.1;
                    notes.push("Has branchless BIC/AND/ORR conditional move".into());
                }

                // Warn about lookup tables
                if has_lut && lower.contains("ntt") {
                    score -= 0.05;
                    notes.push("Contains indexed loads (potential cache-timing in NTT)".into());
                }

                score = score.clamp(0.0, 1.0);

                results.push(FunctionSecurityProfile {
                    name: func_name,
                    size_bytes: size * 4, // ARM64 = 4 bytes per instruction
                    instruction_count: instr_count,
                    branch_count,
                    csel_count,
                    has_cmov_pattern: has_cmov,
                    has_lookup_table: has_lut,
                    security_score: score,
                    notes,
                });

                continue;
            }
        }
        i += 1;
    }

    results
}

fn detect_compiler(binary: &str) -> String {
    if let Ok(out) = Command::new("otool").args(["-l", binary]).output() {
        let text = String::from_utf8_lossy(&out.stdout);
        if text.contains("Apple") { return "Apple Clang (LLVM)".into(); }
    }
    "Unknown".into()
}

fn detect_arch(binary: &str) -> String {
    if let Ok(out) = Command::new("file").arg(binary).output() {
        let text = String::from_utf8_lossy(&out.stdout);
        if text.contains("arm64") { return "ARM64 (Apple Silicon)".into(); }
        if text.contains("x86_64") { return "x86_64".into(); }
    }
    "Unknown".into()
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
