// VÄRN-60 (Anu) — Full Audit Module
//
// One command. All three NIST PQC standards. Professional HTML report.
// This is what a €50,000 security audit looks like — automated.

use crate::attack::*;
use crate::target::SecurityLevel;
use crate::platform::PlatformInfo;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct AuditReport {
    pub timestamp: String,
    pub platform: String,
    pub tool_version: String,
    pub author: String,

    // ML-KEM results
    pub mlkem_768_cohens_d: f64,
    pub mlkem_768_verdict: String,
    pub mlkem_pure_rust_d: f64,
    pub mlkem_pure_rust_verdict: String,

    // ML-DSA results
    pub mldsa_sign_cv: f64,
    pub mldsa_key_cv: f64,
    pub mldsa_iteration_entropy: f64,
    pub mldsa_iteration_accuracy: f64,
    pub mldsa_reject_rate_cv: f64,
    pub mldsa_distinguishable_pct: f64,
    pub mldsa_verdict: String,

    // SLH-DSA results
    pub slhdsa_sign_cv: f64,
    pub slhdsa_msg_cv: f64,
    pub slhdsa_verdict: String,

    pub overall_verdict: String,
}

pub fn run_full_audit(output_dir: &Path, samples: usize) -> AuditReport {
    let info = PlatformInfo::detect();
    let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

    std::fs::create_dir_all(output_dir).ok();

    println!();
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║     V Ä R N - 6 0  (A n u)  —  FULL AUDIT             ║");
    println!("  ║     All Three NIST PQC Standards                       ║");
    println!("  ║     FIPS 203 (ML-KEM) + FIPS 204 (ML-DSA) + FIPS 205  ║");
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Platform:  {}", info.chip);
    println!("  Timestamp: {}", timestamp);
    println!("  Samples:   {} per test", samples);
    println!();

    // ═══════════════════════════════════════════════
    // FIPS 203: ML-KEM
    // ═══════════════════════════════════════════════
    println!("  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓");
    println!("  ┃  FIPS 203: ML-KEM (Kyber)                            ┃");
    println!("  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛");
    println!();

    // ML-KEM-768 with pqcrypto (assembly)
    println!("  ── pqcrypto-kyber (AARCH64 assembly) ──");
    let kem_config = AttackConfig {
        level: SecurityLevel::MlKem768,
        samples_per_variant: samples,
        ..Default::default()
    };
    let kem_result = run_fo_oracle(&kem_config);
    let kem_json = serde_json::to_string_pretty(&kem_result).unwrap();
    std::fs::write(output_dir.join("mlkem-768-asm.json"), &kem_json).ok();

    let mlkem_d = kem_result.fo_cohens_d;
    let mlkem_verdict = if mlkem_d > 0.2 { "LEAK DETECTED" } else { "CONSTANT-TIME ✓" };

    // ML-KEM-768 with pure Rust
    println!("  ── ml-kem (pure Rust / LLVM) ──");
    let pure_result = run_pure_rust_kem_test(SecurityLevel::MlKem768, samples);
    let pure_json = serde_json::to_string_pretty(&pure_result).unwrap();
    std::fs::write(output_dir.join("mlkem-768-pure-rust.json"), &pure_json).ok();

    let pure_d = pure_result.cohens_d;
    let pure_verdict = if pure_d > 0.2 { "LEAK DETECTED" } else { "CONSTANT-TIME ✓" };

    // ═══════════════════════════════════════════════
    // FIPS 204: ML-DSA
    // ═══════════════════════════════════════════════
    println!("  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓");
    println!("  ┃  FIPS 204: ML-DSA (Dilithium)                        ┃");
    println!("  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛");
    println!();

    // Timing variance
    let dsa_timing = run_dilithium_timing(DilithiumLevel::Dilithium3, samples);
    let dsa_json = serde_json::to_string_pretty(&dsa_timing).unwrap();
    std::fs::write(output_dir.join("mldsa-65-timing.json"), &dsa_json).ok();

    // Rejection estimator
    let dsa_reject = run_rejection_estimator(DilithiumLevel::Dilithium3, samples);
    let rej_json = serde_json::to_string_pretty(&dsa_reject).unwrap();
    std::fs::write(output_dir.join("mldsa-65-rejection.json"), &rej_json).ok();

    // Rejection rate fingerprinting (fewer keys for audit speed)
    let dsa_rate = run_rejection_rate_attack(DilithiumLevel::Dilithium3, 20, samples);
    let rate_json = serde_json::to_string_pretty(&dsa_rate).unwrap();
    std::fs::write(output_dir.join("mldsa-65-rate.json"), &rate_json).ok();

    let mldsa_verdict = if dsa_rate.distinguishability_rate > 0.2 {
        "KEY-DISTINGUISHABLE — Rejection rate varies between keys"
    } else {
        "REJECTION RATE UNIFORM ✓ (signing is variable-time but key-independent)"
    };

    // ═══════════════════════════════════════════════
    // FIPS 205: SLH-DSA
    // ═══════════════════════════════════════════════
    println!("  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓");
    println!("  ┃  FIPS 205: SLH-DSA (SPHINCS+)                       ┃");
    println!("  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛");
    println!();

    let slh_result = run_slhdsa_timing(SlhDsaVariant::Shake128f, (samples / 20).max(100));
    let slh_json = serde_json::to_string_pretty(&slh_result).unwrap();
    std::fs::write(output_dir.join("slhdsa-128f.json"), &slh_json).ok();

    let slh_verdict = if slh_result.sign_cv > 0.05 {
        "VARIABLE-TIME SIGNING DETECTED"
    } else {
        "CONSTANT-TIME ✓"
    };

    // ═══════════════════════════════════════════════
    // SUMMARY
    // ═══════════════════════════════════════════════
    let overall = format!(
        "ML-KEM: {} | ML-DSA: {} | SLH-DSA: {}",
        mlkem_verdict, mldsa_verdict, slh_verdict
    );

    println!();
    println!("  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓");
    println!("  ┃  AUDIT SUMMARY                                       ┃");
    println!("  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛");
    println!();
    println!("  FIPS 203 (ML-KEM):");
    println!("    pqcrypto-kyber (asm):   d={:.4} — {}", mlkem_d, mlkem_verdict);
    println!("    ml-kem (pure Rust):     d={:.4} — {}", pure_d, pure_verdict);
    println!();
    println!("  FIPS 204 (ML-DSA):");
    println!("    Signing CV:             {:.2}%", dsa_timing.sign_cv * 100.0);
    println!("    Key-dependent CV:       {:.2}%", dsa_timing.key_cv * 100.0);
    println!("    Iteration entropy:      {:.3} bits/sig", dsa_reject.entropy_bits);
    println!("    Iteration accuracy:     {:.1}%", dsa_reject.validation_accuracy * 100.0);
    println!("    Rejection rate CV:      {:.2}%", dsa_rate.rejection_rate_cv * 100.0);
    println!("    Keys distinguishable:   {:.1}%", dsa_rate.distinguishability_rate * 100.0);
    println!("    Verdict:                {}", mldsa_verdict);
    println!();
    println!("  FIPS 205 (SLH-DSA):");
    println!("    Signing CV:             {:.4}", slh_result.sign_cv);
    println!("    Message CV:             {:.4}", slh_result.msg_cv);
    println!("    Verdict:                {}", slh_verdict);
    println!();

    let report = AuditReport {
        timestamp, platform: info.chip,
        tool_version: "0.3.0".into(), author: "sectio-aurea-q".into(),
        mlkem_768_cohens_d: mlkem_d, mlkem_768_verdict: mlkem_verdict.into(),
        mlkem_pure_rust_d: pure_d, mlkem_pure_rust_verdict: pure_verdict.into(),
        mldsa_sign_cv: dsa_timing.sign_cv, mldsa_key_cv: dsa_timing.key_cv,
        mldsa_iteration_entropy: dsa_reject.entropy_bits,
        mldsa_iteration_accuracy: dsa_reject.validation_accuracy,
        mldsa_reject_rate_cv: dsa_rate.rejection_rate_cv,
        mldsa_distinguishable_pct: dsa_rate.distinguishability_rate,
        mldsa_verdict: mldsa_verdict.into(),
        slhdsa_sign_cv: slh_result.sign_cv, slhdsa_msg_cv: slh_result.msg_cv,
        slhdsa_verdict: slh_verdict.into(),
        overall_verdict: overall.clone(),
    };

    // Save JSON
    let json = serde_json::to_string_pretty(&report).unwrap();
    std::fs::write(output_dir.join("audit-summary.json"), &json).ok();

    // Generate HTML
    let html = generate_audit_html(&report);
    std::fs::write(output_dir.join("audit-report.html"), &html).ok();

    println!("  Output: {}/", output_dir.display());
    println!("    audit-report.html    ← Open this in your browser");
    println!("    audit-summary.json");
    println!("    mlkem-768-asm.json");
    println!("    mlkem-768-pure-rust.json");
    println!("    mldsa-65-timing.json");
    println!("    mldsa-65-rejection.json");
    println!("    mldsa-65-rate.json");
    println!("    slhdsa-128f.json");
    println!();

    report
}

fn generate_audit_html(r: &AuditReport) -> String {
    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VÄRN-60 (Anu) — PQC Security Audit Report</title>
<style>
:root {{ --bg: #0a0a0f; --fg: #e0e0e0; --accent: #00ff88; --warn: #ff6644;
         --card: #12121a; --border: #2a2a3a; --dim: #666; }}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ background: var(--bg); color: var(--fg); font-family: 'JetBrains Mono', 'Fira Code', monospace;
        line-height: 1.6; padding: 40px; max-width: 1000px; margin: 0 auto; }}
h1 {{ color: var(--accent); font-size: 2em; margin-bottom: 10px; letter-spacing: 4px; }}
h2 {{ color: var(--accent); font-size: 1.3em; margin: 30px 0 15px; padding-bottom: 5px;
      border-bottom: 1px solid var(--border); }}
.subtitle {{ color: var(--dim); font-size: 0.9em; margin-bottom: 30px; }}
.card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px;
         padding: 20px; margin: 15px 0; }}
.result-row {{ display: flex; justify-content: space-between; padding: 8px 0;
              border-bottom: 1px solid var(--border); }}
.result-row:last-child {{ border-bottom: none; }}
.label {{ color: var(--dim); }}
.value {{ font-weight: bold; }}
.safe {{ color: var(--accent); }}
.warn {{ color: var(--warn); }}
.info {{ color: #44aaff; }}
.badge {{ display: inline-block; padding: 2px 12px; border-radius: 4px; font-size: 0.8em; }}
.badge-safe {{ background: #00ff8822; color: var(--accent); border: 1px solid var(--accent); }}
.badge-warn {{ background: #ff664422; color: var(--warn); border: 1px solid var(--warn); }}
.badge-info {{ background: #44aaff22; color: #44aaff; border: 1px solid #44aaff; }}
.header-meta {{ display: flex; gap: 30px; margin: 20px 0; flex-wrap: wrap; }}
.meta-item {{ color: var(--dim); font-size: 0.85em; }}
.footer {{ margin-top: 50px; padding-top: 20px; border-top: 1px solid var(--border);
           color: var(--dim); font-size: 0.8em; text-align: center; }}
</style>
</head>
<body>
<h1>⟁ VÄRN-60 (Anu)</h1>
<p class="subtitle">Automated Side-Channel Scanner for Post-Quantum Cryptography</p>

<div class="header-meta">
  <span class="meta-item">Platform: {platform}</span>
  <span class="meta-item">Date: {timestamp}</span>
  <span class="meta-item">Version: {version}</span>
  <span class="meta-item">Author: {author}</span>
</div>

<h2>FIPS 203 — ML-KEM (Kyber)</h2>
<div class="card">
  <div class="result-row">
    <span class="label">pqcrypto-kyber (AARCH64 assembly)</span>
    <span class="value">d = {mlkem_d:.4} <span class="badge {mlkem_badge_class}">{mlkem_verdict}</span></span>
  </div>
  <div class="result-row">
    <span class="label">ml-kem (pure Rust / LLVM)</span>
    <span class="value">d = {pure_d:.4} <span class="badge {pure_badge_class}">{pure_verdict}</span></span>
  </div>
</div>

<h2>FIPS 204 — ML-DSA (Dilithium)</h2>
<div class="card">
  <div class="result-row">
    <span class="label">Signing variance (CV)</span>
    <span class="value warn">{mldsa_sign_cv:.2}%</span>
  </div>
  <div class="result-row">
    <span class="label">Key-dependent variance (CV)</span>
    <span class="value warn">{mldsa_key_cv:.2}%</span>
  </div>
  <div class="result-row">
    <span class="label">Iteration entropy</span>
    <span class="value info">{mldsa_entropy:.3} bits/signature</span>
  </div>
  <div class="result-row">
    <span class="label">Iteration extraction accuracy</span>
    <span class="value info">{mldsa_accuracy:.1}%</span>
  </div>
  <div class="result-row">
    <span class="label">Rejection rate CV (across keys)</span>
    <span class="value">{mldsa_rate_cv:.2}%</span>
  </div>
  <div class="result-row">
    <span class="label">Key-pair distinguishability</span>
    <span class="value">{mldsa_dist:.1}%</span>
  </div>
  <div class="result-row">
    <span class="label">Verdict</span>
    <span class="value"><span class="badge badge-info">{mldsa_verdict}</span></span>
  </div>
</div>

<h2>FIPS 205 — SLH-DSA (SPHINCS+)</h2>
<div class="card">
  <div class="result-row">
    <span class="label">Signing variance (CV)</span>
    <span class="value">{slh_sign_cv:.4}</span>
  </div>
  <div class="result-row">
    <span class="label">Message-dependent variance (CV)</span>
    <span class="value">{slh_msg_cv:.4}</span>
  </div>
  <div class="result-row">
    <span class="label">Verdict</span>
    <span class="value"><span class="badge {slh_badge_class}">{slh_verdict}</span></span>
  </div>
</div>

<h2>Overall Assessment</h2>
<div class="card">
  <p style="font-size: 1.1em;">{overall}</p>
</div>

<div class="footer">
  <p>VÄRN-60 (Anu) v{version} — sectio-aurea-q — meg.depth@proton.me</p>
  <p>This report was generated automatically. All measurements are empirical.</p>
  <p>No theoretical models. No approximations. Only data.</p>
</div>
</body>
</html>"#,
    platform = r.platform,
    timestamp = r.timestamp,
    version = r.tool_version,
    author = r.author,
    mlkem_d = r.mlkem_768_cohens_d,
    mlkem_verdict = r.mlkem_768_verdict,
    mlkem_badge_class = if r.mlkem_768_cohens_d > 0.2 { "badge-warn" } else { "badge-safe" },
    pure_d = r.mlkem_pure_rust_d,
    pure_verdict = r.mlkem_pure_rust_verdict,
    pure_badge_class = if r.mlkem_pure_rust_d > 0.2 { "badge-warn" } else { "badge-safe" },
    mldsa_sign_cv = r.mldsa_sign_cv * 100.0,
    mldsa_key_cv = r.mldsa_key_cv * 100.0,
    mldsa_entropy = r.mldsa_iteration_entropy,
    mldsa_accuracy = r.mldsa_iteration_accuracy * 100.0,
    mldsa_rate_cv = r.mldsa_reject_rate_cv * 100.0,
    mldsa_dist = r.mldsa_distinguishable_pct * 100.0,
    mldsa_verdict = r.mldsa_verdict,
    slh_sign_cv = r.slhdsa_sign_cv,
    slh_msg_cv = r.slhdsa_msg_cv,
    slh_verdict = r.slhdsa_verdict,
    slh_badge_class = if r.slhdsa_sign_cv > 0.05 { "badge-warn" } else { "badge-safe" },
    overall = r.overall_verdict,
    )
}
