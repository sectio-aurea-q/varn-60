// VÄRN-60 (Anu) — Code Scanner
//
// anu scan-code /path/to/repo
//
// Scans any codebase for cryptographic usage and classifies:
// - VULNERABLE: RSA, ECDSA, DH, MD5, SHA-1, RC4, DES, 3DES
// - PARTIAL:    AES-128 (upgrade to AES-256 recommended)
// - SAFE:       AES-256, ML-KEM, ML-DSA, SLH-DSA, ChaCha20
//
// CryptoScan finds "here is RSA" and stops.
// Anu finds "here is RSA" AND checks if the replacement is safe.
// Discovery + Verification in one tool.

use std::fs;
use std::path::{Path, PathBuf};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct CryptoFinding {
    pub file: String,
    pub line: usize,
    pub algorithm: String,
    pub category: String,    // KEM, Signature, Hash, Cipher, KeyExchange
    pub risk: String,        // VULNERABLE, PARTIAL, SAFE
    pub detail: String,
    pub recommendation: String,
}

#[derive(Debug, Serialize)]
pub struct CodeScanResult {
    pub path: String,
    pub files_scanned: usize,
    pub findings: Vec<CryptoFinding>,
    pub vulnerable: usize,
    pub partial: usize,
    pub safe: usize,
    pub summary: String,
}

struct Pattern {
    pattern: &'static str,
    algorithm: &'static str,
    category: &'static str,
    risk: &'static str,
    recommendation: &'static str,
}

const PATTERNS: &[Pattern] = &[
    // ═══ VULNERABLE — quantum-breakable ═══
    // RSA
    Pattern { pattern: "RSA", algorithm: "RSA", category: "KeyExchange", risk: "VULNERABLE",
              recommendation: "Replace with ML-KEM (FIPS 203)" },
    Pattern { pattern: "rsa", algorithm: "RSA", category: "KeyExchange", risk: "VULNERABLE",
              recommendation: "Replace with ML-KEM (FIPS 203)" },
    Pattern { pattern: "PKCS1", algorithm: "RSA-PKCS1", category: "Signature", risk: "VULNERABLE",
              recommendation: "Replace with ML-DSA (FIPS 204)" },
    Pattern { pattern: "pkcs1", algorithm: "RSA-PKCS1", category: "Signature", risk: "VULNERABLE",
              recommendation: "Replace with ML-DSA (FIPS 204)" },
    // ECDSA / ECC
    Pattern { pattern: "ECDSA", algorithm: "ECDSA", category: "Signature", risk: "VULNERABLE",
              recommendation: "Replace with ML-DSA (FIPS 204)" },
    Pattern { pattern: "ecdsa", algorithm: "ECDSA", category: "Signature", risk: "VULNERABLE",
              recommendation: "Replace with ML-DSA (FIPS 204)" },
    Pattern { pattern: "secp256k1", algorithm: "ECDSA-secp256k1", category: "Signature", risk: "VULNERABLE",
              recommendation: "Replace with ML-DSA (FIPS 204)" },
    Pattern { pattern: "P-256", algorithm: "ECDSA-P256", category: "Signature", risk: "VULNERABLE",
              recommendation: "Replace with ML-DSA (FIPS 204)" },
    Pattern { pattern: "P-384", algorithm: "ECDSA-P384", category: "Signature", risk: "VULNERABLE",
              recommendation: "Replace with ML-DSA (FIPS 204)" },
    Pattern { pattern: "Ed25519", algorithm: "Ed25519", category: "Signature", risk: "VULNERABLE",
              recommendation: "Replace with ML-DSA (FIPS 204)" },
    Pattern { pattern: "ed25519", algorithm: "Ed25519", category: "Signature", risk: "VULNERABLE",
              recommendation: "Replace with ML-DSA (FIPS 204)" },
    // Diffie-Hellman
    Pattern { pattern: "DiffieHellman", algorithm: "DH", category: "KeyExchange", risk: "VULNERABLE",
              recommendation: "Replace with ML-KEM (FIPS 203)" },
    Pattern { pattern: "diffie_hellman", algorithm: "DH", category: "KeyExchange", risk: "VULNERABLE",
              recommendation: "Replace with ML-KEM (FIPS 203)" },
    Pattern { pattern: "X25519", algorithm: "X25519", category: "KeyExchange", risk: "VULNERABLE",
              recommendation: "Replace with ML-KEM or X25519_MLKEM768 hybrid" },
    Pattern { pattern: "x25519", algorithm: "X25519", category: "KeyExchange", risk: "VULNERABLE",
              recommendation: "Replace with ML-KEM or X25519_MLKEM768 hybrid" },
    // Weak hashes
    Pattern { pattern: "MD5", algorithm: "MD5", category: "Hash", risk: "VULNERABLE",
              recommendation: "Replace with SHA-256 or SHA-3" },
    Pattern { pattern: "md5", algorithm: "MD5", category: "Hash", risk: "VULNERABLE",
              recommendation: "Replace with SHA-256 or SHA-3" },
    Pattern { pattern: "SHA1", algorithm: "SHA-1", category: "Hash", risk: "VULNERABLE",
              recommendation: "Replace with SHA-256 or SHA-3" },
    Pattern { pattern: "sha1", algorithm: "SHA-1", category: "Hash", risk: "VULNERABLE",
              recommendation: "Replace with SHA-256 or SHA-3" },
    Pattern { pattern: "SHA-1", algorithm: "SHA-1", category: "Hash", risk: "VULNERABLE",
              recommendation: "Replace with SHA-256 or SHA-3" },
    // Weak ciphers
    Pattern { pattern: "DES", algorithm: "DES", category: "Cipher", risk: "VULNERABLE",
              recommendation: "Replace with AES-256-GCM" },
    Pattern { pattern: "3DES", algorithm: "3DES", category: "Cipher", risk: "VULNERABLE",
              recommendation: "Replace with AES-256-GCM" },
    Pattern { pattern: "RC4", algorithm: "RC4", category: "Cipher", risk: "VULNERABLE",
              recommendation: "Replace with AES-256-GCM or ChaCha20-Poly1305" },
    Pattern { pattern: "rc4", algorithm: "RC4", category: "Cipher", risk: "VULNERABLE",
              recommendation: "Replace with AES-256-GCM or ChaCha20-Poly1305" },
    Pattern { pattern: "Blowfish", algorithm: "Blowfish", category: "Cipher", risk: "VULNERABLE",
              recommendation: "Replace with AES-256-GCM" },

    // ═══ PARTIAL — quantum-safe but suboptimal ═══
    Pattern { pattern: "AES-128", algorithm: "AES-128", category: "Cipher", risk: "PARTIAL",
              recommendation: "Upgrade to AES-256 for post-quantum safety margin" },
    Pattern { pattern: "aes_128", algorithm: "AES-128", category: "Cipher", risk: "PARTIAL",
              recommendation: "Upgrade to AES-256 for post-quantum safety margin" },
    Pattern { pattern: "AES128", algorithm: "AES-128", category: "Cipher", risk: "PARTIAL",
              recommendation: "Upgrade to AES-256 for post-quantum safety margin" },
    Pattern { pattern: "SHA-256", algorithm: "SHA-256", category: "Hash", risk: "PARTIAL",
              recommendation: "Consider SHA-384 for long-term post-quantum safety" },

    // ═══ SAFE — quantum-resistant ═══
    Pattern { pattern: "ML-KEM", algorithm: "ML-KEM", category: "KEM", risk: "SAFE",
              recommendation: "Quantum-safe ✓" },
    Pattern { pattern: "ml_kem", algorithm: "ML-KEM", category: "KEM", risk: "SAFE",
              recommendation: "Quantum-safe ✓" },
    Pattern { pattern: "mlkem", algorithm: "ML-KEM", category: "KEM", risk: "SAFE",
              recommendation: "Quantum-safe ✓" },
    Pattern { pattern: "Kyber", algorithm: "ML-KEM (Kyber)", category: "KEM", risk: "SAFE",
              recommendation: "Quantum-safe ✓" },
    Pattern { pattern: "kyber", algorithm: "ML-KEM (Kyber)", category: "KEM", risk: "SAFE",
              recommendation: "Quantum-safe ✓" },
    Pattern { pattern: "ML-DSA", algorithm: "ML-DSA", category: "Signature", risk: "SAFE",
              recommendation: "Quantum-safe ✓" },
    Pattern { pattern: "ml_dsa", algorithm: "ML-DSA", category: "Signature", risk: "SAFE",
              recommendation: "Quantum-safe ✓" },
    Pattern { pattern: "Dilithium", algorithm: "ML-DSA (Dilithium)", category: "Signature", risk: "SAFE",
              recommendation: "Quantum-safe ✓" },
    Pattern { pattern: "dilithium", algorithm: "ML-DSA (Dilithium)", category: "Signature", risk: "SAFE",
              recommendation: "Quantum-safe ✓" },
    Pattern { pattern: "SLH-DSA", algorithm: "SLH-DSA", category: "Signature", risk: "SAFE",
              recommendation: "Quantum-safe ✓" },
    Pattern { pattern: "SPHINCS", algorithm: "SLH-DSA (SPHINCS+)", category: "Signature", risk: "SAFE",
              recommendation: "Quantum-safe ✓" },
    Pattern { pattern: "sphincs", algorithm: "SLH-DSA (SPHINCS+)", category: "Signature", risk: "SAFE",
              recommendation: "Quantum-safe ✓" },
    Pattern { pattern: "AES-256", algorithm: "AES-256", category: "Cipher", risk: "SAFE",
              recommendation: "Quantum-safe ✓" },
    Pattern { pattern: "AES256", algorithm: "AES-256", category: "Cipher", risk: "SAFE",
              recommendation: "Quantum-safe ✓" },
    Pattern { pattern: "aes_256", algorithm: "AES-256", category: "Cipher", risk: "SAFE",
              recommendation: "Quantum-safe ✓" },
    Pattern { pattern: "ChaCha20", algorithm: "ChaCha20-Poly1305", category: "Cipher", risk: "SAFE",
              recommendation: "Quantum-safe ✓" },
    Pattern { pattern: "chacha20", algorithm: "ChaCha20-Poly1305", category: "Cipher", risk: "SAFE",
              recommendation: "Quantum-safe ✓" },
    Pattern { pattern: "SHA-384", algorithm: "SHA-384", category: "Hash", risk: "SAFE",
              recommendation: "Quantum-safe ✓" },
    Pattern { pattern: "SHA-512", algorithm: "SHA-512", category: "Hash", risk: "SAFE",
              recommendation: "Quantum-safe ✓" },
    Pattern { pattern: "SHA3", algorithm: "SHA-3", category: "Hash", risk: "SAFE",
              recommendation: "Quantum-safe ✓" },
    Pattern { pattern: "sha3", algorithm: "SHA-3", category: "Hash", risk: "SAFE",
              recommendation: "Quantum-safe ✓" },
];

fn is_scannable(path: &Path) -> bool {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    matches!(ext,
        "rs" | "c" | "h" | "cpp" | "hpp" | "cc" |
        "py" | "java" | "go" | "js" | "ts" |
        "rb" | "php" | "cs" | "swift" | "kt" |
        "toml" | "yaml" | "yml" | "json" | "xml" |
        "conf" | "cfg" | "ini" | "env" |
        "pem" | "key" | "crt" | "cert"
    )
}

fn scan_file(path: &Path, findings: &mut Vec<CryptoFinding>) {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };

    let file_str = path.to_string_lossy().to_string();

    for (line_num, line) in content.lines().enumerate() {
        // Skip comments (basic heuristic)
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*") {
            continue;
        }

        for pat in PATTERNS {
            if line.contains(pat.pattern) {
                // Avoid duplicate findings for same algorithm on same line
                let already = findings.iter().any(|f|
                    f.file == file_str && f.line == line_num + 1 && f.algorithm == pat.algorithm
                );
                if !already {
                    findings.push(CryptoFinding {
                        file: file_str.clone(),
                        line: line_num + 1,
                        algorithm: pat.algorithm.into(),
                        category: pat.category.into(),
                        risk: pat.risk.into(),
                        detail: trimmed.chars().take(120).collect(),
                        recommendation: pat.recommendation.into(),
                    });
                }
            }
        }
    }
}

fn walk_dir(dir: &Path, files: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // Skip hidden dirs, target, node_modules, .git
        if name.starts_with('.') || name == "target" || name == "node_modules" || name == "vendor" {
            continue;
        }

        if path.is_dir() {
            walk_dir(&path, files);
        } else if is_scannable(&path) {
            files.push(path);
        }
    }
}

pub fn run_code_scan(path: &str) -> CodeScanResult {
    println!();
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║     VÄRN-60 (Anu) — Code Scanner                      ║");
    println!("  ║     Cryptographic Inventory + Quantum Risk Assessment  ║");
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Scanning: {}", path);
    println!();

    let root = Path::new(path);
    let mut files = Vec::new();

    if root.is_file() {
        files.push(root.to_path_buf());
    } else {
        walk_dir(root, &mut files);
    }

    println!("  Files found: {}", files.len());

    let mut findings = Vec::new();
    for f in &files {
        scan_file(f, &mut findings);
    }

    // Sort by risk
    findings.sort_by(|a, b| {
        let risk_order = |r: &str| match r {
            "VULNERABLE" => 0,
            "PARTIAL" => 1,
            "SAFE" => 2,
            _ => 3,
        };
        risk_order(&a.risk).cmp(&risk_order(&b.risk))
    });

    let vulnerable = findings.iter().filter(|f| f.risk == "VULNERABLE").count();
    let partial = findings.iter().filter(|f| f.risk == "PARTIAL").count();
    let safe = findings.iter().filter(|f| f.risk == "SAFE").count();

    // Print findings
    println!("  Findings:    {}", findings.len());
    println!();

    if vulnerable > 0 {
        println!("  ── VULNERABLE (quantum-breakable) ──");
        for f in findings.iter().filter(|f| f.risk == "VULNERABLE") {
            println!("    ✗ {} (line {}) — {}", f.file, f.line, f.algorithm);
            println!("      → {}", f.recommendation);
        }
        println!();
    }

    if partial > 0 {
        println!("  ── PARTIAL (upgrade recommended) ──");
        for f in findings.iter().filter(|f| f.risk == "PARTIAL") {
            println!("    ⚠ {} (line {}) — {}", f.file, f.line, f.algorithm);
            println!("      → {}", f.recommendation);
        }
        println!();
    }

    if safe > 0 {
        println!("  ── SAFE (quantum-resistant) ──");
        for f in findings.iter().filter(|f| f.risk == "SAFE").take(20) {
            println!("    ✓ {} (line {}) — {}", f.file, f.line, f.algorithm);
        }
        if safe > 20 {
            println!("    ... and {} more", safe - 20);
        }
        println!();
    }

    // Summary
    println!("  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓");
    println!("  ┃  CODE SCAN SUMMARY                                   ┃");
    println!("  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛");
    println!();
    println!("  Files scanned:       {}", files.len());
    println!("  Total findings:      {}", findings.len());
    println!("  ✗ VULNERABLE:        {}", vulnerable);
    println!("  ⚠ PARTIAL:           {}", partial);
    println!("  ✓ SAFE:              {}", safe);
    println!();

    let summary = if vulnerable > 0 {
        format!("CRITICAL — {} quantum-vulnerable algorithms found", vulnerable)
    } else if partial > 0 {
        format!("MEDIUM — {} algorithms need upgrade", partial)
    } else if safe > 0 {
        format!("LOW — all {} algorithms are quantum-safe", safe)
    } else {
        "NO CRYPTO FOUND".into()
    };

    println!("  Risk: {}", summary);
    println!();

    CodeScanResult {
        path: path.into(),
        files_scanned: files.len(),
        findings,
        vulnerable,
        partial,
        safe,
        summary,
    }
}
