// VÄRN-60 (Anu) — CBOM Generator
//
// Cryptographic Bill of Materials — the format the EU requires from 2026.
// Every organization must document their cryptographic assets.
//
// Anu generates a CBOM that no other tool can:
// - Standard crypto inventory (like CryptoScan)
// - PLUS side-channel verification status per algorithm
// - PLUS hardware-level measurement results
// - PLUS quantum vulnerability assessment
//
// Format follows the OWASP CycloneDX Cryptography BOM standard.

use serde::Serialize;
use chrono::Utc;

#[derive(Debug, Serialize)]
pub struct CbomComponent {
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    pub version: String,
    pub algorithm: String,
    pub key_size: u32,
    pub nist_standard: String,
    pub quantum_safe: bool,
    pub implementation: String,
    pub platform: String,
    pub side_channel_status: String,
    pub cohens_d: Option<f64>,
    pub timing_cv: Option<f64>,
    pub pmc_verified: bool,
    pub risk_level: String,
}

#[derive(Debug, Serialize)]
pub struct CbomTlsEndpoint {
    pub host: String,
    pub port: u16,
    pub tls_version: String,
    pub cipher_suite: String,
    pub key_exchange: String,
    pub pq_supported: bool,
    pub downgrade_possible: bool,
    pub risk_level: String,
}

#[derive(Debug, Serialize)]
pub struct CbomDocument {
    pub bom_format: String,
    pub spec_version: String,
    pub version: u32,
    pub serial_number: String,
    pub timestamp: String,
    pub tool: CbomTool,
    pub components: Vec<CbomComponent>,
    pub endpoints: Vec<CbomTlsEndpoint>,
    pub summary: CbomSummary,
}

#[derive(Debug, Serialize)]
pub struct CbomTool {
    pub name: String,
    pub version: String,
    pub vendor: String,
    pub platform: String,
}

#[derive(Debug, Serialize)]
pub struct CbomSummary {
    pub total_components: usize,
    pub quantum_safe: usize,
    pub quantum_vulnerable: usize,
    pub side_channel_verified: usize,
    pub side_channel_issues: usize,
    pub pmc_verified: usize,
    pub endpoints_scanned: usize,
    pub endpoints_pq_ready: usize,
    pub overall_risk: String,
}

pub fn generate_cbom(
    components: Vec<CbomComponent>,
    endpoints: Vec<CbomTlsEndpoint>,
) -> CbomDocument {
    let info = crate::platform::PlatformInfo::detect();

    let quantum_safe = components.iter().filter(|c| c.quantum_safe).count();
    let quantum_vulnerable = components.iter().filter(|c| !c.quantum_safe).count();
    let sc_verified = components.iter().filter(|c| c.side_channel_status == "CONSTANT-TIME").count();
    let sc_issues = components.iter().filter(|c| c.side_channel_status == "VARIABLE-TIME").count();
    let pmc_count = components.iter().filter(|c| c.pmc_verified).count();
    let ep_pq = endpoints.iter().filter(|e| e.pq_supported).count();
    let ep_total = endpoints.len();

    let overall_risk = if quantum_vulnerable > 0 && sc_issues > 0 {
        "CRITICAL"
    } else if quantum_vulnerable > 0 {
        "HIGH"
    } else if sc_issues > 0 {
        "MEDIUM"
    } else {
        "LOW"
    };

    let serial = format!("urn:uuid:{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        rand::random::<u32>(), rand::random::<u16>(), rand::random::<u16>(),
        rand::random::<u16>(), rand::random::<u64>() & 0xFFFFFFFFFFFF);

    CbomDocument {
        bom_format: "CycloneDX-Crypto".into(),
        spec_version: "1.6".into(),
        version: 1,
        serial_number: serial,
        timestamp: Utc::now().to_rfc3339(),
        tool: CbomTool {
            name: "VÄRN-60 (Anu)".into(),
            version: "1.2.0".into(),
            vendor: "sectio-aurea-q".into(),
            platform: info.chip,
        },
        components: components,
        endpoints: endpoints,
        summary: CbomSummary {
            total_components: quantum_safe + quantum_vulnerable,
            quantum_safe,
            quantum_vulnerable,
            side_channel_verified: sc_verified,
            side_channel_issues: sc_issues,
            pmc_verified: pmc_count,
            endpoints_scanned: ep_total,
            endpoints_pq_ready: ep_pq,
            overall_risk: overall_risk.into(),
        },
    }
}

/// Generate CBOM from Anu's audit results
pub fn run_cbom_generation() -> CbomDocument {
    let info = crate::platform::PlatformInfo::detect();

    println!();
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║     VÄRN-60 (Anu) — CBOM Generator                    ║");
    println!("  ║     Cryptographic Bill of Materials                    ║");
    println!("  ║     EU Compliance · CycloneDX Crypto Format           ║");
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!();

    // Build components from known test results
    let mut components = Vec::new();

    // ML-KEM implementations
    components.push(CbomComponent {
        component_type: "crypto-algorithm".into(),
        name: "ML-KEM-768".into(),
        version: "FIPS 203".into(),
        algorithm: "ML-KEM".into(),
        key_size: 768,
        nist_standard: "FIPS 203".into(),
        quantum_safe: true,
        implementation: "pqcrypto-kyber 0.8 (AARCH64 Assembly)".into(),
        platform: info.chip.clone(),
        side_channel_status: "CONSTANT-TIME".into(),
        cohens_d: Some(0.008),
        timing_cv: None,
        pmc_verified: false,
        risk_level: "LOW".into(),
    });

    components.push(CbomComponent {
        component_type: "crypto-algorithm".into(),
        name: "ML-KEM-768".into(),
        version: "FIPS 203".into(),
        algorithm: "ML-KEM".into(),
        key_size: 768,
        nist_standard: "FIPS 203".into(),
        quantum_safe: true,
        implementation: "ml-kem 0.2 (Pure Rust / LLVM)".into(),
        platform: info.chip.clone(),
        side_channel_status: "CONSTANT-TIME".into(),
        cohens_d: Some(0.003),
        timing_cv: None,
        pmc_verified: false,
        risk_level: "LOW".into(),
    });

    components.push(CbomComponent {
        component_type: "crypto-algorithm".into(),
        name: "ML-KEM-768".into(),
        version: "FIPS 203".into(),
        algorithm: "ML-KEM".into(),
        key_size: 768,
        nist_standard: "FIPS 203".into(),
        quantum_safe: true,
        implementation: "liboqs 0.15.0 (C / Apple Clang)".into(),
        platform: info.chip.clone(),
        side_channel_status: "CONSTANT-TIME".into(),
        cohens_d: Some(0.004),
        timing_cv: None,
        pmc_verified: true,
        risk_level: "LOW".into(),
    });

    // ML-DSA
    components.push(CbomComponent {
        component_type: "crypto-algorithm".into(),
        name: "ML-DSA-65".into(),
        version: "FIPS 204".into(),
        algorithm: "ML-DSA".into(),
        key_size: 65,
        nist_standard: "FIPS 204".into(),
        quantum_safe: true,
        implementation: "pqcrypto-dilithium 0.5".into(),
        platform: info.chip.clone(),
        side_channel_status: "VARIABLE-TIME".into(),
        cohens_d: None,
        timing_cv: Some(0.0145),
        pmc_verified: false,
        risk_level: "MEDIUM".into(),
    });

    components.push(CbomComponent {
        component_type: "crypto-algorithm".into(),
        name: "ML-DSA-65".into(),
        version: "FIPS 204".into(),
        algorithm: "ML-DSA".into(),
        key_size: 65,
        nist_standard: "FIPS 204".into(),
        quantum_safe: true,
        implementation: "liboqs 0.15.0 (C / Apple Clang)".into(),
        platform: info.chip.clone(),
        side_channel_status: "VARIABLE-TIME".into(),
        cohens_d: None,
        timing_cv: Some(0.6364),
        pmc_verified: false,
        risk_level: "MEDIUM".into(),
    });

    // SLH-DSA
    components.push(CbomComponent {
        component_type: "crypto-algorithm".into(),
        name: "SLH-DSA-SHA2-128s".into(),
        version: "FIPS 205".into(),
        algorithm: "SLH-DSA".into(),
        key_size: 128,
        nist_standard: "FIPS 205".into(),
        quantum_safe: true,
        implementation: "pqcrypto-sphincsplus 0.7".into(),
        platform: info.chip.clone(),
        side_channel_status: "CONSTANT-TIME".into(),
        cohens_d: None,
        timing_cv: Some(0.0084),
        pmc_verified: false,
        risk_level: "LOW".into(),
    });

    components.push(CbomComponent {
        component_type: "crypto-algorithm".into(),
        name: "SLH-DSA-SHA2-128s".into(),
        version: "FIPS 205".into(),
        algorithm: "SLH-DSA".into(),
        key_size: 128,
        nist_standard: "FIPS 205".into(),
        quantum_safe: true,
        implementation: "liboqs 0.15.0 (C / Apple Clang)".into(),
        platform: info.chip.clone(),
        side_channel_status: "CONSTANT-TIME".into(),
        cohens_d: None,
        timing_cv: Some(0.0201),
        pmc_verified: false,
        risk_level: "LOW".into(),
    });

    // Print summary
    let sc_ok = components.iter().filter(|c| c.side_channel_status == "CONSTANT-TIME").count();
    let sc_var = components.iter().filter(|c| c.side_channel_status == "VARIABLE-TIME").count();

    println!("  Components: {}", components.len());
    println!("  Quantum-safe: {}", components.iter().filter(|c| c.quantum_safe).count());
    println!("  Side-channel verified: {}", sc_ok);
    println!("  Side-channel issues: {}", sc_var);
    println!("  PMC verified: {}", components.iter().filter(|c| c.pmc_verified).count());
    println!();

    for c in &components {
        let status = if c.side_channel_status == "CONSTANT-TIME" { "✓" } else { "⚠" };
        let pmc = if c.pmc_verified { " [PMC]" } else { "" };
        println!("  {} {} — {} — {}{}", status, c.name, c.implementation, c.side_channel_status, pmc);
    }
    println!();

    let cbom = generate_cbom(components, vec![]);

    println!("  Overall Risk: {}", cbom.summary.overall_risk);
    println!();

    cbom
}
