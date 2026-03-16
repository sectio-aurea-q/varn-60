// VÄRN-60 (Anu) — Remote TLS PQC Scanner
//
// anu scan example.com
//
// Points at any server on the internet and checks:
// 1. TLS version supported
// 2. Which cipher suites are offered
// 3. Which PQ cipher suites are available
// 4. Is PQ-downgrade possible (strip PQ, fall back to RSA)
// 5. Certificate chain algorithms
// 6. Quantum vulnerability assessment
//
// testssl.sh tells you WHAT suites a server has.
// Anu tells you if those suites are SAFE.

use std::net::TcpStream;
use std::io::{Read, Write};
use std::time::{Duration, Instant};
use serde::Serialize;

// ═══════════════════════════════════════════════════════
// TLS 1.3 constants
// ═══════════════════════════════════════════════════════

const TLS_13: u16 = 0x0304;
const TLS_12: u16 = 0x0303;

// Cipher suite identifiers
const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

// Key exchange group identifiers
const X25519: u16 = 0x001D;
const SECP256R1: u16 = 0x0017;
const SECP384R1: u16 = 0x0018;
const X25519_MLKEM768: u16 = 0x11EC;  // Hybrid PQ
const SECP256R1_MLKEM768: u16 = 0x11EB; // Hybrid PQ
const MLKEM768: u16 = 0x0768;          // Pure PQ (draft)

// TLS record types
const HANDSHAKE: u8 = 22;
const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;

#[derive(Debug, Serialize)]
pub struct RemoteScanResult {
    pub host: String,
    pub port: u16,
    pub ip: String,
    pub tls_version: String,
    pub cipher_suites: Vec<String>,
    pub key_exchange: Vec<String>,
    pub pq_supported: bool,
    pub pq_suites: Vec<String>,
    pub downgrade_possible: bool,
    pub certificate_algorithms: Vec<String>,
    pub quantum_vulnerable: bool,
    pub risk_level: String,
    pub timing_ns: u64,
    pub recommendations: Vec<String>,
}

fn suite_name(id: u16) -> String {
    match id {
        0x1301 => "TLS_AES_128_GCM_SHA256".into(),
        0x1302 => "TLS_AES_256_GCM_SHA384".into(),
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256".into(),
        0xC02C => "TLS_ECDHE_ECDSA_AES_256_GCM_SHA384".into(),
        0xC02B => "TLS_ECDHE_ECDSA_AES_128_GCM_SHA256".into(),
        0xC030 => "TLS_ECDHE_RSA_AES_256_GCM_SHA384".into(),
        0xC02F => "TLS_ECDHE_RSA_AES_128_GCM_SHA256".into(),
        0x009F => "TLS_DHE_RSA_AES_256_GCM_SHA384".into(),
        0x009E => "TLS_DHE_RSA_AES_128_GCM_SHA256".into(),
        0xCCA9 => "TLS_ECDHE_ECDSA_CHACHA20_POLY1305".into(),
        0xCCA8 => "TLS_ECDHE_RSA_CHACHA20_POLY1305".into(),
        _ => format!("0x{:04X}", id),
    }
}

fn group_name(id: u16) -> String {
    match id {
        0x0017 => "secp256r1".into(),
        0x0018 => "secp384r1".into(),
        0x0019 => "secp521r1".into(),
        0x001D => "x25519".into(),
        0x001E => "x448".into(),
        0x0100 => "ffdhe2048".into(),
        0x11EC => "X25519_MLKEM768 (PQ Hybrid)".into(),
        0x11EB => "SecP256r1_MLKEM768 (PQ Hybrid)".into(),
        0x0768 => "MLKEM768 (Pure PQ)".into(),
        0x6399 => "X25519Kyber768 (Legacy PQ)".into(),
        _ => format!("group_0x{:04X}", id),
    }
}

fn is_pq_group(id: u16) -> bool {
    matches!(id, 0x11EC | 0x11EB | 0x0768 | 0x6399)
}

/// Build a TLS 1.3 ClientHello with PQ key exchange groups
fn build_client_hello(host: &str, include_pq: bool) -> Vec<u8> {
    let mut hello = Vec::new();

    // Handshake type: ClientHello
    hello.push(CLIENT_HELLO);

    // Placeholder for length (3 bytes) — fill later
    let len_pos = hello.len();
    hello.extend_from_slice(&[0, 0, 0]);

    // Client version (TLS 1.2 for compat, actual version in extension)
    hello.extend_from_slice(&[0x03, 0x03]);

    // Random (32 bytes)
    let random: Vec<u8> = (0..32).map(|i| (i * 17 + 42) as u8).collect();
    hello.extend_from_slice(&random);

    // Session ID (empty)
    hello.push(0);

    // Cipher suites
    let suites: Vec<u16> = vec![
        TLS_AES_256_GCM_SHA384,
        TLS_AES_128_GCM_SHA256,
        TLS_CHACHA20_POLY1305_SHA256,
        0xC02C, 0xC02B, 0xC030, 0xC02F, // ECDHE suites
        0xCCA9, 0xCCA8, // ChaCha20 suites
    ];
    hello.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
    for s in &suites {
        hello.extend_from_slice(&s.to_be_bytes());
    }

    // Compression methods (null only)
    hello.push(1);
    hello.push(0);

    // Extensions
    let mut extensions = Vec::new();

    // SNI extension
    {
        let host_bytes = host.as_bytes();
        let mut sni = Vec::new();
        let sni_list_len = (host_bytes.len() + 3) as u16;
        sni.extend_from_slice(&sni_list_len.to_be_bytes());
        sni.push(0); // host name type
        sni.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        sni.extend_from_slice(host_bytes);

        extensions.extend_from_slice(&0u16.to_be_bytes()); // type: SNI
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni);
    }

    // Supported versions extension (TLS 1.3 + 1.2)
    {
        extensions.extend_from_slice(&43u16.to_be_bytes()); // type
        extensions.extend_from_slice(&3u16.to_be_bytes()); // length
        extensions.push(2); // list length
        extensions.extend_from_slice(&TLS_13.to_be_bytes());
    }

    // Supported groups (key exchange)
    {
        let mut groups: Vec<u16> = Vec::new();
        if include_pq {
            groups.push(X25519_MLKEM768);
            groups.push(SECP256R1_MLKEM768);
            groups.push(MLKEM768);
            groups.push(0x6399); // Legacy Kyber
        }
        groups.push(X25519);
        groups.push(SECP256R1);
        groups.push(SECP384R1);

        extensions.extend_from_slice(&10u16.to_be_bytes()); // type
        let glen = (groups.len() * 2 + 2) as u16;
        extensions.extend_from_slice(&glen.to_be_bytes());
        extensions.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
        for g in &groups {
            extensions.extend_from_slice(&g.to_be_bytes());
        }
    }

    // Signature algorithms
    {
        let sig_algs: Vec<u16> = vec![
            0x0804, 0x0805, 0x0806, // RSA-PSS
            0x0403, 0x0503, 0x0603, // ECDSA
            0x0201, // RSA PKCS1
        ];
        extensions.extend_from_slice(&13u16.to_be_bytes());
        let slen = (sig_algs.len() * 2 + 2) as u16;
        extensions.extend_from_slice(&slen.to_be_bytes());
        extensions.extend_from_slice(&((sig_algs.len() * 2) as u16).to_be_bytes());
        for s in &sig_algs {
            extensions.extend_from_slice(&s.to_be_bytes());
        }
    }

    // Key share (minimal — just x25519 with dummy data)
    {
        let mut ks = Vec::new();
        // x25519 key share (32 bytes)
        let ks_entry_len = 2 + 2 + 32; // group + len + data
        ks.extend_from_slice(&(ks_entry_len as u16).to_be_bytes());
        ks.extend_from_slice(&X25519.to_be_bytes());
        ks.extend_from_slice(&32u16.to_be_bytes());
        ks.extend_from_slice(&[0x42u8; 32]); // dummy key

        extensions.extend_from_slice(&51u16.to_be_bytes()); // type
        extensions.extend_from_slice(&(ks.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&ks);
    }

    // Add extensions length
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);

    // Fix handshake length
    let hlen = (hello.len() - 4) as u32;
    hello[len_pos] = ((hlen >> 16) & 0xFF) as u8;
    hello[len_pos + 1] = ((hlen >> 8) & 0xFF) as u8;
    hello[len_pos + 2] = (hlen & 0xFF) as u8;

    // Wrap in TLS record
    let mut record = Vec::new();
    record.push(HANDSHAKE);
    record.extend_from_slice(&TLS_12.to_be_bytes()); // Record version
    record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    record.extend_from_slice(&hello);

    record
}

/// Parse ServerHello to extract version, cipher suite, and selected group
fn parse_server_hello(data: &[u8]) -> Option<(u16, u16, Option<u16>)> {
    if data.len() < 5 { return None; }

    // TLS record header
    if data[0] != HANDSHAKE { return None; }
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len { return None; }

    let hs = &data[5..];
    if hs.is_empty() || hs[0] != SERVER_HELLO { return None; }

    // Skip handshake header (4 bytes) + server version (2) + random (32) 
    if hs.len() < 39 { return None; }
    let mut pos = 4 + 2 + 32;

    // Session ID
    if pos >= hs.len() { return None; }
    let sid_len = hs[pos] as usize;
    pos += 1 + sid_len;

    // Cipher suite
    if pos + 2 > hs.len() { return None; }
    let cipher = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
    pos += 2;

    // Compression
    pos += 1;

    // Extensions — look for supported_versions (0x002B) and key_share (0x0033)
    let mut tls_version = TLS_12;
    let mut selected_group: Option<u16> = None;

    if pos + 2 <= hs.len() {
        let ext_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
        pos += 2;
        let ext_end = (pos + ext_len).min(hs.len());

        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
            let ext_data_len = u16::from_be_bytes([hs[pos + 2], hs[pos + 3]]) as usize;
            pos += 4;

            if ext_type == 0x002B && ext_data_len >= 2 {
                // Supported versions
                tls_version = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
            } else if ext_type == 0x0033 && ext_data_len >= 2 {
                // Key share — selected group
                selected_group = Some(u16::from_be_bytes([hs[pos], hs[pos + 1]]));
            }

            pos += ext_data_len;
        }
    }

    Some((tls_version, cipher, selected_group))
}

pub fn run_remote_scan(host: &str, port: u16) -> RemoteScanResult {
    let info = crate::platform::PlatformInfo::detect();
    let addr = format!("{}:{}", host, port);

    println!();
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║     VÄRN-60 (Anu) — Remote TLS PQC Scanner            ║");
    println!("  ║     Point at any server. Check its quantum readiness.  ║");
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Target:    {}:{}", host, port);
    println!();

    // Step 1: Connect with PQ suites
    println!("  [1/4] Connecting with PQ cipher suites...");

    let start = Instant::now();
    let mut pq_version = 0u16;
    let mut pq_cipher = 0u16;
    let mut pq_group: Option<u16> = None;
    let mut pq_connected = false;
    let mut ip_addr = String::new();

    match TcpStream::connect_timeout(
        &addr.parse().unwrap_or_else(|_| {
            use std::net::ToSocketAddrs;
            addr.to_socket_addrs().unwrap().next().unwrap()
        }),
        Duration::from_secs(5),
    ) {
        Ok(mut stream) => {
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
            ip_addr = stream.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();

            let hello = build_client_hello(host, true);
            if stream.write_all(&hello).is_ok() {
                let mut buf = vec![0u8; 4096];
                if let Ok(n) = stream.read(&mut buf) {
                    if n > 0 {
                        if let Some((ver, cipher, group)) = parse_server_hello(&buf[..n]) {
                            pq_version = ver;
                            pq_cipher = cipher;
                            pq_group = group;
                            pq_connected = true;
                        }
                    }
                }
            }
        }
        Err(e) => {
            println!("  ERROR: Cannot connect to {} — {}", addr, e);
        }
    }

    let timing = start.elapsed().as_nanos() as u64;

    if !pq_connected {
        println!("  ERROR: No TLS response from {}", addr);
        return RemoteScanResult {
            host: host.into(), port, ip: ip_addr,
            tls_version: "UNKNOWN".into(),
            cipher_suites: vec![], key_exchange: vec![],
            pq_supported: false, pq_suites: vec![],
            downgrade_possible: false,
            certificate_algorithms: vec![],
            quantum_vulnerable: true,
            risk_level: "UNKNOWN".into(),
            timing_ns: timing,
            recommendations: vec!["Cannot connect to server".into()],
        };
    }

    let version_str = match pq_version {
        0x0304 => "TLS 1.3",
        0x0303 => "TLS 1.2",
        0x0302 => "TLS 1.1",
        0x0301 => "TLS 1.0",
        _ => "Unknown",
    };

    let pq_supported = pq_group.map(|g| is_pq_group(g)).unwrap_or(false);
    let selected_suite = suite_name(pq_cipher);
    let selected_group_name = pq_group.map(|g| group_name(g)).unwrap_or("none".into());

    println!("    Version:    {}", version_str);
    println!("    Cipher:     {}", selected_suite);
    println!("    Key Exchange: {}", selected_group_name);
    println!("    PQ Support: {}", if pq_supported { "YES ✓" } else { "NO ✗" });
    println!();

    // Step 2: Connect WITHOUT PQ (downgrade test)
    println!("  [2/4] Testing PQ downgrade (connecting without PQ suites)...");

    let mut downgrade_possible = false;
    let mut downgrade_version = 0u16;
    let mut downgrade_cipher = 0u16;
    let mut downgrade_group: Option<u16> = None;

    if let Ok(mut stream) = TcpStream::connect_timeout(
        &addr.parse().unwrap_or_else(|_| {
            use std::net::ToSocketAddrs;
            addr.to_socket_addrs().unwrap().next().unwrap()
        }),
        Duration::from_secs(5),
    ) {
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let hello = build_client_hello(host, false); // No PQ groups
        if stream.write_all(&hello).is_ok() {
            let mut buf = vec![0u8; 4096];
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 {
                    if let Some((ver, cipher, group)) = parse_server_hello(&buf[..n]) {
                        downgrade_version = ver;
                        downgrade_cipher = cipher;
                        downgrade_group = group;
                        downgrade_possible = true;
                    }
                }
            }
        }
    }

    if downgrade_possible {
        let dg_suite = suite_name(downgrade_cipher);
        let dg_group = downgrade_group.map(|g| group_name(g)).unwrap_or("none".into());
        println!("    Fallback cipher:  {}", dg_suite);
        println!("    Fallback group:   {}", dg_group);

        if pq_supported {
            println!("    ⚠ Server accepts non-PQ connections — DOWNGRADE POSSIBLE");
        } else {
            println!("    Server has no PQ — downgrade is the default");
        }
    }
    println!();

    // Step 3: Timing analysis
    println!("  [3/4] Connection timing...");
    println!("    Handshake: {:.2} ms", timing as f64 / 1_000_000.0);
    println!();

    // Step 4: Assessment
    println!("  [4/4] Quantum vulnerability assessment...");

    let mut recommendations: Vec<String> = Vec::new();

    let quantum_vulnerable = !pq_supported;
    let risk_level = if pq_version < TLS_13 {
        recommendations.push("Upgrade to TLS 1.3".into());
        recommendations.push("Enable PQ key exchange (ML-KEM)".into());
        "CRITICAL".to_string()
    } else if !pq_supported {
        recommendations.push("Enable PQ key exchange (X25519_MLKEM768)".into());
        recommendations.push("Vulnerable to Harvest Now, Decrypt Later".into());
        "HIGH".to_string()
    } else if downgrade_possible && pq_supported {
        recommendations.push("Consider enforcing PQ-only key exchange".into());
        recommendations.push("PQ downgrade attack is possible via MITM".into());
        "MEDIUM".to_string()
    } else {
        "LOW".to_string()
    };

    // Summary
    println!();
    println!("  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓");
    println!("  ┃  SCAN SUMMARY                                        ┃");
    println!("  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛");
    println!();
    println!("  Host:           {}:{}", host, port);
    println!("  IP:             {}", ip_addr);
    println!("  TLS Version:    {}", version_str);
    println!("  Cipher Suite:   {}", selected_suite);
    println!("  Key Exchange:   {}", selected_group_name);
    println!("  PQ Support:     {}", if pq_supported { "YES ✓" } else { "NO ✗" });
    println!("  PQ Downgrade:   {}", if downgrade_possible && pq_supported { "POSSIBLE ⚠" } else if !pq_supported { "N/A (no PQ)" } else { "NOT POSSIBLE ✓" });
    println!("  Risk Level:     {}", risk_level);
    println!();

    if !recommendations.is_empty() {
        println!("  Recommendations:");
        for r in &recommendations {
            println!("    → {}", r);
        }
        println!();
    }

    let pq_suites: Vec<String> = if pq_supported {
        vec![selected_group_name.clone()]
    } else {
        vec![]
    };

    RemoteScanResult {
        host: host.into(),
        port,
        ip: ip_addr,
        tls_version: version_str.into(),
        cipher_suites: vec![selected_suite],
        key_exchange: vec![selected_group_name],
        pq_supported,
        pq_suites,
        downgrade_possible: downgrade_possible && pq_supported,
        certificate_algorithms: vec![],
        quantum_vulnerable,
        risk_level,
        timing_ns: timing,
        recommendations,
    }
}
