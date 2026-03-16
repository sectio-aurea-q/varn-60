use clap::{Parser, Subcommand};
use std::path::PathBuf;
use varn_60::attack::{
    AttackConfig, run_fo_oracle, run_root_cause, analyze_exploitability,
    run_binary_analysis, run_deep_branch_inspection, run_key_timing_amplifier,
    run_dilithium_timing, DilithiumLevel,
    run_compiler_analysis,
    run_cross_process_server, run_cross_process_client,
    run_fingerprinting,
    run_pure_impl_analysis,
    run_rejection_estimator,
    run_rejection_rate_attack,
    run_fips204_simulation,
    run_pure_rust_kem_test,
    run_slhdsa_timing, SlhDsaVariant,
};
use varn_60::target::SecurityLevel;
use varn_60::target::liboqs::run_liboqs_scan;
use varn_60::attack::perf_scan::run_pmc_kem_scan;
use varn_60::attack::benchmark::run_benchmark;
use varn_60::attack::remote_scan::run_remote_scan;
use varn_60::report::cbom::run_cbom_generation;
use varn_60::platform;
use varn_60::report;
use varn_60::license::License;
use varn_60::audit::run_full_audit;

#[derive(Parser)]
#[command(name = "anu", version = "0.3.0",
    about = "VÄRN-60 (Anu) — Automated Side-Channel Scanner for Post-Quantum Cryptography\n\
             Empirical measurement tool. No theory. Only data.\n\
             sectio-aurea-q · meg.depth@proton.me")]
struct Cli {
    /// License key (or set ANU_LICENSE env var)
    #[arg(long, global = true)]
    license: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // ═══ ML-KEM (Kyber) ═══
    /// ML-KEM FO-Transform timing oracle
    FoOracle {
        #[arg(short, long, default_value = "768")]
        level: u16,
        #[arg(short, long, default_value = "10000")]
        samples: usize,
        #[arg(short, long, default_value = "anu-results.json")]
        output: PathBuf,
        #[arg(long)]
        html: Option<PathBuf>,
    },
    /// ML-KEM root cause analysis
    RootCause {
        #[arg(short, long, default_value = "768")]
        level: u16,
        #[arg(short, long, default_value = "20000")]
        samples: usize,
    },
    /// ML-KEM full investigation (4 phases)
    Investigate {
        #[arg(short, long, default_value = "768")]
        level: u16,
        #[arg(short, long, default_value = "30000")]
        samples: usize,
        #[arg(short, long, default_value = "anu-investigation")]
        output_dir: PathBuf,
    },
    /// ML-KEM key-dependent timing amplifier
    KeyTiming {
        #[arg(short, long, default_value = "768")]
        level: u16,
        #[arg(short = 'k', long, default_value = "50")]
        num_keys: usize,
        #[arg(short, long, default_value = "10000")]
        samples: usize,
    },

    // ═══ ML-DSA (Dilithium) ═══
    /// ML-DSA rejection sampling timing
    Dilithium {
        #[arg(short, long, default_value = "3")]
        level: u16,
        #[arg(short, long, default_value = "5000")]
        samples: usize,
    },
    /// ML-DSA rejection count estimation
    RejectEstimate {
        #[arg(short, long, default_value = "3")]
        level: u16,
        #[arg(short, long, default_value = "10000")]
        samples: usize,
    },
    /// ML-DSA rejection rate key fingerprinting
    RejectRate {
        #[arg(short, long, default_value = "3")]
        level: u16,
        #[arg(short = 'k', long, default_value = "50")]
        num_keys: usize,
        #[arg(short, long, default_value = "10000")]
        samples: usize,
    },
    /// ML-DSA full attack chain (timing + estimation + fingerprinting)
    DilithiumAttack {
        #[arg(short, long, default_value = "3")]
        level: u16,
        #[arg(short = 'k', long, default_value = "50")]
        num_keys: usize,
        #[arg(short, long, default_value = "10000")]
        samples: usize,
    },

    // ═══ Binary & Compiler ═══
    /// Binary branch analysis
    BinaryAnalysis {
        #[arg(short, long, default_value = "768")]
        level: u16,
        #[arg(short, long, default_value = "20000")]
        samples: usize,
    },
    /// Deep branch inspection
    DeepInspect,
    /// Compiler security analysis
    CompilerAnalysis,
    /// Implementation path analysis (asm vs C)
    ImplAnalysis {
        #[arg(short, long, default_value = "768")]
        level: u16,
        #[arg(short, long, default_value = "10000")]
        samples: usize,
    },

    // ═══ Advanced ═══
    /// Microarchitectural fingerprinting
    Fingerprint {
        #[arg(short, long, default_value = "768")]
        level: u16,
        #[arg(short, long, default_value = "50000")]
        samples: usize,
    },
    /// Cross-process timing server
    CrossServer {
        #[arg(short, long, default_value = "768")]
        level: u16,
    },
    /// Cross-process timing client
    CrossClient {
        #[arg(short, long, default_value = "10000")]
        samples: usize,
    },
    /// Cache hierarchy characterization
    CacheProfile,
    /// FIPS-204 full rejection simulation (z-norm + LowBits + Hint)
    Fips204Sim {
        #[arg(short, long, default_value = "3")]
        level: u16,
        #[arg(short, long, default_value = "5000")]
        samples: usize,
    },
    /// Pure Rust ML-KEM analysis (RustCrypto ml-kem, no assembly)
    PureRustKem {
        #[arg(short, long, default_value = "768")]
        level: u16,
        #[arg(short, long, default_value = "20000")]
        samples: usize,
    },
    /// SLH-DSA (SPHINCS+) hash-based signature timing — FIPS 205
    SlhDsa {
        /// Variant: 128f, 128s, 192f, 192s, 256f, 256s
        #[arg(short = 'v', long, default_value = "128f")]
        variant: String,
        #[arg(short, long, default_value = "500")]
        samples: usize,
    },
    /// liboqs scan — test Cloudflare/AWS/Signal's PQC library (all 3 standards)
    LiboqsScan {
        #[arg(short, long, default_value = "10000")]
        samples: usize,
    },
    /// PMC scan — hardware-level side-channel detection via Performance Counters (sudo required)
    PmcScan {
        #[arg(short, long, default_value = "5000")]
        samples: usize,
    },
    /// Benchmark — Speed + Security Score for all libraries
    Bench {
        #[arg(short, long, default_value = "5000")]
        samples: usize,
    },
    /// Remote TLS PQC scan — point at any server, check quantum readiness
    Scan {
        /// Hostname to scan
        host: String,
        /// Port (default 443)
        #[arg(short, long, default_value = "443")]
        port: u16,
    },
    /// Generate Cryptographic Bill of Materials (EU Compliance, CycloneDX format)
    Cbom,
    /// Platform information
    Info,
    /// Demo mode — limited scan, no license needed
    Demo,
    /// Full audit — all three NIST standards, HTML report (license required)
    Audit {
        #[arg(short, long, default_value = "5000")]
        samples: usize,
        #[arg(short, long, default_value = "anu-audit")]
        output_dir: PathBuf,
    },
}

fn parse_level(l: u16) -> SecurityLevel {
    match l {
        512 => SecurityLevel::MlKem512,
        768 => SecurityLevel::MlKem768,
        1024 => SecurityLevel::MlKem1024,
        _ => { eprintln!("Use 512, 768, or 1024"); std::process::exit(1); }
    }
}

fn parse_dilithium_level(l: u16) -> DilithiumLevel {
    match l {
        2 => DilithiumLevel::Dilithium2,
        3 => DilithiumLevel::Dilithium3,
        5 => DilithiumLevel::Dilithium5,
        _ => { eprintln!("Use 2, 3, or 5"); std::process::exit(1); }
    }
}

fn banner() {
    println!();
    println!("    ╔═══════════════════════════════════════════════════╗");
    println!("    ║              V Ä R N - 6 0  (A n u)              ║");
    println!("    ║    Automated Side-Channel Scanner for PQC        ║");
    println!("    ║    sectio-aurea-q              v0.3.0            ║");
    println!("    ╚═══════════════════════════════════════════════════╝");
    println!();
}

fn main() {
    let cli = Cli::parse();
    banner();

    let lic = License::check(cli.license.as_deref());

    match cli.command {
        Commands::Demo => {
            println!("  ═══ DEMO MODE ═══");
            println!("  Running limited ML-KEM-768 scan (1000 samples)...");
            println!();
            let config = AttackConfig {
                level: SecurityLevel::MlKem768, samples_per_variant: 1000, ..Default::default()
            };
            let result = run_fo_oracle(&config);
            println!();
            println!("  Result: d={:.4} — {}",
                result.fo_cohens_d,
                if result.vulnerable { "LEAK DETECTED" } else { "constant-time ✓" });
            println!();
            println!("  This is the DEMO. For the full audit across all three");
            println!("  NIST PQC standards (ML-KEM + ML-DSA + SLH-DSA),");
            println!("  contact: meg.depth@proton.me");
            println!();
        }
        Commands::Audit { samples, output_dir } => {
            if !lic.require_full("Full Audit") { return; }
            run_full_audit(&output_dir, samples);
        }

        // ── ML-KEM (all require license) ──

        Commands::FoOracle { level, samples, output, html } => {
            if !lic.require_full("FO-Oracle") { return; }
            let config = AttackConfig {
                level: parse_level(level), samples_per_variant: samples, ..Default::default()
            };
            let result = run_fo_oracle(&config);
            report::save_json(&result, &output).ok();
            println!("  JSON: {}", output.display());
            if let Some(hp) = html {
                report::save_html(&result, &hp).ok();
                println!("  HTML: {}", hp.display());
            }
        }
        Commands::RootCause { level, samples } => {
            if !lic.require_full("Root Cause") { return; }
            let rc = run_root_cause(parse_level(level), samples);
            let json = serde_json::to_string_pretty(&rc).unwrap();
            std::fs::write("anu-root-cause.json", &json).ok();
            println!("  JSON: anu-root-cause.json");
        }
        Commands::Investigate { level, samples, output_dir } => {
            if !lic.require_full("Investigate") { return; }
            std::fs::create_dir_all(&output_dir).ok();
            let lvl = parse_level(level);

            println!("  ┌─────────────────────────────────────────────┐");
            println!("  │  PHASE 1: FO-Transform Timing Oracle       │");
            println!("  └─────────────────────────────────────────────┘");
            let config = AttackConfig { level: lvl, samples_per_variant: samples, ..Default::default() };
            let fo = run_fo_oracle(&config);
            report::save_json(&fo, &output_dir.join("01-fo-oracle.json")).ok();
            report::save_html(&fo, &output_dir.join("01-fo-oracle.html")).ok();

            println!("  ┌─────────────────────────────────────────────┐");
            println!("  │  PHASE 2: Root Cause Analysis              │");
            println!("  └─────────────────────────────────────────────┘");
            let rc = run_root_cause(lvl, samples);
            let j = serde_json::to_string_pretty(&rc).unwrap();
            std::fs::write(output_dir.join("02-root-cause.json"), &j).ok();

            println!("  ┌─────────────────────────────────────────────┐");
            println!("  │  PHASE 3: Exploitability Assessment        │");
            println!("  └─────────────────────────────────────────────┘");
            let ex = analyze_exploitability(rc.delta_ns, rc.cohens_d, rc.valid_stddev_ns, rc.invalid_stddev_ns, lvl);
            let j = serde_json::to_string_pretty(&ex).unwrap();
            std::fs::write(output_dir.join("03-exploitability.json"), &j).ok();

            println!("  ┌─────────────────────────────────────────────┐");
            println!("  │  PHASE 4: Binary Branch Analysis           │");
            println!("  └─────────────────────────────────────────────┘");
            let ba = run_binary_analysis(lvl, samples / 2);
            let j = serde_json::to_string_pretty(&ba).unwrap();
            std::fs::write(output_dir.join("04-binary-analysis.json"), &j).ok();

            println!();
            println!("  ═══ RESULTS ═══");
            println!("  FO Oracle:  {}", if fo.vulnerable { "LEAK DETECTED" } else { "clean" });
            println!("  Root cause: {}", rc.root_cause);
            println!("  Binary:     {}", ba.verdict);
            println!("  CVSS:       {:.1}", ex.cvss_estimate);
        }
        Commands::KeyTiming { level, num_keys, samples } => {
            if !lic.require_full("Key Timing") { return; }
            let r = run_key_timing_amplifier(parse_level(level), num_keys, samples);
            let j = serde_json::to_string_pretty(&r).unwrap();
            std::fs::write("anu-key-timing.json", &j).ok();
            println!("  JSON: anu-key-timing.json");
        }
        Commands::Dilithium { level, samples } => {
            if !lic.require_full("ML-DSA") { return; }
            let r = run_dilithium_timing(parse_dilithium_level(level), samples);
            let j = serde_json::to_string_pretty(&r).unwrap();
            std::fs::write("anu-dilithium.json", &j).ok();
            println!("  JSON: anu-dilithium.json");
        }
        Commands::RejectEstimate { level, samples } => {
            if !lic.require_full("Reject Estimate") { return; }
            let r = run_rejection_estimator(parse_dilithium_level(level), samples);
            let j = serde_json::to_string_pretty(&r).unwrap();
            std::fs::write("anu-reject-estimate.json", &j).ok();
            println!("  JSON: anu-reject-estimate.json");
        }
        Commands::RejectRate { level, num_keys, samples } => {
            if !lic.require_full("Reject Rate") { return; }
            let r = run_rejection_rate_attack(parse_dilithium_level(level), num_keys, samples);
            let j = serde_json::to_string_pretty(&r).unwrap();
            std::fs::write("anu-reject-rate.json", &j).ok();
            println!("  JSON: anu-reject-rate.json");
        }
        Commands::DilithiumAttack { level, num_keys, samples } => {
            if !lic.require_full("ML-DSA Attack Chain") { return; }
            let dl = parse_dilithium_level(level);
            let dir = PathBuf::from("anu-dilithium-attack");
            std::fs::create_dir_all(&dir).ok();

            println!("  ┌─────────────────────────────────────────────────────┐");
            println!("  │  PHASE 1: ML-DSA Timing Variance                   │");
            println!("  └─────────────────────────────────────────────────────┘");
            let t = run_dilithium_timing(dl, samples);
            let j = serde_json::to_string_pretty(&t).unwrap();
            std::fs::write(dir.join("01-timing.json"), &j).ok();

            println!("  ┌─────────────────────────────────────────────────────┐");
            println!("  │  PHASE 2: Rejection Count Estimation               │");
            println!("  └─────────────────────────────────────────────────────┘");
            let e = run_rejection_estimator(dl, samples);
            let j = serde_json::to_string_pretty(&e).unwrap();
            std::fs::write(dir.join("02-rejection-estimate.json"), &j).ok();

            println!("  ┌─────────────────────────────────────────────────────┐");
            println!("  │  PHASE 3: Rejection Rate Fingerprinting            │");
            println!("  └─────────────────────────────────────────────────────┘");
            let f = run_rejection_rate_attack(dl, num_keys, samples);
            let j = serde_json::to_string_pretty(&f).unwrap();
            std::fs::write(dir.join("03-rejection-rate.json"), &j).ok();

            println!("  ┌─────────────────────────────────────────────────────┐");
            println!("  │  ML-DSA ANALYSIS COMPLETE                          │");
            println!("  └─────────────────────────────────────────────────────┘");
            println!();
            println!("  ═══ EMPIRICAL RESULTS ═══");
            println!("  Signing CV:          {:.2}%", t.sign_cv * 100.0);
            println!("  Key-dependent CV:    {:.2}%", t.key_cv * 100.0);
            println!("  Iteration entropy:   {:.3} bits/sig", e.entropy_bits);
            println!("  Iteration accuracy:  {:.1}%", e.validation_accuracy * 100.0);
            println!("  Rejection rate CV:   {:.2}%", f.rejection_rate_cv * 100.0);
            println!("  Keys distinguishable: {:.1}% ({}/{})",
                f.distinguishability_rate * 100.0,
                f.pairwise_distinguishable, f.pairwise_total);
            println!("  Info per key:        ~{:.1} bits", f.bits_from_rate);
        }
        Commands::BinaryAnalysis { level, samples } => {
            if !lic.require_full("Binary Analysis") { return; }
            let r = run_binary_analysis(parse_level(level), samples);
            let j = serde_json::to_string_pretty(&r).unwrap();
            std::fs::write("anu-binary-analysis.json", &j).ok();
            println!("  JSON: anu-binary-analysis.json");
        }
        Commands::DeepInspect => {
            if !lic.require_full("Deep Inspect") { return; }
            let r = run_deep_branch_inspection("target/release/anu");
            let j = serde_json::to_string_pretty(&r).unwrap();
            std::fs::write("anu-deep-inspect.json", &j).ok();
            println!("  JSON: anu-deep-inspect.json");
        }
        Commands::CompilerAnalysis => {
            if !lic.require_full("Compiler Analysis") { return; }
            let r = run_compiler_analysis("target/release/anu");
            let j = serde_json::to_string_pretty(&r).unwrap();
            std::fs::write("anu-compiler.json", &j).ok();
            println!("  JSON: anu-compiler.json");
        }
        Commands::ImplAnalysis { level, samples } => {
            if !lic.require_full("Impl Analysis") { return; }
            let r = run_pure_impl_analysis("target/release/anu", parse_level(level), samples);
            let j = serde_json::to_string_pretty(&r).unwrap();
            std::fs::write("anu-impl-analysis.json", &j).ok();
            println!("  JSON: anu-impl-analysis.json");
        }
        Commands::Fingerprint { level, samples } => {
            if !lic.require_full("Fingerprint") { return; }
            let r = run_fingerprinting(parse_level(level), samples);
            let j = serde_json::to_string_pretty(&r).unwrap();
            std::fs::write("anu-fingerprint.json", &j).ok();
            println!("  JSON: anu-fingerprint.json");
        }
        Commands::CrossServer { level } => {
            if !lic.require_full("Cross-Process") { return; }
            run_cross_process_server(parse_level(level));
        }
        Commands::CrossClient { samples } => {
            if !lic.require_full("Cross-Process") { return; }
            let r = run_cross_process_client(samples);
            let j = serde_json::to_string_pretty(&r).unwrap();
            std::fs::write("anu-cross-process.json", &j).ok();
            println!("  JSON: anu-cross-process.json");
        }
        Commands::CacheProfile => {
            println!("  Cache Hierarchy Characterization");
            let r = platform::characterize_cache_hierarchy(true);
            for w in r.windows(2) {
                let ratio = w[1].1 / w[0].1;
                if ratio > 1.5 {
                    let l = if w[0].0 >= 1048576 { format!("{}MB", w[0].0/1048576) }
                            else { format!("{}KB", w[0].0/1024) };
                    println!("  → Boundary near {} ({:.1}x jump)", l, ratio);
                }
            }
        }
        Commands::Fips204Sim { level, samples } => {
            if !lic.require_full("FIPS-204 Simulation") { return; }
            let r = run_fips204_simulation(parse_dilithium_level(level), samples);
            let j = serde_json::to_string_pretty(&r).unwrap();
            std::fs::write("anu-fips204-sim.json", &j).ok();
            println!("  JSON: anu-fips204-sim.json");
        }
        Commands::PureRustKem { level, samples } => {
            if !lic.require_full("Pure Rust ML-KEM") { return; }
            let r = run_pure_rust_kem_test(parse_level(level), samples);
            let j = serde_json::to_string_pretty(&r).unwrap();
            std::fs::write("anu-pure-rust-kem.json", &j).ok();
            println!("  JSON: anu-pure-rust-kem.json");
        }
        Commands::SlhDsa { variant, samples } => {
            if !lic.require_full("SLH-DSA") { return; }
            let v = match variant.as_str() {
                "128f" => SlhDsaVariant::Shake128f,
                "128s" => SlhDsaVariant::Shake128s,
                "192f" => SlhDsaVariant::Shake192f,
                "192s" => SlhDsaVariant::Shake192s,
                "256f" => SlhDsaVariant::Shake256f,
                "256s" => SlhDsaVariant::Shake256s,
                _ => { eprintln!("Use 128f, 128s, 192f, 192s, 256f, or 256s"); std::process::exit(1); }
            };
            let r = run_slhdsa_timing(v, samples);
            let j = serde_json::to_string_pretty(&r).unwrap();
            std::fs::write("anu-slhdsa.json", &j).ok();
            println!("  JSON: anu-slhdsa.json");
        }
        Commands::LiboqsScan { samples } => {
            if !lic.require_full("liboqs Scan") { return; }
            let r = run_liboqs_scan(samples);
            let j = serde_json::to_string_pretty(&r).unwrap();
            std::fs::write("anu-liboqs-scan.json", &j).ok();
            println!("  JSON: anu-liboqs-scan.json");
        }
        Commands::PmcScan { samples } => {
            if !lic.require_full("PMC Scan") { return; }
            if let Some(r) = run_pmc_kem_scan(samples) {
                let j = serde_json::to_string_pretty(&r).unwrap();
                std::fs::write("anu-pmc-scan.json", &j).ok();
                println!("  JSON: anu-pmc-scan.json");
            }
        }
        Commands::Bench { samples } => {
            if !lic.require_full("Benchmark") { return; }
            let r = run_benchmark(samples);
            let j = serde_json::to_string_pretty(&r).unwrap();
            std::fs::write("anu-benchmark.json", &j).ok();
            println!("  JSON: anu-benchmark.json");
        }
        Commands::Scan { host, port } => {
            if !lic.require_full("Remote Scan") { return; }
            let r = run_remote_scan(&host, port);
            let j = serde_json::to_string_pretty(&r).unwrap();
            let filename = format!("anu-scan-{}.json", host.replace('.', "-"));
            std::fs::write(&filename, &j).ok();
            println!("  JSON: {}", filename);
        }
        Commands::Cbom => {
            if !lic.require_full("CBOM") { return; }
            let r = run_cbom_generation();
            let j = serde_json::to_string_pretty(&r).unwrap();
            std::fs::write("anu-cbom.json", &j).ok();
            println!("  CBOM: anu-cbom.json");
        }
        Commands::Info => {
            let info = platform::PlatformInfo::detect();
            println!("  Chip:       {}", info.chip);
            println!("  Cache line: {} bytes", info.cache_line_size);
            println!("  Timer res:  {:.1} ns", info.timer_resolution_ns);
            lic.print_status();
        }
    }
}
