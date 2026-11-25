use clap::{Parser, Subcommand};
use std::path::PathBuf;
use varn_60::analysis::harness::MIN_ROUNDS;
use varn_60::checks::ci_mode::run_ci_mode;
use varn_60::checks::multi_lib::{parse_libraries, run_multi_lib_scan, DEFAULT_REF_K, LIBRARY_KEYS, MAX_REF_K};
use varn_60::checks::{run_controls, run_fo_oracle, FoOracleConfig};
use varn_60::platform::{prefer_performance_cores, set_data_independent_timing, BuildInfo, PlatformInfo};
use varn_60::target::SecurityLevel;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// exit code for usage errors (EX_USAGE)
const EXIT_USAGE: i32 = 64;
/// exit code if a library fails the correctness check that precedes every
/// measurement (EX_SOFTWARE)
const EXIT_CHECK: i32 = 70;
/// exit code if the JSON result could not be written (EX_IOERR)
const EXIT_IO: i32 = 74;

#[derive(Parser)]
#[command(name = "anu", version = VERSION,
    about = "VÄRN-60 (Anu) — timing side-channel tests for ML-KEM implementations\n\
             Interleaved measurement in random order · paired sign test · confirmation run · controls\n\
             sectio-aurea-q · meg.depth@proton.me")]
struct Cli {
    /// Switch on the processor's data-independent-timing mode (AArch64, FEAT_DIT) for the measurement
    #[arg(long, global = true)]
    dit: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Negative and positive controls: how small an added delay is detected on this machine? (exit 1 if a control fails)
    Control {
        /// rounds per run (every class is timed once per round)
        #[arg(short, long, default_value = "20000")]
        samples: usize,
        /// file for the result as JSON
        #[arg(short, long, default_value = "anu-control.json")]
        output: PathBuf,
    },
    /// ML-KEM FO-oracle test (PQClean): valid vs. a second valid ciphertext and rejected ciphertexts, with controls
    FoOracle {
        /// parameter set: 512, 768 or 1024
        #[arg(short, long, default_value = "768")]
        level: u16,
        /// rounds per run (every class is timed once per round)
        #[arg(short, long, default_value = "20000")]
        samples: usize,
        /// iterations of added work for the reference delay (0: none)
        #[arg(long, default_value_t = DEFAULT_REF_K)]
        ref_k: u32,
        /// file for the result as JSON
        #[arg(short, long, default_value = "anu-fo-oracle.json")]
        output: PathBuf,
    },
    /// ML-KEM-768 in five libraries: accept vs. other ciphertext / one bit flipped, with controls
    MultiLib {
        /// rounds per run (every class is timed once per round)
        #[arg(short, long, default_value = "20000")]
        samples: usize,
        /// iterations of added work for the reference delay (0: none)
        #[arg(long, default_value_t = DEFAULT_REF_K)]
        ref_k: u32,
        /// libraries to measure, comma-separated: pqclean, rustcrypto, liboqs, aws-lc, libcrux (default: all)
        #[arg(long)]
        libs: Option<String>,
        /// file for the result as JSON
        #[arg(short, long, default_value = "anu-multi-lib.json")]
        output: PathBuf,
    },
    /// CI gate: exit 0 = no difference detected, 1 = confirmed difference, 2 = not tested, a failed control, not sensitive enough or inconclusive
    Ci {
        /// rounds per run (every class is timed once per round)
        #[arg(short, long, default_value = "20000")]
        samples: usize,
        /// iterations of added work for the reference delay; exit 0 refers to differences of about this size
        #[arg(long, default_value_t = DEFAULT_REF_K)]
        ref_k: u32,
        /// libraries to measure, comma-separated: pqclean, rustcrypto, liboqs, aws-lc, libcrux (default: all)
        #[arg(long)]
        libs: Option<String>,
        /// file for the result as JSON
        #[arg(short, long, default_value = "anu-ci-result.json")]
        output: PathBuf,
    },
    /// Short FO-oracle run (ML-KEM-768, 2000 rounds, no JSON)
    Demo,
    /// Platform and versions
    Info,
}

fn parse_level(l: u16) -> SecurityLevel {
    match l {
        512 => SecurityLevel::MlKem512,
        768 => SecurityLevel::MlKem768,
        1024 => SecurityLevel::MlKem1024,
        _ => {
            eprintln!("  --level must be 512, 768 or 1024");
            std::process::exit(EXIT_USAGE);
        }
    }
}

fn check_samples(s: usize) -> usize {
    if s < MIN_ROUNDS {
        eprintln!("  --samples must be at least {}", MIN_ROUNDS);
        std::process::exit(EXIT_USAGE);
    }
    s
}

fn check_ref_k(k: u32) -> u32 {
    if k > MAX_REF_K {
        eprintln!("  --ref-k must be at most {}", MAX_REF_K);
        std::process::exit(EXIT_USAGE);
    }
    k
}

fn check_libs(libs: &Option<String>) -> Vec<&'static str> {
    match libs {
        None => LIBRARY_KEYS.to_vec(),
        Some(list) => parse_libraries(list).unwrap_or_else(|reason| {
            eprintln!("  --libs: {}", reason);
            std::process::exit(EXIT_USAGE)
        }),
    }
}

/// A library failed the correctness check before the measurement.
fn check_failed(reason: String) -> ! {
    eprintln!("  {}", reason);
    eprintln!("  Nothing was measured.");
    std::process::exit(EXIT_CHECK)
}

/// A closed pipe ends the program quietly, as is usual for command-line
/// tools (`anu … | head`), instead of with a panic of the print macros.
fn default_sigpipe() {
    #[cfg(unix)]
    {
        extern "C" {
            fn signal(signum: i32, handler: usize) -> usize;
        }
        const SIGPIPE: i32 = 13;
        const SIG_DFL: usize = 0;
        // SAFETY: restores the default action for SIGPIPE; no handler is installed.
        unsafe {
            signal(SIGPIPE, SIG_DFL);
        }
    }
}

/// The directory of the output file must exist before a measurement starts,
/// so that a long run does not end with a result that cannot be written.
fn check_output(path: &std::path::Path) {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(dir) = parent {
        if !dir.is_dir() {
            eprintln!("  the directory of the output file does not exist: {}", dir.display());
            std::process::exit(EXIT_IO);
        }
    }
}

/// Write the result as JSON; returns false if that failed.
fn write_json<T: serde::Serialize>(value: &T, path: &PathBuf) -> bool {
    match serde_json::to_string_pretty(value) {
        Ok(j) => match std::fs::write(path, j) {
            Ok(_) => {
                println!("  JSON: {}", path.display());
                true
            }
            Err(e) => {
                eprintln!("  could not write {}: {}", path.display(), e);
                false
            }
        },
        Err(e) => {
            eprintln!("  could not serialise the result: {}", e);
            false
        }
    }
}

fn main() {
    default_sigpipe();
    // usage errors exit with 64, so that they cannot be mistaken for a result
    // of `anu ci` (exit 2); --help and --version exit with 0
    let cli = Cli::try_parse().unwrap_or_else(|e| {
        let code = if e.use_stderr() { EXIT_USAGE } else { 0 };
        let _ = e.print();
        std::process::exit(code)
    });
    prefer_performance_cores();
    if cli.dit {
        if let Err(reason) = set_data_independent_timing() {
            eprintln!("  --dit: {}", reason);
            std::process::exit(EXIT_USAGE);
        }
    }
    println!();
    println!("  VÄRN-60 (Anu) v{} — timing side-channel tests for ML-KEM", VERSION);
    if cli.dit {
        println!("  Data-independent timing (DIT) is switched on for this run.");
    }

    match cli.command {
        Commands::Control { samples, output } => {
            check_output(&output);
            let r = run_controls(check_samples(samples)).unwrap_or_else(|reason| check_failed(reason));
            let written = write_json(&r, &output);
            if !r.passed {
                eprintln!("  control FAILED: results of the other commands on this machine are not meaningful");
                std::process::exit(1);
            }
            if !written {
                std::process::exit(EXIT_IO);
            }
        }
        Commands::FoOracle { level, samples, ref_k, output } => {
            check_output(&output);
            let config = FoOracleConfig {
                level: parse_level(level),
                rounds: check_samples(samples),
                ref_k: check_ref_k(ref_k),
                ..Default::default()
            };
            let result = run_fo_oracle(&config).unwrap_or_else(|reason| check_failed(reason));
            if !write_json(&result, &output) {
                std::process::exit(EXIT_IO);
            }
        }
        Commands::MultiLib { samples, ref_k, libs, output } => {
            check_output(&output);
            let selected = check_libs(&libs);
            let r = run_multi_lib_scan(check_samples(samples), check_ref_k(ref_k), &selected);
            if !write_json(&r, &output) {
                std::process::exit(EXIT_IO);
            }
        }
        Commands::Ci { samples, ref_k, libs, output } => {
            check_output(&output);
            let selected = check_libs(&libs);
            let r = run_ci_mode(check_samples(samples), check_ref_k(ref_k), &selected);
            let written = write_json(&r, &output);
            // the result of the gate takes precedence over a file that could not be written
            std::process::exit(if r.exit_code == 0 && !written { EXIT_IO } else { r.exit_code });
        }
        Commands::Demo => {
            let config = FoOracleConfig { rounds: 2000, ..Default::default() };
            if let Err(reason) = run_fo_oracle(&config) {
                check_failed(reason);
            }
            println!("  This was a short run. For a meaningful result run `anu control` first,");
            println!("  then `anu fo-oracle --samples 100000` and `anu multi-lib --samples 100000`.");
            println!();
        }
        Commands::Info => {
            let p = PlatformInfo::detect();
            let b = BuildInfo::collect();
            println!("  Chip:      {} ({}, {})", p.chip, p.os, p.arch);
            println!(
                "  Features:  {}",
                if p.cpu_features.is_empty() {
                    "none of the recorded ones".to_string()
                } else {
                    p.cpu_features.join(", ")
                }
            );
            println!("  Scheduling: {}", p.scheduling);
            println!("  DIT:       {}", p.data_independent_timing);
            println!("  Clock:     step {} ns ({})", p.clock_step_ns, p.clock_source);
            println!("  Source:    commit {}", b.git_commit);
            println!("  Compiler:  {}", b.rustc);
            println!("  C compiler: {}", b.c_compiler);
            println!("  liboqs:    {}", b.liboqs_version);
            println!("  Crates:    {}", b.crate_versions);
            println!();
        }
    }
}
