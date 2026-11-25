// build.rs — link liboqs (feature `liboqs`, on by default) and record the
// versions of the measured libraries.
//
// Where liboqs is looked for
//   OQS_LIB_DIR       directory containing liboqs (static or shared). Every
//                     cargo command needs it, so export it.
//   macOS default     `brew --prefix liboqs`/lib, then /opt/homebrew/lib,
//                     then /usr/local/lib (first one that contains liboqs)
//   elsewhere         OQS_LIB_DIR is required, except with OQS_LINK=dylib,
//                     where the linker's default search path is used
//
// Static or shared
//   OQS_LINK          "static" or "dylib" forces the kind. Otherwise the
//                     directory decides: on macOS the shared library is used
//                     if there is one, elsewhere the static one if there is
//                     one.
//
// A static liboqs that was built with OpenSSL also needs libcrypto. Whether
// it was is read from <dir>/../include/oqs/oqsconfig.h (OQS_USE_OPENSSL); if
// that file is not found, libcrypto is linked.
//   OPENSSL_LIB_DIR   directory containing libcrypto (macOS default:
//                     Homebrew openssl@3, then openssl@4, then openssl)
//   OQS_NO_OPENSSL=1  never link libcrypto
//
// The versions of the measured crates are read from Cargo.lock. They are
// right for builds that use this lock file (`--locked`).
//
// Also recorded: the commit the source was built from (with "-modified" if
// tracked files differed from it), and the first line of `$CC --version` (or
// `cc --version`).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn brew_prefix(formula: &str) -> Option<PathBuf> {
    let out = Command::new("brew").args(["--prefix", formula]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(PathBuf::from(s))
    }
}

fn has(dir: &Path, names: &[&str]) -> bool {
    names.iter().any(|n| dir.join(n).exists())
}

/// Does the liboqs in `dir` use OpenSSL? None if its configuration header is
/// not next to it.
fn liboqs_uses_openssl(dir: &Path) -> Option<bool> {
    let header = dir.parent()?.join("include").join("oqs").join("oqsconfig.h");
    let text = fs::read_to_string(header).ok()?;
    Some(text.lines().any(|l| {
        let mut words = l.split_whitespace();
        words.next() == Some("#define") && words.next() == Some("OQS_USE_OPENSSL")
    }))
}

fn link_liboqs(os: &str) {
    let shared_name = if os == "macos" { "liboqs.dylib" } else { "liboqs.so" };
    let forced = env::var("OQS_LINK").ok();
    if let Some(other) = forced.as_deref() {
        if other != "static" && other != "dylib" {
            panic!("OQS_LINK must be \"static\" or \"dylib\", got {:?}", other);
        }
    }

    // 1. directory
    let mut dir: Option<PathBuf> = env::var_os("OQS_LIB_DIR").map(PathBuf::from);
    if let Some(d) = &dir {
        if !has(d, &[shared_name, "liboqs.a"]) {
            panic!("OQS_LIB_DIR = {} contains neither liboqs.a nor {}", d.display(), shared_name);
        }
    }
    if dir.is_none() && os == "macos" {
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Some(p) = brew_prefix("liboqs") {
            candidates.push(p.join("lib"));
        }
        candidates.push(PathBuf::from("/opt/homebrew/lib"));
        candidates.push(PathBuf::from("/usr/local/lib"));
        dir = candidates.into_iter().find(|d| has(d, &[shared_name, "liboqs.a"]));
        if dir.is_none() {
            panic!(
                "liboqs not found. Install it (`brew install liboqs`) or set and export OQS_LIB_DIR to the \
                 directory that contains it. To build without liboqs: cargo build --release --no-default-features"
            );
        }
    }
    if dir.is_none() && forced.as_deref() != Some("dylib") {
        panic!(
            "liboqs not found: set and export OQS_LIB_DIR to the directory that contains liboqs.a, e.g. \
             `export OQS_LIB_DIR=/path/to/liboqs/build/lib` (every cargo command needs it). \
             To build without liboqs: cargo build --release --no-default-features"
        );
    }
    // absolute path, so that a run-time search path does not depend on the working directory
    let dir = dir.map(|d| fs::canonicalize(&d).unwrap_or(d));

    // 2. static or shared
    let kind: &str = match forced.as_deref() {
        Some("static") => "static",
        Some(_) => "dylib",
        None => {
            let (shared, stat) = match &dir {
                Some(d) => (has(d, &[shared_name]), has(d, &["liboqs.a"])),
                None => (false, false),
            };
            if os == "macos" {
                if stat && !shared {
                    "static"
                } else {
                    "dylib"
                }
            } else if shared && !stat {
                "dylib"
            } else {
                "static"
            }
        }
    };

    // 3. libcrypto for a static liboqs built with OpenSSL; its directory goes
    //    first, so that -lcrypto is not taken from the liboqs directory
    let no_openssl = env::var("OQS_NO_OPENSSL").map(|v| v == "1").unwrap_or(false);
    let needs_crypto = kind == "static" && !no_openssl && dir.as_deref().and_then(liboqs_uses_openssl).unwrap_or(true);
    if needs_crypto {
        let mut ssl: Option<PathBuf> = env::var_os("OPENSSL_LIB_DIR").map(PathBuf::from);
        if ssl.is_none() && os == "macos" {
            let mut candidates: Vec<PathBuf> = Vec::new();
            for formula in ["openssl@3", "openssl@4", "openssl"] {
                if let Some(p) = brew_prefix(formula) {
                    candidates.push(p.join("lib"));
                }
            }
            for root in ["/opt/homebrew/opt", "/usr/local/opt"] {
                for formula in ["openssl@3", "openssl@4", "openssl"] {
                    candidates.push(Path::new(root).join(formula).join("lib"));
                }
            }
            ssl = candidates.into_iter().find(|d| has(d, &["libcrypto.dylib", "libcrypto.a"]));
            if ssl.is_none() {
                panic!(
                    "this liboqs needs OpenSSL's libcrypto, which was not found. Install it (`brew install openssl@3`), \
                     or set OPENSSL_LIB_DIR, or set OQS_NO_OPENSSL=1 if liboqs was built with -DOQS_USE_OPENSSL=OFF"
                );
            }
        }
        if let Some(d) = ssl {
            println!("cargo:rustc-link-search=native={}", d.display());
        }
    }

    if let Some(d) = &dir {
        println!("cargo:rustc-link-search=native={}", d.display());
        if kind == "dylib" {
            // let the binary find the shared library at run time
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", d.display());
        }
    }
    println!("cargo:rustc-link-lib={}=oqs", kind);
    if needs_crypto {
        println!("cargo:rustc-link-lib=dylib=crypto");
    }
}

fn main() {
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    for v in ["OQS_LIB_DIR", "OQS_LINK", "OPENSSL_LIB_DIR", "OQS_NO_OPENSSL", "CC"] {
        println!("cargo:rerun-if-env-changed={}", v);
    }
    // run again whenever the source or the checked-out commit changes, so
    // that the recorded commit belongs to the source that is compiled
    for path in
        ["Cargo.lock", "Cargo.toml", "build.rs", "src", "examples", ".git/HEAD", ".git/index", ".git/packed-refs"]
    {
        if Path::new(path).exists() {
            println!("cargo:rerun-if-changed={}", path);
        }
    }

    if env::var_os("CARGO_FEATURE_LIBOQS").is_some() {
        link_liboqs(&os);
    }

    // versions of the measured crates (from Cargo.lock) and of the compiler
    let lock = fs::read_to_string("Cargo.lock").unwrap_or_default();
    let mut versions = Vec::new();
    for name in ["pqcrypto-mlkem", "ml-kem", "aws-lc-rs", "aws-lc-sys", "libcrux-ml-kem"] {
        let version = lock
            .split("[[package]]")
            .find_map(|block| {
                let mut n = None;
                let mut v = None;
                for line in block.lines() {
                    if let Some(x) = line.strip_prefix("name = ") {
                        n = Some(x.trim_matches('"').to_string());
                    }
                    if let Some(x) = line.strip_prefix("version = ") {
                        v = Some(x.trim_matches('"').to_string());
                    }
                }
                if n.as_deref() == Some(name) {
                    v
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "unknown".into());
        versions.push(format!("{} {}", name, version));
    }
    println!("cargo:rustc-env=VARN_CRATE_VERSIONS={}", versions.join(", "));

    let rustc = Command::new(env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
        .arg("--version")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=VARN_RUSTC={}", rustc);

    // commit of the source
    let git = |args: &[&str]| -> Option<String> {
        let out = Command::new("git").args(args).output().ok()?;
        if out.status.success() {
            Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
        } else {
            None
        }
    };
    let commit = match git(&["rev-parse", "HEAD"]) {
        Some(hash) if !hash.is_empty() => {
            if let Some(reference) = git(&["symbolic-ref", "-q", "HEAD"]) {
                let file = Path::new(".git").join(reference);
                if file.exists() {
                    println!("cargo:rerun-if-changed={}", file.display());
                }
            }
            let modified =
                git(&["status", "--porcelain", "--untracked-files=no"]).map(|s| !s.is_empty()).unwrap_or(false);
            if modified {
                format!("{}-modified", hash)
            } else {
                hash
            }
        }
        _ => "unknown (not built from a git checkout)".to_string(),
    };
    println!("cargo:rustc-env=VARN_GIT_COMMIT={}", commit);

    // C compiler
    let cc = env::var("CC").unwrap_or_else(|_| "cc".into());
    let c_compiler = Command::new(&cc)
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8_lossy(&o.stdout).lines().next().map(|l| l.trim().to_string()))
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=VARN_CC={}", c_compiler);
}
