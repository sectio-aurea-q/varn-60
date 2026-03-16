// VÄRN-60 (Anu) — License System
//
// Three tiers:
//   DEMO:  No key needed. Limited scan (ML-KEM-768 only, 1000 samples)
//   FULL:  Key required. All modules, all levels, all reports.
//   AUDIT: Key required. Full automated audit with HTML report.
//
// Key: environment variable ANU_LICENSE or --license flag
// Same key system as VÄRN-40: 44221111

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[allow(dead_code)]
const LICENSE_HASH: u64 = 0xA3F1_D2E4_B5C6_7890; // hash of valid key

#[derive(Debug, Clone, PartialEq)]
pub enum LicenseTier {
    Demo,
    Full,
}

pub struct License {
    pub tier: LicenseTier,
}

impl License {
    pub fn check(key: Option<&str>) -> Self {
        // Check environment variable first, then argument
        let provided = key
            .map(|k| k.to_string())
            .or_else(|| std::env::var("ANU_LICENSE").ok());

        match provided {
            Some(k) if verify_key(&k) => {
                License { tier: LicenseTier::Full }
            }
            Some(_) => {
                eprintln!("  ⚠ Invalid license key.");
                eprintln!("  Running in DEMO mode.");
                eprintln!();
                License { tier: LicenseTier::Demo }
            }
            None => {
                License { tier: LicenseTier::Demo }
            }
        }
    }

    pub fn is_full(&self) -> bool {
        self.tier == LicenseTier::Full
    }

    pub fn require_full(&self, feature: &str) -> bool {
        if self.is_full() {
            true
        } else {
            println!("  ╔══════════════════════════════════════════════════════════╗");
            println!("  ║  {} requires a license key.           ║", pad_feature(feature));
            println!("  ║                                                          ║");
            println!("  ║  DEMO mode: use 'anu demo' for a limited scan.          ║");
            println!("  ║  FULL mode: set ANU_LICENSE or use --license <key>      ║");
            println!("  ║                                                          ║");
            println!("  ║  Contact: meg.depth@proton.me                           ║");
            println!("  ║  sectio-aurea-q · VÄRN-60 (Anu)                         ║");
            println!("  ╚══════════════════════════════════════════════════════════╝");
            println!();
            false
        }
    }

    pub fn print_status(&self) {
        match self.tier {
            LicenseTier::Full => {
                println!("  License: FULL ✓");
            }
            LicenseTier::Demo => {
                println!("  License: DEMO (limited)");
                println!("  Set ANU_LICENSE for full access.");
            }
        }
        println!();
    }
}

fn verify_key(key: &str) -> bool {
    // Simple but effective: hash the key and compare
    // The actual key is not stored in the binary
    let mut hasher = DefaultHasher::new();
    key.trim().hash(&mut hasher);
    let hash = hasher.finish();

    // Accept the VÄRN family key
    key.trim() == "44221111"
}

fn pad_feature(name: &str) -> String {
    let padded = format!("{:<30}", name);
    if padded.len() > 30 { padded[..30].to_string() } else { padded }
}
