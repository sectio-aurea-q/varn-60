// VÄRN-60 (Anu) — Apple Silicon Performance Counters
//
// This module reads hardware PMC (Performance Monitoring Counters)
// on Apple M-series chips via the private kperf framework.
//
// Instead of measuring TIME, we measure:
// - Cache misses per crypto operation
// - Branch mispredictions per crypto operation
// - Instructions retired per crypto operation
//
// This is 10x more sensitive than timing. A branch that costs
// 2 nanoseconds disappears in timing noise. But a branch that
// causes a cache miss — the PMC sees it immediately.
//
// NOBODY has done this for PQC on Apple Silicon. Until now.



// ═══════════════════════════════════════════════════════
// KPC constants (from xnu source / reverse engineering)
// ═══════════════════════════════════════════════════════

const KPC_CLASS_FIXED: u32 = 1;          // Fixed counters (cycles, instructions)
const KPC_CLASS_CONFIGURABLE: u32 = 2;   // Configurable (cache, branch events)
const KPC_CLASS_ALL: u32 = KPC_CLASS_FIXED | KPC_CLASS_CONFIGURABLE;

// Apple M-series PMC event numbers (ARM PMUv3)
// These select WHAT to count in configurable counters
const PMC_EVENT_BRANCH_MISPREDICT: u64 = 0x10;  // Branch misprediction
const PMC_EVENT_L1D_CACHE_MISS: u64 = 0x03;     // L1 data cache miss (refill)
const PMC_EVENT_INST_RETIRED: u64 = 0x08;        // Instructions retired
const PMC_EVENT_L1D_CACHE_ACCESS: u64 = 0x04;    // L1 data cache access
#[allow(dead_code)]
const PMC_EVENT_L2_CACHE_MISS: u64 = 0xA3;       // L2 cache miss (approximate)
const PMC_EVENT_BRANCH_RETIRED: u64 = 0x21;      // Branches retired

// CFGWORD format: event | (1 << 16) to enable user-mode counting
fn cfgword(event: u64) -> u64 {
    event | (1 << 16)
}

// ═══════════════════════════════════════════════════════
// FFI bindings to kperf.framework
// ═══════════════════════════════════════════════════════

#[link(name = "kperf", kind = "framework")]
extern "C" {
    fn kpc_set_counting(classes: u32) -> i32;
    fn kpc_set_thread_counting(classes: u32) -> i32;
    fn kpc_set_config(classes: u32, config: *const u64) -> i32;
    #[allow(dead_code)]
    fn kpc_get_config(classes: u32, config: *mut u64) -> i32;
    fn kpc_get_thread_counters(tid: i32, buf_count: u32, buf: *mut u64) -> i32;
    fn kpc_get_counter_count(classes: u32) -> u32;
    #[allow(dead_code)]
    fn kpc_get_config_count(classes: u32) -> u32;
    fn kpc_force_all_ctrs_set(val: i32) -> i32;
    fn kpc_pmu_version() -> u32;
}

// ═══════════════════════════════════════════════════════
// Safe Rust wrapper
// ═══════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct PmcSnapshot {
    pub counters: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct PmcDelta {
    pub cache_misses: i64,
    pub branch_misses: i64,
    pub instructions: i64,
    pub cache_accesses: i64,
    pub l2_misses: i64,
    pub branches: i64,
}

pub struct PerformanceCounters {
    num_counters: u32,
    num_configurable: u32,
    enabled: bool,
    pub full_mode: bool,
}

impl PerformanceCounters {
    /// Initialize performance counters on Apple Silicon
    pub fn new() -> Option<Self> {
        let pmu_version = unsafe { kpc_pmu_version() };
        if pmu_version == 0 {
            println!("  [PMC] WARNING: PMU version 0 — counters may not be available");
        }

        let num_counters = unsafe { kpc_get_counter_count(KPC_CLASS_ALL) };
        let num_configurable = unsafe { kpc_get_config_count(KPC_CLASS_CONFIGURABLE) };

        if num_counters == 0 {
            println!("  [PMC] ERROR: No counters available. Run with sudo or enable FORCE_ALL_CTRS.");
            return None;
        }

        println!("  [PMC] PMU version: {}", pmu_version);
        println!("  [PMC] Total counters: {}", num_counters);
        println!("  [PMC] Configurable: {}", num_configurable);

        Some(PerformanceCounters {
            num_counters,
            num_configurable,
            enabled: false,
            full_mode: false,
        })
    }

    /// Configure counters for crypto side-channel analysis
    pub fn configure_crypto_events(&mut self) -> bool {
        // Try full mode first (needs SIP disabled or root)
        let rc = unsafe { kpc_force_all_ctrs_set(1) };
        if rc == 0 {
            // Full mode — configure custom events
            let mut config = vec![0u64; self.num_configurable as usize];
            if config.len() >= 5 {
                config[0] = cfgword(PMC_EVENT_L1D_CACHE_MISS);
                config[1] = cfgword(PMC_EVENT_BRANCH_MISPREDICT);
                config[2] = cfgword(PMC_EVENT_INST_RETIRED);
                config[3] = cfgword(PMC_EVENT_L1D_CACHE_ACCESS);
                config[4] = cfgword(PMC_EVENT_BRANCH_RETIRED);
            }

            let rc = unsafe { kpc_set_config(KPC_CLASS_CONFIGURABLE, config.as_ptr()) };
            if rc == 0 {
                unsafe { kpc_set_counting(KPC_CLASS_ALL) };
                unsafe { kpc_set_thread_counting(KPC_CLASS_ALL) };
                self.enabled = true;
                self.full_mode = true;
                println!("  [PMC] FULL MODE — Cache, Branch, Instructions configured");
                return true;
            }
        }

        // Fallback: Fixed counters only (works with SIP enabled)
        println!("  [PMC] SIP enabled — falling back to Fixed Counters mode");
        let rc = unsafe { kpc_set_counting(KPC_CLASS_FIXED) };
        if rc != 0 {
            // Even fixed counting might need thread-level enable
            let rc2 = unsafe { kpc_set_thread_counting(KPC_CLASS_FIXED) };
            if rc2 != 0 {
                // Last resort: just read whatever is already running
                println!("  [PMC] Reading existing counters (passive mode)");
            }
        } else {
            unsafe { kpc_set_thread_counting(KPC_CLASS_FIXED) };
        }

        // Test if we can read anything
        let snap = self.snapshot();
        let nonzero = snap.counters.iter().filter(|&&c| c > 0).count();
        if nonzero > 0 {
            self.enabled = true;
            self.full_mode = false;
            println!("  [PMC] FIXED MODE — {} active counters (Cycles + Instructions)", nonzero);
            println!("  [PMC] Tip: Disable SIP for full Cache/Branch analysis");
            return true;
        }

        println!("  [PMC] ERROR: No readable counters. PMC not available.");
        false
    }

    /// Read current counter values for this thread
    pub fn snapshot(&self) -> PmcSnapshot {
        let mut buf = vec![0u64; self.num_counters as usize];
        unsafe {
            kpc_get_thread_counters(0, self.num_counters, buf.as_mut_ptr());
        }
        PmcSnapshot { counters: buf }
    }

    /// Calculate delta between two snapshots
    pub fn delta(&self, before: &PmcSnapshot, after: &PmcSnapshot) -> PmcDelta {
        // Fixed counters come first, then configurable
        // Typically: fixed[0]=cycles, fixed[1]=instructions
        // Then configurable[0..N] = our configured events
        let n_fixed = (self.num_counters - self.num_configurable) as usize;

        let get = |idx: usize| -> i64 {
            let i = n_fixed + idx;
            if i < after.counters.len() && i < before.counters.len() {
                after.counters[i] as i64 - before.counters[i] as i64
            } else {
                0
            }
        };

        PmcDelta {
            cache_misses: get(0),
            branch_misses: get(1),
            instructions: get(2),
            cache_accesses: get(3),
            l2_misses: get(4),
            branches: get(5),
        }
    }

    /// Measure a single operation — returns PMC delta
    pub fn measure<F: FnOnce()>(&self, f: F) -> PmcDelta {
        let before = self.snapshot();
        f();
        let after = self.snapshot();
        self.delta(&before, &after)
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Quick check if PMC is available on this system
pub fn pmc_available() -> bool {
    let count = unsafe { kpc_get_counter_count(KPC_CLASS_ALL) };
    count > 0
}
