use std::time::Instant;
use serde::Serialize;

pub struct Timer;

impl Timer {
    #[inline(always)]
    pub fn now_ns() -> u64 {
        // mach_absolute_time on macOS gives nanosecond precision
        Instant::now().elapsed().as_nanos() as u64
    }

    #[inline(always)]
    pub fn measure<F: FnOnce() -> T, T>(f: F) -> (T, u64) {
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        let start = Instant::now();
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        let result = f();
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        let elapsed = start.elapsed().as_nanos() as u64;
        (result, elapsed)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PlatformInfo {
    pub chip: String,
    pub cache_line_size: usize,
    pub timer_resolution_ns: f64,
}

impl PlatformInfo {
    pub fn detect() -> Self {
        // Measure timer resolution
        let mut min_delta = u64::MAX;
        for _ in 0..10000 {
            let t1 = Instant::now();
            let t2 = Instant::now();
            let delta = t2.duration_since(t1).as_nanos() as u64;
            if delta > 0 && delta < min_delta {
                min_delta = delta;
            }
        }

        PlatformInfo {
            chip: Self::detect_chip(),
            cache_line_size: 128, // Apple Silicon uses 128-byte cache lines
            timer_resolution_ns: min_delta as f64,
        }
    }

    fn detect_chip() -> String {
        #[cfg(target_os = "macos")]
        {
            if let Ok(output) = std::process::Command::new("sysctl")
                .args(["-n", "machdep.cpu.brand_string"])
                .output()
            {
                if let Ok(s) = String::from_utf8(output.stdout) {
                    let trimmed = s.trim().to_string();
                    if !trimmed.is_empty() {
                        return trimmed;
                    }
                }
            }
            // Fallback for Apple Silicon (M-series doesn't have brand_string)
            if let Ok(output) = std::process::Command::new("sysctl")
                .args(["-n", "hw.model"])
                .output()
            {
                if let Ok(s) = String::from_utf8(output.stdout) {
                    return format!("Apple Silicon ({})", s.trim());
                }
            }
        }
        "Unknown".into()
    }
}

pub fn characterize_cache_hierarchy(verbose: bool) -> Vec<(usize, f64)> {
    let sizes: Vec<usize> = (10..=26).map(|exp| 1usize << exp).collect();
    let mut results = Vec::new();
    let iterations = 500_000u64;

    for &size in &sizes {
        let buffer: Vec<u8> = vec![0u8; size];
        let stride = 128usize; // Apple Silicon cache line
        let num_lines = size / stride;
        if num_lines == 0 { continue; }

        // Warm up
        for i in 0..num_lines {
            unsafe { std::ptr::read_volatile(&buffer[i * stride]); }
        }

        let start = Instant::now();
        let mut rng_state: u64 = 0xDEAD_BEEF_CAFE_BABE;

        for _ in 0..iterations {
            rng_state ^= rng_state << 13;
            rng_state ^= rng_state >> 7;
            rng_state ^= rng_state << 17;
            let idx = (rng_state as usize % num_lines) * stride;
            unsafe { std::ptr::read_volatile(&buffer[idx]); }
        }

        let elapsed_ns = start.elapsed().as_nanos() as f64;
        let avg_ns = elapsed_ns / iterations as f64;
        results.push((size, avg_ns));

        if verbose {
            let label = if size >= 1024 * 1024 {
                format!("{}MB", size / (1024 * 1024))
            } else {
                format!("{}KB", size / 1024)
            };
            println!("  {:>6} | avg: {:>8.2} ns", label, avg_ns);
        }
    }
    results
}
