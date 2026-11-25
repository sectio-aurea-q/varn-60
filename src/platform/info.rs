// VÄRN-60 (Anu) — platform and build information recorded with every result.

use serde::Serialize;
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize)]
pub struct PlatformInfo {
    /// CPU model as reported by the operating system
    pub chip: String,
    pub os: String,
    pub arch: String,
    /// CPU features that decide which code path several of the measured
    /// libraries take (detected at run time)
    pub cpu_features: Vec<String>,
    /// what the tool did about scheduling (see `prefer_performance_cores`)
    pub scheduling: String,
    /// whether the processor's data-independent-timing mode was switched on
    /// for the measuring thread (`--dit`, see `set_data_independent_timing`)
    pub data_independent_timing: String,
    /// Step of the clock behind the timings (`std::time::Instant`) in whole
    /// ns, determined by reading it many times in a row
    /// (`analysis::harness::clock_step_ns`): 1 for a clock that resolves
    /// nanoseconds, 41 on Apple Silicon (the system counter ticks at 24 MHz,
    /// 125/3 ns). Above 1 the clipped mean is reported instead of the median.
    pub clock_step_ns: u64,
    /// Clock source of the operating system where it can be read (Linux:
    /// current_clocksource), otherwise a note.
    pub clock_source: String,
}

static SCHEDULING: OnceLock<String> = OnceLock::new();
static DIT: OnceLock<String> = OnceLock::new();

const DIT_NOT_REQUESTED: &str = "not requested";

/// Switch on the data-independent-timing mode of the processor (AArch64,
/// FEAT_DIT: PSTATE.DIT = 1) for the calling thread. With DIT set, the
/// processor promises that the timing of a defined set of instructions does
/// not depend on the data they process; without it, a processor may take
/// shortcuts that depend on data. Libraries may or may not set it themselves.
/// The option exists to find out whether an observed timing difference comes
/// from such shortcuts.
///
/// Call once at program start, on the thread that measures. The state is
/// recorded in every result.
pub fn set_data_independent_timing() -> Result<(), String> {
    #[cfg(target_arch = "aarch64")]
    {
        if !std::arch::is_aarch64_feature_detected!("dit") {
            return Err("this processor does not report the DIT feature".into());
        }
        let state: u64;
        // SAFETY: with FEAT_DIT present, `msr dit, #1` and `mrs x0, dit` are
        // permitted in user mode and change nothing but the DIT bit of the
        // processor state. They are given as encodings because not every
        // assembler configuration accepts the names.
        unsafe {
            core::arch::asm!(
                ".inst 0xd503415f", // msr dit, #1
                ".inst 0xd53b42a0", // mrs x0, dit
                out("x0") state,
                options(nomem, nostack, preserves_flags)
            );
        }
        if state & (1 << 24) == 0 {
            return Err("the processor did not accept the DIT setting".into());
        }
        let _ = DIT.set("set for the measuring thread (PSTATE.DIT = 1)".to_string());
        Ok(())
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        Err("the data-independent-timing mode (DIT) exists on AArch64 only".into())
    }
}

/// Ask the operating system to run this thread on performance cores where
/// the system distinguishes them. Called once at program start; the answer
/// is recorded in every result.
///
/// macOS: the thread gets the quality-of-service class "user interactive",
/// which keeps it off the efficiency cores of Apple Silicon as far as the
/// scheduler allows. Other systems: nothing is changed; pin the process from
/// outside if wanted (e.g. `taskset -c 2 anu …` on Linux).
pub fn prefer_performance_cores() {
    SCHEDULING.get_or_init(|| {
        #[cfg(target_os = "macos")]
        {
            extern "C" {
                fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
            }
            const QOS_CLASS_USER_INTERACTIVE: u32 = 0x21;
            let rc = unsafe { pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0) };
            if rc == 0 {
                "macOS quality-of-service class user-interactive requested for the measuring thread".to_string()
            } else {
                format!("macOS quality-of-service request failed (code {}); default scheduling", rc)
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            "default scheduling, no pinning by the tool".to_string()
        }
    });
}

impl PlatformInfo {
    pub fn detect() -> Self {
        PlatformInfo {
            chip: detect_chip(),
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            cpu_features: detect_features(),
            scheduling: SCHEDULING
                .get()
                .cloned()
                .unwrap_or_else(|| "default scheduling, no pinning by the tool".to_string()),
            data_independent_timing: DIT.get().cloned().unwrap_or_else(|| DIT_NOT_REQUESTED.to_string()),
            clock_step_ns: crate::analysis::harness::clock_step_ns(),
            clock_source: detect_clock_source(),
        }
    }
}

fn detect_clock_source() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/sys/devices/system/clocksource/clocksource0/current_clocksource") {
            let s = s.trim();
            if !s.is_empty() {
                return format!("{} (CLOCK_MONOTONIC)", s);
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        "macOS system counter (mach absolute time)".to_string()
    }
    #[cfg(not(target_os = "macos"))]
    {
        "not recorded on this system".to_string()
    }
}

/// Current time in UTC as "YYYY-MM-DDThh:mm:ssZ".
pub fn utc_timestamp() -> String {
    let seconds = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format_utc(seconds)
}

/// Seconds since 1970-01-01T00:00:00Z as "YYYY-MM-DDThh:mm:ssZ".
fn format_utc(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    // date from a day count in the Gregorian calendar (algorithm
    // "civil_from_days" by Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let m = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * m + 2) / 5 + 1;
    let month = if m < 10 { m + 3 } else { m - 9 };
    let year = year_of_era + era * 400 + if month <= 2 { 1 } else { 0 };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, rest / 3600, rest % 3600 / 60, rest % 60)
}

fn detect_features() -> Vec<String> {
    #[allow(unused_mut)]
    let mut found: Vec<String> = Vec::new();
    #[cfg(target_arch = "x86_64")]
    {
        for (name, present) in [
            ("avx2", std::arch::is_x86_feature_detected!("avx2")),
            ("bmi2", std::arch::is_x86_feature_detected!("bmi2")),
            ("popcnt", std::arch::is_x86_feature_detected!("popcnt")),
            ("aes", std::arch::is_x86_feature_detected!("aes")),
            ("avx512f", std::arch::is_x86_feature_detected!("avx512f")),
        ] {
            if present {
                found.push(name.to_string());
            }
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        for (name, present) in [
            ("neon", std::arch::is_aarch64_feature_detected!("neon")),
            ("aes", std::arch::is_aarch64_feature_detected!("aes")),
            ("sha3", std::arch::is_aarch64_feature_detected!("sha3")),
        ] {
            if present {
                found.push(name.to_string());
            }
        }
    }
    found
}

fn detect_chip() -> String {
    #[cfg(target_os = "macos")]
    {
        for key in ["machdep.cpu.brand_string", "hw.model"] {
            if let Ok(out) = std::process::Command::new("sysctl").args(["-n", key]).output() {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !s.is_empty() {
                    return s;
                }
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(c) = std::fs::read_to_string("/proc/cpuinfo") {
            for line in c.lines() {
                if line.starts_with("model name") || line.starts_with("Model") {
                    if let Some(v) = line.split(':').nth(1) {
                        return v.trim().to_string();
                    }
                }
            }
        }
    }
    "unknown".into()
}

/// Versions of the tool, the compilers and the measured libraries.
#[derive(Debug, Clone, Serialize)]
pub struct BuildInfo {
    pub tool_version: String,
    /// commit of the source the binary was built from, with "-modified" if
    /// tracked files differed from it at build time
    pub git_commit: String,
    pub rustc: String,
    /// first line of `$CC --version` (or `cc --version`) at build time: the C
    /// compiler that the build scripts of the measured crates use unless they
    /// are told otherwise. liboqs is built separately, with a compiler that
    /// is not recorded here.
    pub c_compiler: String,
    /// versions of the measured Rust crates, from Cargo.lock at build time
    pub crate_versions: String,
    /// version reported by the linked liboqs at run time
    pub liboqs_version: String,
}

impl BuildInfo {
    pub fn collect() -> Self {
        BuildInfo {
            tool_version: env!("CARGO_PKG_VERSION").into(),
            git_commit: env!("VARN_GIT_COMMIT").into(),
            rustc: env!("VARN_RUSTC").into(),
            c_compiler: env!("VARN_CC").into(),
            crate_versions: env!("VARN_CRATE_VERSIONS").into(),
            liboqs_version: liboqs_version(),
        }
    }
}

#[cfg(feature = "liboqs")]
fn liboqs_version() -> String {
    crate::target::liboqs::liboqs_version()
}

#[cfg(not(feature = "liboqs"))]
fn liboqs_version() -> String {
    "not built in".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_are_utc_calendar_dates() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        // a leap day in a year divisible by 400
        assert_eq!(format_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(format_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(format_utc(1_795_824_000), "2026-11-28T00:00:00Z");
        // the last second of a century
        assert_eq!(format_utc(4_102_444_799), "2099-12-31T23:59:59Z");
        let now = utc_timestamp();
        assert!(now.len() == 20 && now.ends_with('Z') && now.as_str() > "2026-01-01", "{}", now);
    }
}
