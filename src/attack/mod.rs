// VÄRN-60 (Anu) — Attack Modules
// Only empirically proven, measurement-backed modules.
// No theoretical models. No approximations. Only data.

pub mod fo_oracle;
pub mod root_cause;
pub mod exploitability;
pub mod binary_analysis;
pub mod deep_inspect;
pub mod dilithium;
pub mod compiler_analysis;
pub mod cross_process;
pub mod fingerprint;
pub mod pure_rust;
pub mod rejection_estimator;
pub mod rejection_rate;
pub mod fips204_sim;
pub mod pure_rust_kem;
pub mod slhdsa;
pub mod perf_scan;
pub mod benchmark;
pub mod remote_scan;
pub mod ci_mode;
pub mod code_scan;
pub mod dual_proof;
pub mod multi_lib;

pub use fo_oracle::*;
pub use root_cause::*;
pub use exploitability::*;
pub use binary_analysis::*;
pub use deep_inspect::*;
pub use dilithium::*;
pub use compiler_analysis::*;
pub use cross_process::*;
pub use fingerprint::*;
pub use pure_rust::*;
pub use rejection_estimator::*;
pub use rejection_rate::*;
pub use fips204_sim::*;
pub use pure_rust_kem::*;
pub use slhdsa::*;
