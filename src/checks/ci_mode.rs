// VÄRN-60 (Anu) — CI gate
//
//   anu ci [--samples N] [--ref-k K] [--libs a,b,…]
//
// Runs the multi-library ML-KEM-768 scan (checks::multi_lib) for the selected
// libraries (all five by default) and exits with
//   0  if every selected library was tested, its controls behaved as they
//      must (no detection between identical inputs; the reference delay
//      visible and of the expected size), and no test comparison showed a
//      detection,
//   1  if a difference was confirmed in a library in which no control failed
//      (takes precedence over 2; a reference delay that was not visible is
//      then listed as open),
//   2  otherwise: a library could not be tested, a control failed (the
//      comparisons of that library are then not used, whatever they show), a
//      needed further run failed, the reference delay was not visible in a
//      library (the run was not sensitive enough to say anything about it) or
//      not of the expected size, or a detection of the first run was not
//      confirmed (inconclusive).
//
// Exit 0 means: no detected difference in a run that detected the reference
// delay (--ref-k iterations of added work; its size in ns is printed for each
// library) and whose controls behaved as they must. It says nothing about
// differences smaller than that, and it is not a proof of constant-time
// behaviour.
//
// Note for CI use: shared CI runners are noisy. Use enough rounds, select the
// libraries that matter to the project, and treat a confirmed difference as a
// reason to re-measure on a quiet machine. The ciphertext is a public input:
// a confirmed difference in only one of the two rejection classes points to
// input-dependent timing, a difference of the same sign in both to a
// difference between accept and rejection path.

use crate::checks::multi_lib::{run_multi_lib_scan, MultiLibResult, MultiLibScanResult, SkippedLibrary};
use serde::Serialize;

pub const EXIT_PASS: i32 = 0;
pub const EXIT_CONFIRMED: i32 = 1;
pub const EXIT_OPEN: i32 = 2;

#[derive(Debug, Serialize)]
pub struct CiResult {
    pub exit_code: i32,
    /// "no difference detected" | "confirmed difference" |
    /// "not tested, a failed control, not sensitive enough or inconclusive"
    pub outcome: String,
    pub libraries_tested: usize,
    pub confirmed_differences: Vec<String>,
    /// reasons for exit code 2
    pub open_points: Vec<String>,
    pub scan: MultiLibScanResult,
}

/// Decision of the gate from the results of a scan.
#[derive(Debug, PartialEq)]
pub struct Gate {
    pub exit_code: i32,
    pub outcome: &'static str,
    pub confirmed: Vec<String>,
    pub open: Vec<String>,
}

pub fn gate(results: &[MultiLibResult], skipped: &[SkippedLibrary]) -> Gate {
    let mut confirmed = Vec::new();
    let mut open = Vec::new();
    for s in skipped {
        open.push(format!("{} (skipped: {})", s.library, s.reason));
    }
    for r in results {
        if !r.usable {
            // a failed control: nothing else from this library is used
            let reason = r.unusable_reason.as_deref().unwrap_or("a control failed");
            open.push(format!("{} (not usable: {})", r.library, reason));
            continue;
        }
        for (p, what) in [(&r.other_ciphertext, "other ciphertext"), (&r.bit_flip, "one bit flipped")] {
            if p.confirmed {
                confirmed.push(format!("{} — {}", r.library, what));
            } else if p.first_run.difference_detected {
                open.push(format!("{} ({}: detected in the first run, not confirmed)", r.library, what));
            }
        }
        if let Some(reason) = &r.incomplete {
            open.push(format!("{} ({})", r.library, reason));
        }
        if !r.reference_visible {
            open.push(format!("{} (reference delay not visible)", r.library));
        } else if r.reference_size_plausible == Some(false) {
            open.push(format!(
                "{} (reference delay visible, but its measured size does not match the added work)",
                r.library
            ));
        }
    }
    if results.is_empty() && skipped.is_empty() {
        open.push("no library was tested".to_string());
    }

    // a confirmed difference takes precedence over everything else
    let (exit_code, outcome) = if !confirmed.is_empty() {
        (EXIT_CONFIRMED, "confirmed difference")
    } else if !open.is_empty() {
        (EXIT_OPEN, "not tested, a failed control, not sensitive enough or inconclusive")
    } else {
        (EXIT_PASS, "no difference detected")
    };
    Gate { exit_code, outcome, confirmed, open }
}

pub fn run_ci_mode(samples: usize, ref_k: u32, selected: &[&str]) -> CiResult {
    let scan = run_multi_lib_scan(samples, ref_k, selected);
    let g = gate(&scan.results, &scan.skipped);

    match g.exit_code {
        EXIT_PASS => {
            println!("  CI: PASS — libraries tested: {}; no difference detected;", scan.results.len());
            println!(
                "      negative controls without detection, reference delay (k = {}) visible in every library.",
                scan.reference_iterations
            );
            println!("      This holds for differences of at least about the size of that delay; it is not a proof of constant-time behaviour.");
        }
        EXIT_CONFIRMED => {
            println!("  CI: FAIL — confirmed difference: {}", g.confirmed.join("; "));
            if !g.open.is_empty() {
                println!("      also open: {}", g.open.join("; "));
            }
        }
        _ => println!("  CI: INCOMPLETE — {}", g.open.join("; ")),
    }
    println!();

    CiResult {
        exit_code: g.exit_code,
        outcome: g.outcome.into(),
        libraries_tested: scan.results.len(),
        confirmed_differences: g.confirmed,
        open_points: g.open,
        scan,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::harness::comparison_with_z;
    use crate::checks::multi_lib::PairResult;

    fn pair(first_z: f64, confirmed: bool) -> PairResult {
        PairResult {
            first_run: comparison_with_z(first_z),
            confirmation_run: None,
            confirmed,
            fresh_inputs_run: None,
            reproduced_with_fresh_inputs: None,
            outcome: String::new(),
        }
    }

    /// A library whose run gives no reason for anything but exit 0.
    fn clean(name: &str) -> MultiLibResult {
        MultiLibResult {
            library: name.into(),
            implementation: String::new(),
            algorithm: "ML-KEM-768".into(),
            other_ciphertext: pair(0.5, false),
            bit_flip: pair(-1.0, false),
            negative_control: comparison_with_z(0.3),
            negative_control_passed: true,
            reference: comparison_with_z(30.0),
            reference_visible: true,
            reference_nominal_ns: Some(19.0),
            reference_size_plausible: Some(true),
            detectable_shift_50_ns: Some(2.0),
            detectable_shift_95_ns: Some(2.7),
            further_negative_controls: Vec::new(),
            usable: true,
            unusable_reason: None,
            incomplete: None,
        }
    }

    #[test]
    fn passes_only_if_every_library_is_clean() {
        let g = gate(&[clean("a"), clean("b")], &[]);
        assert_eq!((g.exit_code, g.outcome), (EXIT_PASS, "no difference detected"));
        assert!(g.confirmed.is_empty() && g.open.is_empty());
    }

    #[test]
    fn nothing_tested_is_not_a_pass() {
        assert_eq!(gate(&[], &[]).exit_code, EXIT_OPEN);
    }

    #[test]
    fn skipped_library_gives_exit_2() {
        let skipped = [SkippedLibrary { library: "liboqs".into(), reason: "not built in".into() }];
        let g = gate(&[clean("a")], &skipped);
        assert_eq!(g.exit_code, EXIT_OPEN);
        assert_eq!(g.open.len(), 1);
    }

    #[test]
    fn unconfirmed_detection_gives_exit_2() {
        let mut r = clean("a");
        r.bit_flip = pair(6.0, false);
        let g = gate(&[r, clean("b")], &[]);
        assert_eq!(g.exit_code, EXIT_OPEN);
        assert!(g.open[0].contains("not confirmed"));
    }

    #[test]
    fn failed_controls_give_exit_2() {
        let mut reference = clean("a");
        reference.reference_visible = false;
        assert_eq!(gate(&[reference], &[]).exit_code, EXIT_OPEN);
        let mut size = clean("a");
        size.reference_size_plausible = Some(false);
        let g = gate(&[size], &[]);
        assert_eq!(g.exit_code, EXIT_OPEN);
        assert!(g.open[0].contains("does not match"));
        let mut incomplete = clean("a");
        incomplete.incomplete = Some("confirmation run failed".into());
        assert_eq!(gate(&[incomplete], &[]).exit_code, EXIT_OPEN);
    }

    #[test]
    fn a_library_with_a_failed_control_is_never_reported_as_a_finding() {
        // the negative control failed and a test comparison looks confirmed:
        // the library counts as not usable, not as a confirmed difference
        let mut broken = clean("a");
        broken.usable = false;
        broken.unusable_reason = Some("the negative control shows a difference between identical inputs".into());
        broken.negative_control_passed = false;
        broken.bit_flip = pair(9.0, true);
        let g = gate(&[broken, clean("b")], &[]);
        assert_eq!(g.exit_code, EXIT_OPEN);
        assert!(g.confirmed.is_empty());
        assert_eq!(g.open.len(), 1);
        assert!(g.open[0].contains("not usable"));
    }

    #[test]
    fn confirmed_difference_takes_precedence() {
        let mut found = clean("a");
        found.other_ciphertext = pair(9.0, true);
        let mut noisy = clean("b");
        noisy.reference_visible = false;
        let skipped = [SkippedLibrary { library: "c".into(), reason: "x".into() }];
        let g = gate(&[found, noisy], &skipped);
        assert_eq!((g.exit_code, g.outcome), (EXIT_CONFIRMED, "confirmed difference"));
        assert_eq!(g.confirmed, vec!["a — other ciphertext".to_string()]);
        // the open points are still listed
        assert_eq!(g.open.len(), 2);
    }
}
