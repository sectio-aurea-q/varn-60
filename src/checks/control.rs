// VÄRN-60 (Anu) — controls: calibration of the measurement on this machine.
//
// Both controls use the input path of the scans: the inputs of the two
// classes are two slots of an InterleavedInputs buffer and are copied into
// one working buffer before each timed call. Both classes decapsulate the
// same honest ciphertext with the same key (two slots with identical bytes).
// As in the scans, the library call is followed inside the timed region by
// dummy_work with a length drawn fresh for every call (AddedWork).
//
// Negative controls
//   Nothing is added. The classes are identical by construction, so every
//   detection is a false positive of the setup. Ten runs are made. A single
//   run is judged by the rule of the scans (|z| > Z_THRESHOLD). Ten runs
//   without a detection say little about the false-positive rate itself, so
//   the pairs of all runs are also pooled into one sign statistic: it tests
//   with ten times the data whether the setup treats identical classes alike.
//   |pooled z| > Z_THRESHOLD fails the control.
//
// Positive controls
//   Class 1 runs k more iterations of dummy_work than class 0. This adds a
//   delay of known origin and adjustable size without touching the library:
//   k times the cost of one iteration, which is measured during the same run
//   (AddedWork) and reported next to the measured difference. k is swept
//   upwards. A step counts as detected only if the first
//   run detects it with the expected sign (class 1 slower) and a second run
//   confirms it (same rule as in the scans). The sensitivity of the setup is
//   the smallest k from which every larger step is confirmed.
//
//   The size of the delay at that step is then measured in one more run that
//   is not used for any decision. The first and the second run were selected
//   for showing the delay, so their estimates are biased upwards near the
//   detection limit; the third run is not.
//
// What the controls do not show
//   They calibrate how small an added delay in the decapsulation time of one
//   library (PQClean ML-KEM-768) is detected on this machine. They do not
//   reproduce a leak inside the polynomial arithmetic (such as KyberSlash, a
//   secret-dependent division), and other libraries have different noise;
//   `multi-lib` and `fo-oracle` therefore carry controls of their own in
//   every run.

use crate::analysis::harness::{
    compare, confirms, effect, measure_interleaved, median_sorted, pooled_sign_z, time_with_work, verdict, AddedWork,
    Comparison, InterleavedInputs, MIN_ROUNDS, Z_CONFIRM, Z_THRESHOLD,
};
use crate::platform::{utc_timestamp, BuildInfo, PlatformInfo};
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{Ciphertext as _, SharedSecret as _};
use serde::Serialize;
use std::hint::black_box;

pub const NEGATIVE_REPEATS: usize = 10;
pub const K_SWEEP: [u32; 11] = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];
/// |pooled z| of the negative runs above which a note is printed
pub const POOLED_NOTE: f64 = 3.0;
const WARMUP: usize = 200;

#[derive(Debug, Serialize)]
pub struct ControlStep {
    pub added_iterations: u32,
    /// k × cost of one iteration during the first run (ns)
    pub nominal_delay_ns: f64,
    pub first_run: Comparison,
    pub confirmation_run: Option<Comparison>,
    /// detected with the expected sign and confirmed by the second run
    pub confirmed: bool,
}

#[derive(Debug, Serialize)]
pub struct ControlResult {
    pub build: BuildInfo,
    pub platform: PlatformInfo,
    pub rounds: usize,
    pub threshold_abs_z: f64,
    pub confirmation_z: f64,
    /// cost of one iteration of dummy_work during the negative runs (ns, median)
    pub iteration_cost_ns: f64,
    pub negative_runs: Vec<Comparison>,
    pub negative_false_positives: usize,
    /// sign statistic of all negative runs pooled
    pub negative_pooled_z: f64,
    pub negative_control_passed: bool,
    pub positive_controls: Vec<ControlStep>,
    /// smallest k from which every larger step was confirmed
    pub sensitivity_iterations: Option<u32>,
    /// the delay at that step, measured in a further run that is not used for
    /// any decision
    pub sensitivity_estimate: Option<Comparison>,
    /// k × cost of one iteration during that further run (ns)
    pub sensitivity_nominal_delay_ns: Option<f64>,
    /// negative controls passed and a sensitivity could be determined
    pub passed: bool,
    pub timestamp: String,
}

/// One timed decapsulation followed by `n` iterations of added work. A
/// function of its own, so that both classes run the same machine code.
#[inline(never)]
fn timed_call(ct: &mlkem768::Ciphertext, sk: &mlkem768::SecretKey, n: u32) -> u64 {
    time_with_work(n, || mlkem768::decapsulate(black_box(ct), black_box(sk)))
}

/// Smallest step from which every larger step is confirmed.
fn sensitivity_step(steps: &[ControlStep]) -> Option<usize> {
    let mut start = None;
    for i in (0..steps.len()).rev() {
        if steps[i].confirmed {
            start = Some(i);
        } else {
            break;
        }
    }
    start
}

/// `Err` if the library does not pass the correctness check that precedes
/// every measurement.
pub fn run_controls(rounds: usize) -> Result<ControlResult, String> {
    let rounds = rounds.max(MIN_ROUNDS);
    let platform = PlatformInfo::detect();

    println!();
    println!("  VÄRN-60 (Anu) — negative and positive controls");
    println!("  Target: PQClean ML-KEM-768 (pqcrypto-mlkem), {} rounds per run", rounds);
    println!(
        "  Rule: paired sign test, first run |z| > {}, confirmation |z| > {} with the same sign",
        Z_THRESHOLD, Z_CONFIRM
    );
    println!("  Δ is the interpolated median of the paired differences, or their clipped mean where they take");
    println!("  only a few clock values (clock step {} ns); positive: class 1 is slower", platform.clock_step_ns);
    println!();

    let (pk, sk) = mlkem768::keypair();
    let (valid_ss, valid_ct) = mlkem768::encapsulate(&pk);
    if mlkem768::decapsulate(&valid_ct, &sk).as_bytes() != valid_ss.as_bytes() {
        return Err("correctness check failed: decapsulation does not return the encapsulated secret".into());
    }
    // two input slots with identical bytes
    let inputs = InterleavedInputs::new(&[valid_ct.as_bytes(), valid_ct.as_bytes()]);
    let mut buf = vec![0u8; inputs.input_len()];
    let mut ct = valid_ct;
    // one measurement: class 1 runs k more iterations of dummy work than
    // class 0. Returns the comparison and the cost of one iteration during
    // the run.
    let mut measure = |k: u32| {
        let mut work = AddedWork::last_class(2, k);
        let m = measure_interleaved(2, rounds, WARMUP, |c| {
            let n = work.next(c);
            inputs.load(c, &mut buf);
            ct = mlkem768::Ciphertext::from_bytes(&buf).expect("ciphertext length");
            timed_call(&ct, &sk, n)
        });
        let cost = work.take_iteration_cost_ns().expect("at least MIN_ROUNDS rounds");
        (compare(&m[0], &m[1]), cost)
    };

    // ── Negative controls ──
    println!("  [1] Negative controls: identical inputs, nothing added, {} runs", NEGATIVE_REPEATS);
    let mut negative_runs = Vec::new();
    let mut costs = Vec::new();
    let mut fp = 0usize;
    for r in 0..NEGATIVE_REPEATS {
        let (c, cost) = measure(0);
        if c.difference_detected {
            fp += 1;
        }
        println!("      run {:>2}: {}", r + 1, verdict(&c));
        negative_runs.push(c);
        costs.push(cost);
    }
    costs.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let iteration_cost = median_sorted(&costs);
    let pooled = pooled_sign_z(&negative_runs);
    let neg_ok = fp == 0 && pooled.abs() <= Z_THRESHOLD;
    println!("      detections: {} of {}", fp, NEGATIVE_REPEATS);
    println!(
        "      all runs pooled ({} pairs): z = {:+.2}{}",
        negative_runs.iter().map(|c| c.n_pairs).sum::<usize>(),
        pooled,
        if pooled.abs() > Z_THRESHOLD {
            "  — the setup treats identical inputs differently"
        } else if pooled.abs() > POOLED_NOTE {
            "  — unusually large for identical inputs; repeat the control"
        } else {
            ""
        }
    );
    println!("      →  {}", if neg_ok { "PASS" } else { "FAIL" });
    println!();

    // ── Positive controls ──
    println!("  [2] Positive controls: identical inputs, class 1 runs k more iterations of dummy_work");
    println!(
        "      (one iteration cost ≈ {:.2} ns during the negative runs; per step it is measured again)",
        iteration_cost
    );
    let mut steps: Vec<ControlStep> = Vec::new();
    for &k in K_SWEEP.iter() {
        let (first, cost) = measure(k);
        let nominal = k as f64 * cost;
        let (second, confirmed) = if first.difference_detected && first.sign_z > 0.0 {
            let (s, _) = measure(k);
            let ok = confirms(&first, &s);
            (Some(s), ok)
        } else {
            (None, false)
        };
        let status = match (&second, confirmed) {
            (Some(s), true) => format!("confirmed (second run z = {:+.2})", s.sign_z),
            (Some(s), false) => format!("not confirmed (second run z = {:+.2})", s.sign_z),
            (None, _) if first.difference_detected => "detected with the wrong sign".to_string(),
            (None, _) => "not detected".to_string(),
        };
        println!(
            "      k = {:>4} (≈ {:>6.1} ns): {}, z = {:+.2}  →  {}",
            k,
            nominal,
            effect(&first),
            first.sign_z,
            status
        );
        steps.push(ControlStep {
            added_iterations: k,
            nominal_delay_ns: nominal,
            first_run: first,
            confirmation_run: second,
            confirmed,
        });
    }

    let start = sensitivity_step(&steps);
    // size of the delay at the sensitivity step, from a run of its own
    let estimate = start.map(|i| measure(steps[i].added_iterations));
    println!();
    match (start, &estimate) {
        (Some(i), Some((e, cost))) => {
            let k = steps[i].added_iterations;
            println!("  Sensitivity on this machine: k = {} and every larger step was detected and confirmed.", k);
            println!("  Size of that delay, from a further run that is not used for the decision:");
            println!("    added work   {} × {:.2} ns ≈ {:.1} ns", k, cost, k as f64 * cost);
            println!("    measured     {}", effect(e));
        }
        _ => println!("  No sensitivity could be determined — the largest added delay was not confirmed."),
    }
    println!();

    let passed = neg_ok && start.is_some();
    Ok(ControlResult {
        build: BuildInfo::collect(),
        platform,
        rounds,
        threshold_abs_z: Z_THRESHOLD,
        confirmation_z: Z_CONFIRM,
        iteration_cost_ns: iteration_cost,
        negative_runs,
        negative_false_positives: fp,
        negative_pooled_z: pooled,
        negative_control_passed: neg_ok,
        sensitivity_iterations: start.map(|i| steps[i].added_iterations),
        sensitivity_nominal_delay_ns: start
            .zip(estimate.as_ref())
            .map(|(i, (_, cost))| steps[i].added_iterations as f64 * cost),
        sensitivity_estimate: estimate.map(|(e, _)| e),
        positive_controls: steps,
        passed,
        timestamp: utc_timestamp(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::harness::comparison_with_z;

    fn step(k: u32, confirmed: bool) -> ControlStep {
        ControlStep {
            added_iterations: k,
            nominal_delay_ns: k as f64,
            first_run: comparison_with_z(if confirmed { 9.0 } else { 1.0 }),
            confirmation_run: None,
            confirmed,
        }
    }

    #[test]
    fn sensitivity_is_the_start_of_the_unbroken_run_of_confirmed_steps() {
        // a confirmed step below an unconfirmed one does not count
        let steps = [step(1, false), step(2, true), step(4, false), step(8, true), step(16, true)];
        assert_eq!(sensitivity_step(&steps), Some(3));
        let all = [step(1, true), step(2, true)];
        assert_eq!(sensitivity_step(&all), Some(0));
        // the largest step must be confirmed
        let none = [step(1, true), step(2, false)];
        assert_eq!(sensitivity_step(&none), None);
    }
}
