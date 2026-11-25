// VÄRN-60 (Anu) — FO-oracle test for ML-KEM decapsulation (PQClean)
//
// Test classes (see target::mlkem): valid, valid-2, other-key, all-zero,
// all-ones, eight bit flips spread over the ciphertext, four random strings.
// All classes are decapsulated with the same key and measured interleaved in
// random order per round; every test class is compared with "valid" by the
// paired sign test (analysis::harness). A detection counts only if a second
// run (same key and ciphertexts, new random order) confirms it.
//
// Controls of the run: three further classes use one more honest ciphertext
// for the same key —
//   control-a, control-b   the same bytes twice. Their comparison is the
//                          negative control: identical inputs, so every
//                          detection is a false positive of the setup.
//   control-ref            the same bytes, with ref_k more iterations of
//                          added work in the timed region. Compared with
//                          control-a it is the reference delay: is an added
//                          delay of known origin visible in this run, and
//                          does its measured size agree with the added work?
// The controls are judged by harness::judge_controls, in the first run and in
// the confirmation run. If a control fails, the result is reported as not
// usable, whatever the test comparisons show.
// The controls use a ciphertext of their own so that every tested input is
// used by exactly one class. (The eight bit-flip classes are byte strings of
// their own, but each differs from "valid" in one bit only.) In the timed
// region every class runs the library call followed by dummy_work(n), with n
// drawn fresh for every call and ref_k iterations more for control-ref
// (harness::AddedWork; no branch on the class).
//
// Reading a result: every test class differs from "valid" in the ciphertext,
// which is a public input. A confirmed difference shows that the running time
// depends on the input; whether secret data are involved has to be judged
// from the pattern:
//   * the same difference in all rejection classes (other-key, all-zero,
//     all-ones, bit flips, random) — accept and rejection path differ;
//   * a difference for "valid-2" — the accept path depends on the message or
//     the ciphertext (the kind of dependence behind KyberSlash);
//   * a difference in single classes only — input-dependent timing that needs
//     a closer look.
// All classes use one key, because decapsulation time differs between keys
// through public data (examples/key_dependence.rs).

use crate::analysis::harness::{
    compare, confirms, control_lines, effect, judge_controls, measure_interleaved, median_ns, verdict, AddedWork,
    Comparison, InterleavedInputs, MIN_ROUNDS, Z_CONFIRM, Z_THRESHOLD,
};
use crate::platform::{utc_timestamp, BuildInfo, PlatformInfo};
use crate::target::{MlKemTarget, SecurityLevel};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct FoOracleConfig {
    pub rounds: usize,
    pub warmup_rounds: usize,
    pub level: SecurityLevel,
    /// iterations of added work for the reference class
    pub ref_k: u32,
}

impl Default for FoOracleConfig {
    fn default() -> Self {
        FoOracleConfig { rounds: 20_000, warmup_rounds: 200, level: SecurityLevel::MlKem768, ref_k: 32 }
    }
}

#[derive(Debug, Serialize)]
pub struct ClassSummary {
    pub name: String,
    /// "test" or "control"
    pub role: String,
    /// true for honest ciphertexts (accept path), false for implicit rejection
    pub accept_path: bool,
    pub rounds: usize,
    pub median_ns: f64,
    pub min_ns: u64,
    pub max_ns: u64,
}

#[derive(Debug, Serialize)]
pub struct ClassComparison {
    pub class: String,
    /// this class vs. "valid" in the first run (positive Δ: this class slower)
    pub first_run: Comparison,
    pub confirmation_run: Option<Comparison>,
    pub confirmed: bool,
}

#[derive(Debug, Serialize)]
pub struct FoOracleResult {
    pub build: BuildInfo,
    pub platform: PlatformInfo,
    pub config: FoOracleConfig,
    pub threshold_abs_z: f64,
    pub confirmation_z: f64,
    pub classes: Vec<ClassSummary>,
    pub comparisons: Vec<ClassComparison>,
    /// control-a vs. control-b (identical inputs), first run
    pub negative_control: Comparison,
    pub negative_control_passed: bool,
    /// control-ref vs. control-a, first run
    pub reference: Comparison,
    /// the reference delay was detected with the expected sign
    pub reference_visible: bool,
    /// ref_k × cost of one iteration of added work during the first run (ns)
    pub reference_nominal_ns: Option<f64>,
    /// the measured size of the reference delay agrees with
    /// reference_nominal_ns (its interval overlaps that value ± 50 %)
    pub reference_size_plausible: Option<bool>,
    /// size of a shift that about half of such runs would have detected,
    /// extrapolated from the reference delay (ns)
    pub detectable_shift_50_ns: Option<f64>,
    /// size of a shift that about 95 % of such runs would have detected (ns)
    pub detectable_shift_95_ns: Option<f64>,
    /// control-a vs. control-b in the confirmation run, if there was one
    pub confirmation_run_negative_control: Option<Comparison>,
    /// false if a control failed in any run; the comparisons then say nothing
    pub usable: bool,
    pub unusable_reason: Option<String>,
    pub max_abs_z: f64,
    pub delta_at_max_z_ns: f64,
    pub confirmed_classes: Vec<String>,
    pub timing_difference_confirmed: bool,
    pub timestamp: String,
}

/// `Err` if the library does not pass the correctness check that precedes
/// every measurement.
pub fn run_fo_oracle(config: &FoOracleConfig) -> Result<FoOracleResult, String> {
    let platform = PlatformInfo::detect();
    let rounds = config.rounds.max(MIN_ROUNDS);
    let ref_k = config.ref_k;

    println!();
    println!("  VÄRN-60 (Anu) — FO-oracle test, ML-KEM decapsulation (PQClean via pqcrypto-mlkem)");
    println!("  Target:   {}", config.level);
    println!("  Platform: {}", platform.chip);
    println!("  Rounds:   {} (every class once per round, random order)", rounds);
    println!("  Estimate: Δ is the interpolated median of the paired differences, or their clipped mean where they");
    println!(
        "            take only a few clock values (clock step {} ns); positive: the class is slower than \"valid\"",
        platform.clock_step_ns
    );
    println!();

    let target = MlKemTarget::new(config.level);
    let tests = target.generate_test_classes();
    let (control_ct, control_secret) = target.encapsulate();

    // correctness check before any timing
    let valid_secret = tests[0].expected_secret.clone().expect("valid class has a secret");
    for c in &tests {
        let got = target.decapsulate(&c.ciphertext);
        let ok = match &c.expected_secret {
            Some(expected) => &got == expected,
            None => got != valid_secret && got != control_secret,
        };
        if !ok {
            return Err(format!("correctness check failed for class {}", c.name));
        }
    }
    if target.decapsulate(&control_ct) != control_secret {
        return Err("correctness check failed for the control ciphertext".into());
    }

    // class list: the test classes, then control-a, control-b, control-ref
    let n_tests = tests.len();
    let (ctl_a, ctl_b, ctl_ref) = (n_tests, n_tests + 1, n_tests + 2);
    let n = n_tests + 3;
    let mut names: Vec<String> = tests.iter().map(|c| c.name.clone()).collect();
    names.extend(["control-a", "control-b", "control-ref"].map(String::from));
    let mut class_inputs: Vec<&[u8]> = tests.iter().map(|c| c.ciphertext.as_slice()).collect();
    class_inputs.extend([control_ct.as_slice(); 3]);
    let inputs = InterleavedInputs::new(&class_inputs);
    let mut buf = vec![0u8; inputs.input_len()];
    // added work: the amount drawn per call for every class, ref_k iterations
    // more for control-ref (the last class)
    let mut work = AddedWork::last_class(n, ref_k);
    // one run: the timings per class and the cost of one iteration of added
    // work during the run
    let mut run = || {
        let timings = measure_interleaved(n, rounds, config.warmup_rounds, |c| {
            let extra = work.next(c);
            inputs.load(c, &mut buf);
            target.timed_decapsulate(&buf, extra)
        });
        (timings, work.take_iteration_cost_ns())
    };
    let (first, iteration_cost) = run();
    let reference_nominal = iteration_cost.map(|c| c * ref_k as f64);

    let mut summaries: Vec<ClassSummary> = Vec::new();
    for (i, m) in first.iter().enumerate() {
        let s = ClassSummary {
            name: names[i].clone(),
            role: if i < n_tests { "test".into() } else { "control".into() },
            accept_path: if i < n_tests { tests[i].expected_secret.is_some() } else { true },
            rounds: m.len(),
            median_ns: median_ns(m),
            min_ns: m.iter().copied().min().unwrap_or(0),
            max_ns: m.iter().copied().max().unwrap_or(0),
        };
        println!("    {:>16} | median {:>9.1} ns | min {:>7} ns", s.name, s.median_ns, s.min_ns);
        summaries.push(s);
    }

    println!();
    println!(
        "  Comparison with the valid class (first run |z| > {}, confirmation |z| > {} with the same sign):",
        Z_THRESHOLD, Z_CONFIRM
    );
    println!();
    let mut comps: Vec<ClassComparison> = Vec::new();
    for (i, c) in tests.iter().enumerate().skip(1) {
        let cmp = compare(&first[0], &first[i]);
        println!("    {:>16}: {}", c.name, verdict(&cmp));
        comps.push(ClassComparison { class: c.name.clone(), first_run: cmp, confirmation_run: None, confirmed: false });
    }

    let negative = compare(&first[ctl_a], &first[ctl_b]);
    let reference = compare(&first[ctl_a], &first[ctl_ref]);
    let negative_control_passed = !negative.difference_detected;
    let controls = judge_controls(&negative, &reference, ref_k, reference_nominal);
    let mut unusable_reason = controls.unusable.clone();
    println!();
    println!("  Controls of this run (a ciphertext of their own):");
    for line in control_lines(&negative, &reference, ref_k, reference_nominal, &controls) {
        println!("    {}", line);
    }

    let mut confirmation_run_negative_control = None;
    if comps.iter().any(|c| c.first_run.difference_detected) {
        println!();
        println!("  Confirmation run (same key and ciphertexts, new random order):");
        let (second, second_cost) = run();
        // the controls of the confirmation run count as well, and they are
        // judged before anything is called confirmed
        let second_negative = compare(&second[ctl_a], &second[ctl_b]);
        let second_reference = compare(&second[ctl_a], &second[ctl_ref]);
        let second_nominal = second_cost.map(|c| c * ref_k as f64);
        let second_controls = judge_controls(&second_negative, &second_reference, ref_k, second_nominal);
        if let (None, Some(reason)) = (&unusable_reason, &second_controls.unusable) {
            unusable_reason = Some(format!("confirmation run: {}", reason));
        }
        let usable = unusable_reason.is_none();
        for (j, cc) in comps.iter_mut().enumerate() {
            if !cc.first_run.difference_detected {
                continue;
            }
            let c2 = compare(&second[0], &second[j + 1]);
            cc.confirmed = usable && confirms(&cc.first_run, &c2);
            println!(
                "    {:>16}: second run z = {:+.2}  →  {}",
                cc.class,
                c2.sign_z,
                if cc.confirmed {
                    "confirmed"
                } else if !usable {
                    "not usable: a control failed"
                } else {
                    "not confirmed (inconclusive)"
                }
            );
            cc.confirmation_run = Some(c2);
        }
        let lines = control_lines(&second_negative, &second_reference, ref_k, second_nominal, &second_controls);
        for line in lines.iter().take(2) {
            println!("    {}", line);
        }
        confirmation_run_negative_control = Some(second_negative);
    }
    if unusable_reason.is_some() {
        for cc in comps.iter_mut() {
            cc.confirmed = false;
        }
    }

    let confirmed_classes: Vec<String> = comps.iter().filter(|c| c.confirmed).map(|c| c.class.clone()).collect();
    let (mut max_z, mut delta_at) = (0.0f64, 0.0f64);
    for c in &comps {
        if c.first_run.sign_z.abs() > max_z {
            max_z = c.first_run.sign_z.abs();
            delta_at = c.first_run.delta_ns;
        }
    }

    println!();
    println!("  ════════════════════════════════════════════════════════");
    if let Some(reason) = &unusable_reason {
        println!("  RESULT: not usable — {}.", reason);
        println!("  The comparisons of this run say nothing. Repeat the run, on a quieter machine if possible.");
    } else if confirmed_classes.is_empty() {
        println!("  RESULT: no confirmed timing difference for these input classes");
        println!("  largest |z| in the first run: {:.2} (Δ there = {:+.1} ns)", max_z, delta_at);
        if let (Some(half), Some(most)) = (controls.detectable_shift_50_ns, controls.detectable_shift_95_ns) {
            println!("  The reference delay of this run ({}) was visible;", effect(&reference));
            println!("  a shift of about {:.1} ns would have reached the threshold in half of such runs,", half);
            println!("  about {:.1} ns in 95 % of them.", most);
        } else if controls.reference_visible {
            println!("  The reference delay of this run was visible, but its measured size ({})", effect(&reference));
            println!("  does not match the added work. No statement about the size of detectable shifts.");
        } else if ref_k == 0 {
            println!("  No reference delay was added (--ref-k 0): the run does not show what it could have detected.");
        } else {
            println!("  The reference delay of this run was NOT visible: the run was not sensitive");
            println!("  enough to say anything about differences of that size. Use more rounds.");
        }
        println!("  Not a proof of constant-time behaviour.");
    } else {
        println!("  RESULT: timing difference detected and confirmed for: {}", confirmed_classes.join(", "));
        println!("  The classes differ from \"valid\" in the ciphertext (a public input). The result shows");
        println!("  input-dependent timing. The same difference in all rejection classes points to the");
        println!("  accept/rejection path; a difference for valid-2 to message-dependent timing.");
    }
    println!("  ════════════════════════════════════════════════════════");
    println!();

    Ok(FoOracleResult {
        build: BuildInfo::collect(),
        platform,
        config: FoOracleConfig { rounds, ..config.clone() },
        threshold_abs_z: Z_THRESHOLD,
        confirmation_z: Z_CONFIRM,
        classes: summaries,
        comparisons: comps,
        negative_control: negative,
        negative_control_passed,
        reference,
        reference_visible: controls.reference_visible,
        reference_nominal_ns: reference_nominal,
        reference_size_plausible: controls.reference_size_plausible,
        detectable_shift_50_ns: controls.detectable_shift_50_ns,
        detectable_shift_95_ns: controls.detectable_shift_95_ns,
        confirmation_run_negative_control,
        usable: unusable_reason.is_none(),
        unusable_reason,
        max_abs_z: max_z,
        delta_at_max_z_ns: delta_at,
        timing_difference_confirmed: !confirmed_classes.is_empty(),
        confirmed_classes,
        timestamp: utc_timestamp(),
    })
}
