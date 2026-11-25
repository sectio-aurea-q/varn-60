// VÄRN-60 (Anu) — multi-library ML-KEM-768 scan
//
// The same test for five ML-KEM-768 libraries, in the same run:
//   PQClean (via pqcrypto-mlkem), RustCrypto ml-kem, liboqs, AWS-LC (via
//   aws-lc-rs), libcrux-ml-kem.
// These are five libraries, not five independent implementations: liboqs
// (since 0.13) and AWS-LC both ship code from mlkem-native. `--libs` selects
// a subset.
//
// Per library one key pair A is generated, with two honest ciphertexts for it
// (ct_A for the test, ct_C for the controls), and an honest ciphertext ct_B
// for a second key pair. Six classes are measured interleaved in random order
// per round, all with the secret key of A:
//
//   0  accept            decaps(ct_A)
//   1  other ciphertext  decaps(ct_B)            implicit rejection, entirely
//                                                different ciphertext
//   2  bit flip          decaps(ct_A, one bit    implicit rejection, ciphertext
//                        flipped)                differs from class 0 in one bit
//   3  control a         decaps(ct_C)
//   4  control b         decaps(ct_C)            the same bytes as class 3
//   5  reference         decaps(ct_C)            the same bytes, with ref_k more
//                                                iterations of added work
//
// Comparisons (paired sign test, analysis::harness):
//   * 0 vs 1 and 0 vs 2 — the test: accept vs. implicit rejection. The
//     ciphertext is a public input, so a difference in only one of the two
//     classes points to input-dependent timing; a difference of the same sign
//     in both points to a timing difference between the accept and the
//     rejection path.
//   * 3 vs 4 — negative control of this run: identical inputs, so every
//     detection is a false positive of the setup.
//   * 3 vs 5 — reference delay (positive control of this run): is an added
//     delay of known origin visible in the noise of this library, and does
//     its measured size agree with the added work? From it the size of the
//     shift at the detection threshold of this run is estimated.
//   The controls are judged by harness::judge_controls. If a control fails in
//   any run of a library (the first run, the confirmation run, the run with
//   fresh inputs), the comparisons of that library are reported as not
//   usable, whatever they show.
//
// Every tested input (ct_A, ct_B, the flipped ciphertext) is used by exactly
// one class, and the controls use a ciphertext of their own. An input that is
// used by more classes than another one can be measured faster for that
// reason alone (see analysis::harness), which would distort the test. Two of
// the three test inputs differ in one bit only; the flipped ciphertext is a
// byte string of its own, but its first decryption steps process almost the
// same data as class 0.
//
// Why every class uses the same key: decapsulation time differs from key to
// key through public data (examples/key_dependence.rs).
//
// Decision
//   1. First run. |z| > Z_THRESHOLD in a test comparison is a detection.
//   2. A detection is confirmed by a second run with the same key and the
//      same ciphertexts in a new random order (same sign, |z| > Z_CONFIRM).
//      The question of this step is: is the difference real for these inputs?
//   3. A confirmed difference is measured once more with a fresh key and
//      fresh ciphertexts, to classify it: if it appears again with the same
//      sign it belongs to the kind of input (accept vs. rejection); if not,
//      it depends on the particular inputs. Both are confirmed differences.
//
// All classes execute the same code in the timed region (harness::
// time_with_work): the library call followed by dummy_work(n), with n drawn
// fresh for every call and ref_k iterations more for the reference
// (harness::AddedWork; the extra iterations are read from a table, there is
// no branch on the class). The ciphertexts of
// the six classes are six slots of an InterleavedInputs buffer; before every
// timed call the slot of the class is copied into one fixed working buffer.
// The classes therefore differ in the bytes of the ciphertext and, for the
// reference, in the number of added iterations — in nothing else (see
// analysis::harness).

use crate::analysis::harness::{
    compare, confirms, control_lines, effect, judge_controls, measure_interleaved, time_with_work, AddedWork,
    Comparison, InterleavedInputs, MIN_ROUNDS, Z_CONFIRM, Z_THRESHOLD,
};
use crate::platform::{utc_timestamp, BuildInfo, PlatformInfo};
use serde::Serialize;
use std::hint::black_box;

/// default number of dummy_work iterations for the reference class
pub const DEFAULT_REF_K: u32 = 32;
/// largest accepted number of iterations for the reference class
pub const MAX_REF_K: u32 = 1_000_000;
/// Names of the libraries for `--libs`, in the order in which they are measured.
pub const LIBRARY_KEYS: [&str; 5] = ["pqclean", "rustcrypto", "liboqs", "aws-lc", "libcrux"];
const NOT_USABLE: &str = "not usable: a control of this library failed";
const WARMUP: usize = 200;
const N_CLASSES: usize = 6;
const CT_LEN: usize = 1088;
/// bit flipped for class 2 (bit 0 of the middle byte)
const FLIP_BYTE: usize = CT_LEN / 2;
const CHECK_FAILED: &str = "correctness check failed";
const SETUP_FAILED: &str = "key generation or encapsulation failed";
const DECAPS_FAILED: &str = "decapsulation reported an error during the measurement";

const ACCEPT: usize = 0;
const OTHER_CT: usize = 1;
const BIT_FLIP: usize = 2;
const CONTROL_A: usize = 3;
const CONTROL_B: usize = 4;
const REFERENCE: usize = 5;

/// Input slots of the six classes: ct_A, ct_B, ct_A with one bit flipped,
/// and three times ct_C.
fn class_inputs(ct_a: &[u8], ct_b: &[u8], ct_c: &[u8]) -> InterleavedInputs {
    let mut flipped = ct_a.to_vec();
    flipped[FLIP_BYTE] ^= 1;
    InterleavedInputs::new(&[ct_a, ct_b, &flipped, ct_c, ct_c, ct_c])
}

/// Added work of the six classes: the amount drawn per call for every class,
/// ref_k iterations more for the reference (the last class).
fn added_work(ref_k: u32) -> AddedWork {
    const _: () = assert!(REFERENCE == N_CLASSES - 1);
    AddedWork::last_class(N_CLASSES, ref_k)
}

/// Correctness check: does decapsulating the input of `class` give what it
/// must give? ss_a and ss_c are the secrets encapsulated in ct_A and ct_C.
fn output_ok(class: usize, got: &[u8], ss_a: &[u8], ss_c: &[u8]) -> bool {
    match class {
        ACCEPT => got == ss_a,
        OTHER_CT | BIT_FLIP => got != ss_a && got != ss_c,
        _ => got == ss_c,
    }
}

#[derive(Debug, Serialize)]
pub struct PairResult {
    pub first_run: Comparison,
    /// second run with the same key and ciphertexts (only after a detection)
    pub confirmation_run: Option<Comparison>,
    pub confirmed: bool,
    /// further run with a fresh key and fresh ciphertexts (only after a
    /// confirmation)
    pub fresh_inputs_run: Option<Comparison>,
    /// the run with fresh inputs shows the same sign with |z| > Z_CONFIRM
    pub reproduced_with_fresh_inputs: Option<bool>,
    /// "no difference detected" | "not confirmed (inconclusive)" |
    /// "detected, confirmation run failed" | "difference confirmed" (with the
    /// classification from the run with fresh inputs, if there is one) |
    /// "not usable: a control of this library failed"
    pub outcome: String,
}

#[derive(Debug, Serialize)]
pub struct MultiLibResult {
    pub library: String,
    pub implementation: String,
    pub algorithm: String,
    /// accept vs. rejection of an honest ciphertext for another key
    pub other_ciphertext: PairResult,
    /// accept vs. rejection of the same ciphertext with one bit flipped
    pub bit_flip: PairResult,
    /// control a vs. control b (identical inputs), first run
    pub negative_control: Comparison,
    pub negative_control_passed: bool,
    /// control with the reference delay vs. control a, first run
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
    /// negative controls of the further runs of this library (confirmation
    /// run, run with fresh inputs), in that order
    pub further_negative_controls: Vec<Comparison>,
    /// false if a control failed in any run of this library; its comparisons
    /// then say nothing
    pub usable: bool,
    pub unusable_reason: Option<String>,
    /// set if a needed further run could not be performed
    pub incomplete: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SkippedLibrary {
    pub library: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct MultiLibScanResult {
    pub build: BuildInfo,
    pub platform: PlatformInfo,
    pub rounds: usize,
    pub threshold_abs_z: f64,
    pub confirmation_z: f64,
    pub reference_iterations: u32,
    /// libraries selected for this scan (`--libs`; all by default)
    pub libraries_selected: Vec<String>,
    pub results: Vec<MultiLibResult>,
    pub skipped: Vec<SkippedLibrary>,
    pub timestamp: String,
}

/// One measured run: the timings per class, and the cost of one iteration of
/// added work during the run (ns).
struct Run {
    timings: Vec<Vec<u64>>,
    iteration_cost_ns: Option<f64>,
}
/// A library with a fixed key and fixed ciphertexts, checked and ready to be
/// measured. Calling it measures the given number of rounds.
type Prepared = Box<dyn FnMut(usize) -> Result<Run, String>>;
type Prepare = fn(u32) -> Result<Prepared, String>;

/// PQClean ML-KEM-768 via pqcrypto-mlkem.
fn prepare_pqclean(ref_k: u32) -> Result<Prepared, String> {
    use pqcrypto_mlkem::mlkem768;
    use pqcrypto_traits::kem::{Ciphertext as _, SharedSecret as _};
    let (pk_a, sk) = mlkem768::keypair();
    let (pk_b, _) = mlkem768::keypair();
    let (ss_a, ct_a) = mlkem768::encapsulate(&pk_a);
    let (ss_c, ct_c) = mlkem768::encapsulate(&pk_a);
    let (_, ct_b) = mlkem768::encapsulate(&pk_b);
    let inputs = class_inputs(ct_a.as_bytes(), ct_b.as_bytes(), ct_c.as_bytes());
    let mut buf = vec![0u8; CT_LEN];
    let mut ct_buf = ct_a;
    let mut check = true;
    for class in 0..N_CLASSES {
        inputs.load(class, &mut buf);
        ct_buf = mlkem768::Ciphertext::from_bytes(&buf).map_err(|_| "ciphertext length".to_string())?;
        let got = mlkem768::decapsulate(&ct_buf, &sk);
        check &= output_ok(class, got.as_bytes(), ss_a.as_bytes(), ss_c.as_bytes());
    }
    if !check {
        return Err(CHECK_FAILED.into());
    }
    let mut work = added_work(ref_k);
    Ok(Box::new(move |rounds| {
        let timings = measure_interleaved(N_CLASSES, rounds, WARMUP, |c| {
            let n = work.next(c);
            inputs.load(c, &mut buf);
            ct_buf = mlkem768::Ciphertext::from_bytes(&buf).expect("ciphertext length");
            time_with_work(n, || mlkem768::decapsulate(black_box(&ct_buf), black_box(&sk)))
        });
        Ok(Run { timings, iteration_cost_ns: work.take_iteration_cost_ns() })
    }))
}

/// RustCrypto ml-kem (pure Rust).
fn prepare_rustcrypto(ref_k: u32) -> Result<Prepared, String> {
    use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
    use ml_kem::MlKem768;
    let (dk, ek_a) = MlKem768::generate_keypair();
    let (_, ek_b) = MlKem768::generate_keypair();
    let (ct_a, ss_a) = ek_a.encapsulate();
    let (ct_c, ss_c) = ek_a.encapsulate();
    let (ct_b, _) = ek_b.encapsulate();
    let inputs = class_inputs(ct_a.as_slice(), ct_b.as_slice(), ct_c.as_slice());
    let mut ct_buf = ct_a;
    let mut check = true;
    for class in 0..N_CLASSES {
        inputs.load(class, ct_buf.as_mut_slice());
        let got = dk.decapsulate(&ct_buf);
        check &= output_ok(class, got.as_slice(), ss_a.as_slice(), ss_c.as_slice());
    }
    if !check {
        return Err(CHECK_FAILED.into());
    }
    let mut work = added_work(ref_k);
    Ok(Box::new(move |rounds| {
        let timings = measure_interleaved(N_CLASSES, rounds, WARMUP, |c| {
            let n = work.next(c);
            inputs.load(c, ct_buf.as_mut_slice());
            time_with_work(n, || black_box(&dk).decapsulate(black_box(&ct_buf)))
        });
        Ok(Run { timings, iteration_cost_ns: work.take_iteration_cost_ns() })
    }))
}

/// liboqs ML-KEM-768 (C, via FFI).
#[cfg(feature = "liboqs")]
fn prepare_liboqs(ref_k: u32) -> Result<Prepared, String> {
    use crate::target::liboqs::*;
    use std::ffi::CString;

    /// Owns the liboqs object and frees it when dropped.
    struct Handle(*mut OQS_KEM);
    impl Handle {
        fn ptr(&self) -> *mut OQS_KEM {
            self.0
        }
    }
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe { OQS_KEM_free(self.0) }
        }
    }

    init();
    let name = CString::new("ML-KEM-768").map_err(|_| "invalid algorithm name".to_string())?;
    let kem = unsafe { OQS_KEM_new(name.as_ptr()) };
    if kem.is_null() {
        return Err("ML-KEM-768 is not available in this liboqs build".into());
    }
    let handle = Handle(kem);
    let len = unsafe { kem_lengths(handle.ptr()) };
    let fips203 = KemLengths { public_key: 1184, secret_key: 2400, ciphertext: CT_LEN, shared_secret: 32 };
    if len != fips203 {
        return Err(format!("liboqs reports unexpected ML-KEM-768 buffer lengths: {:?}", len));
    }
    let mut pk_a = vec![0u8; len.public_key];
    let mut sk = vec![0u8; len.secret_key];
    let mut pk_b = vec![0u8; len.public_key];
    let mut sk_b = vec![0u8; len.secret_key];
    let mut ct_a = vec![0u8; len.ciphertext];
    let mut ct_b = vec![0u8; len.ciphertext];
    let mut ct_c = vec![0u8; len.ciphertext];
    let mut ss_a = vec![0u8; len.shared_secret];
    let mut ss_b = vec![0u8; len.shared_secret];
    let mut ss_c = vec![0u8; len.shared_secret];
    let mut out = vec![0u8; len.shared_secret];

    let setup_ok = unsafe {
        OQS_KEM_keypair(handle.ptr(), pk_a.as_mut_ptr(), sk.as_mut_ptr()) == OQS_SUCCESS
            && OQS_KEM_keypair(handle.ptr(), pk_b.as_mut_ptr(), sk_b.as_mut_ptr()) == OQS_SUCCESS
            && OQS_KEM_encaps(handle.ptr(), ct_a.as_mut_ptr(), ss_a.as_mut_ptr(), pk_a.as_ptr()) == OQS_SUCCESS
            && OQS_KEM_encaps(handle.ptr(), ct_c.as_mut_ptr(), ss_c.as_mut_ptr(), pk_a.as_ptr()) == OQS_SUCCESS
            && OQS_KEM_encaps(handle.ptr(), ct_b.as_mut_ptr(), ss_b.as_mut_ptr(), pk_b.as_ptr()) == OQS_SUCCESS
    };
    if !setup_ok {
        return Err(SETUP_FAILED.into());
    }
    let inputs = class_inputs(&ct_a, &ct_b, &ct_c);
    let mut ct_buf = vec![0u8; len.ciphertext];

    let mut check = true;
    for class in 0..N_CLASSES {
        inputs.load(class, &mut ct_buf);
        let st = unsafe { OQS_KEM_decaps(handle.ptr(), out.as_mut_ptr(), ct_buf.as_ptr(), sk.as_ptr()) };
        check &= st == OQS_SUCCESS && output_ok(class, &out, &ss_a, &ss_c);
    }
    if !check {
        return Err(CHECK_FAILED.into());
    }

    let mut work = added_work(ref_k);
    Ok(Box::new(move |rounds| {
        // `handle.ptr()` borrows the whole handle, so this closure takes
        // ownership of it and the liboqs object lives as long as the closure.
        // (Reading the pointer field directly would capture a copy of the
        // pointer only, and the object would be freed when this function
        // returns.)
        let kem = handle.ptr();
        let mut status_or: OqsStatus = OQS_SUCCESS;
        let m = measure_interleaved(N_CLASSES, rounds, WARMUP, |c| {
            let n = work.next(c);
            inputs.load(c, &mut ct_buf);
            let (skp, ctp) = (sk.as_ptr(), ct_buf.as_ptr());
            let mut st: OqsStatus = OQS_SUCCESS;
            let ns = time_with_work(n, || {
                st = unsafe { OQS_KEM_decaps(kem, out.as_mut_ptr(), black_box(ctp), black_box(skp)) };
            });
            status_or |= st;
            ns
        });
        if status_or != OQS_SUCCESS {
            return Err(DECAPS_FAILED.into());
        }
        Ok(Run { timings: m, iteration_cost_ns: work.take_iteration_cost_ns() })
    }))
}

#[cfg(not(feature = "liboqs"))]
fn prepare_liboqs(_ref_k: u32) -> Result<Prepared, String> {
    Err("built without the `liboqs` feature".into())
}

/// AWS-LC via aws-lc-rs, default (non-FIPS) build.
fn prepare_aws_lc(ref_k: u32) -> Result<Prepared, String> {
    use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, ML_KEM_768};
    let fail = |_| SETUP_FAILED.to_string();
    let dk = DecapsulationKey::generate(&ML_KEM_768).map_err(fail)?;
    let dk_b = DecapsulationKey::generate(&ML_KEM_768).map_err(fail)?;
    let ek_a = dk.encapsulation_key().map_err(fail)?;
    let (ct_a, ss_a) = ek_a.encapsulate().map_err(fail)?;
    let (ct_c, ss_c) = ek_a.encapsulate().map_err(fail)?;
    let (ct_b, _) = dk_b.encapsulation_key().map_err(fail)?.encapsulate().map_err(fail)?;
    let ss_a: Vec<u8> = ss_a.as_ref().to_vec();
    let ss_c: Vec<u8> = ss_c.as_ref().to_vec();
    let inputs = class_inputs(ct_a.as_ref(), ct_b.as_ref(), ct_c.as_ref());
    let mut ct_buf = vec![0u8; CT_LEN];

    let mut check = true;
    for class in 0..N_CLASSES {
        inputs.load(class, &mut ct_buf);
        match dk.decapsulate(Ciphertext::from(&ct_buf[..])) {
            Ok(s) => check &= output_ok(class, s.as_ref(), &ss_a, &ss_c),
            Err(_) => check = false,
        }
    }
    if !check {
        return Err(CHECK_FAILED.into());
    }

    let mut work = added_work(ref_k);
    Ok(Box::new(move |rounds| {
        let mut any_err = false;
        let m = measure_interleaved(N_CLASSES, rounds, WARMUP, |c| {
            let n = work.next(c);
            inputs.load(c, &mut ct_buf);
            let cipher = Ciphertext::from(black_box(&ct_buf[..]));
            let mut err = false;
            let ns = time_with_work(n, || {
                let r = black_box(&dk).decapsulate(cipher);
                err = r.is_err();
                r
            });
            any_err |= err;
            ns
        });
        if any_err {
            return Err(DECAPS_FAILED.into());
        }
        Ok(Run { timings: m, iteration_cost_ns: work.take_iteration_cost_ns() })
    }))
}

/// libcrux-ml-kem (Cryspen).
fn prepare_libcrux(ref_k: u32) -> Result<Prepared, String> {
    use libcrux_ml_kem::mlkem768;
    use rand::{rngs::OsRng, RngCore};
    let mut seed = [0u8; 64];
    let mut coins = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let kp = mlkem768::generate_key_pair(seed);
    OsRng.fill_bytes(&mut seed);
    let kp_b = mlkem768::generate_key_pair(seed);
    OsRng.fill_bytes(&mut coins);
    let (ct_a, ss_a) = mlkem768::encapsulate(kp.public_key(), coins);
    OsRng.fill_bytes(&mut coins);
    let (ct_c, ss_c) = mlkem768::encapsulate(kp.public_key(), coins);
    OsRng.fill_bytes(&mut coins);
    let (ct_b, _) = mlkem768::encapsulate(kp_b.public_key(), coins);
    let inputs = class_inputs(ct_a.as_slice(), ct_b.as_slice(), ct_c.as_slice());
    let mut buf = [0u8; CT_LEN];
    let mut ct_buf = mlkem768::MlKem768Ciphertext::from(buf);
    let mut check = true;
    for class in 0..N_CLASSES {
        inputs.load(class, &mut buf);
        ct_buf = mlkem768::MlKem768Ciphertext::from(buf);
        let got = mlkem768::decapsulate(kp.private_key(), &ct_buf);
        check &= output_ok(class, &got, &ss_a, &ss_c);
    }
    if !check {
        return Err(CHECK_FAILED.into());
    }
    let mut work = added_work(ref_k);
    Ok(Box::new(move |rounds| {
        let sk = kp.private_key();
        let timings = measure_interleaved(N_CLASSES, rounds, WARMUP, |c| {
            let n = work.next(c);
            inputs.load(c, &mut buf);
            ct_buf = mlkem768::MlKem768Ciphertext::from(buf);
            time_with_work(n, || mlkem768::decapsulate(black_box(sk), black_box(&ct_buf)))
        });
        Ok(Run { timings, iteration_cost_ns: work.take_iteration_cost_ns() })
    }))
}

/// Which PQClean code pqcrypto-mlkem runs on this machine (its build script
/// compiles the AVX2 code only on x86-64 outside macOS and Windows, and
/// selects it at run time; on AArch64 it always uses the aarch64 code).
fn pqclean_code_path() -> &'static str {
    #[cfg(target_arch = "aarch64")]
    {
        "PQClean aarch64 (NEON) code"
    }
    #[cfg(all(target_arch = "x86_64", not(target_os = "macos"), not(target_os = "windows")))]
    {
        if std::arch::is_x86_feature_detected!("avx2") {
            "PQClean avx2 code"
        } else {
            "PQClean clean (portable C) code"
        }
    }
    #[cfg(not(any(
        target_arch = "aarch64",
        all(target_arch = "x86_64", not(target_os = "macos"), not(target_os = "windows"))
    )))]
    {
        "PQClean clean (portable C) code"
    }
}

/// Parse the value of `--libs`: a comma-separated list of names from
/// LIBRARY_KEYS.
pub fn parse_libraries(list: &str) -> Result<Vec<&'static str>, String> {
    let mut chosen: Vec<&'static str> = Vec::new();
    for name in list.split(',').map(|n| n.trim()).filter(|n| !n.is_empty()) {
        match LIBRARY_KEYS.iter().find(|key| key.eq_ignore_ascii_case(name)) {
            Some(key) => {
                if !chosen.contains(key) {
                    chosen.push(key);
                }
            }
            None => return Err(format!("unknown library \"{}\" (known: {})", name, LIBRARY_KEYS.join(", "))),
        }
    }
    if chosen.is_empty() {
        return Err(format!("--libs needs at least one of: {}", LIBRARY_KEYS.join(", ")));
    }
    Ok(chosen)
}

fn pair(first: Comparison, second: Option<Comparison>, fresh: Option<Comparison>, run_failed: bool) -> PairResult {
    if !first.difference_detected {
        return PairResult {
            first_run: first,
            confirmation_run: None,
            confirmed: false,
            fresh_inputs_run: None,
            reproduced_with_fresh_inputs: None,
            outcome: "no difference detected".into(),
        };
    }
    let confirmed = second.as_ref().map(|c| confirms(&first, c)).unwrap_or(false);
    if !confirmed {
        let outcome = if second.is_none() && run_failed {
            "detected, confirmation run failed"
        } else {
            "not confirmed (inconclusive)"
        };
        return PairResult {
            first_run: first,
            confirmation_run: second,
            confirmed: false,
            fresh_inputs_run: None,
            reproduced_with_fresh_inputs: None,
            outcome: outcome.into(),
        };
    }
    let reproduced = fresh.as_ref().map(|c| c.sign_z.signum() == first.sign_z.signum() && c.sign_z.abs() > Z_CONFIRM);
    let outcome = match reproduced {
        Some(true) => "difference confirmed; also present with a fresh key and fresh ciphertexts",
        Some(false) => {
            "difference confirmed; not reproduced with a fresh key and fresh ciphertexts (depends on the inputs)"
        }
        None => "difference confirmed",
    };
    PairResult {
        first_run: first,
        confirmation_run: second,
        confirmed: true,
        fresh_inputs_run: fresh,
        reproduced_with_fresh_inputs: reproduced,
        outcome: outcome.into(),
    }
}

fn print_pair(label: &str, p: &PairResult) {
    let second = match &p.confirmation_run {
        Some(c) => format!(", second run z = {:+.2}", c.sign_z),
        None => String::new(),
    };
    let fresh = match &p.fresh_inputs_run {
        Some(c) => format!(", fresh inputs z = {:+.2}", c.sign_z),
        None => String::new(),
    };
    println!(
        "    {:<26}: {}, z = {:+.2}{}{}  →  {}",
        label,
        effect(&p.first_run),
        p.first_run.sign_z,
        second,
        fresh,
        p.outcome
    );
}

/// Measure the libraries named in `selected` (names from LIBRARY_KEYS; the
/// order of measurement is always that of LIBRARY_KEYS).
pub fn run_multi_lib_scan(samples: usize, ref_k: u32, selected: &[&str]) -> MultiLibScanResult {
    let rounds = samples.max(MIN_ROUNDS);
    let platform = PlatformInfo::detect();
    let build = BuildInfo::collect();

    println!();
    println!("  VÄRN-60 (Anu) — ML-KEM-768, the same test for every library");
    println!("  Platform: {}", platform.chip);
    println!("  Versions: liboqs {}; {}", build.liboqs_version, build.crate_versions);
    println!("  Rounds:   {} (six classes per round, random order)", rounds);
    println!(
        "  Rule:     paired sign test, first run |z| > {}, confirmation |z| > {} with the same sign",
        Z_THRESHOLD, Z_CONFIRM
    );
    println!(
        "  Sign:     positive Δ and z: the class named in the line (rejection, second control, added delay) is slower"
    );
    println!("  Estimate: Δ is the interpolated median of the paired differences, or their clipped mean where they");
    println!("            take only a few clock values (clock step {} ns)", platform.clock_step_ns);
    println!();

    let libs: [(&str, &str, String, Prepare); 5] = [
        (
            LIBRARY_KEYS[0],
            "PQClean (pqcrypto-mlkem)",
            format!("{}, via pqcrypto-mlkem", pqclean_code_path()),
            prepare_pqclean,
        ),
        (LIBRARY_KEYS[1], "RustCrypto ml-kem", "pure Rust".to_string(), prepare_rustcrypto),
        (
            LIBRARY_KEYS[2],
            "liboqs",
            "C library as linked; its code path is chosen by its build options and the CPU".to_string(),
            prepare_liboqs,
        ),
        (LIBRARY_KEYS[3], "aws-lc-rs", "AWS-LC via aws-lc-sys, default (non-FIPS) build".to_string(), prepare_aws_lc),
        (
            LIBRARY_KEYS[4],
            "libcrux-ml-kem",
            "Rust; AVX2 code on x86-64 with AVX2, NEON code on AArch64, portable code otherwise".to_string(),
            prepare_libcrux,
        ),
    ];

    let mut results = Vec::new();
    let mut skipped = Vec::new();
    for (key, name, implementation, prepare) in libs.iter() {
        if !selected.contains(key) {
            continue;
        }
        println!("  ── {} ──", name);
        let first = prepare(ref_k).and_then(|mut target| target(rounds).map(|m| (target, m)));
        let (mut target, first) = match first {
            Ok(x) => x,
            Err(reason) => {
                println!("    SKIPPED: {}", reason);
                println!();
                skipped.push(SkippedLibrary { library: name.to_string(), reason });
                continue;
            }
        };
        let ct_first = compare(&first.timings[ACCEPT], &first.timings[OTHER_CT]);
        let flip_first = compare(&first.timings[ACCEPT], &first.timings[BIT_FLIP]);
        let negative = compare(&first.timings[CONTROL_A], &first.timings[CONTROL_B]);
        let reference = compare(&first.timings[CONTROL_A], &first.timings[REFERENCE]);
        let negative_control_passed = !negative.difference_detected;
        let reference_nominal = first.iteration_cost_ns.map(|c| c * ref_k as f64);
        let controls = judge_controls(&negative, &reference, ref_k, reference_nominal);
        let mut unusable_reason = controls.unusable.clone();

        // confirmation: same key and ciphertexts, new random order
        let mut incomplete = None;
        let second = if ct_first.difference_detected || flip_first.difference_detected {
            match target(rounds) {
                Ok(m) => Some(m),
                Err(reason) => {
                    incomplete = Some(format!("confirmation run failed: {}", reason));
                    None
                }
            }
        } else {
            None
        };
        let confirmation_failed = incomplete.is_some();
        let ct_second = second
            .as_ref()
            .filter(|_| ct_first.difference_detected)
            .map(|m| compare(&m.timings[ACCEPT], &m.timings[OTHER_CT]));
        let flip_second = second
            .as_ref()
            .filter(|_| flip_first.difference_detected)
            .map(|m| compare(&m.timings[ACCEPT], &m.timings[BIT_FLIP]));
        let ct_confirmed = ct_second.as_ref().map(|c| confirms(&ct_first, c)).unwrap_or(false);
        let flip_confirmed = flip_second.as_ref().map(|c| confirms(&flip_first, c)).unwrap_or(false);

        // classification of a confirmed difference: fresh key and ciphertexts
        let fresh = if ct_confirmed || flip_confirmed {
            match prepare(ref_k).and_then(|mut t| t(rounds)) {
                Ok(m) => Some(m),
                Err(reason) => {
                    incomplete = Some(format!("run with fresh inputs failed: {}", reason));
                    None
                }
            }
        } else {
            None
        };
        let ct_fresh =
            fresh.as_ref().filter(|_| ct_confirmed).map(|m| compare(&m.timings[ACCEPT], &m.timings[OTHER_CT]));
        let flip_fresh =
            fresh.as_ref().filter(|_| flip_confirmed).map(|m| compare(&m.timings[ACCEPT], &m.timings[BIT_FLIP]));

        // the controls of the further runs count as well
        let mut further_negative_controls = Vec::new();
        for (run, what) in [(&second, "confirmation run"), (&fresh, "run with fresh inputs")] {
            if let Some(m) = run {
                let further_negative = compare(&m.timings[CONTROL_A], &m.timings[CONTROL_B]);
                let further_reference = compare(&m.timings[CONTROL_A], &m.timings[REFERENCE]);
                let nominal = m.iteration_cost_ns.map(|c| c * ref_k as f64);
                let verdict = judge_controls(&further_negative, &further_reference, ref_k, nominal);
                if let (None, Some(reason)) = (&unusable_reason, verdict.unusable) {
                    unusable_reason = Some(format!("{}: {}", what, reason));
                }
                further_negative_controls.push(further_negative);
            }
        }

        let mut other_ciphertext = pair(ct_first, ct_second, ct_fresh, confirmation_failed);
        let mut bit_flip = pair(flip_first, flip_second, flip_fresh, confirmation_failed);
        if unusable_reason.is_some() {
            for p in [&mut other_ciphertext, &mut bit_flip] {
                p.confirmed = false;
                p.outcome = NOT_USABLE.into();
            }
        }

        print_pair("other ciphertext", &other_ciphertext);
        print_pair("one bit flipped", &bit_flip);
        for line in control_lines(&negative, &reference, ref_k, reference_nominal, &controls) {
            println!("    {}", line);
        }
        if let Some(reason) = &unusable_reason {
            println!("    NOT USABLE: {}", reason);
        }
        if let Some(r) = &incomplete {
            println!("    INCOMPLETE: {}", r);
        }
        println!();

        results.push(MultiLibResult {
            library: name.to_string(),
            implementation: implementation.clone(),
            algorithm: "ML-KEM-768".into(),
            other_ciphertext,
            bit_flip,
            negative_control: negative,
            negative_control_passed,
            reference,
            reference_visible: controls.reference_visible,
            reference_nominal_ns: reference_nominal,
            reference_size_plausible: controls.reference_size_plausible,
            detectable_shift_50_ns: controls.detectable_shift_50_ns,
            detectable_shift_95_ns: controls.detectable_shift_95_ns,
            further_negative_controls,
            usable: unusable_reason.is_none(),
            unusable_reason,
            incomplete,
        });
    }

    let confirmed: Vec<String> = results
        .iter()
        .flat_map(|r| {
            let mut v = Vec::new();
            if r.other_ciphertext.confirmed {
                v.push(format!("{} (other ciphertext)", r.library));
            }
            if r.bit_flip.confirmed {
                v.push(format!("{} (one bit flipped)", r.library));
            }
            v
        })
        .collect();
    let visible = results.iter().filter(|r| r.reference_visible).count();
    let negative_ok = results.iter().filter(|r| r.negative_control_passed).count();
    println!("  Summary");
    println!(
        "    confirmed differences: {}",
        if confirmed.is_empty() { "none".to_string() } else { confirmed.join(", ") }
    );
    println!(
        "    negative control (identical inputs) without detection in {} of {} tested libraries",
        negative_ok,
        results.len()
    );
    println!("    reference delay visible in {} of {} tested libraries", visible, results.len());
    for r in results.iter().filter(|r| !r.usable) {
        println!("    not usable: {} ({})", r.library, r.unusable_reason.as_deref().unwrap_or("a control failed"));
    }
    for r in results.iter().filter(|r| r.reference_size_plausible == Some(false)) {
        println!("    size of the reference delay does not match the added work: {}", r.library);
    }
    for s in &skipped {
        println!("    skipped: {} ({})", s.library, s.reason);
    }
    println!("    \"No difference detected\" is not a proof of constant-time behaviour.");
    println!();

    MultiLibScanResult {
        build,
        platform,
        rounds,
        threshold_abs_z: Z_THRESHOLD,
        confirmation_z: Z_CONFIRM,
        reference_iterations: ref_k,
        libraries_selected: LIBRARY_KEYS.iter().filter(|k| selected.contains(k)).map(|k| k.to_string()).collect(),
        results,
        skipped,
        timestamp: utc_timestamp(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::harness::comparison_with_z as comparison;

    #[test]
    fn no_detection_needs_no_further_run() {
        let p = pair(comparison(2.0), None, None, false);
        assert!(!p.confirmed);
        assert_eq!(p.outcome, "no difference detected");
    }

    #[test]
    fn detection_is_confirmed_by_the_same_inputs_only() {
        // same sign and |z| > 3 with the same inputs: confirmed
        let p = pair(comparison(9.0), Some(comparison(6.0)), None, false);
        assert!(p.confirmed);
        // opposite sign with the same inputs: not confirmed
        let p = pair(comparison(9.0), Some(comparison(-6.0)), None, false);
        assert!(!p.confirmed);
        assert_eq!(p.outcome, "not confirmed (inconclusive)");
        // confirmation run could not be performed
        let p = pair(comparison(9.0), None, None, true);
        assert!(!p.confirmed);
        assert_eq!(p.outcome, "detected, confirmation run failed");
    }

    #[test]
    fn fresh_inputs_classify_but_never_unconfirm() {
        // an input-dependent difference: confirmed with the same inputs,
        // opposite sign with a fresh key and fresh ciphertexts
        let p = pair(comparison(-18.7), Some(comparison(-17.0)), Some(comparison(35.3)), false);
        assert!(p.confirmed);
        assert_eq!(p.reproduced_with_fresh_inputs, Some(false));
        assert!(p.outcome.contains("depends on the inputs"));
        // a difference between accept and rejection: same sign again
        let p = pair(comparison(12.0), Some(comparison(11.0)), Some(comparison(13.0)), false);
        assert!(p.confirmed);
        assert_eq!(p.reproduced_with_fresh_inputs, Some(true));
    }

    /// Every library can be set up and measured: the correctness checks
    /// pass, and a short run returns one timing per class and round. (Run the
    /// tests under a memory checker to exercise the foreign-function calls,
    /// e.g. `valgrind` on the test binary.)
    #[test]
    fn every_library_can_be_prepared_and_measured() {
        let all: [(&str, Prepare); 5] = [
            ("pqclean", prepare_pqclean),
            ("rustcrypto", prepare_rustcrypto),
            ("liboqs", prepare_liboqs),
            ("aws-lc", prepare_aws_lc),
            ("libcrux", prepare_libcrux),
        ];
        for (name, prepare) in all {
            if name == "liboqs" && !cfg!(feature = "liboqs") {
                assert!(prepare(DEFAULT_REF_K).is_err());
                continue;
            }
            let mut target = prepare(DEFAULT_REF_K).unwrap_or_else(|e| panic!("{}: {}", name, e));
            // two runs with the same prepared inputs, as the scan makes them
            for _ in 0..2 {
                let run = target(30).unwrap_or_else(|e| panic!("{}: {}", name, e));
                assert_eq!(run.timings.len(), N_CLASSES, "{}", name);
                assert!(run.timings.iter().all(|t| t.len() == 30 && t.iter().all(|&ns| ns > 0)), "{}", name);
            }
        }
    }

    #[test]
    fn library_selection() {
        assert_eq!(parse_libraries("liboqs,aws-lc").unwrap(), vec!["liboqs", "aws-lc"]);
        // case and blanks do not matter, a repeated name counts once
        assert_eq!(parse_libraries(" PQClean , pqclean,libcrux ").unwrap(), vec!["pqclean", "libcrux"]);
        assert!(parse_libraries("openssl").unwrap_err().contains("unknown library"));
        assert!(parse_libraries(" , ").is_err());
    }

    #[test]
    fn correctness_check_per_class() {
        let (a, c, other) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        assert!(output_ok(ACCEPT, &a, &a, &c));
        assert!(!output_ok(ACCEPT, &other, &a, &c));
        for class in [OTHER_CT, BIT_FLIP] {
            assert!(output_ok(class, &other, &a, &c));
            assert!(!output_ok(class, &a, &a, &c));
        }
        for class in [CONTROL_A, CONTROL_B, REFERENCE] {
            assert!(output_ok(class, &c, &a, &c));
            assert!(!output_ok(class, &a, &a, &c));
        }
    }
}
