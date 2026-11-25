// VÄRN-60 (Anu) — shared measurement harness
//
// One measurement procedure for every timing test.
//
// Measurement
//   Classes are measured interleaved: in every round each class is timed
//   exactly once, in a fresh uniformly random order (Fisher–Yates). Drift
//   (warm-up, frequency scaling, temperature) falls on all classes equally.
//   Carry-over from preceding calls (caches, branch predictor) is equal only
//   for inputs that occur equally often in a round: a key or ciphertext that
//   is used by more classes than another one is measured faster for that
//   reason alone. The checks are therefore built so that every tested input
//   is used by exactly one class, and the controls use an input of their own.
//
// Inputs
//   The inputs of all classes are kept byte-interleaved in one buffer
//   (InterleavedInputs). Before every timed call the input of the class is
//   copied from there into one fixed working buffer, outside the timed
//   region. Every class is therefore processed at the same address, and
//   loading any class touches the same memory range in the same pattern.
//
// The same code for every class
//   Every class executes the same code, inside and around the timed region.
//   The classes differ in data only: in the bytes of the input and in one
//   entry of a table (the number of added iterations, AddedWork). A branch on
//   the class shortly before the timed region is enough to shift the measured
//   time by a few nanoseconds. Whether a build really treats the classes
//   alike is not guaranteed by the source code; it is what the negative
//   controls test.
//
// Timed region (time_with_work)
//   barrier · clock · library call · barrier · added work · barrier · clock
//   A barrier (LFENCE on x86-64, ISB on AArch64) lets everything issued so
//   far finish before anything later starts. (For LFENCE this is documented
//   for Intel processors; on AMD processors it holds only if the operating
//   system has made LFENCE serialising, which current Linux kernels do where
//   the processor allows it.) Without the barrier after the library call, a
//   processor can execute the added work alongside the last instructions of
//   the call, and the two times need not add up. With the barriers the
//   measured time is the time of the call plus the time of the added work.
//   Whether that holds on a given machine is checked by every run: the
//   measured size of the added delay is compared with its expected size
//   (judge_controls).
//
// Added work
//   In the timed region the library call is followed by a short loop
//   (dummy_work) in every class. Its length is drawn fresh for every call;
//   one class of a run (the reference, or the positive control) runs a fixed
//   number of iterations more. That is the added delay against which a run
//   is calibrated. Its expected size is the number of added iterations times
//   the cost of one iteration, which is measured during the run (AddedWork).
//
// Analysis (paired, because all classes are measured in the same round)
//   For two classes a and b, the per-round differences δ_i = b_i − a_i are
//   formed. Drift that affects a whole round cancels out. Because the order
//   within a round is random, δ is symmetric around 0 if the two classes
//   behave identically.
//
//   * Decision: sign test on the δ_i (rounds with δ_i = 0 are dropped).
//     z = (n₊ − n₋) / √(n₊ + n₋); |z| > Z_THRESHOLD (4.5, two-sided
//     p ≈ 7·10⁻⁶ per comparison) counts as a detected difference. The sign
//     test is distribution-free: the heavy tails of timing data (interrupts,
//     preemption) cannot create a detection; they only reduce its power.
//   * Confirmation: a detection is confirmed if a second run with the same
//     inputs in a new random order shows the same sign with |z| > Z_CONFIRM
//     (3.0, one-sided p ≈ 1.3·10⁻³). Both thresholds are fixed in advance.
//     The second run guards against chance and transient disturbances. It
//     does not guard against a systematic error of the measurement; that is
//     the task of the negative controls.
//   * Effect: an estimate of the shift with an approximate 95 % interval,
//     reported next to every decision and never used for one. Two estimators
//     are computed; which one is shown depends on how the δ_i are spread over
//     the values that the clock can produce (whole nanoseconds, or whole
//     steps of a coarser clock such as the 41.7 ns of Apple Silicon):
//       - the central half of the δ_i is spread over at least BROAD_VALUES
//         clock values: the interpolated median. The observations with one
//         clock value are treated as spread evenly over the step around it,
//         so that the median and its interval (from the order statistics
//         that belong to the sign test) are not tied to whole steps. Like the
//         sign test it describes the typical call and is not disturbed by
//         heavy tails.
//       - the δ_i take only a few clock values (a coarse clock and little
//         noise): the mean of the δ_i after removing values further than
//         CLIP robust standard deviations from the median. An interpolated
//         median is then inaccurate; a mean follows shifts far below one
//         step, because the position of a call relative to the steps is
//         random. Unlike the sign test, a mean also contains the rare slow
//         calls inside that limit, so it can differ from zero in a
//         comparison in which the sign test detects nothing.
//       The step of the clock is determined once per process by reading the
//       clock many times in a row (clock_step_ns) and is recorded with the
//       platform information of every result.
//     Δ is the difference in this interleaved design, not the cost of an
//     operation measured on its own. Positive Δ and positive z mean that the
//     second-named class (b) is the slower one.
//   * Welch's t and Cohen's d on the raw data are stored for information
//     only; they are not used for any decision.
//
// What this does NOT show: absence of a detected difference for the tested
// input classes on this machine is not a proof of constant-time behaviour.
// The sign test detects shifts of the typical running time; a leak that only
// appears in rare calls can stay undetected.

use rand::seq::SliceRandom;
use rand::Rng;
use serde::Serialize;

/// Decision threshold on |z| of the paired sign test (first run, two-sided).
pub const Z_THRESHOLD: f64 = 4.5;

/// Confirmation threshold on |z| (second run, same sign as the first run).
pub const Z_CONFIRM: f64 = 3.0;

/// Smallest accepted number of rounds.
pub const MIN_ROUNDS: usize = 1000;

/// Largest clock step (ns) at which every whole nanosecond counts as a clock
/// value of its own.
pub const FINE_STEP_NS: u64 = 1;

/// Number of clock values over which the central half of the differences
/// must be spread for the interpolated median to be shown.
pub const BROAD_VALUES: usize = 5;

/// Number of consecutive clock readings from which the step of the clock is
/// determined.
const CLOCK_READS: usize = 200_000;

/// One-sided 95 % point of the standard normal distribution.
pub const Z_95: f64 = 1.645;

/// The measured size of a reference delay counts as plausible if its 95 %
/// interval overlaps the expected size ± this fraction of it.
pub const REFERENCE_SIZE_TOLERANCE: f64 = 0.5;

/// Outlier limit of the clipped mean, in robust standard deviations.
pub const CLIP: f64 = 10.0;

/// Measure `n_classes` classes for `rounds` rounds after `warmup` untimed rounds.
/// `f(class)` must perform the operation for that class and return its duration in ns.
/// Returns one vector of timings per class; index i of every vector is round i.
pub fn measure_interleaved<F: FnMut(usize) -> u64>(
    n_classes: usize,
    rounds: usize,
    warmup: usize,
    mut f: F,
) -> Vec<Vec<u64>> {
    assert!(n_classes >= 2, "need at least two classes");
    let mut rng = rand::thread_rng();
    let mut order: Vec<usize> = (0..n_classes).collect();

    for _ in 0..warmup {
        order.shuffle(&mut rng);
        for &c in &order {
            let _ = f(c);
        }
    }

    // every class gets its full capacity now, so that no class allocates
    // inside the measurement loop
    let mut out: Vec<Vec<u64>> = (0..n_classes).map(|_| Vec::with_capacity(rounds)).collect();
    for _ in 0..rounds {
        order.shuffle(&mut rng);
        for &c in &order {
            out[c].push(f(c));
        }
    }
    out
}

/// Inputs of all classes, stored byte-interleaved in one buffer (see the
/// module comment).
pub struct InterleavedInputs {
    classes: usize,
    input_len: usize,
    mix: Vec<u8>,
}

impl InterleavedInputs {
    /// `inputs[c]` is the input of class c; all inputs must have the same length.
    pub fn new(inputs: &[&[u8]]) -> Self {
        let classes = inputs.len();
        assert!(classes >= 1, "need at least one input");
        let input_len = inputs[0].len();
        assert!(inputs.iter().all(|x| x.len() == input_len), "inputs must have equal length");
        let mut mix = vec![0u8; classes * input_len];
        for (c, input) in inputs.iter().enumerate() {
            for (i, &b) in input.iter().enumerate() {
                mix[i * classes + c] = b;
            }
        }
        InterleavedInputs { classes, input_len, mix }
    }

    pub fn classes(&self) -> usize {
        self.classes
    }

    pub fn input_len(&self) -> usize {
        self.input_len
    }

    /// Copy the input of `class` into `dst`.
    #[inline(never)]
    pub fn load(&self, class: usize, dst: &mut [u8]) {
        assert!(class < self.classes && dst.len() == self.input_len);
        let n = self.classes;
        for (i, d) in dst.iter_mut().enumerate() {
            *d = self.mix[i * n + class];
        }
    }
}

/// Work whose running time grows with `iters`: a chain of rotations and
/// exclusive-ors, each step of which needs the result of the step before.
/// Called inside the timed region after the library call, by every class;
/// how many iterations a call gets is decided by `AddedWork`.
///
/// The chain stays in registers. A loop that stores its value to memory and
/// loads it again in every iteration (which `black_box` inside the loop would
/// cause) depends on store-to-load forwarding, and its speed can then change
/// with the placement of the code and with the length of the loop. Callers
/// apply `black_box` to the number of iterations and to the result instead.
#[inline(never)]
pub fn dummy_work(iters: u32) -> u64 {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    for i in 0..iters {
        x = x.rotate_left(7) ^ (i as u64).wrapping_mul(0x2545_F491_4F6C_DD1D);
    }
    x
}

/// Barrier: everything issued so far finishes before anything later starts
/// (x86-64: LFENCE; AArch64: ISB). On other architectures a clock read is
/// used instead, which is a weaker separation.
#[inline(always)]
pub fn barrier() {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: LFENCE is part of SSE2, which every x86-64 processor has.
    unsafe {
        core::arch::x86_64::_mm_lfence()
    };
    #[cfg(target_arch = "aarch64")]
    // SAFETY: ISB has no operands and changes no state visible to the program.
    unsafe {
        core::arch::asm!("isb", options(nomem, nostack, preserves_flags))
    };
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        std::hint::black_box(std::time::Instant::now());
    }
}

/// How many iterations of `dummy_work` a call runs in the timed region.
///
/// Every call of every class runs a base amount that is drawn fresh for the
/// call (BASE_MIN .. BASE_MIN + BASE_SPAN iterations), plus the extra
/// iterations of its class: 0 for all classes except the one that carries the
/// added delay.
///
/// Why every class runs the loop, with a random length: a loop that only one
/// class enters, or that most calls skip, meets a different state of the
/// branch predictor when it runs, and the class with the added delay can
/// then pay for more than its extra iterations. With the loop in every call
/// and an unpredictable length, the classes differ by the extra iterations
/// only. The base amount is at least BASE_MIN iterations, to stay away from
/// very short loops, whose running time is dominated by entering and leaving
/// the loop.
///
/// The extra iterations are read from a table by the class index, never
/// selected by a branch on the class (see the module comment).
///
/// To state k added iterations in ns, the cost of one iteration is measured
/// while the measurement is running: once every CALIBRATE_EVERY calls two
/// loops of CALIBRATE_LONG and CALIBRATE_SHORT iterations are timed, outside
/// the timed region of the test and before a call of whichever class happens
/// to be next. The difference of the two times, divided by the difference of
/// the two lengths, is the cost of one iteration (the fixed cost of reading
/// the clock cancels). The median over a run is the cost of an iteration
/// under the conditions of that run. A calibration before the run would miss
/// changes of the clock frequency and of the load on the machine.
///
/// This is the cost of an iteration in a long loop. The few iterations that
/// one class runs in addition need not cost exactly the same, and the call
/// that follows a longer loop can itself be slower or faster. The expected
/// size "k × cost" is therefore approximate; every run compares it with the
/// measured size (judge_controls).
pub struct AddedWork {
    extra: Vec<u32>,
    state: u64,
    calls: u32,
    calibration: Vec<f64>,
}

const _: () = assert!(AddedWork::CALIBRATE_EVERY.is_power_of_two());

impl AddedWork {
    pub const BASE_MIN: u32 = 32;
    pub const BASE_SPAN: u32 = 64;
    pub const CALIBRATE_EVERY: u32 = 512;
    pub const CALIBRATE_LONG: u32 = 36_864;
    pub const CALIBRATE_SHORT: u32 = 4_096;

    /// `extra[c]`: iterations that class c runs in addition to the base
    /// amount (0 for the classes without added delay).
    pub fn new(extra: &[u32]) -> Self {
        let state = rand::thread_rng().gen::<u64>() | 1;
        AddedWork {
            extra: std::hint::black_box(extra.to_vec()),
            state,
            calls: 0,
            calibration: Vec::with_capacity(4096),
        }
    }

    /// No class runs extra iterations.
    pub fn none(n_classes: usize) -> Self {
        Self::new(&vec![0; n_classes])
    }

    /// Only the last of `n_classes` classes runs `k` extra iterations.
    pub fn last_class(n_classes: usize, k: u32) -> Self {
        let mut extra = vec![0; n_classes];
        extra[n_classes - 1] = k;
        Self::new(&extra)
    }

    #[cold]
    #[inline(never)]
    fn calibrate(&mut self) {
        let time = |iters: u32| -> f64 {
            barrier();
            let start = std::time::Instant::now();
            std::hint::black_box(dummy_work(std::hint::black_box(iters)));
            barrier();
            start.elapsed().as_nanos() as f64
        };
        let long = time(Self::CALIBRATE_LONG);
        let short = time(Self::CALIBRATE_SHORT);
        self.calibration.push((long - short) / (Self::CALIBRATE_LONG - Self::CALIBRATE_SHORT) as f64);
    }

    /// Cost of one iteration of `dummy_work` in ns during the calls made since
    /// the last call of this function (median of the calibrations).
    /// `None` if there were fewer than CALIBRATE_EVERY calls.
    pub fn take_iteration_cost_ns(&mut self) -> Option<f64> {
        if self.calibration.is_empty() {
            return None;
        }
        self.calibration.sort_by(|x, y| x.partial_cmp(y).unwrap());
        let cost = median_sorted(&self.calibration);
        self.calibration.clear();
        Some(cost)
    }

    /// Iterations for the next call of `class`.
    #[inline]
    pub fn next(&mut self, class: usize) -> u32 {
        self.calls = self.calls.wrapping_add(1);
        // CALIBRATE_EVERY is a power of two
        if self.calls & (Self::CALIBRATE_EVERY - 1) == 0 {
            self.calibrate();
        }
        // xorshift64*
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        let r = (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 32) as u32;
        let base = Self::BASE_MIN + r % Self::BASE_SPAN;
        base + self.extra[class]
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Comparison {
    /// number of rounds (pairs)
    pub n_pairs: usize,
    /// pairs with b slower than a / b faster than a / equal (ties are dropped)
    pub n_b_slower: usize,
    pub n_b_faster: usize,
    pub n_ties: usize,
    /// sign-test statistic; positive = b slower than a
    pub sign_z: f64,
    /// estimate of the shift b − a in ns, by the estimator named below
    pub delta_ns: f64,
    /// approximate 95 % interval of delta_ns
    pub delta_ci95_ns: (f64, f64),
    /// "interpolated median" (the differences are spread over many clock
    /// values) or "clipped mean" (they take only a few)
    pub delta_estimator: String,
    /// plain median of the per-round differences and its distribution-free
    /// interval (whole or half clock values)
    pub median_delta_ns: f64,
    pub median_delta_ci95_ns: (f64, f64),
    /// mean of the per-round differences without outliers, and its interval
    pub clipped_mean_delta_ns: f64,
    pub clipped_mean_delta_ci95_ns: (f64, f64),
    pub median_a_ns: f64,
    pub median_b_ns: f64,
    /// informational only
    pub welch_t_raw: f64,
    /// informational only
    pub cohens_d_raw: f64,
    /// |sign_z| > Z_THRESHOLD
    pub difference_detected: bool,
}

pub(crate) fn median_sorted(v: &[f64]) -> f64 {
    let n = v.len();
    if n == 0 {
        0.0
    } else if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

/// Median of a slice of timings, in ns.
pub fn median_ns(v: &[u64]) -> f64 {
    let mut f: Vec<f64> = v.iter().map(|&x| x as f64).collect();
    f.sort_by(|x, y| x.partial_cmp(y).unwrap());
    median_sorted(&f)
}

fn mean_var(x: &[u64]) -> (f64, f64) {
    if x.is_empty() {
        return (0.0, 0.0);
    }
    let n = x.len() as f64;
    let mean = x.iter().map(|&v| v as f64).sum::<f64>() / n;
    let var = if x.len() > 1 {
        x.iter()
            .map(|&v| {
                let d = v as f64 - mean;
                d * d
            })
            .sum::<f64>()
            / (n - 1.0)
    } else {
        0.0
    };
    (mean, var)
}

/// Median of sorted data with the distribution-free 95 % interval from order
/// statistics (the interval that belongs to the sign test).
fn median_ci(sorted: &[f64]) -> (f64, (f64, f64)) {
    let n = sorted.len();
    if n == 0 {
        return (0.0, (0.0, 0.0));
    }
    let med = median_sorted(sorted);
    // ranks r and n − r + 1 (counted from 1) with r = ⌊(n − 1.96·√n) / 2⌋
    let r = (((n as f64) - 1.96 * (n as f64).sqrt()) / 2.0).floor().max(1.0) as usize;
    (med, (sorted[r - 1], sorted[n - r]))
}

/// The clock values that occur in sorted differences, as (value, count) in
/// ascending order. On a clock with a step above 1 ns (`merge`), differences
/// at most 1 ns apart are one clock value: the same number of steps can come
/// out as neighbouring whole nanoseconds (see `step_from_increments`).
fn clock_values(sorted: &[f64], merge: bool) -> Vec<(f64, usize)> {
    let tolerance = if merge { 1.0 } else { 0.0 };
    let mut out: Vec<(f64, usize)> = Vec::new();
    let mut start = 0;
    for i in 1..=sorted.len() {
        if i == sorted.len() || sorted[i] - sorted[i - 1] > tolerance {
            let group = &sorted[start..i];
            out.push((group.iter().sum::<f64>() / group.len() as f64, group.len()));
            start = i;
        }
    }
    out
}

/// Number of clock values that hold the central half of the observations.
fn central_values(values: &[(f64, usize)]) -> usize {
    let n: usize = values.iter().map(|v| v.1).sum();
    let (from, to) = (n as f64 / 4.0, 3.0 * n as f64 / 4.0);
    let mut below = 0.0;
    let mut count = 0;
    for &(_, c) in values {
        let above = below + c as f64;
        if above > from && below < to {
            count += 1;
        }
        below = above;
    }
    count
}

/// Value at position `pos` (counted in observations from the bottom, 0 to n)
/// if the observations of every clock value are spread evenly between the
/// midpoints to its neighbouring clock values (half a step beyond the
/// outermost ones).
fn interpolated_quantile(values: &[(f64, usize)], step: f64, pos: f64) -> f64 {
    let mut below = 0.0;
    for (k, &(value, count)) in values.iter().enumerate() {
        let c = count as f64;
        if pos <= below + c || k + 1 == values.len() {
            let lower = if k == 0 { value - step / 2.0 } else { (values[k - 1].0 + value) / 2.0 };
            let upper = if k + 1 == values.len() { value + step / 2.0 } else { (value + values[k + 1].0) / 2.0 };
            return lower + ((pos - below) / c).clamp(0.0, 1.0) * (upper - lower);
        }
        below += c;
    }
    0.0
}

/// Interpolated median with the 95 % interval from the order statistics that
/// belong to the sign test (the same ranks as `median_ci`).
fn interpolated_median_ci(values: &[(f64, usize)], step: f64) -> (f64, (f64, f64)) {
    let n: usize = values.iter().map(|v| v.1).sum();
    if n == 0 {
        return (0.0, (0.0, 0.0));
    }
    let nf = n as f64;
    let r = ((nf - 1.96 * nf.sqrt()) / 2.0).floor().max(1.0);
    (
        interpolated_quantile(values, step, nf / 2.0),
        (interpolated_quantile(values, step, r - 0.5), interpolated_quantile(values, step, nf - r + 0.5)),
    )
}

/// Mean of sorted data after removing values further than CLIP robust
/// standard deviations from the median, with a normal 95 % interval. The
/// robust standard deviation is 1.4826 · MAD (if more than half of the values
/// equal the median: the smallest non-zero distance from the median), but
/// never less than `step`, the step of the clock. On a coarse clock most
/// differences can coincide with the median, and the values one step away
/// carry the information about the shift; they are not outliers.
fn clipped_mean_ci(sorted: &[f64], step: u64) -> (f64, (f64, f64)) {
    let n = sorted.len();
    if n == 0 {
        return (0.0, (0.0, 0.0));
    }
    let med = median_sorted(sorted);
    let mut dev: Vec<f64> = sorted.iter().map(|x| (x - med).abs()).collect();
    dev.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let mad = median_sorted(&dev);
    let scale = if mad > 0.0 { 1.4826 * mad } else { dev.iter().copied().find(|&d| d > 0.0).unwrap_or(0.0) };
    if scale == 0.0 {
        return (med, (med, med));
    }
    let limit = CLIP * scale.max(step as f64);
    let kept: Vec<f64> = sorted.iter().copied().filter(|x| (x - med).abs() <= limit).collect();
    let m = kept.len() as f64;
    let mean = kept.iter().sum::<f64>() / m;
    let var = if kept.len() > 1 { kept.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / (m - 1.0) } else { 0.0 };
    let half = 1.96 * (var / m).sqrt();
    (mean, (mean - half, mean + half))
}

/// Step of the clock behind all timings (`std::time::Instant`) in ns, as
/// seen by this process. Determined once: the clock is read CLOCK_READS times
/// in a row, with a short piece of work of changing length between two
/// readings, and the increments from one reading to the next are examined
/// (`step_from_increments`).
pub fn clock_step_ns() -> u64 {
    static STEP: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *STEP.get_or_init(|| {
        let base = std::time::Instant::now();
        let mut previous = 0u64;
        let mut increments = Vec::with_capacity(CLOCK_READS);
        for i in 0..CLOCK_READS {
            std::hint::black_box(dummy_work(std::hint::black_box((i & 63) as u32)));
            let now = base.elapsed().as_nanos() as u64;
            increments.push(now.saturating_sub(previous));
            previous = now;
        }
        step_from_increments(increments)
    })
}

/// Step of a clock, from the increments between consecutive readings (ns).
///
/// Only values that occur at least twice are used, so that a single stray
/// value cannot decide. If three consecutive whole numbers of nanoseconds are
/// among them, the clock resolves nanoseconds and the step is 1. A clock with
/// a step of 3 ns or more cannot produce that: its increments are multiples
/// of the step, and their conversion to whole nanoseconds gives at most two
/// neighbouring values per multiple (41 and 42 ns for the 125/3 ns step of
/// Apple Silicon). The step is then the smallest distance of at least 2 ns
/// between two of the values, which is the step rounded down, or 1 ns less.
/// (A clock with a step between 1 and 3 ns is treated like one that resolves
/// nanoseconds.) 1 if the readings do not allow a statement.
pub fn step_from_increments(mut increments: Vec<u64>) -> u64 {
    increments.sort_unstable();
    let mut repeated: Vec<u64> = increments.windows(2).filter(|w| w[0] == w[1]).map(|w| w[0]).collect();
    repeated.dedup();
    if repeated.windows(3).any(|w| w[1] == w[0] + 1 && w[2] == w[1] + 1) {
        return 1;
    }
    repeated.windows(2).map(|w| w[1] - w[0]).filter(|&gap| gap >= 2).min().unwrap_or(1)
}

/// Paired comparison of class a and class b. Both slices must come from the
/// same `measure_interleaved` call (index i = round i).
pub fn compare(a: &[u64], b: &[u64]) -> Comparison {
    compare_with_step(a, b, clock_step_ns())
}

/// `compare` for timings taken with a clock of the given step (ns).
pub fn compare_with_step(a: &[u64], b: &[u64], step: u64) -> Comparison {
    let n = a.len().min(b.len());
    let mut deltas: Vec<f64> = (0..n).map(|i| b[i] as f64 - a[i] as f64).collect();
    let pos = deltas.iter().filter(|&&d| d > 0.0).count();
    let neg = deltas.iter().filter(|&&d| d < 0.0).count();
    let ties = n - pos - neg;
    let m = (pos + neg) as f64;
    let z = if m > 0.0 { (pos as f64 - neg as f64) / m.sqrt() } else { 0.0 };

    deltas.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let (med, med_ci) = median_ci(&deltas);
    let (cm, cm_ci) = clipped_mean_ci(&deltas, step);
    // interpolated median if the differences are spread over enough clock
    // values, otherwise the clipped mean (see the module comment)
    let values = clock_values(&deltas, step > FINE_STEP_NS);
    let (delta, delta_ci, estimator) = if central_values(&values) >= BROAD_VALUES {
        let (im, im_ci) = interpolated_median_ci(&values, step.max(1) as f64);
        (im, im_ci, "interpolated median")
    } else {
        (cm, cm_ci, "clipped mean")
    };

    let (ma, va) = mean_var(&a[..n]);
    let (mb, vb) = mean_var(&b[..n]);
    let nn = n.max(1) as f64;
    let se = (va / nn + vb / nn).sqrt();
    let t = if se > 0.0 { (mb - ma) / se } else { 0.0 };
    let pooled = ((va + vb) / 2.0).sqrt();
    let d = if pooled > 0.0 { (mb - ma).abs() / pooled } else { 0.0 };

    Comparison {
        n_pairs: n,
        n_b_slower: pos,
        n_b_faster: neg,
        n_ties: ties,
        sign_z: z,
        delta_ns: delta,
        delta_ci95_ns: delta_ci,
        delta_estimator: estimator.into(),
        median_delta_ns: med,
        median_delta_ci95_ns: med_ci,
        clipped_mean_delta_ns: cm,
        clipped_mean_delta_ci95_ns: cm_ci,
        median_a_ns: median_ns(&a[..n]),
        median_b_ns: median_ns(&b[..n]),
        welch_t_raw: t,
        cohens_d_raw: d,
        difference_detected: z.abs() > Z_THRESHOLD,
    }
}

/// Sign statistic of several comparisons taken together (all pairs pooled).
pub fn pooled_sign_z(comparisons: &[Comparison]) -> f64 {
    let pos: usize = comparisons.iter().map(|c| c.n_b_slower).sum();
    let neg: usize = comparisons.iter().map(|c| c.n_b_faster).sum();
    let m = (pos + neg) as f64;
    if m > 0.0 {
        (pos as f64 - neg as f64) / m.sqrt()
    } else {
        0.0
    }
}

/// Does `second` (a further run with the same inputs) confirm the detection
/// in `first`?
pub fn confirms(first: &Comparison, second: &Comparison) -> bool {
    first.difference_detected && second.sign_z.signum() == first.sign_z.signum() && second.sign_z.abs() > Z_CONFIRM
}

/// Size of the shift at the detection threshold of a run, extrapolated
/// linearly from a comparison in which an added delay was detected with the
/// expected sign: Δ · Z_THRESHOLD / z. A shift of this size has an expected z
/// equal to the threshold, so about half of such runs detect it. `None` if
/// the added delay was not detected. Because the figure exists only for runs
/// in which the delay was detected, it comes out too small for delays close
/// to the threshold.
pub fn detectable_shift_ns(reference: &Comparison) -> Option<f64> {
    if reference.difference_detected && reference.sign_z > 0.0 && reference.delta_ns > 0.0 {
        Some(reference.delta_ns * Z_THRESHOLD / reference.sign_z)
    } else {
        None
    }
}

/// The shift that about 95 % of such runs detect: its expected z lies Z_95
/// above the threshold.
pub fn detectable_shift_95_ns(reference: &Comparison) -> Option<f64> {
    detectable_shift_ns(reference).map(|shift| shift * (Z_THRESHOLD + Z_95) / Z_THRESHOLD)
}

/// What the two controls of a run say (`judge_controls`).
#[derive(Debug, Clone, PartialEq)]
pub struct ControlVerdict {
    /// `None`: the run can be used. `Some(reason)`: it cannot.
    pub unusable: Option<String>,
    /// the added delay was detected with the expected sign
    pub reference_visible: bool,
    /// the measured size of the added delay agrees with its expected size
    /// (`None`: not visible, or the expected size is not known)
    pub reference_size_plausible: Option<bool>,
    /// shift that about half of such runs detect (ns)
    pub detectable_shift_50_ns: Option<f64>,
    /// shift that about 95 % of such runs detect (ns)
    pub detectable_shift_95_ns: Option<f64>,
}

/// Judge the controls that every run of `multi-lib` and `fo-oracle` carries.
///
/// `negative`: two classes with identical input. `reference`: the first of
/// them against a third class with the same input and `ref_k` added
/// iterations. `nominal_ns`: the expected size of that delay (ref_k × cost of
/// one iteration during the run).
///
/// A run cannot be used if the negative control shows a detection, if the
/// class with the added delay is detected as faster, or (with ref_k = 0,
/// where the third class is one more identical control) if that class is
/// detected at all.
pub fn judge_controls(
    negative: &Comparison,
    reference: &Comparison,
    ref_k: u32,
    nominal_ns: Option<f64>,
) -> ControlVerdict {
    let unusable = if negative.difference_detected {
        Some("the negative control shows a difference between identical inputs".to_string())
    } else if reference.difference_detected && ref_k == 0 {
        Some("a difference between identical inputs was detected (third control, --ref-k 0)".to_string())
    } else if reference.difference_detected && reference.sign_z < 0.0 {
        Some("the class with the added delay was measured as the faster one".to_string())
    } else {
        None
    };
    let visible = unusable.is_none() && ref_k > 0 && reference.difference_detected && reference.sign_z > 0.0;
    let plausible = match nominal_ns {
        Some(nominal) if visible && nominal > 0.0 => {
            let (low, high) = reference.delta_ci95_ns;
            Some(
                high >= (1.0 - REFERENCE_SIZE_TOLERANCE) * nominal && low <= (1.0 + REFERENCE_SIZE_TOLERANCE) * nominal,
            )
        }
        _ => None,
    };
    let sized = visible && plausible != Some(false);
    ControlVerdict {
        unusable,
        reference_visible: visible,
        reference_size_plausible: plausible,
        detectable_shift_50_ns: if sized { detectable_shift_ns(reference) } else { None },
        detectable_shift_95_ns: if sized { detectable_shift_95_ns(reference) } else { None },
    }
}

/// Report lines for the controls of a run (without indentation).
pub fn control_lines(
    negative: &Comparison,
    reference: &Comparison,
    ref_k: u32,
    nominal_ns: Option<f64>,
    verdict: &ControlVerdict,
) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!(
        "{:<26}: {}, z = {:+.2}  →  {}",
        "identical inputs (control)",
        effect(negative),
        negative.sign_z,
        if negative.difference_detected {
            "DIFFERENCE DETECTED: false positive, this run is not usable"
        } else {
            "no difference detected, as it must be"
        }
    ));
    let added = match nominal_ns {
        Some(ns) if ref_k > 0 => format!("; added work ≈ {:.1} ns", ns),
        _ => String::new(),
    };
    let state = if ref_k == 0 {
        if reference.difference_detected {
            "DIFFERENCE DETECTED between identical inputs (--ref-k 0): this run is not usable".to_string()
        } else {
            "nothing added (--ref-k 0): a third identical control".to_string()
        }
    } else if reference.difference_detected && reference.sign_z < 0.0 {
        format!("WRONG SIGN: the class with the added delay was faster, this run is not usable{}", added)
    } else if verdict.reference_visible && verdict.reference_size_plausible == Some(false) {
        format!("visible, but its size does not match the added work{}: sizes from this run are not reliable", added)
    } else if verdict.reference_visible {
        format!("visible{}", added)
    } else if verdict.unusable.is_some() {
        format!("not judged: this run is not usable{}", added)
    } else {
        format!("NOT visible (too noisy for this delay){}", added)
    };
    lines.push(format!(
        "{:<26}: {}, z = {:+.2}  →  {}",
        format!("reference delay (k = {})", ref_k),
        effect(reference),
        reference.sign_z,
        state
    ));
    if let (Some(half), Some(most)) = (verdict.detectable_shift_50_ns, verdict.detectable_shift_95_ns) {
        lines.push(format!(
            "{:<26}  a shift of about {:.1} ns would have reached the threshold in half of such runs, about {:.1} ns in 95 %",
            "", half, most
        ));
    }
    lines
}

/// "Δ = +x ns [95% CI a, b]"
pub fn effect(c: &Comparison) -> String {
    format!("Δ = {:+.1} ns [95% CI {:+.1}, {:+.1}]", c.delta_ns, c.delta_ci95_ns.0, c.delta_ci95_ns.1)
}

/// Human-readable result of one first-run comparison.
pub fn verdict(c: &Comparison) -> String {
    if c.difference_detected {
        format!("difference detected in this run (|z| = {:.2} > {}; {})", c.sign_z.abs(), Z_THRESHOLD, effect(c))
    } else {
        format!("no difference detected (|z| = {:.2} ≤ {}; {})", c.sign_z.abs(), Z_THRESHOLD, effect(c))
    }
}

/// Time one call, in ns. `black_box` is applied to the result before the
/// clock is stopped (best effort against the compiler removing or moving the
/// work); the result is dropped after the clock has stopped.
#[inline(always)]
pub fn time_ns<T, F: FnOnce() -> T>(f: F) -> u64 {
    barrier();
    let start = std::time::Instant::now();
    let r = std::hint::black_box(f());
    barrier();
    let ns = start.elapsed().as_nanos() as u64;
    drop(r);
    ns
}

/// Time one call followed by `work` iterations of added work, in ns (the
/// timed region described in the module comment).
#[inline(always)]
pub fn time_with_work<T, F: FnOnce() -> T>(work: u32, f: F) -> u64 {
    // the number of iterations is fixed before the timed region begins, so
    // that no part of its computation is moved behind the first clock read
    let work = std::hint::black_box(work);
    barrier();
    let start = std::time::Instant::now();
    let r = std::hint::black_box(f());
    barrier();
    std::hint::black_box(dummy_work(std::hint::black_box(work)));
    barrier();
    let ns = start.elapsed().as_nanos() as u64;
    drop(r);
    ns
}

/// A comparison with a given sign statistic and nothing else, for the tests
/// of the decision rules in other modules.
#[cfg(test)]
pub(crate) fn comparison_with_z(z: f64) -> Comparison {
    Comparison {
        n_pairs: 20_000,
        n_b_slower: 0,
        n_b_faster: 0,
        n_ties: 0,
        sign_z: z,
        delta_ns: 0.0,
        delta_ci95_ns: (0.0, 0.0),
        delta_estimator: "interpolated median".into(),
        median_delta_ns: 0.0,
        median_delta_ci95_ns: (0.0, 0.0),
        clipped_mean_delta_ns: 0.0,
        clipped_mean_delta_ci95_ns: (0.0, 0.0),
        median_a_ns: 0.0,
        median_b_ns: 0.0,
        welch_t_raw: 0.0,
        cohens_d_raw: 0.0,
        difference_detected: z.abs() > Z_THRESHOLD,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    fn gauss(r: &mut StdRng) -> f64 {
        // sum of 12 uniforms − 6 ≈ N(0,1)
        (0..12).map(|_| r.gen::<f64>()).sum::<f64>() - 6.0
    }

    fn noisy(n: usize, base: u64, seed: u64) -> Vec<u64> {
        let mut r = StdRng::seed_from_u64(seed);
        (0..n).map(|_| base + r.gen_range(0..41)).collect()
    }

    /// Step that `clock_step_ns` finds for the simulated coarse clock below.
    const COARSE: u64 = 41;

    fn fine(a: &[u64], b: &[u64]) -> Comparison {
        compare_with_step(a, b, 1)
    }

    fn coarse(a: &[u64], b: &[u64]) -> Comparison {
        compare_with_step(a, b, COARSE)
    }

    /// Timings with Gaussian noise (standard deviation `sd` ns) around `base`,
    /// taken with a clock that counts ticks of 125/3 ns (Apple Silicon); class
    /// b is `shift` ns slower than class a. As on the real system, a reading
    /// is the tick count converted to whole nanoseconds (× 125 / 3, rounded
    /// down) and a duration is the difference of two readings, so that the
    /// same number of ticks can come out as two neighbouring values.
    fn coarse_timer(n: usize, base: f64, sd: f64, shift: f64, seed: u64) -> (Vec<u64>, Vec<u64>) {
        let tick = 125.0 / 3.0;
        let mut r = StdRng::seed_from_u64(seed);
        let mut read = |mean: f64| -> u64 {
            let t = mean + sd * gauss(&mut r);
            let start: u64 = r.gen_range(1_000_000..2_000_000);
            let phase = r.gen::<f64>() * tick;
            let ticks = ((phase + t) / tick).floor().max(0.0) as u64;
            (start + ticks) * 125 / 3 - start * 125 / 3
        };
        let mut a = Vec::with_capacity(n);
        let mut b = Vec::with_capacity(n);
        for _ in 0..n {
            a.push(read(base));
            b.push(read(base + shift));
        }
        (a, b)
    }

    #[test]
    fn every_class_measured_equally_often_and_preallocated() {
        let m = measure_interleaved(5, 200, 10, |c| c as u64);
        for (c, v) in m.iter().enumerate() {
            assert_eq!(v.len(), 200);
            assert!(v.capacity() >= 200);
            assert!(v.iter().all(|&x| x == c as u64));
        }
    }

    #[test]
    #[allow(clippy::needless_range_loop)]
    fn all_orders_of_three_classes_occur_about_equally_often() {
        // record the position of every class in every round
        let mut pos = 0u64;
        let m = measure_interleaved(3, 60_000, 0, |_| {
            pos += 1;
            pos
        });
        let mut counts = std::collections::HashMap::new();
        for i in 0..60_000 {
            let mut order = [0usize, 1, 2];
            order.sort_by_key(|&c| m[c][i]);
            *counts.entry(order).or_insert(0u32) += 1;
        }
        assert_eq!(counts.len(), 6);
        // expected 10 000 each, standard deviation about 91
        for (&o, &k) in &counts {
            assert!((9_500..=10_500).contains(&k), "order {:?} occurred {} times", o, k);
        }
    }

    #[test]
    fn interleaved_inputs_return_each_class_unchanged() {
        let a: Vec<u8> = (0..=255).collect();
        let b: Vec<u8> = (0..=255).rev().collect();
        let c = vec![7u8; 256];
        let inputs = InterleavedInputs::new(&[&a, &b, &c]);
        assert_eq!((inputs.classes(), inputs.input_len()), (3, 256));
        let mut buf = vec![0u8; 256];
        inputs.load(0, &mut buf);
        assert_eq!(buf, a);
        inputs.load(1, &mut buf);
        assert_eq!(buf, b);
        inputs.load(2, &mut buf);
        assert_eq!(buf, c);
    }

    #[test]
    fn added_work_gives_every_class_the_base_and_one_class_the_extra() {
        let mut w = AddedWork::last_class(3, 32);
        let (lo, hi) = (AddedWork::BASE_MIN, AddedWork::BASE_MIN + AddedWork::BASE_SPAN);
        let mut sum = [0u64; 3];
        let mut seen = std::collections::HashSet::new();
        for _ in 0..30_000 {
            let a = w.next(0);
            let b = w.next(1);
            let r = w.next(2);
            assert!((lo..hi).contains(&a) && (lo..hi).contains(&b));
            assert!((lo + 32..hi + 32).contains(&r));
            seen.insert(a);
            sum[0] += a as u64;
            sum[1] += b as u64;
            sum[2] += r as u64;
        }
        // every base length occurs
        assert_eq!(seen.len(), AddedWork::BASE_SPAN as usize);
        // same base distribution for all classes: the means differ by the extra only
        let mean = |i: usize| sum[i] as f64 / 30_000.0;
        assert!((mean(1) - mean(0)).abs() < 1.0, "means {} {}", mean(0), mean(1));
        assert!((mean(2) - mean(0) - 32.0).abs() < 1.0, "means {} {}", mean(0), mean(2));
        // no extra for any class
        let mut none = AddedWork::none(2);
        assert!((0..1000).all(|i| (lo..hi).contains(&none.next(i % 2))));
    }

    #[test]
    fn added_work_is_inside_the_timed_region() {
        // the fastest of several calls: without added work, and with a loop
        // that takes tens of microseconds
        let fastest = |work: u32| (0..20).map(|_| time_with_work(work, || 1u8)).min().unwrap();
        let (without, with) = (fastest(0), fastest(100_000));
        assert!(with > without + 10_000, "without {} ns, with {} ns", without, with);
        // time_ns times the call itself
        let call = (0..20).map(|_| time_ns(|| dummy_work(std::hint::black_box(100_000)))).min().unwrap();
        assert!(call > 10_000, "call {} ns", call);
    }

    #[test]
    fn added_work_measures_the_cost_of_an_iteration_during_the_run() {
        let mut w = AddedWork::last_class(2, 8);
        assert!(w.take_iteration_cost_ns().is_none());
        for i in 0..(5 * AddedWork::CALIBRATE_EVERY as usize) {
            std::hint::black_box(dummy_work(w.next(i % 2)));
        }
        let cost = w.take_iteration_cost_ns().expect("five calibration loops");
        assert!(cost > 0.01 && cost < 100.0, "cost {} ns", cost);
        // the samples are used up
        assert!(w.take_iteration_cost_ns().is_none());
    }

    #[test]
    fn sign_statistic_for_known_counts_with_ties() {
        // 600 pairs with b slower, 400 with b faster, 1000 ties
        let mut a = Vec::new();
        let mut b = Vec::new();
        for _ in 0..600 {
            a.push(100);
            b.push(110);
        }
        for _ in 0..400 {
            a.push(110);
            b.push(100);
        }
        for _ in 0..1000 {
            a.push(100);
            b.push(100);
        }
        let c = fine(&a, &b);
        assert_eq!((c.n_b_slower, c.n_b_faster, c.n_ties), (600, 400, 1000));
        // ties are dropped: z = (600 − 400) / √1000
        assert!((c.sign_z - 200.0 / 1000f64.sqrt()).abs() < 1e-9);
        assert!(c.difference_detected && c.sign_z > 0.0);
        // the differences take three values only (−10, 0, 10): the clipped
        // mean is reported, the plain median says nothing
        assert_eq!(c.median_delta_ci95_ns, (0.0, 0.0));
        assert_eq!(c.delta_estimator, "clipped mean");
        assert!((c.delta_ns - 1.0).abs() < 1e-9, "delta {}", c.delta_ns);
    }

    #[test]
    fn identical_classes_not_flagged() {
        let a = noisy(10_000, 1000, 1);
        let b = noisy(10_000, 1000, 2);
        let c = fine(&a, &b);
        assert!(!c.difference_detected);
        assert!(c.delta_ci95_ns.0 <= 0.0 && c.delta_ci95_ns.1 >= 0.0);
    }

    #[test]
    fn pairing_removes_drift_and_keeps_a_small_shift() {
        // strong drift over the run, equal for both classes in each round;
        // b is 5 ns slower. Unpaired, the drift (0 … 5000 ns) would hide it.
        let na = noisy(20_000, 0, 5);
        let nb = noisy(20_000, 0, 6);
        let a: Vec<u64> = (0..20_000).map(|i| 1000 + (i as u64) / 4 + na[i]).collect();
        let b: Vec<u64> = (0..20_000).map(|i| 1005 + (i as u64) / 4 + nb[i]).collect();
        let c = fine(&a, &b);
        assert!(c.difference_detected && c.sign_z > 0.0);
        assert!(c.delta_ns > 3.5 && c.delta_ns < 6.5, "delta {}", c.delta_ns);
        assert!(c.delta_ci95_ns.1 - c.delta_ci95_ns.0 < 3.0, "interval {:?}", c.delta_ci95_ns);
        // the same data paired wrongly (b taken from half a run later): the
        // drift no longer cancels, the 5 ns cannot be seen
        let b_shifted: Vec<u64> = (0..20_000).map(|i| b[(i + 10_000) % 20_000]).collect();
        let c2 = fine(&a, &b_shifted);
        assert!(!c2.difference_detected, "z {}", c2.sign_z);
        assert!(
            c2.median_delta_ci95_ns.1 - c2.median_delta_ci95_ns.0 > 1000.0,
            "interval {:?}",
            c2.median_delta_ci95_ns
        );
    }

    #[test]
    fn fine_timer_uses_the_median_and_survives_heavy_tails() {
        // 70 % of the rounds with 50 ns noise, 30 % with 10 µs noise; b is
        // 40 ns slower
        let mut r = StdRng::seed_from_u64(21);
        let n = 20_000;
        let mut a = Vec::with_capacity(n);
        let mut b = Vec::with_capacity(n);
        for _ in 0..n {
            let sd = if r.gen::<f64>() < 0.7 { 50.0 } else { 10_000.0 };
            a.push((60_000.0 + sd * gauss(&mut r)).max(0.0) as u64);
            b.push((60_040.0 + sd * gauss(&mut r)).max(0.0) as u64);
        }
        let c = fine(&a, &b);
        assert_eq!(c.delta_estimator, "interpolated median");
        // with thousands of different values the interpolation changes little
        assert!((c.delta_ns - c.median_delta_ns).abs() <= 1.0, "{} {}", c.delta_ns, c.median_delta_ns);
        assert!(c.difference_detected && c.sign_z > 0.0);
        assert!(c.delta_ns > 30.0 && c.delta_ns < 50.0, "delta {}", c.delta_ns);
        assert!(c.delta_ci95_ns.0 < 40.0 && c.delta_ci95_ns.1 > 40.0, "interval {:?}", c.delta_ci95_ns);
        assert!(c.delta_ci95_ns.1 - c.delta_ci95_ns.0 < 15.0, "interval {:?}", c.delta_ci95_ns);
    }

    #[test]
    fn coarse_timer_shift_is_estimated_without_bias() {
        // noise from far below to far above the tick, shifts far below the
        // tick, running times at several positions relative to the tick grid
        // (8000 ns is a whole number of ticks: with little noise almost all
        // differences are then 0, and the few that are one tick away carry
        // the shift)
        let n = 200_000;
        let mut seed = 100;
        for &sd in &[0.2, 1.0, 5.0, 15.0, 30.0, 60.0, 100.0, 150.0, 300.0] {
            for &shift in &[2.0, 10.0] {
                for &base in &[8000.0, 8001.0, 8010.4, 8020.8, 8031.3] {
                    seed += 1;
                    let (a, b) = coarse_timer(n, base, sd, shift, seed);
                    let c = coarse(&a, &b);
                    // few clock values with little noise, many with much noise
                    let expected = if sd < 100.0 { "clipped mean" } else { "interpolated median" };
                    assert_eq!(c.delta_estimator, expected, "sd {} shift {} base {}", sd, shift, base);
                    let half = (c.delta_ci95_ns.1 - c.delta_ci95_ns.0) / 2.0;
                    // within two interval half-widths (about four standard
                    // errors), plus 3 % of the shift for the interpolation
                    assert!(
                        (c.delta_ns - shift).abs() <= 2.0 * half + 0.05 + 0.03 * shift,
                        "sd {} shift {} base {}: delta {} ± {}",
                        sd,
                        shift,
                        base,
                        c.delta_ns,
                        half
                    );
                    // the sign of z is certain only where the expected z
                    // (about 250 · shift / noise for this number of rounds)
                    // is well above its standard deviation of 1
                    if shift / sd > 0.016 {
                        assert!(c.sign_z > 0.0, "sd {} shift {} base {}: z {}", sd, shift, base, c.sign_z);
                    }
                }
            }
        }
    }

    #[test]
    fn coarse_timer_large_shift_is_not_rounded_to_whole_steps() {
        // a shift of several steps: no pair is tied, and the median of the
        // differences is a whole number of steps (125 or 167 ns)
        let (a, b) = coarse_timer(100_000, 8000.0, 30.0, 145.0, 51);
        let c = coarse(&a, &b);
        assert!(c.n_ties < 2000, "ties {}", c.n_ties);
        assert_eq!(c.delta_estimator, "clipped mean");
        assert!((c.delta_ns - 145.0).abs() < 1.5, "delta {}", c.delta_ns);
        assert!((c.median_delta_ns - 145.0).abs() > 15.0, "median {}", c.median_delta_ns);
    }

    #[test]
    fn clock_step_from_consecutive_readings() {
        let mut r = StdRng::seed_from_u64(61);
        // a clock that resolves nanoseconds, read every 20 to 60 ns
        let fine: Vec<u64> = (0..50_000).map(|_| r.gen_range(20..60)).collect();
        assert_eq!(step_from_increments(fine), 1);
        // readings of a clock with the given tick (numerator / denominator ns)
        // taken `gap` ns apart
        let mut readings = |numerator: u64, denominator: u64, gap: std::ops::Range<f64>| -> Vec<u64> {
            let tick = numerator as f64 / denominator as f64;
            let (mut t, mut previous) = (0.0f64, 0u64);
            (0..50_000)
                .map(|_| {
                    t += r.gen_range(gap.clone());
                    let now = (t / tick) as u64 * numerator / denominator;
                    let increment = now - previous;
                    previous = now;
                    increment
                })
                .collect()
        };
        // Apple Silicon: ticks of 125/3 ns, read faster than one tick, so
        // that many readings repeat (increments 0, 41, 42)
        let mut apple = readings(125, 3, 8.0..40.0);
        assert_eq!(step_from_increments(apple.clone()), COARSE);
        // single stray values do not decide
        apple.extend([100, 101, 102, 7]);
        assert_eq!(step_from_increments(apple), COARSE);
        // a tick of 69.84 ns read about once per microsecond: no reading
        // repeats, the increments are whole numbers of ticks
        let hpet = step_from_increments(readings(6984, 100, 900.0..1100.0));
        assert!((68..=69).contains(&hpet), "step {}", hpet);
        // a clock that stands still, or a single value: no statement
        assert_eq!(step_from_increments(vec![0; 100]), 1);
        assert_eq!(step_from_increments(vec![25; 100]), 1);
        // the clock of the machine that runs this test has a step of at least 1 ns
        assert!(clock_step_ns() >= 1);
    }

    #[test]
    fn fine_clock_with_almost_no_noise_falls_back_to_the_mean() {
        // b is 5 ns slower in three rounds out of four, 6 ns in the fourth:
        // the median of the differences and its interval are 5 exactly
        let a: Vec<u64> = vec![1000; 8000];
        let b: Vec<u64> = (0..8000).map(|i| if i % 4 == 0 { 1006 } else { 1005 }).collect();
        let c = fine(&a, &b);
        assert_eq!(c.median_delta_ci95_ns, (5.0, 5.0));
        assert_eq!(c.delta_estimator, "clipped mean");
        assert!((c.delta_ns - 5.25).abs() < 1e-9, "delta {}", c.delta_ns);
    }

    #[test]
    fn coarse_timer_identical_classes_not_flagged() {
        for (sd, seed) in [(300.0, 11), (30.0, 12), (3.0, 13)] {
            let (a, b) = coarse_timer(100_000, 8000.0, sd, 0.0, seed);
            let c = coarse(&a, &b);
            assert!(!c.difference_detected, "sd {}: z = {}", sd, c.sign_z);
            assert!(c.delta_ns.abs() < 3.0, "sd {}: delta {}", sd, c.delta_ns);
        }
    }

    #[test]
    fn coarse_timer_outliers_do_not_move_the_estimate() {
        // b is 10 ns slower; one call in 200 is interrupted for 50–500 µs
        let (mut a, mut b) = coarse_timer(100_000, 8000.0, 30.0, 10.0, 31);
        let mut r = StdRng::seed_from_u64(32);
        for i in 0..100_000 {
            if r.gen_range(0..200) == 0 {
                a[i] += r.gen_range(50_000..500_000);
            }
            if r.gen_range(0..200) == 0 {
                b[i] += r.gen_range(50_000..500_000);
            }
        }
        let c = coarse(&a, &b);
        assert!(c.difference_detected && c.sign_z > 0.0);
        assert!(c.delta_ns > 8.5 && c.delta_ns < 11.5, "delta {}", c.delta_ns);
    }

    #[test]
    fn median_interval_uses_the_ranks_of_the_sign_test() {
        // δ_i = i − 5000 for i = 0 … 9999: sorted values −5000 … 4999
        let a: Vec<u64> = vec![10_000; 10_000];
        let b: Vec<u64> = (0..10_000u64).map(|i| 5_000 + i).collect();
        let c = fine(&a, &b);
        assert!((c.median_delta_ns - (-0.5)).abs() < 1e-9);
        // r = ⌊(10000 − 196) / 2⌋ = 4902: the 4902nd and the 5099th value
        assert_eq!(c.median_delta_ci95_ns, (-99.0, 98.0));
        // every value occurs once: the interpolated median and its interval
        // are the same numbers
        assert_eq!(c.delta_estimator, "interpolated median");
        assert!((c.delta_ns - (-0.5)).abs() < 1e-9, "delta {}", c.delta_ns);
        assert!(
            (c.delta_ci95_ns.0 + 99.0).abs() < 1e-9 && (c.delta_ci95_ns.1 - 98.0).abs() < 1e-9,
            "{:?}",
            c.delta_ci95_ns
        );
    }

    #[test]
    fn detectable_shift_is_extrapolated_from_a_detected_delay() {
        let mut r = comparison_with_z(45.0);
        r.delta_ns = 12.0;
        assert!((detectable_shift_ns(&r).unwrap() - 1.2).abs() < 1e-9);
        // not detected, or detected with the wrong sign: no statement
        let mut weak = comparison_with_z(3.0);
        weak.delta_ns = 12.0;
        assert!(detectable_shift_ns(&weak).is_none());
        let mut wrong = comparison_with_z(-45.0);
        wrong.delta_ns = -12.0;
        assert!(detectable_shift_ns(&wrong).is_none());
        // the shift that 95 % of such runs detect lies 1.645 above the threshold
        assert!((detectable_shift_95_ns(&r).unwrap() - 1.2 * 6.145 / 4.5).abs() < 1e-9);
        assert!(detectable_shift_95_ns(&weak).is_none());
    }

    #[test]
    fn interpolated_median_resolves_shifts_below_one_clock_value() {
        // a clock with nanosecond steps, 30 ns of noise per call, 100 000
        // rounds: the plain median and its interval are whole or half
        // nanoseconds, the interpolated ones are not
        let mut r = StdRng::seed_from_u64(71);
        let n = 100_000;
        let a: Vec<u64> = (0..n).map(|_| (5_000.0 + 30.0 * gauss(&mut r)) as u64).collect();
        let b: Vec<u64> = (0..n).map(|_| (5_000.4 + 30.0 * gauss(&mut r)) as u64).collect();
        let c = fine(&a, &b);
        assert_eq!(c.delta_estimator, "interpolated median");
        assert!(c.median_delta_ns.fract() == 0.0 || c.median_delta_ns.fract().abs() == 0.5);
        let half = (c.delta_ci95_ns.1 - c.delta_ci95_ns.0) / 2.0;
        assert!(half > 0.1 && half < 0.6, "half-width {}", half);
        assert!((c.delta_ns - 0.4).abs() <= 2.0 * half, "delta {} ± {}", c.delta_ns, half);
    }

    #[test]
    fn coarse_clock_with_heavy_tails_uses_the_interpolated_median() {
        // 150 ns of noise per call, and every fifth call takes about 3 µs
        // longer; b is 12 ns slower. The clipped mean has its limit in the
        // middle of the slow calls and loses most of the shift; the
        // interpolated median does not depend on them.
        let (a, b) = coarse_timer(200_000, 30_000.0, 150.0, 12.0, 81);
        let mut r = StdRng::seed_from_u64(82);
        let mut slow = |v: Vec<u64>| -> Vec<u64> {
            v.into_iter()
                .map(|x| if r.gen_range(0..5) == 0 { x + 3_000 + r.gen_range(0..400) / 42 * 125 / 3 } else { x })
                .collect()
        };
        let (a, b) = (slow(a), slow(b));
        let c = coarse(&a, &b);
        assert_eq!(c.delta_estimator, "interpolated median");
        assert!(c.sign_z > Z_THRESHOLD, "z {}", c.sign_z);
        let half = (c.delta_ci95_ns.1 - c.delta_ci95_ns.0) / 2.0;
        assert!(half < 4.0, "half-width {}", half);
        assert!((c.delta_ns - 12.0).abs() <= 2.0 * half, "delta {} ± {}", c.delta_ns, half);
    }

    #[test]
    fn controls_decide_whether_a_run_can_be_used() {
        let quiet = comparison_with_z(0.4);
        let mut reference = comparison_with_z(40.0);
        reference.delta_ns = 20.0;
        reference.delta_ci95_ns = (18.0, 22.0);
        // everything as it must be
        let v = judge_controls(&quiet, &reference, 32, Some(19.5));
        assert!(v.unusable.is_none() && v.reference_visible);
        assert_eq!(v.reference_size_plausible, Some(true));
        assert!((v.detectable_shift_50_ns.unwrap() - 2.25).abs() < 1e-9);
        assert!((v.detectable_shift_95_ns.unwrap() - 2.25 * 6.145 / 4.5).abs() < 1e-9);
        // measured 18 to 22 ns where 8 ns were added: visible, but no
        // statement about sizes
        let v = judge_controls(&quiet, &reference, 32, Some(8.0));
        assert!(v.unusable.is_none() && v.reference_visible);
        assert_eq!(v.reference_size_plausible, Some(false));
        assert!(v.detectable_shift_50_ns.is_none() && v.detectable_shift_95_ns.is_none());
        // the interval only has to overlap expected size ± 50 %
        assert_eq!(judge_controls(&quiet, &reference, 32, Some(13.0)).reference_size_plausible, Some(true));
        assert_eq!(judge_controls(&quiet, &reference, 32, Some(11.9)).reference_size_plausible, Some(false));
        assert_eq!(judge_controls(&quiet, &reference, 32, Some(36.0)).reference_size_plausible, Some(true));
        assert_eq!(judge_controls(&quiet, &reference, 32, Some(45.0)).reference_size_plausible, Some(false));
        // a detection between identical inputs
        let v = judge_controls(&comparison_with_z(5.0), &reference, 32, Some(19.5));
        assert!(v.unusable.is_some() && !v.reference_visible && v.detectable_shift_50_ns.is_none());
        // the class with the added delay detected as faster
        let v = judge_controls(&quiet, &comparison_with_z(-9.0), 32, Some(19.5));
        assert!(v.unusable.is_some() && !v.reference_visible);
        // nothing added: the third class is one more identical control
        let v = judge_controls(&quiet, &comparison_with_z(1.0), 0, Some(0.0));
        assert!(v.unusable.is_none() && !v.reference_visible && v.reference_size_plausible.is_none());
        assert!(judge_controls(&quiet, &comparison_with_z(6.0), 0, Some(0.0)).unusable.is_some());
        // added delay not detected: usable, but not shown to be sensitive
        let v = judge_controls(&quiet, &comparison_with_z(2.0), 32, Some(19.5));
        assert!(v.unusable.is_none() && !v.reference_visible && v.detectable_shift_50_ns.is_none());
        // the report names each state
        let lines =
            control_lines(&quiet, &reference, 32, Some(19.5), &judge_controls(&quiet, &reference, 32, Some(19.5)));
        assert_eq!(lines.len(), 3);
        assert!(lines[1].contains("visible; added work ≈ 19.5 ns") && lines[2].contains("in 95 %"));
        let wrong = comparison_with_z(-9.0);
        let lines = control_lines(&quiet, &wrong, 32, Some(19.5), &judge_controls(&quiet, &wrong, 32, Some(19.5)));
        assert!(lines.len() == 2 && lines[1].contains("WRONG SIGN"));
    }

    #[test]
    fn pooled_statistic_adds_up_the_pairs() {
        let one = fine(&noisy(5000, 1000, 40), &noisy(5000, 1002, 41));
        let two = fine(&noisy(5000, 1000, 42), &noisy(5000, 1002, 43));
        let pooled = pooled_sign_z(&[one.clone(), two.clone()]);
        let pos = (one.n_b_slower + two.n_b_slower) as f64;
        let neg = (one.n_b_faster + two.n_b_faster) as f64;
        assert!((pooled - (pos - neg) / (pos + neg).sqrt()).abs() < 1e-9);
        assert!(pooled > one.sign_z.max(two.sign_z));
    }

    #[test]
    fn confirmation_needs_same_sign_and_z_above_three() {
        let base = fine(&noisy(5000, 1000, 8), &noisy(5000, 1010, 9));
        assert!(base.difference_detected && base.sign_z > 0.0);
        let mut weak = base.clone();
        weak.sign_z = 2.9;
        assert!(!confirms(&base, &weak));
        let mut ok = base.clone();
        ok.sign_z = 3.1;
        assert!(confirms(&base, &ok));
        let mut wrong_sign = base.clone();
        wrong_sign.sign_z = -9.0;
        assert!(!confirms(&base, &wrong_sign));
        let mut not_detected = base.clone();
        not_detected.difference_detected = false;
        assert!(!confirms(&not_detected, &ok));
    }
}
