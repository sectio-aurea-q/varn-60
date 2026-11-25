# VÄRN-60 (Anu)

**Timing side-channel tests for ML-KEM (FIPS 203) decapsulation, with controls in every run that
show what the test can and cannot detect on the machine it runs on.**

VÄRN-60 measures whether ML-KEM decapsulation takes measurably different time for different
ciphertexts, in particular for an accepted ciphertext compared with ciphertexts that take the
implicit-rejection path of the Fujisaki–Okamoto transform. Five ML-KEM-768 libraries are tested
with one and the same procedure, in the same run.

It does not prove that an implementation is constant-time. It reports whether a timing difference
was detected and confirmed for the tested inputs on the tested machine. Every run carries its own
controls: a pair of identical inputs, which must show no difference, and an added delay, which
must be visible and must come out at about its expected size. From the added delay the run states
how small a difference it could have detected.

Status: version 2.0.0 is a prototype. The measurement procedure and its controls are implemented
and tested; what is still missing is listed under [Limitations](#limitations).

## Commands

| Command | What it does |
|---|---|
| `anu control` | Negative and positive controls with PQClean ML-KEM-768. Run this first on every machine: it shows the false-positive behaviour and the smallest added delay that is detected there. Exit code 1 if a control fails. |
| `anu multi-lib` | ML-KEM-768 in five libraries in one run. Per library: an accepted ciphertext against a rejected ciphertext for another key and against itself with one bit flipped, plus the controls of the run. |
| `anu fo-oracle` | PQClean ML-KEM-512/768/1024 (`--level`): an accepted ciphertext against a second accepted ciphertext and 15 rejected ones (ciphertext for another key, all-zero, all-ones, eight single-bit flips spread over the ciphertext, four random strings), plus the controls of the run. |
| `anu ci` | The `multi-lib` scan as a gate, see [below](#anu-ci). |
| `anu demo`, `anu info` | Short run without JSON output; platform, clock and versions. |

`control`, `multi-lib`, `fo-oracle` and `ci` print a report and write a JSON file (`-o`) with every
statistic, the thresholds, the tool version, the commit of the source, the compilers, the versions
of the measured libraries and the platform.

| Option | Meaning |
|---|---|
| `--samples N` | number of rounds per run (default 20 000, at least 1000); every class is timed once per round |
| `--ref-k K` | size of the reference delay in iterations of added work (default 32; 0 adds nothing) |
| `--libs a,b` | `multi-lib` and `ci`: measure only the named libraries (`pqclean`, `rustcrypto`, `liboqs`, `aws-lc`, `libcrux`) |
| `--level L` | `fo-oracle`: 512, 768 or 1024 |
| `--dit` | AArch64 only: switch on the data-independent-timing mode of the processor (PSTATE.DIT) for the measurement |

In all reports a positive Δ and a positive *z* mean that the class named in the line is the
slower one: the rejected ciphertext against the accepted one, the second control against the
first, the class with the added delay against the control.

| Exit code | Meaning |
|---|---|
| 0 | the command ran (`control`: the controls passed; `ci`: see below) |
| 1 | `control`: a control failed. `ci`: a confirmed difference |
| 2 | `ci` only: not tested, not sensitive enough, a failed control, or inconclusive |
| 64 | usage error |
| 70 | a library failed the correctness check that precedes every measurement of `control` and `fo-oracle`; nothing was measured |
| 74 | the JSON file could not be written, or its directory does not exist (`control` and `ci` report a result that could not be written only if their own result was 0) |

### `anu ci`

Runs the `multi-lib` scan for the selected libraries (all five by default) and turns the result
into an exit code.

- **0** — every selected library was tested, its controls behaved as they must (no detection
  between identical inputs; the reference delay visible and of about the expected size), and no
  test comparison showed a detection.
- **1** — a difference was confirmed in a library in which no control failed. (If the reference
  delay of that library was not visible, this is listed as an open point.)
- **2** — anything else: a library could not be tested; a control failed (the comparisons of that
  library are then not used, whatever they show); the reference delay was not visible or not of
  the expected size; a needed further run failed; or a detection was not confirmed.

Exit 0 refers to the reference delay of that run: no difference was detected in a run that did
detect `--ref-k` iterations of added work (the report prints their size in ns for each library).
It says nothing about smaller differences. On a noisy machine a slow library may not show the
default reference delay, and the gate then ends with 2. Select the libraries that matter with
`--libs`, and raise `--samples` or `--ref-k` until the reference delay is visible. With
`--ref-k 0` there is no reference delay, so the gate cannot end with 0.

## What is measured

| Library | Code |
|---|---|
| PQClean via `pqcrypto-mlkem` | C and assembly from PQClean: the AVX2 code on x86-64 with AVX2 (not on macOS and Windows), the aarch64 code on AArch64, portable C otherwise. The PQClean repository was archived on 4 August 2026, and `pqcrypto-mlkem` is unmaintained (RUSTSEC-2026-0161). It also carries an open advisory, RUSTSEC-2026-0585 of 20 November 2026: the code does not perform the input checks of FIPS 203, sections 7.2 and 7.3, and no fixed version is expected. It is measured here because this code is still in use, not as a recommendation. |
| RustCrypto `ml-kem` | Pure Rust. |
| liboqs | C library as installed on the machine; since version 0.13 its ML-KEM code comes from mlkem-native. |
| AWS-LC via `aws-lc-rs` | Default (non-FIPS) build; its ML-KEM code also comes from mlkem-native. The timed call is `DecapsulationKey::decapsulate`, which includes the EVP layer of AWS-LC (a context object is created and freed) and an allocation for the result. |
| `libcrux-ml-kem` (Cryspen) | Rust, with AVX2, NEON and portable code. |

These are five libraries but four code bases. The versions of the Rust crates are pinned by
`Cargo.lock` (build with `--locked`); they and the version of liboqs found at run time are recorded
in every result. For every library the timed region is one call of its decapsulation function,
including whatever that call does around the arithmetic.

## Method

All timing tests use one procedure (`src/analysis/harness.rs`).

**Measurement**

- **Interleaved, in random order.** In every round each input class is timed exactly once, in a
  fresh uniformly random order. Warm-up, clock-frequency changes and temperature drift fall on all
  classes equally.
- **Every tested input belongs to one class.** What a call leaves behind in caches and predictors
  can help the next call with the same input, so an input that is used by more classes than
  another one can be measured faster for that reason alone. Each tested ciphertext is therefore
  used by exactly one class, and the controls use a ciphertext of their own. This is a rule about
  byte strings: the classes with a single flipped bit are strings of their own, but they differ
  from the accepted ciphertext in one bit only.
- **Same address for every class.** The inputs of all classes are stored byte-interleaved in one
  buffer. Before each timed call the input of the class is copied from there into one fixed
  working buffer, outside the timed region. The classes differ in the bytes of the ciphertext, not
  in where the data are stored.
- **Same code for every class.** Nothing that runs for a call depends on the class except through
  data: the bytes of the input and one table entry (the number of added iterations, see below).
  There is no branch on the class. Whether a build really treats the classes alike is not
  guaranteed by the source code; it is what the negative controls test.
- **One key per comparison.** Decapsulation time differs from key to key through public data, see
  [below](#decapsulation-time-depends-on-the-key).
- **Timed region.** `barrier · clock · library call · barrier · added work · barrier · clock`. A
  barrier (`LFENCE` on x86-64, `ISB` on AArch64) lets everything issued so far finish before
  anything later starts. The added work is a short loop that every class runs after the library
  call, with a length drawn fresh for every call; one class of each run runs a fixed number of
  iterations more. That is the added delay. The barrier after the library call keeps the processor
  from executing the loop alongside the last instructions of the call, so that the two times add
  up.
- `std::hint::black_box` is applied to the inputs and the result of the timed call (best effort
  against the compiler moving or removing work).

**Decision**

- **Paired sign test.** For two classes *a* and *b* the per-round differences δᵢ = bᵢ − aᵢ are
  formed; drift that affects a whole round cancels. Rounds with δᵢ = 0 are dropped, and
  *z* = (n₊ − n₋) / √(n₊ + n₋). A difference is detected if |*z*| > 4.5. If the two classes behave
  identically, the random order makes the sign of every difference a fair coin flip, whatever the
  timing noise looks like. The false-positive rate therefore follows from the threshold alone
  (two-sided *p* ≈ 7 · 10⁻⁶ per comparison); interrupts and other outliers cannot create a
  detection, they only reduce the power of the test.
- **Confirmation.** A detection counts only if a second run with the same key and the same
  ciphertexts, in a new random order, shows the same sign with |*z*| > 3.0. Both thresholds are
  fixed in the source. The second run guards against chance and passing disturbances, not against
  a systematic error of the setup; that is what the controls are for. A `multi-lib` run makes 10
  test comparisons and an `fo-oracle` run 16, so a first-run detection by chance is expected about
  once in 10 000 runs, and a confirmed one about a thousand times less often.
- **Classification.** `multi-lib` measures a confirmed difference once more with a fresh key and
  fresh ciphertexts. If it appears again with the same sign it belongs to the kind of input
  (accepted against rejected); if not, it depends on the particular inputs. Both are confirmed
  differences.

**Size of a difference**

An estimate Δ with an approximate 95 % interval is reported next to every decision and never used
for one. Which estimate is shown depends on how the δᵢ are spread over the values that the clock
can produce: whole nanoseconds, or whole steps of a coarser clock (41.7 ns on Apple Silicon). At
its start the tool reads the clock 200 000 times in a row and determines the step in which it
advances; `anu info` prints it, and every result records it.

- **Interpolated median**, if the central half of the δᵢ is spread over at least five clock
  values. The observations that share a clock value are treated as spread evenly over the step
  around it, so that the median and its interval are not tied to whole steps. The interval comes
  from the order statistics that belong to the sign test. Like the sign test, this estimate
  describes the typical call and is not disturbed by outliers.
- **Clipped mean**, if the δᵢ take only a few clock values, which happens on a coarse clock when
  there is little noise. An interpolated median is then inaccurate. The mean of the δᵢ is used
  instead, after removing values further than ten robust standard deviations from the median; a
  mean follows shifts far below one step, because the position of a call relative to the steps is
  random. Unlike the sign test, a mean also contains the rare slow calls inside that limit. It can
  therefore differ from zero in a comparison in which the sign test detects nothing.

The JSON names the estimate that is shown for each comparison and also stores the plain median and
the clipped mean. Welch's *t* and Cohen's *d* on the raw data are stored for information only.

**What shrinks a measured difference.** A call can be slowed by what the call before it did.
Because the order is random this does not favour any class, but a class that takes longer can
also slow calls of the other classes that follow it, and the measured Δ then comes out smaller
than the true difference. The controls show the size of this effect on the machine at hand: the measured
size of the added delay is compared with its expected size.

**Checks before timing.** For every library, every class must decapsulate to what it has to: the
accepted ciphertexts to the encapsulated secrets, every rejected ciphertext to a different value.
`multi-lib` and `ci` report a library that fails as skipped; `control` and `fo-oracle` stop with
exit code 70.

## Controls

### In every scan

`multi-lib`, `fo-oracle` and `ci` measure three control classes together with the test classes.
All three decapsulate one further honest ciphertext for the same key.

- **Negative control: control a against control b.** Identical inputs, identical code. Every
  detection here is a false positive of the setup.
- **Reference delay: control a against the reference class**, which runs `--ref-k` iterations of
  added work more (default 32). It must be detected, and with the right sign. The report gives
  the measured Δ next to its expected size: *k* times the cost of one iteration. That cost is
  measured during the same run, from the difference between a long and a short loop. The expected
  size is approximate (the few added iterations need not cost exactly what an iteration of a long
  loop costs), so the two are compared with a wide tolerance: the 95 % interval of the measured Δ
  must overlap the expected size ± 50 %. If it does not, something in the build or on the machine
  makes the added work behave differently from what is assumed, and the run makes no statement
  about sizes.
- **Detectable shift.** If the reference delay was detected, two sizes are reported. Δ · 4.5 / *z*
  is the shift whose expected *z* equals the threshold: about half of such runs would detect it.
  1.37 times that is the shift that about 95 % of such runs would detect. Both are linear
  extrapolations from one delay, and because they exist only for runs in which the delay was
  detected, they come out too small when the delay is close to the detection threshold.

A run in which a control fails **cannot be used**: a detection between the identical inputs, the
class with the added delay detected as the faster one, or (with `--ref-k 0`, where the third class
is one more identical control) any detection of that class. This holds for every run of a library,
including the confirmation run and the run with fresh inputs. The comparisons of such a library
are reported as not usable, whatever they show, and `ci` exits with 2. If the reference delay was
not detected, the run says nothing about differences of that size, and `ci` also exits with 2.

### `anu control`

Calibrates the procedure on the machine at hand, with PQClean ML-KEM-768. Both classes are the same
ciphertext with the same key.

- **Negative controls.** Ten runs in which nothing is added. Besides the decision for each run,
  the pairs of all ten runs are pooled into one sign statistic, which tests with ten times the
  data whether the setup treats identical inputs alike. A detection in a single run or
  |pooled *z*| > 4.5 fails the control.
- **Positive controls.** One class runs *k* more iterations of added work, *k* = 1 … 1024 in powers
  of two. A step counts as detected only if the first run detects it with the expected sign and a
  second run confirms it. The **sensitivity** is the smallest *k* from which every larger step is
  confirmed. The size of the delay at that step is then measured in one further run that is not
  used for any decision (the first two runs were selected for showing the delay, so their
  estimates are biased upwards near the detection limit), and reported next to *k* times the cost
  of one iteration.

## Decapsulation time depends on the key

Decapsulation re-encrypts, and re-encryption regenerates the public matrix from the seed ρ in the
key by rejection sampling. How many candidates are rejected depends on ρ, which is public. Two
honest keys therefore differ in decapsulation time, by an amount that is the same whether the
ciphertext is accepted or rejected:

```
cargo run --release --example key_dependence
```

The example measures pairs of fresh PQClean ML-KEM-768 keys and, for each pair, two hybrid keys:
the secret part of one key with the seed of the other. A hybrid key runs like the key whose seed it
carries, not like the key whose secret part it carries. The difference is not a leak of secret
data, but a comparison between classes that use different keys shows it as a timing difference.

The hybrid keys are test objects, not valid keys: the hash stored in them no longer matches, and
an implementation that performs the key check of FIPS 203, section 7.3, rejects them. The PQClean
code does not perform that check (the subject of RUSTSEC-2026-0585), which is what makes this
experiment possible with it.

## Results

The numbers below are printed by `python3 scripts/summarize.py <directory>` from the JSON files of
a series, or follow from its output; the `key_dependence` rows come from `key-dependence.txt`.
`scripts/series.sh` runs a series, `scripts/dit-experiment.sh` the runs with and without `--dit`.
All of them were measured with the source of commit `45efab4`, the commit before the one that
added them; every JSON file records it (`build.git_commit`).

### Apple M4 Pro, 25 November 2026

Apple M4 Pro (macOS, AArch64) on mains power and without other load; 100 000 rounds per run,
default settings (the tool asks the system for performance cores). The clock advances in steps of
41.7 ns (recorded as 41). rustc 1.94.1, Apple clang 17.0.0, liboqs 0.15.0 (static library as installed on that
machine), pqcrypto-mlkem 0.1.1, ml-kem 0.3.4, aws-lc-rs 1.19.0 (aws-lc-sys 0.47.0),
libcrux-ml-kem 0.0.12. One iteration of the added work cost 0.44 to 0.49 ns. Δ is the clipped mean
in most comparisons and the interpolated median where the noise is larger (all comparisons of
RustCrypto `ml-kem`, most of liboqs, a few of libcrux, and nearly all in the runs with `--dit`). All files of the series are in
[`results/2026-11-25-apple-m4-pro`](results/2026-11-25-apple-m4-pro), those of the runs with and
without `--dit` in [`results/2026-11-25-apple-m4-pro-dit`](results/2026-11-25-apple-m4-pro-dit).

| Check | Result |
|---|---|
| `control`, negative: 5 × 10 runs with identical inputs | no detection in 50 runs. *z* of the 50 runs: mean +0.14, root mean square 1.02 (0 and 1 are expected for identical behaviour), largest \|z\| 2.2. Pooled *z* of the five control runs between −1.1 and +2.6 |
| `control`, positive: 5 sweeps, *k* = 1 … 1024 | sensitivity *k* = 4 in all five sweeps: an added delay of 1.8 ns was detected and confirmed in every sweep, one of 0.9 ns (*k* = 2) in none (one of its five first runs crossed the threshold and was not confirmed). The further runs measured 1.3 to 1.9 ns for the delay of 1.8 ns, with 95 % intervals of about ±0.6 ns |
| measured against expected size of the added delay, the 30 steps with *k* ≥ 32 | ratio between 0.91 and 1.03, median 1.00. The expected size lay inside the 95 % interval of the measured one in 9 of the 30 steps; these intervals are about ±0.6 ns |
| `multi-lib`: 12 runs, 5 libraries, 2 test comparisons each | no detection in any first run, so there was nothing to confirm. *z* of the 120 comparisons: mean +0.05, root mean square 1.07, largest \|z\| 3.3 |
| negative controls of these runs | no detection in 60 library runs. *z*: mean 0.00, root mean square 1.05, largest \|z\| 2.9 |
| reference delay of these runs (32 iterations, 14.2 to 15.8 ns) | visible in 60 of 60 library runs, measured 10.7 to 14.8 ns. The median measured size was 0.97 of the expected one for PQClean, AWS-LC and libcrux, 0.86 for RustCrypto `ml-kem` and 0.79 for liboqs (single runs 0.68 to 1.04) |
| detectable shift, median of the 12 runs (range of the single runs) | detected by half of such runs: AWS-LC 0.9 ns (0.8–1.0), libcrux 1.0 ns (0.9–1.6), PQClean 1.1 ns (1.1–1.2), liboqs 1.3 ns (1.2–1.5), RustCrypto `ml-kem` 4.8 ns (4.6–5.1). Detected by 95 % of such runs: 1.2, 1.3, 1.5, 1.8 and 6.5 ns |
| `fo-oracle`, ML-KEM-768: 3 runs, 16 test comparisons each | one class stood out, the string of zero bytes: see below. The other 15 classes showed no detection (largest \|z\| 2.3). Negative controls without detection; reference delay visible in 3 of 3 runs; detectable shift 1.2 ns (half of such runs), 1.7 ns (95 %) |
| `ci` | exit 0: five libraries tested, controls as they must be, no detection |
| `key_dependence`: 8 pairs of keys | seven of the eight pairs differed by 6 to 17 ns (\|z\| 26 to 69), each by the same amount for the accepted and the rejected ciphertexts (within 1 ns). A hybrid key ran like the key whose seed it carries: no difference from that key was detected (16 comparisons, at most 0.5 ns, \|z\| at most 2.4), and its difference from the key whose secret part it carries was that of the two keys (within 1 ns). No key showed a difference between its accepted and its rejected ciphertext (largest \|z\| 2.6) |

What these numbers say: on this machine identical inputs were not told apart (113 comparisons of
identical classes without a detection, *z* spread as expected). An added delay of 1.8 ns in an
operation of 7 µs was found in every sweep, one of 0.9 ns in none (one first run crossed the
threshold and was not confirmed). The measured size of the reference delay was within a few per
cent of the expected size for three libraries and up to a third below it for the other two.
Between an accepted ciphertext and a ciphertext for another key or with one flipped bit, runs of
this length detect (by extrapolation from the reference delay) a shift of 1.2 to 1.8 ns in about
95 % of cases for four libraries and of 6.5 ns for RustCrypto `ml-kem`; none was detected.

#### The string of zero bytes on the M4

One of the 15 rejected classes of `fo-oracle` is a string of zero bytes. On the M4 it was
decapsulated faster than the valid ciphertext in all seven runs made without `--dit` (the three
runs of the series and four further ones): first-run *z* between −2.6 and −6.5, measured
difference −0.7 to −1.7 ns. That is at the detection limit of a single run. Two of the seven first
runs crossed the threshold, and both were confirmed by their second run. Taken together the runs
leave little doubt: the first runs of the series pooled give *z* = −8.2, those of the four further
runs *z* = −8.7. The string of 0xFF bytes shows the same tendency at a little under half the size
(*z* between −1.3 and −2.6 in every run, pooled −3.7 and −4.0). No other class does.

With the data-independent-timing mode of the processor switched on (`--dit`, PSTATE.DIT = 1) the
difference was no longer detected. Four such runs alternated with the four further runs named
above: *z* of the zero string between −2.1 and +1.4, pooled −0.2; no detection among the 64
comparisons (*z*: mean −0.20, root mean square 0.88). The runs with DIT were somewhat noisier
(detectable shift 1.6 to 1.7 ns for half of such runs instead of 1.2 to 1.3 ns), which does not
account for a change of the pooled *z* from −8.7 to −0.2.

What this shows, and what it does not. A string of zeros is a public input that any sender can
choose; the difference reveals nothing secret. It indicates that on this processor the running
time of this code depends on data values while DIT is clear; with DIT set the dependence was not
seen. The mechanism was not identified. With DIT clear the architecture does not promise that the
time of an instruction is independent of its operands, and data-dependent prefetching is a second
candidate (B. Chen et al., *GoFetch*, USENIX Security 2024, report that setting DIT switches the
data memory-dependent prefetcher off on the M3). The PQClean code in `pqcrypto-mlkem` does not set
the mode (its source contains no such instruction), which fits the difference between the two
conditions. A dependence on data values is the condition under which values that depend on a
secret could show in the timing as well. Whether they do was not tested here. The `multi-lib` scan
does not contain this class, so nothing is said about the other four libraries. On the x86-64
machine (below) the class showed nothing (pooled *z* +0.1), at a detection limit of about 10 ns,
which is about ten times the effect seen on the M4; the x86-64 build also runs other (AVX2) code.

### Development machine, 25 November 2026

Shared two-core cloud VM (Intel Xeon at 2.1 GHz with AVX2 and AVX-512, Linux, x86-64; clock source
tsc, clock step 1 ns), 20 000 rounds per run, default settings. rustc 1.97.0, gcc 13.3.0, liboqs
0.15.0 (built from source as a static library, CMake build type Release, without OpenSSL),
pqcrypto-mlkem 0.1.1, ml-kem 0.3.4, aws-lc-rs 1.19.0 (aws-lc-sys 0.47.0), libcrux-ml-kem 0.0.12.
One iteration of the added work cost about 0.6 ns (0.48 to 0.66 ns in single runs). Δ is the
interpolated median in every comparison. All files of the series are in
[`results/2026-11-25-dev-vm-x86_64`](results/2026-11-25-dev-vm-x86_64).

| Check | Result |
|---|---|
| `control`, negative: 5 × 10 runs with identical inputs | no detection in 50 runs. *z* of the 50 runs: mean +0.01, root mean square 1.12 (0 and 1 are expected for identical behaviour), largest \|z\| 3.0. Pooled *z* of the five control runs between −1.2 and +1.1 |
| `control`, positive: 5 sweeps, *k* = 1 … 1024 | sensitivity *k* = 16 in all five sweeps: this delay (9.7 ns of added work, 7.6 ns in one sweep) was detected and confirmed every time, *k* = 8 (3.8 to 4.9 ns) never. The further runs measured 7.2 to 9.7 ns for *k* = 16, with 95 % intervals of about ±3 ns |
| measured against expected size of the added delay, the 30 steps with *k* ≥ 32 | ratio between 0.86 and 1.05, median 0.97. The expected size lay inside the 95 % interval of the measured one in 12 of the 30 steps; the delays of 0.15 µs and more were measured 2 to 7 % too small |
| `multi-lib`: 12 runs, 5 libraries, 2 test comparisons each | no detection in any first run, so there was nothing to confirm. *z* of the 120 comparisons: mean −0.11, root mean square 1.00, largest \|z\| 2.3 |
| negative controls of these runs | no detection in 60 library runs. *z*: mean −0.21, root mean square 0.99, largest \|z\| 2.2 |
| reference delay of these runs (32 iterations, about 19.4 ns) | PQClean, liboqs, AWS-LC, libcrux: visible in 48 of 48 library runs, measured 14 to 25 ns. Per library the median measured size was 0.93 to 0.99 of the expected one (single runs 0.75 to 1.27). RustCrypto `ml-kem`: visible in none of its 12 runs (*z* between −0.5 and +1.9) |
| detectable shift, median of the 12 runs (range of the single runs) | detected by half of such runs: liboqs 4.9 ns (3.7–10.4), AWS-LC 7.6 ns (5.9–13.0), PQClean 8.4 ns (7.2–11.4), libcrux 8.8 ns (6.2–14.2). Detected by 95 % of such runs: 6.6, 10.4, 11.4 and 12.0 ns (up to 19.5 ns in a single run). No statement for RustCrypto `ml-kem` |
| `fo-oracle`, ML-KEM-768: 3 runs, 16 test comparisons each | no detection. *z* of the 48 comparisons: mean +0.29, root mean square 0.95, largest \|z\| 2.4. Negative controls without detection; reference delay visible in 3 of 3 runs; detectable shift 9.7 to 10.4 ns (half of such runs), 13.2 to 14.2 ns (95 %) |
| `ci` | exit 2: reference delay not visible for RustCrypto `ml-kem` |
| `key_dependence`: 8 pairs of keys | two pairs differed by about half a microsecond (482 and 504 ns), the same for the accepted and the rejected ciphertexts. In both, the hybrid key ran like the key whose seed it carries: 477 and 507 ns away from the key whose secret part it carries, and without a detected difference from the other one (+2 and +4 ns, \|z\| 1.1 and 2.0). The other six pairs differed by 0 to 13 ns; in two of them one of the two comparisons reached the detection threshold. No key showed a difference between its accepted and its rejected ciphertext (largest \|z\| 2.0) |

What these numbers say: on this machine identical inputs were not told apart. None of the 113
comparisons of identical classes showed a detection, and their *z* values are spread as expected
for identical behaviour. An added delay of about 10 ns in an operation of 12 µs was found in every
sweep, one of 5 ns in none. For delays of 19 ns and more the measured size was within about 30 %
of the expected size, and its median 1 to 7 % below it. For four libraries, runs of this length
detect (by extrapolation from the reference delay) a shift of 7 to 12 ns between an accepted and a
rejected ciphertext in about 95 % of cases, and one of 5 to 9 ns in half of the cases; in single
runs these figures were up to about twice as large. None was detected. For RustCrypto `ml-kem` the runs were not
sensitive enough: one call takes 90 to 106 µs there, and the noise of this machine hides a delay
of 19 ns at 20 000 rounds. The tool reports that instead of a pass.

These are not statements about the libraries on other hardware, and a shared VM is not a quiet
measurement environment.

## Reading a result

- **no difference detected** — no difference in the typical running time that reached the
  threshold, for these input classes, this build and this machine. How small a difference could
  have been detected is stated by the run itself (reference delay, detectable shift). Not a proof
  of constant-time behaviour.
- **difference confirmed** — the ciphertext is a public input, so a confirmed difference first of
  all shows that the running time depends on the input. Whether secret data are involved has to be
  judged from the pattern: the same difference for all rejected classes points to a difference
  between the accept and the rejection path; a difference for the second accepted ciphertext
  (`valid-2` in `fo-oracle`) to a dependence on the message or the ciphertext; a difference in
  single classes to input-dependent timing that needs a closer look. A confirmed difference is a
  reason to re-measure on a quiet machine and to read the code. It is not a vulnerability report.
- **not confirmed (inconclusive)** — detected in the first run, not confirmed in the second.
- **not usable** — a control of the run failed. Nothing else in that run can be used.
- **reference delay not visible** — the run was too noisy to see the added delay. "No difference
  detected" then says nothing about differences of that size. Use more rounds or a quieter machine.
- **size does not match the added work** — the reference delay was detected, but far from its
  expected size. The detection decisions stand; the sizes reported by that run do not.

## Limitations

- "No difference detected" holds for the tested input classes, this build, this machine and the
  sensitivity shown by the controls. Nothing more.
- Each class is one fixed ciphertext, repeated in every round, and each run uses one key. Timing
  that depends on the message or on the secret key in a way that these few inputs do not exercise
  is not found. A leak of the KyberSlash type (a division inside the polynomial arithmetic whose
  time depends on secret data) is not tested systematically: the input classes are not built to
  provoke it.
- No implementation with a known leak has been measured with this tool yet. The positive controls
  add a delay after the library call. They show how small a delay the procedure detects; they do
  not show that a leak inside the arithmetic of a library would be found.
- The sign test compares typical running times. A leak that appears only in rare calls can stay
  undetected.
- The detectable shift is an extrapolation from one added delay, and a real difference is measured
  smaller than it is when it slows the calls that follow (see Method).
- The negative control compares one pair of identical classes. It cannot show that every other
  class is treated alike. `--ref-k 0` turns the reference class into a third identical one.
- Keys, ciphertexts and the order of the calls are random and are not stored. A detection can be
  repeated with new inputs, not re-examined with the same ones. Raw timings are not stored
  either, only the statistics of every comparison.
- One build per machine: one compiler version and one set of compiler options for each library. A
  different compiler can turn the same source into code that behaves differently.
- Measured so far on two machines only (see Results): an x86-64 Linux VM and an Apple M4 Pro.
  Other AArch64 systems, AMD processors and Windows have not been tested; the build script does
  not support Windows.
- The added work that every class runs has a random length (32 to 95 iterations). It adds noise
  to every measurement, with a standard deviation of about 18 iterations per call, which reduces
  the power of the test a little.
- The barriers are `LFENCE` and `ISB`. That `LFENCE` waits for everything before it is documented
  for Intel processors; on AMD processors it holds only if the operating system has switched that
  on (Linux does so where the processor allows it). On architectures other than x86-64 and AArch64
  a clock read is used instead, which separates the library call from the added work less
  strictly.
- Timer: `std::time::Instant`. On Apple Silicon it advances in steps of about 41.7 ns; smaller
  differences are only visible statistically, through the share of rounds in which one class reads
  one step more than the other.
- The processor modes for data-independent timing are not set by default: PSTATE.DIT on AArch64
  only with `--dit`, and the corresponding mode of Intel processors (DOITM) not at all. A library
  may set them itself.
- User-space timing on one machine. Power, electromagnetic and cache-based side channels are out
  of scope, and so is a remote attacker's view through a network.
- Only ML-KEM decapsulation is covered. `multi-lib` covers ML-KEM-768 only, `fo-oracle` PQClean
  only.

## Build and run

Requirements: a Rust toolchain, a C compiler (some of the measured crates compile C code) and
liboqs. Tested with rustc 1.97.0 on Linux and rustc 1.94.1 on macOS, and with liboqs 0.15.0 on
both. With another version of liboqs the tool still checks the buffer lengths that the library
reports and skips it if they are not those of ML-KEM-768, but such a combination has not been
tried.

macOS, with liboqs from Homebrew:

```bash
brew install liboqs
cargo build --release --all-targets --locked
```

Linux, with liboqs built from source (every cargo command needs the variable, so export it):

```bash
export OQS_LIB_DIR=/path/to/liboqs/build/lib
cargo build --release --all-targets --locked
```

Without liboqs (it is then reported as skipped):

```bash
cargo build --release --all-targets --locked --no-default-features
```

Then:

```bash
cargo test --release                      # unit tests of the statistics and the decision rules
./target/release/anu info                 # platform, clock step, versions
./target/release/anu control              # first: controls on this machine
./target/release/anu multi-lib --samples 100000
./target/release/anu fo-oracle --samples 100000
scripts/series.sh results/my-machine 100000   # a whole series as under Results
python3 scripts/summarize.py results/my-machine
```

`OQS_LIB_DIR` names the directory that contains liboqs. `OQS_LINK=static|dylib` overrides how it is
linked (default: the shared library on macOS if there is one, the static one elsewhere). A static
liboqs that was built with OpenSSL also needs libcrypto: `OPENSSL_LIB_DIR` names its directory
(macOS default: Homebrew `openssl@3`, then `openssl@4`); `OQS_NO_OPENSSL=1` skips it.

For meaningful numbers use a quiet machine: no other load, mains power, and enough rounds. On
Linux the process can be pinned from outside (`taskset -c 2 ./target/release/anu …`); on macOS the
tool asks the system to prefer performance cores for the measuring thread (quality-of-service
class user-interactive).

## History and corrections

- **Version 2.0.0 (25 November 2026)** is the first version in this repository. The measurement
  procedure was built anew: random order, a common input address, one class per tested input, the
  same code for every class, barriers around the library call, one key per comparison, paired sign
  test, confirmation run, correctness checks, and negative and positive controls inside every run.
  The scope is what has been validated: timing of ML-KEM decapsulation. The tool is free software
  under the Apache License 2.0.
- **All statements that earlier versions made about this tool, and all results reported with
  them, are withdrawn.** Versions 0.3
  to 1.3 were public at this address from March to November 2026. Their licence statements were
  not consistent: the package metadata declared them proprietary throughout and the full scan
  needed a licence key, while the README named the MIT licence until 21 October 2026 and
  "proprietary" afterwards. Their history is not part of this repository. What is withdrawn:
  - **16 March to 21 October 2026.** The README of the repository described a collection of
    security tools under another name, called it "the world's first unified cryptographic
    security tool", and stated a "proven" timing leak in the CRYSTALS-Kyber reference
    implementation of 1200 to 1500 ns (Cohen's *d* 0.63 to 0.73). That statement was wrong. Those
    versions measured each ciphertext class in a block of its own, one after another, and drift
    between the blocks looked like a difference between valid and malformed ciphertexts. The
    statement was withdrawn in the README of 21 October 2026.
  - **21 October to 25 November 2026.** The README stated "no timing leak", that five ML-KEM-768
    implementations "are constant-time", and that the tool was, to the author's knowledge, the
    first scanner of its kind. A timing test cannot show that an implementation is constant-time,
    and tools for this purpose existed before (see [Prior work](#prior-work)).
  - Outputs of a TLS probe that reported a possible post-quantum downgrade for servers which also
    accept clients without post-quantum key exchange. Accepting such clients is ordinary
    behaviour; the output did not show a weakness of any server.
  - Modules that were never validated: static branch counting, performance counters, the TLS
    probe, a CBOM draft, timing statistics for ML-DSA and SLH-DSA, a benchmark and a code scanner.
    They are no longer part of the tool.

  The README of the first period also summarised findings of a separate memory-scanning tool in
  other software. They were not made with this tool, and this repository makes no statement about
  them.

## Prior work

- ctgrind (A. Langley, 2010) and TIMECOP in SUPERCOP: Valgrind runs the compiled program with the
  secret data marked as undefined and reports branches and memory accesses that depend on them.
- dudect (O. Reparaz, J. Balasch, I. Verbauwhede: *Dude, is my code constant time?*, DATE 2017):
  leakage detection on timing measurements with Welch's *t*-test; `dudect-bencher` brings the
  method to Rust.
- tlsfuzzer (H. Kario: *Everlasting ROBOT: the Marvin Attack*, ESORICS 2023, IACR ePrint
  2023/1442): sign test and Wilcoxon signed-rank test on pairwise differences of interleaved
  measurements, with bootstrapped confidence intervals. The statistical approach of VÄRN-60
  follows this line.
- `mlkem-sct-toolkit` of the tlsfuzzer project (github.com/tlsfuzzer/mlkem-sct-toolkit, since
  October 2024; described there as a very early version): generates classes of ML-KEM ciphertexts,
  among them ones built to exercise particular coefficients, times decapsulation through one small
  harness per library (C harnesses for OpenSSL, NSS, Nettle and leancrypto, a Python one for
  kyber-py) and analyses the timings with tlsfuzzer, optionally against intermediate values of the
  decapsulation. It is the closest existing tool. Its ciphertext classes and its analysis go
  further than those of VÄRN-60.
- RTLF (M. Dunsche et al.: *With Great Power Come Great Side Channels: Statistical Timing
  Side-Channel Analyses with Bounded Type-1 Errors*, USENIX Security 2024): a decision rule with a
  bounded false-positive rate.
- KyberSlash (D. J. Bernstein et al., IACR TCHES 2025(2), 209–234): secret-dependent division
  timings in Kyber implementations; the paper also presents a patched Valgrind that detects
  variable-time instructions operating on secret data.
- "Clangover" (CVE-2024-37880, 2024): a compiler turned constant-time source code of the Kyber
  reference implementation into a secret-dependent branch. CVE-2026-44519 (liboqs before 0.16.0,
  FrodoKEM): with some compilers and optimisation levels the constant-time selection in the
  implicit-rejection path became a secret-dependent load, a cache side channel; the ML-KEM code of
  liboqs is not affected. Both show that constant-time behaviour is a property of the built
  program, not of the source. VÄRN-60 has not been tried on either of them.
- CT-KAT (S.-W. Lee, M.-S. Kim, S.-M. Jeong, H.-J. Seo, IACR ePrint 2026/1418): a platform that
  combines several checks, among them Valgrind-based ones and optional dudect measurements, to
  screen C implementations of post-quantum schemes for constant-time risks.
- A. T. Anne: *Phantom Timing Leaks on Cortex-M4: A Pre-registered Evaluation of ML-KEM
  Decapsulation* (IACR ePrint 2026/2744): a pre-registered timing evaluation in the style of dudect
  of the ML-KEM implementations of PQM4 on a microcontroller, with a comparison of identical
  classes and a positive control that restores the code from before the KyberSlash fix.

VÄRN-60 does not replace these tools. What it adds is one program that measures further C and
Rust libraries with one procedure in the same run, with a common input address, one key per
comparison, and negative and positive controls inside every run that state the sensitivity of
that run on that machine.

## Licence

Copyright 2026 Sabrina Hackfort. Licensed under the Apache License, Version 2.0 — see
[LICENSE](LICENSE).

## Author

Sabrina Hackfort (sectio-aurea-q) · ORCID [0009-0007-7458-2487](https://orcid.org/0009-0007-7458-2487) · meg.depth@proton.me
