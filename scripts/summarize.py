#!/usr/bin/env python3
"""Summary of a measurement series written by scripts/series.sh.

    python3 scripts/summarize.py <series directory>

Reads the JSON results and prints the numbers that the README quotes for the
series. Standard library only.
"""
import glob
import json
import os
import sys


def load(directory, pattern):
    files = sorted(glob.glob(os.path.join(directory, pattern)),
                   key=lambda f: int(f.rsplit("-", 1)[1].split(".")[0]))
    return [json.load(open(f, encoding="utf-8")) for f in files]


def span(values, fmt="{:.1f}"):
    values = [v for v in values if v is not None]
    if not values:
        return "n/a"
    lo, hi = min(values), max(values)
    return fmt.format(lo) if fmt.format(lo) == fmt.format(hi) else fmt.format(lo) + " … " + fmt.format(hi)


def median(values):
    values = sorted(v for v in values if v is not None)
    if not values:
        return None
    n = len(values)
    return values[n // 2] if n % 2 else (values[n // 2 - 1] + values[n // 2]) / 2


def med(values, fmt="{:.1f}"):
    m = median(values)
    return "n/a" if m is None else fmt.format(m)


def interval(c):
    return "{:+.1f} [{:+.1f}, {:+.1f}]".format(c["delta_ns"], c["delta_ci95_ns"][0], c["delta_ci95_ns"][1])


def spread(comparisons):
    """Mean and root mean square of z; 0 and 1 are expected if nothing differs."""
    z = [c["sign_z"] for c in comparisons]
    if not z:
        return "n/a"
    return "mean {:+.2f}, root mean square {:.2f} (expected for identical behaviour: 0 and 1), largest |z| {:.2f}".format(
        sum(z) / len(z), (sum(v * v for v in z) / len(z)) ** 0.5, max(abs(v) for v in z))


def inside(comparison, nominal):
    return nominal is not None and comparison["delta_ci95_ns"][0] <= nominal <= comparison["delta_ci95_ns"][1]


def ratios(pairs):
    """measured / expected for (comparison, nominal) pairs"""
    return [c["delta_ns"] / n for c, n in pairs if n]


def build(directory):
    for pattern in ("control-*.json", "multi-lib-*.json", "fo-oracle-*.json"):
        runs = load(directory, pattern)
        if runs:
            b, p = runs[0]["build"], runs[0]["platform"]
            print("build: commit {}; {}; C compiler: {}".format(
                b.get("git_commit", "not recorded"), b.get("rustc", "?"), b.get("c_compiler", "not recorded")))
            print("       liboqs {}; {}".format(b.get("liboqs_version", "?"), b.get("crate_versions", "?")))
            print("clock: step {} ns ({}); scheduling: {}".format(
                p.get("clock_step_ns", "not recorded"), p.get("clock_source", "not recorded"), p.get("scheduling", "?")))
            print()
            return


def controls(directory):
    runs = load(directory, "control-*.json")
    if not runs:
        return
    print("anu control: {} runs, {} rounds each".format(len(runs), runs[0]["rounds"]))
    negative = [c for r in runs for c in r["negative_runs"]]
    print("  negative runs: {} detections in {} runs; z: {}".format(
        sum(c["difference_detected"] for c in negative), len(negative), spread(negative)))
    print("  pooled z per control run: " + ", ".join("{:+.2f}".format(r["negative_pooled_z"]) for r in runs))
    print("  cost of one added iteration: " + span([r["iteration_cost_ns"] for r in runs], "{:.2f}") + " ns")
    print("  sensitivity (k): " + ", ".join(str(r["sensitivity_iterations"]) for r in runs))
    for r in runs:
        if r["sensitivity_estimate"] is not None:
            print("    k = {:>3}: added work ≈ {:.1f} ns, measured in the further run Δ = {} ns ({})".format(
                r["sensitivity_iterations"], r["sensitivity_nominal_delay_ns"],
                interval(r["sensitivity_estimate"]), r["sensitivity_estimate"]["delta_estimator"]))
    ks = [s["added_iterations"] for s in runs[0]["positive_controls"]]
    for i, k in enumerate(ks):
        steps = [r["positive_controls"][i] for r in runs]
        pairs = [(s["first_run"], s["nominal_delay_ns"]) for s in steps]
        print("    k = {:>4}: confirmed in {} of {} sweeps; first-run Δ {} ns; added work {} ns; measured/added {}; "
              "added work inside the 95 % interval in {} of {}".format(
                  k, sum(s["confirmed"] for s in steps), len(steps),
                  span([s["first_run"]["delta_ns"] for s in steps]),
                  span([s["nominal_delay_ns"] for s in steps]),
                  span(ratios(pairs), "{:.2f}"),
                  sum(inside(c, n) for c, n in pairs), len(pairs)))
    large = [(s["first_run"], s["nominal_delay_ns"]) for r in runs for s in r["positive_controls"]
             if s["added_iterations"] >= 32]
    print("  steps with k ≥ 32: measured/added {} (median {}); added work inside the 95 % interval in {} of {}".format(
        span(ratios(large), "{:.2f}"), med(ratios(large), "{:.2f}"), sum(inside(c, n) for c, n in large), len(large)))
    print("  passed: {} of {}".format(sum(r["passed"] for r in runs), len(runs)))
    print()


def scan_table(scans, title):
    if not scans:
        return
    print("{}: {} runs, {} rounds each, reference delay k = {}".format(
        title, len(scans), scans[0]["rounds"], scans[0]["reference_iterations"]))
    libraries = []
    for s in scans:
        for r in s["results"]:
            if r["library"] not in libraries:
                libraries.append(r["library"])
    all_tests, all_negative = [], []
    for lib in libraries:
        rows = [r for s in scans for r in s["results"] if r["library"] == lib]
        tests = [r[k] for r in rows for k in ("other_ciphertext", "bit_flip")]
        first = [t["first_run"] for t in tests]
        all_tests += first
        print("  " + lib)
        print("    test comparisons: {}; detected in the first run {}, confirmed {}; largest |z| {:.2f}".format(
            len(tests), sum(c["difference_detected"] for c in first), sum(t["confirmed"] for t in tests),
            max(abs(c["sign_z"]) for c in first)))
        for t in tests:
            if t["first_run"]["difference_detected"]:
                print("      detection: first run z = {:+.2f}, Δ = {} ns → {}".format(
                    t["first_run"]["sign_z"], interval(t["first_run"]), t["outcome"]))
        negative = [r["negative_control"] for r in rows] + [c for r in rows for c in r.get("further_negative_controls", [])]
        all_negative += negative
        print("    negative control: {} detections in {} runs, largest |z| {:.2f}".format(
            sum(c["difference_detected"] for c in negative), len(negative), max(abs(c["sign_z"]) for c in negative)))
        unusable = [r["unusable_reason"] for r in rows if not r.get("usable", True)]
        if unusable:
            print("    NOT USABLE in {} runs: {}".format(len(unusable), "; ".join(sorted(set(unusable)))))
        reference = [r["reference"] for r in rows]
        pairs = [(r["reference"], r["reference_nominal_ns"]) for r in rows if r["reference_visible"]]
        print("    reference delay: visible in {} of {} runs; z {}".format(
            sum(r["reference_visible"] for r in rows), len(rows), span([c["sign_z"] for c in reference], "{:+.1f}")))
        print("      measured Δ {} ns (median {}); added work {} ns (median {})".format(
            span([c["delta_ns"] for c in reference]), med([c["delta_ns"] for c in reference]),
            span([r["reference_nominal_ns"] for r in rows]), med([r["reference_nominal_ns"] for r in rows])))
        if pairs:
            print("      where visible: measured/added {} (median {}); added work inside the 95 % interval in {} of {}; "
                  "size judged implausible in {}".format(
                      span(ratios(pairs), "{:.2f}"), med(ratios(pairs), "{:.2f}"),
                      sum(inside(c, n) for c, n in pairs), len(pairs),
                      sum(1 for r in rows if r.get("reference_size_plausible") is False)))
        print("    shift detected by half of such runs: {} ns (median {}); by 95 %: {} ns (median {})".format(
            span([r.get("detectable_shift_50_ns") for r in rows]), med([r.get("detectable_shift_50_ns") for r in rows]),
            span([r.get("detectable_shift_95_ns") for r in rows]), med([r.get("detectable_shift_95_ns") for r in rows])))
        print("    estimator: " + ", ".join(sorted({c["delta_estimator"] for c in first})) +
              "; median running time " + span([c["median_a_ns"] for c in first], "{:.0f}") + " ns")
        incomplete = [r["incomplete"] for r in rows if r["incomplete"]]
        if incomplete:
            print("    incomplete: " + "; ".join(incomplete))
    print("  all libraries, z of the {} test comparisons: {}".format(len(all_tests), spread(all_tests)))
    print("  all libraries, z of the {} negative controls: {}".format(len(all_negative), spread(all_negative)))
    skipped = ["{} ({})".format(x["library"], x["reason"]) for s in scans for x in s["skipped"]]
    if skipped:
        print("  skipped: " + "; ".join(skipped))
    print()


def fo_oracle(directory):
    runs = load(directory, "fo-oracle-*.json")
    if not runs:
        return
    print("anu fo-oracle: {} runs, {} rounds each, {}".format(len(runs), runs[0]["config"]["rounds"], runs[0]["config"]["level"]))
    comparisons = [c for r in runs for c in r["comparisons"]]
    print("  test comparisons: {}; detected in the first run {}, confirmed {}".format(
        len(comparisons), sum(c["first_run"]["difference_detected"] for c in comparisons),
        sum(c["confirmed"] for c in comparisons)))
    print("  z of the test comparisons: " + spread([c["first_run"] for c in comparisons]))
    for i, r in enumerate(runs, 1):
        for c in r["comparisons"]:
            if c["first_run"]["difference_detected"]:
                second = c["confirmation_run"]
                print("    run {}: {} first run z = {:+.2f}, Δ = {} ns; second run z = {}; confirmed: {}".format(
                    i, c["class"], c["first_run"]["sign_z"], interval(c["first_run"]),
                    "n/a" if second is None else "{:+.2f}".format(second["sign_z"]), c["confirmed"]))
        if not r.get("usable", True):
            print("    run {}: NOT USABLE: {}".format(i, r.get("unusable_reason")))
    print("  negative control: {} detections in {} runs, z {}".format(
        sum(r["negative_control"]["difference_detected"] for r in runs), len(runs),
        span([r["negative_control"]["sign_z"] for r in runs], "{:+.2f}")))
    pairs = [(r["reference"], r["reference_nominal_ns"]) for r in runs if r["reference_visible"]]
    print("  reference delay: visible in {} of {} runs; measured Δ {} ns; added work {} ns; measured/added {}".format(
        sum(r["reference_visible"] for r in runs), len(runs),
        span([r["reference"]["delta_ns"] for r in runs]),
        span([r["reference_nominal_ns"] for r in runs]),
        span(ratios(pairs), "{:.2f}")))
    print("  shift detected by half of such runs: {} ns; by 95 %: {} ns".format(
        span([r.get("detectable_shift_50_ns") for r in runs]), span([r.get("detectable_shift_95_ns") for r in runs])))
    # every test class over all runs: z and Δ of the first runs, and the sign
    # statistic of all first runs pooled (every run uses a key of its own)
    names = [c["class"] for c in runs[0]["comparisons"]]
    for name in names:
        first = [c["first_run"] for r in runs for c in r["comparisons"] if c["class"] == name]
        slower = sum(c["n_b_slower"] for c in first)
        faster = sum(c["n_b_faster"] for c in first)
        pooled = (slower - faster) / (slower + faster) ** 0.5 if slower + faster else 0.0
        print("    {:>16}: z {}   Δ {} ns   pooled z {:+.2f}".format(
            name, ", ".join("{:+.2f}".format(c["sign_z"]) for c in first),
            ", ".join("{:+.1f}".format(c["delta_ns"]) for c in first), pooled))
    dit = {r["platform"].get("data_independent_timing", "not recorded") for r in runs}
    print("  data-independent timing (DIT): " + "; ".join(sorted(dit)))
    print()


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(64)
    directory = sys.argv[1]
    if not os.path.isdir(directory):
        sys.exit("not a directory: " + directory)
    if not glob.glob(os.path.join(directory, "*.json")):
        sys.exit("no JSON results in " + directory)
    info = os.path.join(directory, "info.txt")
    if os.path.exists(info):
        print(open(info, encoding="utf-8").read().strip())
        print()
    build(directory)
    log = os.path.join(directory, "log.txt")
    if os.path.exists(log):
        runs = [line.split() for line in open(log, encoding="utf-8").read().splitlines()]
        runs = [w for w in runs if len(w) == 3 and w[1] == "exit" and w[2].isdigit()]
        nonzero = ["{} (exit {})".format(w[0], w[2]) for w in runs if w[2] != "0"]
        print("log: {} runs, with a non-zero exit code: {}".format(len(runs), ", ".join(nonzero) if nonzero else "none"))
        print()
    controls(directory)
    scan_table(load(directory, "multi-lib-*.json"), "anu multi-lib")
    fo_oracle(directory)
    ci = load(directory, "ci-*.json")
    for i, r in enumerate(ci, 1):
        print("anu ci, run {}: exit code {} ({}); open points: {}".format(
            i, r["exit_code"], r["outcome"], "; ".join(r["open_points"]) if r["open_points"] else "none"))
    if ci:
        print()
        scan_table([r["scan"] for r in ci], "scan of anu ci")
    key_dependence = os.path.join(directory, "key-dependence.txt")
    if os.path.exists(key_dependence):
        print("key_dependence example (key-dependence.txt):")
        print(open(key_dependence, encoding="utf-8").read().rstrip())
        print()


if __name__ == "__main__":
    main()
