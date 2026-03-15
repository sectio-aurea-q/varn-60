use crate::attack::AttackResult;
use std::path::Path;

pub fn save_json(result: &AttackResult, path: &Path) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(result)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(path, json)
}

pub fn save_html(result: &AttackResult, path: &Path) -> std::io::Result<()> {
    let vc = if result.vulnerable { "vulnerable" } else { "secure" };
    let vt = if result.vulnerable { "TIMING LEAK DETECTED" } else { "No significant leak" };

    let mut rows = String::new();
    for (i, v) in result.variants.iter().enumerate() {
        let d = if i > 0 { format!("{:+.1}", v.mean_ns - result.variants[0].mean_ns) } else { "-".into() };
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{:.1}</td><td>{:.1}</td><td>{:.1}</td><td>{}</td></tr>\n",
            v.name, v.mean_ns, v.median_ns, v.stddev_ns, d
        ));
    }

    let html = format!(r#"<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Anu Report</title>
<style>
:root{{--bg:#0a0a0f;--fg:#e0e0e0;--g:#00ff88;--r:#ff4444;--c:#12121a}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:var(--bg);color:var(--fg);font-family:'JetBrains Mono',monospace;padding:2rem}}
h1{{color:var(--g);text-align:center;letter-spacing:.15em;margin-bottom:.5rem}}
.sub{{text-align:center;color:#888;margin-bottom:2rem}}
.card{{background:var(--c);border:1px solid #222;border-radius:8px;padding:1.5rem;margin-bottom:1.5rem}}
.card h2{{color:var(--g);margin-bottom:1rem}}
.v{{text-align:center;padding:1.5rem;font-size:1.3rem;font-weight:bold;border-radius:8px;margin-bottom:1.5rem}}
.vulnerable{{background:#2a0a0a;border:2px solid var(--r);color:var(--r)}}
.secure{{background:#0a2a0a;border:2px solid var(--g);color:var(--g)}}
table{{width:100%;border-collapse:collapse}}
th,td{{padding:.5rem 1rem;text-align:right;border-bottom:1px solid #222}}
th{{color:var(--g)}}td:first-child,th:first-child{{text-align:left}}
.m{{display:inline-block;margin:.5rem 1.5rem;text-align:center}}
.m .l{{color:#888;font-size:.8rem}}.m .n{{color:var(--g);font-size:1.3rem;font-weight:bold}}
</style></head><body>
<h1>VÄRN-60 (Anu)</h1>
<div class="sub">Automated Side-Channel Scanner for Post-Quantum Cryptography<br>sectio-aurea-q | {ts}</div>
<div class="v {vc}">{vt}</div>
<div class="card"><h2>Metrics</h2><div style="text-align:center">
<div class="m"><div class="l">Cohen's d</div><div class="n">{d:.4}</div></div>
<div class="m"><div class="l">Timing Delta</div><div class="n">{dn:.1} ns</div></div>
<div class="m"><div class="l">t-statistic</div><div class="n">{t:.2}</div></div>
<div class="m"><div class="l">p-value</div><div class="n">{p:.2e}</div></div>
</div></div>
<div class="card"><h2>Platform</h2><p>{chip} | {lvl} | {smp} samples/variant</p></div>
<div class="card"><h2>Variants</h2>
<table><tr><th>Variant</th><th>Mean(ns)</th><th>Median(ns)</th><th>StdDev</th><th>Delta</th></tr>
{rows}</table></div>
</body></html>"#,
        ts = result.timestamp, vc = vc, vt = vt,
        d = result.fo_cohens_d, dn = result.fo_timing_delta_ns,
        t = result.fo_t_statistic, p = result.fo_p_value,
        chip = result.platform.chip, lvl = result.config.level,
        smp = result.config.samples_per_variant, rows = rows
    );
    std::fs::write(path, html)
}
