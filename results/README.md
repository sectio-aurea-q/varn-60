# Results

One folder per measurement series, named by date and machine. Every folder contains, for each
run, the printed report (`.txt`) and the JSON result with all statistics, thresholds, versions
and the platform; `info.txt` is the output of `anu info`, `log.txt` the exit code of every run.

`scripts/series.sh <output directory> [rounds]` produces such a folder;
`python3 scripts/summarize.py <folder>` prints the numbers that the main README quotes from it.

Every JSON file records the commit of the source it was produced with (`build.git_commit`). The
series are therefore added in a commit of their own, after the commit of the code they measure.

| Folder | Machine | Rounds per run | Source |
|---|---|---|---|
| [`2026-11-25-apple-m4-pro`](2026-11-25-apple-m4-pro) | Apple M4 Pro, macOS, AArch64 | 100 000 | `45efab4` |
| [`2026-11-25-apple-m4-pro-dit`](2026-11-25-apple-m4-pro-dit) | the same machine: `anu fo-oracle` alternately without (`plain/`) and with `--dit` (`dit/`), four runs each, written by `scripts/dit-experiment.sh` | 100 000 | `45efab4` |
| [`2026-11-25-dev-vm-x86_64`](2026-11-25-dev-vm-x86_64) | shared two-core cloud VM, Intel Xeon 2.1 GHz, Linux, x86-64 | 20 000 | `45efab4` |

A series shows how the procedure behaved on that machine on that day. It is not a statement about
the libraries on other hardware, and a shared VM is not a quiet measurement environment.
