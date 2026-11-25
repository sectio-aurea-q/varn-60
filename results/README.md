# Results

One folder per measurement series, named by date and machine. Every folder contains, for each
run, the printed report (`.txt`) and the JSON result with all statistics, thresholds, versions
and the platform; `info.txt` is the output of `anu info`, `log.txt` the exit code of every run.

`scripts/series.sh <output directory> [rounds]` produces such a folder;
`python3 scripts/summarize.py <folder>` prints the numbers that the main README quotes from it.

Every JSON file records the commit of the source it was produced with (`build.git_commit`). The
series are therefore added in a commit of their own, after the commit of the code they measure.
