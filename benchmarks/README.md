# Dogfooding benchmarks

The dogfooding benchmark measures gohawk against pinned revisions of
representative Go repositories. It is intended to produce reproducible
evidence about whole-repository analysis cost, not to enforce a noisy CI
performance threshold.

Run the complete benchmark from the repository root:

```sh
scripts/benchmark-dogfood.sh
```

The script checks out each revision from
[`repositories.tsv`](repositories.tsv), warms the Go compile cache with one
unmeasured run, and then records three measured runs using a repository-owned
process measurement helper.

`go vet` caches each package's analysis result, keyed by the vet tool's build
ID. A second run with the same gohawk binary therefore replays cached results
instead of analyzing, and measures almost nothing. Each measured run instead
links a fresh gohawk binary, so it reuses compiled packages but analyzes every
package, including dependency facts, again. The numbers are the cost of the
first run of a new gohawk version against an already-built project.

Results are written beneath `benchmark-results/` and include:

- the exact gohawk and target revisions;
- the Go version and host details;
- package counts;
- wall-clock and CPU time for every run, with CPU time covering every process
  the run waited for;
- memory for the whole process tree: the cgroup peak, which includes page
  cache, and sampled anonymous memory, both reported as unknown without a
  systemd user scope;
- the largest single process's peak resident memory; and
- complete warm-up and measured analyzer output.

The generated `summary.md` is suitable for attaching to the dogfooding
tracking issue. Raw measurements are also available in `results.csv`.

Large repositories can take significant time and disk space. To validate the
harness or measure a single project, use `--only`:

```sh
scripts/benchmark-dogfood.sh --only gohawk --runs 1
scripts/benchmark-dogfood.sh --only caddy --runs 5
```

Pass analyzer selection flags without changing the manifest:

```sh
scripts/benchmark-dogfood.sh \
  --only caddy \
  --gohawk-arg=-enable=lockorder \
  --runs 5
```

Add `--profile` to find where the time goes. After the measured runs, it makes
one more run per repository with `GOHAWK_PROFILE_DIR` set, which makes each
vet-tool process write a timing record and a CPU profile for its unit. The
script writes, under `profiles/`:

- `NAME.md`, from `tools/profilesummary`: setup (parsing, type checking and
  fact decoding) versus analysis time, split by full and facts-only units,
  per-analyzer totals, and the slowest and largest units;
- `NAME-cpu.pb.gz`, every unit's CPU profile merged, for `go tool pprof`;
- `NAME-cpu-top.txt`, the merged profile's hottest functions; and
- `NAME-cpu-analyzers.txt`, CPU time by the `analyzer` sample label.
  Unlabelled samples are setup.

Each unit also writes `*.allocs`, its sampled allocations, for
`go tool pprof -sample_index=alloc_space`; garbage collection is a large share
of unit CPU, and this names the code that makes the garbage.

Each unit's record also lists the size, count and a content fingerprint of
every fact file it imported. Comparing the fingerprints of two profiled runs
checks that an optimization left every dependency's facts unchanged, which is
a much stronger check than the few diagnostics a repository reports. The
fingerprint covers fact content, not file bytes: gob numbers types in
registration order, which varies between runs.

Profiling adds sampling overhead, and fingerprinting decodes every imported
fact, so the profiled run is not one of the measured runs. The same variable works outside the script, but only for units
`go vet` actually runs: use a freshly built binary, or a cleared cache.

Use `--manifest` to supply another tab-separated repository list. Each data
row has four fields: a stable name, Git repository URL, revision, and one Go
package pattern. A repository value of `.` refers to the current gohawk
checkout. Revisions should normally be full commit hashes; `HEAD` is resolved
and recorded before measurement.

The first run for each repository is an unmeasured warm-up. Clone time,
dependency downloads, binary and measurement-helper construction, and
`go list` are deliberately excluded from the measurements. Exit status 3 is
accepted because Go analysis drivers use it when diagnostics are reported;
other nonzero statuses stop the benchmark.

Results from different machines should not be compared as if they came from a
controlled environment. When publishing measurements, retain the metadata and
compare revisions on the same otherwise-idle machine.
