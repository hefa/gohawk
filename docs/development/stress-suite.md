# Stress suite

The stress suite checks that gohawk stays bounded on code far outside the
ordinary range. It is too slow for every push, so it runs in the release
workflow before anything is published, and by hand through the Stress
workflow (`gh workflow run stress.yml --ref <branch>`). It runs on Linux only.

The suite lives in `internal/testsupport/stress`, behind the `stress` build
tag, and has three parts.

- **Pathological code.** The go-json case analyzes goccy/go-json v0.10.5, whose
  generated encoders held 17 to 20 GB before the points-to graph build was
  bounded ([issue 51](https://github.com/kojah/gohawk/issues/51)).
- **Generated shapes.** The shape cases write programs that are far
  larger than ordinary code along one axis: an opcode switch, a huge package
  initializer, deep nesting, a long call chain, goroutine fan-out, wide struct
  copies and deferred closures.
- **Fuzzing.** The fuzz target turns fuzz input into a type-correct program
  and runs every analyzer over it in process. It fails on a panic, an analyzer
  error, or an analysis that takes over 30 seconds.

The first two parts run the real `gohawk -enable-all ./...` command. A watcher
sums the resident memory of the whole process tree, because go vet spreads
the work over several processes, and stops the run when the sum crosses the
case's limit. The suite passes or fails on crashes and memory only. Wall time
is logged but never asserted, because shared runners vary too much.

## Running it

```bash
make stress
```

```bash
make stress-fuzz STRESS_FUZZTIME=5m
```

Each fuzz worker analyzes thousands of packages in one process, so the
fuzz target also guards the heap model's cache lifetime. Its first run found
that the caches kept every analyzed package alive; they are now released with
each package's SSA program (see the points-to model).

`make stress` also replays every saved fuzz input. When fuzzing fails, the
input is written to `internal/testsupport/stress/testdata/fuzz/FuzzAnalyzers`,
and CI uploads it as the `fuzz-failures` artifact. Commit the input with the
fix so it stays a regression case.

## Adding a case

Add a real-world pathology as a pinned module version, with a link to the
report that found it. Add a new axis of size as a generator in
`pathological_test.go`, sized well past ordinary code but still able to
finish. A shape that exceeds a proof budget must make the analysis give up
on it, not grow with it.

Peaks measured when the suite was added, with four CPUs:

| Case | Peak tree memory | Limit |
|---|---|---|
| go-json | 576 MiB | 3 GiB |
| package initializer | 165 MiB | 2 GiB |
| call chain | 436 MiB | 2 GiB |
| other shapes | under 210 MiB | 2 GiB |
