// Package runner analyzes packages in one process with go vet's units: each
// package, test variant and dependency is type-checked from its source
// against its imports' export data and analyzed on its own, its SSA and
// heap-model state freed when it is done, exactly as a go vet tool process
// would. What one process saves is what go vet repeated per unit: decoding
// each dependency's export data in every importer, encoding facts to files
// and decoding them again, and starting a process. On caddy that halved the
// bytes allocated and the CPU time, with the same findings.
package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/token"
	"runtime"
	"sync"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/ssa"
)

// Options configures a run.
type Options struct {
	// Dir is the directory go list runs in.
	Dir string
	// Patterns name the packages to analyze; BuildFlags are passed to go list.
	Patterns, BuildFlags []string
	// Analyzers are the analyzers to run on the named packages, with their
	// flags already applied. Their dependencies run only for their facts.
	Analyzers []*analysis.Analyzer
	// FactsOnlyRun replaces an analyzer's Run on a unit analyzed only for its
	// facts, as go vet's tool may when it analyzes a dependency.
	FactsOnlyRun map[*analysis.Analyzer]func(*analysis.Pass) (any, error)
	// Release forgets what the analyzers kept for a unit's SSA program once
	// the unit is done.
	Release func(*ssa.Program)
	// Jobs bounds how many units are analyzed at once; zero means GOMAXPROCS.
	Jobs int
	// CacheDir holds the results of earlier runs; empty disables the cache.
	CacheDir string
}

// A session is one run's shared state.
type session struct {
	fset          *token.FileSet
	importer      *importer
	analyzers     []*analysis.Analyzer
	factAnalyzers []*analysis.Analyzer
	factsOnlyRun  map[*analysis.Analyzer]func(*analysis.Pass) (any, error)
	release       func(*ssa.Program)
	// results caches unit results across runs, by keys; nil disables it.
	// cached holds this run's hits.
	results *cache
	keys    map[string][]byte
	cached  map[string]unitResult
	// slots bounds the units analyzed at once.
	slots chan struct{}
	// remaining counts each test's units not yet done.
	worlds    sync.Mutex
	remaining map[string]int
}

// Run analyzes the packages and returns the findings in the JSON go vet
// writes with -json, one object per unit with findings, and the errors of
// units that could not be analyzed. A unit that fails leaves its importers
// without its facts, as a failed go vet unit does.
func Run(ctx context.Context, options Options) ([]byte, []error) {
	units, err := listUnits(ctx, options.Dir, options.BuildFlags, options.Patterns)
	if err != nil {
		return nil, []error{err}
	}
	byID := make(map[string]*unit, len(units))
	for _, listed := range units {
		byID[listed.id()] = listed
	}
	fset := token.NewFileSet()
	run := &session{
		fset: fset, importer: newImporter(fset, byID), analyzers: options.Analyzers,
		factAnalyzers: factAnalyzers(options.Analyzers), factsOnlyRun: options.FactsOnlyRun, release: options.Release,
		results: openCache(options.CacheDir, options.Analyzers),
	}
	if run.release == nil {
		run.release = func(*ssa.Program) {}
	}
	run.keys = run.unitKeys(units)
	jobs := options.Jobs
	if jobs <= 0 {
		jobs = runtime.GOMAXPROCS(0)
	}
	run.slots = make(chan struct{}, jobs)
	run.remaining = map[string]int{}
	for _, listed := range units {
		if listed.ForTest != "" {
			run.remaining[listed.ForTest]++
		}
	}
	outcomes := make(map[string]*outcome, len(units))
	for _, listed := range units {
		outcomes[listed.id()] = &outcome{done: make(chan struct{})}
	}
	run.cached = run.cachedResults(units)
	run.preload(units)
	var wait sync.WaitGroup
	for _, listed := range units {
		wait.Go(func() { run.schedule(ctx, listed, outcomes) })
	}
	wait.Wait()
	return collect(units, outcomes)
}

// An outcome is a unit's result once done is closed.
type outcome struct {
	result unitResult
	err    error
	done   chan struct{}
}

// unitKeys returns every unit's cache key, or nil when the cache is off or
// a unit's files cannot be read; the run then analyzes every unit.
func (run *session) unitKeys(units []*unit) map[string][]byte {
	if run.results == nil {
		return nil
	}
	keys := map[string][]byte{}
	for _, listed := range units {
		key, err := run.results.key(listed, keys)
		if err != nil {
			run.results = nil
			return nil
		}
		keys[listed.id()] = key
	}
	return keys
}

// schedule analyzes the unit once its imports are done, from the cache when
// an earlier run left its result, and within the run's job limit otherwise.
func (run *session) schedule(ctx context.Context, listed *unit, outcomes map[string]*outcome) {
	current := outcomes[listed.id()]
	defer close(current.done)
	defer run.leaveWorld(listed.ForTest)
	var published [][]publishedFact
	for _, id := range listed.Imports {
		if imported, ok := outcomes[id]; ok {
			<-imported.done
			published = append(published, imported.result.facts())
		}
	}
	if !listed.analyzed() || ctx.Err() != nil {
		return
	}
	if cached, ok := run.cached[listed.id()]; ok {
		current.result = cached
		return
	}
	run.slots <- struct{}{}
	defer func() { <-run.slots }()
	current.result, current.err = run.analyzeUnit(listed, published)
	if run.results != nil && current.err == nil {
		run.results.save(run.keys[listed.id()], current.result)
	}
}

// cachedResults returns the results an earlier run left for the units.
func (run *session) cachedResults(units []*unit) map[string]unitResult {
	cached := map[string]unitResult{}
	if run.results == nil {
		return cached
	}
	for _, listed := range units {
		if !listed.analyzed() {
			continue
		}
		if result, ok := run.results.load(run.keys[listed.id()]); ok {
			cached[listed.id()] = result
		}
	}
	return cached
}

// preload decodes the imports of every unit to be analyzed, one package at
// a time in dependency order, before any unit is analyzed. Decoding a
// package's export data can add objects to the scope of another package it
// refers to, and type checks and fact lookups read those scopes; once every
// package is decoded, units only read them and can run at once.
func (run *session) preload(units []*unit) {
	for _, listed := range units {
		if !listed.analyzed() || listed.Error != nil {
			continue
		}
		if _, ok := run.cached[listed.id()]; ok {
			continue
		}
		for _, id := range listed.Imports {
			run.importer.load(listed.ForTest, id)
		}
	}
}

// leaveWorld releases a test's world once its last unit is done.
func (run *session) leaveWorld(world string) {
	if world == "" {
		return
	}
	run.worlds.Lock()
	run.remaining[world]--
	last := run.remaining[world] == 0
	run.worlds.Unlock()
	if last {
		run.importer.release(world)
	}
}

// collect renders the units' findings in go list order and gathers their
// errors.
func collect(units []*unit, outcomes map[string]*outcome) ([]byte, []error) {
	var output bytes.Buffer
	var failures []error
	for _, listed := range units {
		current := outcomes[listed.id()]
		if current.err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", listed.id(), current.err))
			continue
		}
		if len(current.result.reports) == 0 {
			continue
		}
		encoded, err := json.MarshalIndent(map[string]any{listed.id(): current.result.reports}, "", "\t")
		if err != nil {
			failures = append(failures, err)
			continue
		}
		output.Write(encoded)
		output.WriteByte('\n')
	}
	return output.Bytes(), failures
}

// factAnalyzers returns the analyzers that produce facts, among analyzers
// and those they require: what go vet's tool runs on a dependency.
func factAnalyzers(analyzers []*analysis.Analyzer) []*analysis.Analyzer {
	var selected []*analysis.Analyzer
	seen := map[*analysis.Analyzer]bool{}
	var visit func(*analysis.Analyzer)
	visit = func(analyzer *analysis.Analyzer) {
		if seen[analyzer] {
			return
		}
		seen[analyzer] = true
		for _, required := range analyzer.Requires {
			visit(required)
		}
		if len(analyzer.FactTypes) > 0 {
			selected = append(selected, analyzer)
		}
	}
	for _, analyzer := range analyzers {
		visit(analyzer)
	}
	return selected
}
