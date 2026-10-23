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
}

// A session is one run's shared state.
type session struct {
	fset          *token.FileSet
	importer      *importer
	analyzers     []*analysis.Analyzer
	factAnalyzers []*analysis.Analyzer
	factsOnlyRun  map[*analysis.Analyzer]func(*analysis.Pass) (any, error)
	release       func(*ssa.Program)
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
	}
	if run.release == nil {
		run.release = func(*ssa.Program) {}
	}
	jobs := options.Jobs
	if jobs <= 0 {
		jobs = runtime.GOMAXPROCS(0)
	}
	// A test's world is released once all of its units are done.
	remaining := map[string]int{}
	for _, listed := range units {
		if listed.ForTest != "" {
			remaining[listed.ForTest]++
		}
	}
	type outcome struct {
		result unitResult
		err    error
		done   chan struct{}
	}
	outcomes := make(map[string]*outcome, len(units))
	for _, listed := range units {
		outcomes[listed.id()] = &outcome{done: make(chan struct{})}
	}
	var worlds sync.Mutex
	slots := make(chan struct{}, jobs)
	var wait sync.WaitGroup
	for _, listed := range units {
		current := outcomes[listed.id()]
		wait.Go(func() {
			defer close(current.done)
			defer func() {
				if listed.ForTest == "" {
					return
				}
				worlds.Lock()
				remaining[listed.ForTest]--
				last := remaining[listed.ForTest] == 0
				worlds.Unlock()
				if last {
					run.importer.release(listed.ForTest)
				}
			}()
			var published [][]publishedFact
			for _, id := range listed.Imports {
				if imported, ok := outcomes[id]; ok {
					<-imported.done
					published = append(published, imported.result.published)
				}
			}
			if !listed.analyzed() || ctx.Err() != nil {
				return
			}
			slots <- struct{}{}
			defer func() { <-slots }()
			current.result, current.err = run.analyzeUnit(listed, published)
		})
	}
	wait.Wait()
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
