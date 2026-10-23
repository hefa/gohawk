package resultfacts

import (
	"go/types"
	"reflect"
	"slices"

	"github.com/kojah/gohawk/internal/analysis/factcodec"
	"github.com/kojah/gohawk/internal/analysis/factscope"
	"github.com/kojah/gohawk/internal/engine/ssaflow"

	proofs "github.com/kojah/gohawk/internal/engine/proof"
	ssacall "github.com/kojah/gohawk/internal/engine/ssaflow/calls"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
)

const factVersion = 4

// Fact publishes independent result guarantees, the result cases that hold
// under a condition, and the results proven to be a parameter. A case is an
// implication that held on every return under its condition; its absence is
// not the opposite implication.
type Fact struct {
	_            struct{} `cbor:",toarray"` // published as a CBOR array; see factcodec
	Version      int
	Results      []Guarantee
	Cases        []ResultCase
	Returned     []ReturnedParameter
	NeverReturns bool
}

// publishedFact hides the result schema from gob's per-stream descriptors.
type publishedFact struct{ publication }

// An unexported embedded alias also hides the envelope's descriptor from gob.
type publication = factcodec.Envelope[Fact]

// Analyzer computes result knowledge only when required before dependency
// analysis. It does not require lifecycle or concurrency inference.
var Analyzer = &analysis.Analyzer{
	Name: "resultfacts", Doc: "exports bounded unconditional result guarantees",
	Requires: []*analysis.Analyzer{buildssa.Analyzer}, FactTypes: []analysis.Fact{new(publishedFact), new(publishedTypes), new(publishedFunctions)},
	ResultType: reflect.TypeFor[*Engine](), Run: run,
}

func run(pass *analysis.Pass) (any, error) {
	functions, err := ssaflow.SourceSSAFunctions(pass)
	if err != nil {
		return nil, err
	}
	engine := NewEngine()
	// Imported facts decode on first lookup; most are never consulted.
	engine.imported = make(map[*types.Func]*publishedFact)
	for _, imported := range pass.AllObjectFacts() {
		object, ok := imported.Object.(*types.Func)
		published, valid := imported.Fact.(*publishedFact)
		if ok && valid {
			engine.imported[object] = published
		}
	}
	engine.groups = importGroups(pass)
	visible := factscope.API(pass.Pkg)
	var groups factGroups
	for _, function := range functions {
		object := function.Object()
		// A function with no results still has something to say when it
		// never returns; every other claim needs a result to be about. One no
		// importer can see is never an importer's callee.
		if object == nil || !object.Exported() || !visible.Contains(object) {
			continue
		}
		summary := engine.Function(function, proofs.NewSearchBudget(proofs.SummaryBudget))
		if !summary.Available || !summary.claimsAnything() {
			continue
		}
		fact := Fact{
			Version: factVersion, Results: slices.Clone(summary.results), Cases: slices.Clone(summary.cases), Returned: slices.Clone(summary.returned),
			NeverReturns: summary.neverReturns,
		}
		if declared, ok := object.(*types.Func); !ok || !groups.add(declared, fact) {
			pass.ExportObjectFact(object, &publishedFact{factcodec.Wrap(fact)})
		}
	}
	if err := groups.publish(pass, engine.groups); err != nil {
		return nil, err
	}
	return engine, nil
}

// claimsAnything reports whether a summary says something an importer can
// use. Every consumer needs a known result, a case, a returned parameter or
// termination as well as availability, so a summary with none of them reads
// the same as no fact, and nine in ten exported functions have one: every
// importer down the build paid to read it.
func (summary Summary) claimsAnything() bool {
	if summary.neverReturns || len(summary.cases) != 0 || len(summary.returned) != 0 {
		return true
	}
	for _, result := range summary.results {
		if result != Unknown {
			return true
		}
	}
	return false
}

// importedFact decodes the fact published for object. A fact that does not
// decode or validate is unavailable, never an empty guarantee.
func (engine *Engine) importedFact(object *types.Func) (Fact, bool) {
	var fact Fact
	if published, ok := engine.imported[object]; ok {
		value, err := published.Value()
		if err != nil {
			return Fact{}, false
		}
		fact = value
	} else if grouped, ok := engine.groups.lookup(object); ok {
		fact = grouped
	} else {
		return Fact{}, false
	}
	if !validFact(&fact) {
		return Fact{}, false
	}
	return fact, true
}

func validFact(fact *Fact) bool {
	if fact.Version != factVersion || len(fact.Results) > maxResults {
		return false
	}
	for _, result := range fact.Results {
		if result > AlwaysFalse {
			return false
		}
	}
	for _, proven := range fact.Cases {
		if proven.Result < 0 || proven.Result >= len(fact.Results) || proven.Outcome == ssacall.OutcomeAny || proven.Outcome > ssacall.OutcomeNonNil {
			return false
		}
	}
	for _, returned := range fact.Returned {
		if returned.Result < 0 || returned.Result >= len(fact.Results) || returned.Parameter < 0 || returned.Parameter >= 64 {
			return false
		}
	}
	return true
}
