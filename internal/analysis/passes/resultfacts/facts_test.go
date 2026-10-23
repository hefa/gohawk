package resultfacts

import (
	"slices"
	"testing"

	proofs "github.com/kojah/gohawk/internal/engine/proof"
	"github.com/kojah/gohawk/internal/engine/ssaflow"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/analysistest"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

func TestCrossPackageResults(t *testing.T) {
	consumer := &analysis.Analyzer{
		Name: "resultconsumer", Doc: "assert cross-package result composition",
		Requires: []*analysis.Analyzer{Analyzer, buildssa.Analyzer},
		Run: func(pass *analysis.Pass) (any, error) {
			engine := pass.ResultOf[Analyzer].(*Engine)
			functions, err := ssaflow.SourceSSAFunctions(pass)
			if err != nil {
				return nil, err
			}
			want := map[string][]Guarantee{
				"Nil": {AlwaysNil}, "TypedNil": {AlwaysNonNil}, "Pair": {AlwaysFalse, AlwaysNil},
				"Mixed": {Unknown}, "Global": {Unknown}, "Deferred": {Unknown},
				"StoredTrue": {AlwaysTrue}, "StoredTypedNil": {AlwaysNonNil},
			}
			for _, function := range functions {
				expected, ok := want[function.Name()]
				if !ok {
					continue
				}
				local := engine.Function(function, proofs.NewSearchBudget(2000))
				call := ssaflow.InstructionsOf[*ssa.Call](function)[0]
				imported := engine.Function(call.Common().StaticCallee(), proofs.NewSearchBudget(2000))
				// A summary that claims nothing is not published, which every
				// consumer reads the same as an unavailable one.
				claims := slices.ContainsFunc(expected, func(guarantee Guarantee) bool { return guarantee != Unknown })
				if !local.Available || claims && !imported.Available {
					t.Errorf("%s: missing component", function)
				}
				for index, guarantee := range expected {
					if local.Result(index) != guarantee || imported.Result(index) != guarantee {
						t.Errorf("%s result %d: local=%v imported=%v want=%v", function, index, local.Result(index), imported.Result(index), guarantee)
					}
				}
				delete(want, function.Name())
			}
			if len(want) != 0 {
				t.Errorf("missing cases: %v", want)
			}
			return nil, nil
		},
	}
	analysistest.Run(t, analysistest.TestData(), consumer, "resultconsumer")
}
