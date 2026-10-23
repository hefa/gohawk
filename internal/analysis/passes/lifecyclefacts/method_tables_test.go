package lifecyclefacts

import (
	"testing"

	"github.com/kojah/gohawk/internal/engine/ssaflow"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/analysistest"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

// A method of a type an importer reaches only through another package's API
// keeps its summary there: c imports b alone, yet calls a's method.
func TestMethodSummaryReachesIndirectImporter(t *testing.T) {
	directory, cleanup, err := analysistest.WriteFiles(map[string]string{
		"a/a.go": `package a
import "os"
type Closer struct{}
func (*Closer) Release(f *os.File) { f.Close() }
`,
		"b/b.go": `package b
import "a"
func New() *a.Closer { return &a.Closer{} }
`,
		"c/c.go": `package c
import ("b"; "os")
func Use(f *os.File) { b.New().Release(f) }
`,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	found := false
	consumer := &analysis.Analyzer{
		Name: "indirectmethods", Doc: "find a method summary through an indirect import",
		Requires: []*analysis.Analyzer{Analyzer, buildssa.Analyzer},
		Run: func(pass *analysis.Pass) (any, error) {
			if pass.Pkg.Path() != "c" {
				return nil, nil
			}
			summaries := pass.ResultOf[Analyzer].(Summaries)
			functions, err := ssaflow.SourceSSAFunctions(pass)
			if err != nil {
				return nil, err
			}
			for _, function := range functions {
				for _, call := range ssaflow.InstructionsOf[*ssa.Call](function) {
					callee := call.Common().StaticCallee()
					if callee == nil || callee.Name() != "Release" {
						continue
					}
					fact, ok := summaries[callee]
					if !ok || len(fact.Discharges) == 0 {
						t.Errorf("c lost a.Closer.Release's summary: %+v, %v", fact, ok)
					}
					found = true
				}
			}
			return nil, nil
		},
	}
	analysistest.Run(t, directory, consumer, "c")
	if !found {
		t.Fatal("c's call to Release was not checked")
	}
}
