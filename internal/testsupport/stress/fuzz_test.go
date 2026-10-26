//go:build stress

// Package stress holds the release-only stress suite: real code known to be
// pathological, generated programs far larger than ordinary code along one
// axis, and a fuzz target that runs every analyzer over generated programs.
// It is too slow for ordinary CI, so its files build only with the stress tag.
package stress

import (
	"errors"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"runtime"
	"testing"
	"time"

	gohawk "github.com/kojah/gohawk/analyzers"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/checker"
	"golang.org/x/tools/go/packages"
)

// perProgram bounds one generated program's analysis. The programs hold a
// few hundred statements and analyze in well under a second; a run that
// takes this long has stopped converging.
const perProgram = 30 * time.Second

// FuzzAnalyzers runs every analyzer, with every check enabled, over a
// generated program. It fails when an analyzer panics, returns an error, or
// does not finish. The generator always emits valid Go, so a type error is
// a generator bug and fails too.
func FuzzAnalyzers(f *testing.F) {
	for _, seed := range fuzzSeeds() {
		f.Add(seed)
	}
	analyzers := gohawk.Analyzers()
	f.Fuzz(func(t *testing.T, data []byte) {
		source := generateProgram(data)
		pkg, err := typeCheck(source)
		if err != nil {
			t.Fatalf("generator emitted invalid Go: %v\n%s", err, source)
		}
		finished := make(chan error, 1)
		go func() { finished <- analyze(analyzers, pkg) }()
		select {
		case err := <-finished:
			if err != nil {
				t.Fatalf("%v\n%s", err, source)
			}
		case <-time.After(perProgram):
			t.Fatalf("analysis did not finish within %s\n%s", perProgram, source)
		}
	})
}

// fuzzSeeds starts the corpus with every statement kind reachable from a
// short input, and a long input that reaches the depth and size limits.
func fuzzSeeds() [][]byte {
	seeds := [][]byte{{}}
	for kind := range byte(26) {
		seeds = append(seeds, []byte{3, kind, 1, 2, 3, kind, 4, 5, 0, 7})
	}
	long := make([]byte, 4096)
	for index := range long {
		long[index] = byte(index*131 + index/7)
	}
	return append(seeds, long)
}

// typeCheck builds the package value the checker needs without go list,
// which would cost far more than the analysis itself.
func typeCheck(source string) (*packages.Package, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fuzz.go", source, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	info := &types.Info{
		Types:        map[ast.Expr]types.TypeAndValue{},
		Instances:    map[*ast.Ident]types.Instance{},
		Defs:         map[*ast.Ident]types.Object{},
		Uses:         map[*ast.Ident]types.Object{},
		Implicits:    map[ast.Node]types.Object{},
		Selections:   map[*ast.SelectorExpr]*types.Selection{},
		Scopes:       map[ast.Node]*types.Scope{},
		FileVersions: map[*ast.File]string{},
	}
	sizes := types.SizesFor("gc", runtime.GOARCH)
	config := types.Config{GoVersion: "go1.26", Importer: importer.Default(), Sizes: sizes}
	checked, err := config.Check("example.com/fuzz", fset, []*ast.File{file}, info)
	if err != nil {
		return nil, err
	}
	return &packages.Package{
		ID:              "example.com/fuzz",
		Name:            checked.Name(),
		PkgPath:         checked.Path(),
		GoFiles:         []string{"fuzz.go"},
		CompiledGoFiles: []string{"fuzz.go"},
		Fset:            fset,
		Syntax:          []*ast.File{file},
		Types:           checked,
		TypesInfo:       info,
		TypesSizes:      sizes,
		Imports:         map[string]*packages.Package{},
	}, nil
}

func analyze(analyzers []*analysis.Analyzer, pkg *packages.Package) error {
	graph, err := checker.Analyze(analyzers, []*packages.Package{pkg}, &checker.Options{Sequential: true})
	if err != nil {
		return err
	}
	var failures error
	for action := range graph.All() {
		if action.Err != nil {
			failures = errors.Join(failures, action.Err)
		}
	}
	return failures
}
