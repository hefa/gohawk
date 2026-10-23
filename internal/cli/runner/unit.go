package runner

import (
	"cmp"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
)

// A unitResult is what analyzing one unit leaves: the facts its importers
// see, and the diagnostics or errors of each analyzer, as go vet's tool
// writes them.
type unitResult struct {
	published []publishedFact
	reports   map[string]any
	// lazyFacts, for a result read from the cache, decodes its published
	// facts when an importer first needs them.
	lazyFacts func() []publishedFact
}

// facts returns the facts the unit published.
func (result *unitResult) facts() []publishedFact {
	if result.lazyFacts != nil {
		return result.lazyFacts()
	}
	return result.published
}

// analyzeUnit type-checks the unit against its imports' export data and
// runs the analyzers over it. A facts-only unit, a dependency go vet would
// analyze only for its facts, runs only the analyzers that produce facts
// and those they require, and reports nothing.
func (run *session) analyzeUnit(target *unit, published [][]publishedFact) (unitResult, error) {
	checked, err := run.checkUnit(target)
	if err != nil {
		return unitResult{}, err
	}
	defer run.forgetFiles(checked.files)
	files, pkg, info, config, typeErrors, analysisModule := checked.files, checked.pkg, checked.info, checked.config, checked.typeErrors, checked.module
	store := newFactStore(pkg, published)
	analyzers := run.analyzers
	if target.DepOnly {
		analyzers = run.factAnalyzers
	}
	result := unitResult{reports: map[string]any{}}
	results := map[*analysis.Analyzer]any{}
	done := map[*analysis.Analyzer]bool{}
	var analyze func(*analysis.Analyzer)
	analyze = func(analyzer *analysis.Analyzer) {
		if done[analyzer] {
			return
		}
		done[analyzer] = true
		for _, required := range analyzer.Requires {
			analyze(required)
		}
		var diagnostics []analysis.Diagnostic
		pass := &analysis.Pass{
			Analyzer: analyzer, Fset: run.fset, Files: files, Pkg: pkg, TypesInfo: info, TypesSizes: config.Sizes,
			TypeErrors: typeErrors, Module: analysisModule, ResultOf: map[*analysis.Analyzer]any{}, ReadFile: os.ReadFile,
			Report: func(diagnostic analysis.Diagnostic) { diagnostics = append(diagnostics, diagnostic) },
		}
		for _, required := range analyzer.Requires {
			pass.ResultOf[required] = results[required]
		}
		store.bind(pass)
		analyzerRun := analyzer.Run
		if target.DepOnly && run.factsOnlyRun[analyzer] != nil {
			analyzerRun = run.factsOnlyRun[analyzer]
		}
		output, err := analyzerRun(pass)
		results[analyzer] = output
		switch {
		case target.DepOnly:
		case err != nil:
			result.reports[analyzer.Name] = struct {
				Error string `json:"error"`
			}{fmt.Sprintf("%v", err)}
		case len(diagnostics) > 0:
			result.reports[analyzer.Name] = jsonDiagnostics(run.fset, diagnostics)
		}
	}
	for _, analyzer := range analyzers {
		analyze(analyzer)
	}
	result.published = store.publish()
	if built, ok := results[buildssa.Analyzer].(*buildssa.SSA); ok && built != nil {
		run.release(built.Pkg.Prog)
	}
	return result, nil
}

// A checkedUnit is a unit parsed and type-checked against its imports.
type checkedUnit struct {
	files      []*ast.File
	pkg        *types.Package
	info       *types.Info
	config     *types.Config
	typeErrors []types.Error
	module     *analysis.Module
}

// checkUnit parses the unit's files and type-checks them.
func (run *session) checkUnit(target *unit) (checkedUnit, error) {
	if target.Error != nil {
		return checkedUnit{}, errors.New(target.Error.Err)
	}
	var files []*ast.File
	for _, name := range target.CompiledGoFiles {
		if !filepath.IsAbs(name) {
			name = filepath.Join(target.Dir, name)
		}
		file, err := parser.ParseFile(run.fset, name, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			run.forgetFiles(files)
			return checkedUnit{}, err
		}
		files = append(files, file)
	}
	info := &types.Info{
		Types:        map[ast.Expr]types.TypeAndValue{},
		Defs:         map[*ast.Ident]types.Object{},
		Uses:         map[*ast.Ident]types.Object{},
		Implicits:    map[ast.Node]types.Object{},
		Instances:    map[*ast.Ident]types.Instance{},
		Scopes:       map[ast.Node]*types.Scope{},
		Selections:   map[*ast.SelectorExpr]*types.Selection{},
		FileVersions: map[*ast.File]string{},
	}
	var typeErrors []types.Error
	config := &types.Config{
		Importer: run.importer.forUnit(target),
		Sizes:    types.SizesFor("gc", runtime.GOARCH),
		Error: func(err error) {
			if typed, ok := errors.AsType[types.Error](err); ok {
				typeErrors = append(typeErrors, typed)
			}
		},
	}
	var analysisModule *analysis.Module
	if target.Module != nil {
		if target.Module.GoVersion != "" {
			config.GoVersion = "go" + target.Module.GoVersion
		}
		analysisModule = &analysis.Module{Path: target.Module.Path, Version: target.Module.Version, GoVersion: target.Module.GoVersion}
	}
	pkg, err := config.Check(target.path(), run.fset, files, info)
	if err != nil {
		run.forgetFiles(files)
		return checkedUnit{}, err
	}
	return checkedUnit{files: files, pkg: pkg, info: info, config: config, typeErrors: typeErrors, module: analysisModule}, nil
}

// forgetFiles drops the unit's files from the shared file set once nothing
// will ask for their positions again.
func (run *session) forgetFiles(files []*ast.File) {
	for _, file := range files {
		if handle := run.fset.File(file.Pos()); handle != nil {
			run.fset.RemoveFile(handle)
		}
	}
}

type jsonDiagnostic struct {
	Category string        `json:"category,omitempty"`
	Posn     string        `json:"posn"`
	End      string        `json:"end"`
	Message  string        `json:"message"`
	Related  []jsonRelated `json:"related,omitempty"`
}

type jsonRelated struct {
	Posn    string `json:"posn"`
	End     string `json:"end"`
	Message string `json:"message"`
}

// jsonDiagnostics renders diagnostics as go vet's tool writes them with
// -json. gohawk suggests no fixes.
func jsonDiagnostics(fset *token.FileSet, diagnostics []analysis.Diagnostic) []jsonDiagnostic {
	rendered := make([]jsonDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		var related []jsonRelated
		for _, information := range diagnostic.Related {
			related = append(related, jsonRelated{
				Posn:    fset.Position(information.Pos).String(),
				End:     fset.Position(cmp.Or(information.End, information.Pos)).String(),
				Message: information.Message,
			})
		}
		rendered = append(rendered, jsonDiagnostic{
			Category: diagnostic.Category, Posn: fset.Position(diagnostic.Pos).String(),
			End: fset.Position(cmp.Or(diagnostic.End, diagnostic.Pos)).String(), Message: diagnostic.Message, Related: related,
		})
	}
	return rendered
}
