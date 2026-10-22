// Package vetunit describes the single go vet unit a vet-tool process analyzes.
//
// go vet invokes gohawk once per package with a .cfg file naming the unit. A
// dependency is analyzed only for the facts its importers need: unitchecker
// discards its diagnostics but still runs every analyzer that requires a fact
// producer, which is every gohawk analyzer. SkipDiagnosticsOnly removes that
// work without changing any fact or reported diagnostic.
package vetunit

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// Config is the part of unitchecker's .cfg file that identifies the unit.
type Config struct {
	ID         string `json:"ID"`
	ImportPath string `json:"ImportPath"`
	// VetxOnly reports that the unit runs only to compute facts for
	// importers; its diagnostics are discarded.
	VetxOnly bool `json:"VetxOnly"`
	// PackageVetx maps each import path to the fact file go vet wrote for it.
	PackageVetx map[string]string `json:"PackageVetx"`
}

// ConfigPath returns the .cfg file that ends a vet-tool unit invocation, or
// "" for a handshake such as -flags or -V=full.
func ConfigPath(arguments []string) string {
	if len(arguments) == 0 || !strings.HasSuffix(arguments[len(arguments)-1], ".cfg") {
		return ""
	}
	return arguments[len(arguments)-1]
}

// ReadConfig reads the unit configuration at path.
func ReadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // go vet names the unit's config file.
	if err != nil {
		return Config{}, fmt.Errorf("read vet unit config: %w", err)
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, fmt.Errorf("decode vet unit config %s: %w", path, err)
	}
	return config, nil
}

// SkipDiagnosticsOnly makes every analyzer that neither exports facts nor is
// required by an analyzer that does return its zero result without running.
// Call it only for a facts-only unit. Those analyzers can affect nothing but
// diagnostics, which unitchecker discards for such a unit, so skipping them
// leaves the exported facts unchanged.
//
// Run is replaced on the shared analyzer values: passes look up prerequisite
// results by the original analyzer pointers, and a vet-tool process analyzes
// exactly one unit.
func SkipDiagnosticsOnly(roots []*analysis.Analyzer) {
	needed := make(map[*analysis.Analyzer]bool)
	all := make(map[*analysis.Analyzer]bool)
	var visit func(*analysis.Analyzer)
	visit = func(analyzer *analysis.Analyzer) {
		if all[analyzer] {
			return
		}
		all[analyzer] = true
		for _, required := range analyzer.Requires {
			visit(required)
		}
		if len(analyzer.FactTypes) > 0 {
			markNeeded(analyzer, needed)
		}
	}
	for _, root := range roots {
		visit(root)
	}
	for analyzer := range all {
		if needed[analyzer] {
			continue
		}
		var zero any
		if analyzer.ResultType != nil {
			zero = reflect.Zero(analyzer.ResultType).Interface()
		}
		analyzer.Run = func(*analysis.Pass) (any, error) { return zero, nil }
	}
}

func markNeeded(analyzer *analysis.Analyzer, needed map[*analysis.Analyzer]bool) {
	if needed[analyzer] {
		return
	}
	needed[analyzer] = true
	for _, required := range analyzer.Requires {
		markNeeded(required, needed)
	}
}
