package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// A unit is one package as go vet would hand it to its tool: a package, a
// test variant of one, or a dependency of either, with the export data the
// compiler wrote for it. go list names a test variant by its import path and
// the test it belongs to, "p [p.test]"; that name is the unit's ID, and its
// path is the import path alone.
type unit struct {
	ImportPath      string            `json:"ImportPath"`
	Dir             string            `json:"Dir"`
	Export          string            `json:"Export"`
	Name            string            `json:"Name"`
	ForTest         string            `json:"ForTest"`
	CompiledGoFiles []string          `json:"CompiledGoFiles"`
	Imports         []string          `json:"Imports"`
	ImportMap       map[string]string `json:"ImportMap"`
	DepOnly         bool              `json:"DepOnly"`
	Module          *module           `json:"Module"`
	Error           *listError        `json:"Error"`
}

type module struct {
	Path      string `json:"Path"`
	Version   string `json:"Version"`
	GoVersion string `json:"GoVersion"`
}

type listError struct {
	Err string `json:"Err"`
}

// id is the name go list gives the unit, unique among units.
func (u *unit) id() string { return u.ImportPath }

// path is the unit's import path without go list's test-variant suffix.
func (u *unit) path() string {
	path, _, _ := strings.Cut(u.ImportPath, " ")
	return path
}

// analyzed reports whether go vet would analyze the unit: every package with
// Go files except unsafe and the generated main package of a test binary.
func (u *unit) analyzed() bool {
	return u.Name != "" && u.path() != "unsafe" && len(u.CompiledGoFiles) > 0 && !strings.HasSuffix(u.path(), ".test")
}

// importID returns the unit ID an import path names within the unit.
func (u *unit) importID(path string) string {
	if mapped, ok := u.ImportMap[path]; ok {
		return mapped
	}
	return path
}

const listFields = "ImportPath,Dir,Export,Name,ForTest,CompiledGoFiles,Imports,ImportMap,DepOnly,Module,Error"

// listUnits asks go list for the units of the patterns and their
// dependencies, in dependency order, with test variants and export data.
// Building export data compiles the packages, as go vet does before it
// runs its tool.
func listUnits(ctx context.Context, dir string, buildFlags, patterns []string) ([]*unit, error) {
	arguments := append([]string{"list", "-deps", "-test", "-export", "-compiled", "-e", "-json=" + listFields}, buildFlags...)
	arguments = append(arguments, "--")
	arguments = append(arguments, patterns...)
	command := exec.CommandContext(ctx, "go", arguments...) //nolint:gosec // The build flags and patterns are the user's request.
	command.Dir = dir
	var stderr bytes.Buffer
	command.Stderr = &stderr
	// A package that does not compile still lists, with its error; go list
	// then exits with a failure, but every other package can be analyzed.
	output, err := command.Output()
	if err != nil && len(bytes.TrimSpace(output)) == 0 {
		return nil, fmt.Errorf("go list: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var units []*unit
	decoder := json.NewDecoder(bytes.NewReader(output))
	for decoder.More() {
		listed := new(unit)
		if err := decoder.Decode(listed); err != nil {
			return nil, fmt.Errorf("go list output: %w", err)
		}
		units = append(units, listed)
	}
	return units, nil
}
