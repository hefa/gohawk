package runner

import (
	"fmt"
	"go/token"
	"go/types"
	"os"
	"sync"

	"golang.org/x/tools/go/gcexportdata"
)

// An importer hands each unit its imports as go vet's tool sees them: the
// packages the compiler's export data describes, not their sources. go vet
// decoded a dependency's export data again in every unit that imported it,
// which was most of what a unit allocated; here each package is decoded
// once and every importer shares it.
//
// A test variant shares its import path with the package it varies, so the
// variants of one test live in a world of their own. A world starts with the
// ordinary packages its variants depend on, shared with every other world;
// only the variants are decoded into it.
type importer struct {
	fset  *token.FileSet
	units map[string]*unit

	mu sync.Mutex
	// worlds maps a test, "" for none, to its packages by import path.
	worlds map[string]map[string]*types.Package
}

func newImporter(fset *token.FileSet, units map[string]*unit) *importer {
	return &importer{fset: fset, units: units, worlds: map[string]map[string]*types.Package{"": {}}}
}

// forUnit returns the importer the unit's type check uses.
func (imp *importer) forUnit(from *unit) types.Importer {
	return importerFunc(func(path string) (*types.Package, error) {
		if path == "unsafe" {
			return types.Unsafe, nil
		}
		imp.mu.Lock()
		defer imp.mu.Unlock()
		return imp.loadLocked(from.ForTest, from.importID(path))
	})
}

// load decodes the package the unit ID names into the world of a unit in
// world. An error is left for the importing unit's type check to report.
func (imp *importer) load(world, id string) {
	if dependency := imp.units[id]; dependency == nil || dependency.path() == "unsafe" {
		return
	}
	imp.mu.Lock()
	defer imp.mu.Unlock()
	_, _ = imp.loadLocked(world, id)
}

// loadLocked returns the package the unit ID names, decoding it into its
// world first if need be. gcexportdata reads into the world's map, which
// is not safe for concurrent use; the caller holds imp.mu.
func (imp *importer) loadLocked(world, id string) (*types.Package, error) {
	target := imp.units[id]
	if target == nil {
		return nil, fmt.Errorf("no package %s", id)
	}
	if target.ForTest == "" {
		world = ""
	}
	packages := imp.worlds[world]
	if packages == nil {
		packages = map[string]*types.Package{}
		imp.worlds[world] = packages
	}
	if pkg := packages[target.path()]; pkg != nil && pkg.Complete() {
		return pkg, nil
	}
	if world != "" {
		// A variant's export data names its dependencies by path; the
		// ordinary ones must already be the shared packages, and the
		// variant ones decoded into this world.
		if err := imp.seedLocked(world, target, map[string]bool{}); err != nil {
			return nil, err
		}
	}
	if target.Export == "" {
		return nil, fmt.Errorf("no export data for %s", id)
	}
	file, err := os.Open(target.Export)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	reader, err := gcexportdata.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("export data for %s: %w", id, err)
	}
	return gcexportdata.Read(reader, imp.fset, packages, target.path())
}

// seedLocked makes the transitive dependencies of target present in world:
// each ordinary one as the shared package, each variant decoded.
func (imp *importer) seedLocked(world string, target *unit, seen map[string]bool) error {
	packages := imp.worlds[world]
	for _, id := range target.Imports {
		if seen[id] {
			continue
		}
		seen[id] = true
		dependency := imp.units[id]
		if dependency == nil || dependency.path() == "unsafe" {
			continue
		}
		if dependency.ForTest != "" {
			if _, err := imp.loadLocked(world, id); err != nil {
				return err
			}
			continue
		}
		shared, err := imp.loadLocked("", id)
		if err != nil {
			return err
		}
		packages[dependency.path()] = shared
		if err := imp.seedLocked(world, dependency, seen); err != nil {
			return err
		}
	}
	return nil
}

// release forgets a test's world once every unit in it is done.
func (imp *importer) release(world string) {
	if world == "" {
		return
	}
	imp.mu.Lock()
	delete(imp.worlds, world)
	imp.mu.Unlock()
}

type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }
