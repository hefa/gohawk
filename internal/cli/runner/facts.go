package runner

import (
	"go/types"
	"reflect"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/types/objectpath"
)

// Facts pass from unit to unit in memory, never encoded, but each unit sees
// exactly the facts go vet's tool would have decoded for it. x/tools writes
// a unit's own facts and, of those it imported, the facts about types,
// fields and methods, each named by its package path and object path; an
// importer reads the files of its direct imports and resolves each name in
// its own view of the packages, dropping what it cannot resolve. Fact
// values are shared between units: a published fact is immutable.

type factKey struct {
	pkg    *types.Package
	object types.Object
	kind   reflect.Type
}

// A factStore holds the facts one unit sees and publishes.
type factStore struct {
	pkg   *types.Package
	facts map[factKey]analysis.Fact
}

// publishedFact is a fact as a unit's importers find it.
type publishedFact struct {
	pkgPath string
	object  objectpath.Path
	fact    analysis.Fact
}

// newFactStore gathers the facts the unit's direct imports published,
// resolved in the unit's view of the packages.
func newFactStore(pkg *types.Package, published [][]publishedFact) *factStore {
	store := &factStore{pkg: pkg, facts: map[factKey]analysis.Fact{}}
	reachable := packagesReachable(pkg.Imports())
	for _, facts := range published {
		for _, entry := range facts {
			owner := reachable[entry.pkgPath]
			if owner == nil {
				continue
			}
			var object types.Object
			if entry.object != "" {
				resolved, err := objectpath.Object(owner, entry.object)
				if err != nil {
					continue
				}
				object = resolved
			}
			store.facts[factKey{owner, object, reflect.TypeOf(entry.fact)}] = entry.fact
		}
	}
	return store
}

// packagesReachable maps the path of every package the imports reach to it.
func packagesReachable(imports []*types.Package) map[string]*types.Package {
	all := map[string]*types.Package{}
	var add func([]*types.Package)
	add = func(packages []*types.Package) {
		for _, pkg := range packages {
			if all[pkg.Path()] == nil {
				all[pkg.Path()] = pkg
				add(pkg.Imports())
			}
		}
	}
	add(imports)
	return all
}

// bind gives the pass the store's fact functions, limited to the facts of
// the pass's analyzer as x/tools limits them.
func (store *factStore) bind(pass *analysis.Pass) {
	owns := func(fact analysis.Fact) bool {
		for _, kind := range pass.Analyzer.FactTypes {
			if reflect.TypeOf(kind) == reflect.TypeOf(fact) {
				return true
			}
		}
		return false
	}
	pass.ImportObjectFact = func(object types.Object, ptr analysis.Fact) bool {
		return store.load(factKey{object.Pkg(), object, reflect.TypeOf(ptr)}, ptr)
	}
	pass.ExportObjectFact = func(object types.Object, fact analysis.Fact) {
		store.facts[factKey{object.Pkg(), object, reflect.TypeOf(fact)}] = fact
	}
	pass.ImportPackageFact = func(pkg *types.Package, ptr analysis.Fact) bool {
		return store.load(factKey{pkg, nil, reflect.TypeOf(ptr)}, ptr)
	}
	pass.ExportPackageFact = func(fact analysis.Fact) {
		store.facts[factKey{store.pkg, nil, reflect.TypeOf(fact)}] = fact
	}
	pass.AllObjectFacts = func() []analysis.ObjectFact {
		var all []analysis.ObjectFact
		for key, fact := range store.facts {
			if key.object != nil && owns(fact) {
				all = append(all, analysis.ObjectFact{Object: key.object, Fact: fact})
			}
		}
		return all
	}
	pass.AllPackageFacts = func() []analysis.PackageFact {
		var all []analysis.PackageFact
		for key, fact := range store.facts {
			if key.object == nil && owns(fact) {
				all = append(all, analysis.PackageFact{Package: key.pkg, Fact: fact})
			}
		}
		return all
	}
}

// load copies the stored fact into ptr, as decoding it would.
func (store *factStore) load(key factKey, ptr analysis.Fact) bool {
	fact, ok := store.facts[key]
	if ok {
		reflect.ValueOf(ptr).Elem().Set(reflect.ValueOf(fact).Elem())
	}
	return ok
}

// publish returns what the unit's importers see: its own facts, and the
// imported facts about types, fields and methods its importers can name.
func (store *factStore) publish() []publishedFact {
	var encoder objectpath.Encoder
	var published []publishedFact
	for key, fact := range store.facts {
		if key.pkg != store.pkg {
			if key.object == nil {
				continue
			}
			if _, isType := key.object.(*types.TypeName); !isType && key.object.Parent() == key.object.Pkg().Scope() {
				continue
			}
		}
		var path objectpath.Path
		if key.object != nil {
			encoded, err := encoder.For(key.object)
			if err != nil {
				continue
			}
			path = encoded
		}
		published = append(published, publishedFact{pkgPath: key.pkg.Path(), object: path, fact: fact})
	}
	return published
}
