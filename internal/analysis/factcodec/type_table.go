package factcodec

import (
	"go/types"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/kojah/gohawk/internal/analysis/factscope"
	"golang.org/x/tools/go/analysis"
)

// A method can be reached through the API of a package that does not import
// the method's own, and x/tools carries a type's facts to every importer
// down the build, reachable or not. A TypeTable publishes a package's method
// groups instead as one package fact, keyed by type, which x/tools gives to
// direct importers only. A package also carries, in its table, the groups
// its direct imports carried for foreign types its own API reaches, as
// factscope decides, copying their encodings without decoding them; an
// importer finds a method's group in the table of whichever direct import
// let it name the type.

// TypeTable maps a type's key to the group of its methods' summaries.
type TypeTable[T any] = Group[Group[T]]

// ImportTable returns the table a package published, if any.
type ImportTable[T any] func(*types.Package) (TypeTable[T], bool)

// typeKey names a declared type across packages.
func typeKey(name *types.TypeName) string {
	return name.Pkg().Path() + " " + name.Name()
}

// NewTypeTable encodes pkg's own method groups and carries its direct
// imports' groups for the foreign types pkg reaches. An empty table is
// left unpublished.
func NewTypeTable[T any](pkg *types.Package, own map[*types.TypeName]map[string]T, imported ImportTable[T]) (TypeTable[T], error) {
	table := map[string]cbor.RawMessage{}
	for receiver, entries := range own {
		group, err := NewGroup(entries)
		if err != nil {
			return TypeTable[T]{}, err
		}
		encoded, err := MarshalPart(&group)
		if err != nil {
			return TypeTable[T]{}, err
		}
		table[typeKey(receiver)] = encoded
	}
	carryImportedTypes(pkg, table, imported)
	return NewRawGroup[Group[T]](table), nil
}

func carryImportedTypes[T any](pkg *types.Package, table map[string]cbor.RawMessage, imported ImportTable[T]) {
	reached := map[string]bool{}
	for name := range factscope.Types(pkg) {
		if name.Pkg() != nil && name.Pkg() != pkg {
			reached[typeKey(name)] = true
		}
	}
	if len(reached) == 0 {
		return
	}
	for _, dependency := range pkg.Imports() {
		carried, ok := imported(dependency)
		if !ok {
			continue
		}
		for _, key := range carried.Names {
			if _, have := table[key]; have || !reached[key] {
				continue
			}
			if encoded, ok := carried.Raw(key); ok {
				table[key] = encoded
			}
		}
	}
}

// LookupMethod returns a method's summary from the table of the direct
// import of pkg that carried its type.
func LookupMethod[T any](pkg *types.Package, method *types.Func, imported ImportTable[T]) (T, bool) {
	var zero T
	receiver := factscope.Receiver(method)
	if receiver == nil || receiver.Pkg() == nil {
		return zero, false
	}
	key := typeKey(receiver)
	for _, dependency := range pkg.Imports() {
		table, ok := imported(dependency)
		if !ok {
			continue
		}
		if group, ok := table.Lookup(key); ok {
			return group.Lookup(method.Name())
		}
	}
	return zero, false
}

// TableMembers expands a table into its methods' summaries, for a dump: those
// of types pkg can name. wrap makes an entry the fact its method's own
// would have been.
func TableMembers[T any](table *TypeTable[T], pkg *types.Package, wrap func(T) analysis.Fact) []analysis.ObjectFact {
	packages := map[string]*types.Package{pkg.Path(): pkg}
	for _, imported := range pkg.Imports() {
		packages[imported.Path()] = imported
	}
	var members []analysis.ObjectFact
	for _, key := range table.Names {
		path, name, _ := strings.Cut(key, " ")
		owner, ok := packages[path]
		if !ok {
			continue
		}
		typeName, ok := owner.Scope().Lookup(name).(*types.TypeName)
		group, found := table.Lookup(key)
		if !ok || !found {
			continue
		}
		members = append(members, group.Members(typeName, nil, wrap)...)
	}
	return members
}
