package lifecyclefacts

import (
	"go/types"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/kojah/gohawk/internal/analysis/factcodec"
	"github.com/kojah/gohawk/internal/analysis/factscope"
	"golang.org/x/tools/go/analysis"
)

// Methods and functions are most of a package's lifecycle facts, so they are
// published in groups (see factcodec.Group), all as package facts: a
// package's functions in one, and its types' method groups in a table keyed
// by type. x/tools never carries a package fact beyond the package's direct
// importers, and only a direct importer can call a package-level function.
//
// A method can be reached through the API of a package that does not import
// the method's own, so a package also carries, in its table, the method
// groups its direct imports carried for types its own API reaches; an
// importer finds a method's group in the table of whichever direct import
// let it name the type. x/tools carried a type's facts to every importer
// down the build, reachable or not; the table carries only those an
// importer can reach, as factscope decides, and copies their encodings
// without decoding them.

// publishedFunctions and publishedTypes hide the groups' schema from gob, as
// publishedFact does.
type publishedFunctions struct {
	publication[factcodec.Group[Fact]]
}

type publishedTypes struct {
	publication[factcodec.Group[factcodec.Group[Fact]]]
}

// typeKey names a declared type across packages.
func typeKey(name *types.TypeName) string {
	return name.Pkg().Path() + " " + name.Name()
}

// summaryGroups gathers a package's summaries: methods by receiver type,
// package-level functions together.
type summaryGroups struct {
	methods   map[*types.TypeName]map[string]Fact
	functions map[string]Fact
}

// add records a summary, and reports false for a method of an undeclared
// type, whose fact is published on its own.
func (groups *summaryGroups) add(object *types.Func, fact Fact) bool {
	signature, ok := object.Type().(*types.Signature)
	if !ok {
		return false
	}
	if signature.Recv() == nil {
		if groups.functions == nil {
			groups.functions = map[string]Fact{}
		}
		groups.functions[object.Name()] = fact
		return true
	}
	receiver := factscope.Receiver(object)
	if receiver == nil {
		return false
	}
	if groups.methods == nil {
		groups.methods = map[*types.TypeName]map[string]Fact{}
	}
	if groups.methods[receiver] == nil {
		groups.methods[receiver] = map[string]Fact{}
	}
	groups.methods[receiver][object.Name()] = fact
	return true
}

func (groups *summaryGroups) publish(pass *analysis.Pass) error {
	if len(groups.functions) != 0 {
		functions, err := factcodec.NewGroup(groups.functions)
		if err != nil {
			return err
		}
		pass.ExportPackageFact(&publishedFunctions{factcodec.Wrap(functions)})
	}
	table := map[string]cbor.RawMessage{}
	for receiver, facts := range groups.methods {
		group, err := factcodec.NewGroup(facts)
		if err != nil {
			return err
		}
		encoded, err := factcodec.MarshalPart(&group)
		if err != nil {
			return err
		}
		table[typeKey(receiver)] = encoded
	}
	carryImportedTypes(pass, table)
	if len(table) != 0 {
		pass.ExportPackageFact(&publishedTypes{factcodec.Wrap(factcodec.NewRawGroup[factcodec.Group[Fact]](table))})
	}
	return nil
}

// carryImportedTypes adds to table the method groups of imported types the
// package's API reaches.
func carryImportedTypes(pass *analysis.Pass, table map[string]cbor.RawMessage) {
	if pass.ImportPackageFact == nil {
		return
	}
	reached := map[string]bool{}
	for name := range factscope.Types(pass.Pkg) {
		if name.Pkg() != nil && name.Pkg() != pass.Pkg {
			reached[typeKey(name)] = true
		}
	}
	if len(reached) == 0 {
		return
	}
	for _, imported := range pass.Pkg.Imports() {
		var published publishedTypes
		if !pass.ImportPackageFact(imported, &published) {
			continue
		}
		types, err := published.Value()
		if err != nil {
			continue
		}
		for _, key := range types.Names {
			if _, have := table[key]; have || !reached[key] {
				continue
			}
			if encoded, ok := types.Raw(key); ok {
				table[key] = encoded
			}
		}
	}
}

// importedGroupFact returns a function's summary from its group: its
// package's for a package-level function, its type's otherwise, found in
// the table of a direct import that carried it.
func importedGroupFact(pass *analysis.Pass, object *types.Func) (Fact, bool) {
	signature, ok := object.Type().(*types.Signature)
	if !ok || pass.ImportPackageFact == nil {
		return Fact{}, false
	}
	if signature.Recv() == nil {
		var published publishedFunctions
		if object.Pkg() == nil || !pass.ImportPackageFact(object.Pkg(), &published) {
			return Fact{}, false
		}
		group, err := published.Value()
		if err != nil {
			return Fact{}, false
		}
		return group.Lookup(object.Name())
	}
	receiver := factscope.Receiver(object)
	if receiver == nil || receiver.Pkg() == nil {
		return Fact{}, false
	}
	key := typeKey(receiver)
	for _, imported := range pass.Pkg.Imports() {
		var published publishedTypes
		if !pass.ImportPackageFact(imported, &published) {
			continue
		}
		types, err := published.Value()
		if err != nil {
			continue
		}
		if group, ok := types.Lookup(key); ok {
			return group.Lookup(object.Name())
		}
	}
	return Fact{}, false
}

// PackageMembers expands the functions' group into their facts, for a dump.
func (fact *publishedFunctions) PackageMembers(pkg *types.Package) []analysis.ObjectFact {
	group, err := fact.Value()
	if err != nil {
		return nil
	}
	return group.Members(nil, pkg, func(fact Fact) analysis.Fact { return publish(fact) })
}

// PackageMembers expands the types' groups into their methods' facts, for a
// dump: those of types the dumping package's universe can name.
func (fact *publishedTypes) PackageMembers(pkg *types.Package) []analysis.ObjectFact {
	table, err := fact.Value()
	if err != nil {
		return nil
	}
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
		members = append(members, group.Members(typeName, nil, func(fact Fact) analysis.Fact { return publish(fact) })...)
	}
	return members
}
