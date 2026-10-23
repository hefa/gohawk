package lifecyclefacts

import (
	"go/types"

	"github.com/kojah/gohawk/internal/analysis/factcodec"
	"github.com/kojah/gohawk/internal/analysis/factscope"
	"golang.org/x/tools/go/analysis"
)

// Methods and functions are most of a package's lifecycle facts, so they are
// published in groups (see factcodec.Group), all as package facts: a
// package's functions in one, and its types' method groups in a
// factcodec.TypeTable. x/tools never carries a package fact beyond the
// package's direct importers, and only a direct importer can call a
// package-level function.

// publishedFunctions and publishedTypes hide the groups' schema from gob, as
// publishedFact does.
type publishedFunctions struct {
	publication[factcodec.Group[Fact]]
}

type publishedTypes struct {
	publication[factcodec.Group[factcodec.Group[Fact]]]
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
	table, err := factcodec.NewTypeTable(pass.Pkg, groups.methods, importTable(pass))
	if err != nil {
		return err
	}
	if len(table.Names) != 0 {
		pass.ExportPackageFact(&publishedTypes{factcodec.Wrap(table)})
	}
	return nil
}

// importTable reads the type tables of pass's imports.
func importTable(pass *analysis.Pass) factcodec.ImportTable[Fact] {
	return func(pkg *types.Package) (factcodec.TypeTable[Fact], bool) {
		var published publishedTypes
		if pass.ImportPackageFact == nil || !pass.ImportPackageFact(pkg, &published) {
			return factcodec.TypeTable[Fact]{}, false
		}
		table, err := published.Value()
		return table, err == nil
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
	return factcodec.LookupMethod(pass.Pkg, object, importTable(pass))
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
	return factcodec.TableMembers(&table, pkg, func(fact Fact) analysis.Fact { return publish(fact) })
}
