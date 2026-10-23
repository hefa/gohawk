package resultfacts

import (
	"go/types"

	"github.com/kojah/gohawk/internal/analysis/factcodec"
	"github.com/kojah/gohawk/internal/analysis/factscope"
	"golang.org/x/tools/go/analysis"
)

// Result facts are published in groups, as lifecycle facts are (see
// factcodec.Group), all as package facts: a package's functions in one, and
// its types' method groups in a factcodec.TypeTable, which carries a method's
// group to every importer that can reach the type.

type publishedTypes struct {
	factcodec.Envelope[factcodec.TypeTable[Fact]]
}

type publishedFunctions struct {
	groupPublication
}

type groupPublication = factcodec.Envelope[factcodec.Group[Fact]]

// factGroups gathers a package's facts for publication.
type factGroups struct {
	methods   map[*types.TypeName]map[string]Fact
	functions map[string]Fact
}

// add records a fact, and reports false for a method of an undeclared type,
// whose fact is published on its own.
func (groups *factGroups) add(object *types.Func, fact Fact) bool {
	if receiver := factscope.Receiver(object); receiver != nil {
		if groups.methods == nil {
			groups.methods = map[*types.TypeName]map[string]Fact{}
		}
		if groups.methods[receiver] == nil {
			groups.methods[receiver] = map[string]Fact{}
		}
		groups.methods[receiver][object.Name()] = fact
		return true
	}
	if signature, ok := object.Type().(*types.Signature); !ok || signature.Recv() != nil {
		return false
	}
	if groups.functions == nil {
		groups.functions = map[string]Fact{}
	}
	groups.functions[object.Name()] = fact
	return true
}

func (groups *factGroups) publish(pass *analysis.Pass, imported importedGroups) error {
	table, err := factcodec.NewTypeTable(pass.Pkg, groups.methods, imported.table)
	if err != nil {
		return err
	}
	if len(table.Names) != 0 {
		pass.ExportPackageFact(&publishedTypes{factcodec.Wrap(table)})
	}
	if len(groups.functions) != 0 {
		group, err := factcodec.NewGroup(groups.functions)
		if err != nil {
			return err
		}
		pass.ExportPackageFact(&publishedFunctions{factcodec.Wrap(group)})
	}
	return nil
}

// importedGroups are the groups a pass's direct imports published.
type importedGroups struct {
	pkg       *types.Package
	types     map[*types.Package]*publishedTypes
	functions map[*types.Package]*publishedFunctions
}

func importGroups(pass *analysis.Pass) importedGroups {
	groups := importedGroups{pkg: pass.Pkg, types: map[*types.Package]*publishedTypes{}, functions: map[*types.Package]*publishedFunctions{}}
	for _, imported := range pass.AllPackageFacts() {
		switch published := imported.Fact.(type) {
		case *publishedTypes:
			groups.types[imported.Package] = published
		case *publishedFunctions:
			groups.functions[imported.Package] = published
		}
	}
	return groups
}

func (groups importedGroups) table(pkg *types.Package) (factcodec.TypeTable[Fact], bool) {
	published, ok := groups.types[pkg]
	if !ok {
		return factcodec.TypeTable[Fact]{}, false
	}
	table, err := published.Value()
	return table, err == nil
}

// lookup returns object's fact from its group.
func (groups importedGroups) lookup(object *types.Func) (Fact, bool) {
	if factscope.Receiver(object) != nil {
		if groups.pkg == nil {
			return Fact{}, false
		}
		return factcodec.LookupMethod(groups.pkg, object, groups.table)
	}
	published, ok := groups.functions[object.Pkg()]
	if !ok {
		return Fact{}, false
	}
	group, err := published.Value()
	if err != nil {
		return Fact{}, false
	}
	return group.Lookup(object.Name())
}

// PackageMembers expands the table into its methods' facts, for a dump.
func (fact *publishedTypes) PackageMembers(pkg *types.Package) []analysis.ObjectFact {
	table, err := fact.Value()
	if err != nil {
		return nil
	}
	return factcodec.TableMembers(&table, pkg, func(fact Fact) analysis.Fact { return wrapFact(fact) })
}

// PackageMembers expands the group into its functions' facts, for a dump.
func (fact *publishedFunctions) PackageMembers(pkg *types.Package) []analysis.ObjectFact {
	return groupMembers(&fact.groupPublication, nil, pkg)
}

func groupMembers(envelope *groupPublication, owner types.Object, pkg *types.Package) []analysis.ObjectFact {
	group, err := envelope.Value()
	if err != nil {
		return nil
	}
	return group.Members(owner, pkg, func(fact Fact) analysis.Fact { return wrapFact(fact) })
}

func wrapFact(fact Fact) *publishedFact { return &publishedFact{factcodec.Wrap(fact)} }
