package lifecyclefacts

import (
	"go/types"

	"github.com/kojah/gohawk/internal/analysis/factcodec"
	"github.com/kojah/gohawk/internal/analysis/factscope"
	"golang.org/x/tools/go/analysis"
)

// Methods and functions are most of a package's lifecycle facts, so they are
// published in groups (see factcodec.Group): a type's methods as one fact on
// the type, which x/tools carries wherever it carried the methods' facts, and
// a package's functions as one package fact. x/tools never carries a fact
// about a package-level function beyond the package's direct importers, and
// only a direct importer can call one, so the package fact reaches exactly
// the importers the functions' facts did.

// publishedMethods and publishedFunctions hide the group's schema from gob,
// as publishedFact does: one is a type's fact, the other a package's.
type publishedMethods struct {
	publication[factcodec.Group[Fact]]
}

type publishedFunctions struct {
	publication[factcodec.Group[Fact]]
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
	for receiver, facts := range groups.methods {
		group, err := factcodec.NewGroup(facts)
		if err != nil {
			return err
		}
		pass.ExportObjectFact(receiver, &publishedMethods{factcodec.Wrap(group)})
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

// importedGroupFact returns a function's summary from its group: its type's
// for a method, its package's otherwise.
func importedGroupFact(pass *analysis.Pass, object *types.Func) (Fact, bool) {
	signature, ok := object.Type().(*types.Signature)
	if !ok {
		return Fact{}, false
	}
	var group factcodec.Group[Fact]
	var err error
	if signature.Recv() == nil {
		var published publishedFunctions
		if object.Pkg() == nil || pass.ImportPackageFact == nil || !pass.ImportPackageFact(object.Pkg(), &published) {
			return Fact{}, false
		}
		group, err = published.Value()
	} else {
		receiver := factscope.Receiver(object)
		var published publishedMethods
		if receiver == nil || !pass.ImportObjectFact(receiver, &published) {
			return Fact{}, false
		}
		group, err = published.Value()
	}
	if err != nil {
		return Fact{}, false
	}
	return group.Lookup(object.Name())
}

// Members expands the group into its methods' facts, for a dump.
func (fact *publishedMethods) Members(owner types.Object) []analysis.ObjectFact {
	return groupMembers(&fact.publication, owner, nil)
}

// PackageMembers expands the group into its functions' facts, for a dump.
func (fact *publishedFunctions) PackageMembers(pkg *types.Package) []analysis.ObjectFact {
	return groupMembers(&fact.publication, nil, pkg)
}

func groupMembers(envelope *publication[factcodec.Group[Fact]], owner types.Object, pkg *types.Package) []analysis.ObjectFact {
	group, err := envelope.Value()
	if err != nil {
		return nil
	}
	return group.Members(owner, pkg, func(fact Fact) analysis.Fact { return publish(fact) })
}
