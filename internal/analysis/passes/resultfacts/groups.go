package resultfacts

import (
	"go/types"

	"github.com/kojah/gohawk/internal/analysis/factcodec"
	"github.com/kojah/gohawk/internal/analysis/factscope"
	"golang.org/x/tools/go/analysis"
)

// Result facts are published in groups, as lifecycle facts are (see
// factcodec.Group): a type's methods as one fact on the type, a package's
// functions as one package fact. Each reaches exactly the importers the
// functions' own facts did.

type publishedMethods struct {
	groupPublication
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

func (groups *factGroups) publish(pass *analysis.Pass) error {
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

// importedGroups are the groups a pass imported, found by type and package.
type importedGroups struct {
	methods   map[*types.TypeName]*publishedMethods
	functions map[*types.Package]*publishedFunctions
}

func importGroups(pass *analysis.Pass) importedGroups {
	groups := importedGroups{methods: map[*types.TypeName]*publishedMethods{}, functions: map[*types.Package]*publishedFunctions{}}
	for _, imported := range pass.AllObjectFacts() {
		object, ok := imported.Object.(*types.TypeName)
		if published, valid := imported.Fact.(*publishedMethods); ok && valid {
			groups.methods[object] = published
		}
	}
	for _, imported := range pass.AllPackageFacts() {
		if published, ok := imported.Fact.(*publishedFunctions); ok {
			groups.functions[imported.Package] = published
		}
	}
	return groups
}

// lookup returns object's fact from its group.
func (groups importedGroups) lookup(object *types.Func) (Fact, bool) {
	var envelope *groupPublication
	if receiver := factscope.Receiver(object); receiver != nil {
		if published, ok := groups.methods[receiver]; ok {
			envelope = &published.groupPublication
		}
	} else if published, ok := groups.functions[object.Pkg()]; ok {
		envelope = &published.groupPublication
	}
	if envelope == nil {
		return Fact{}, false
	}
	group, err := envelope.Value()
	if err != nil {
		return Fact{}, false
	}
	return group.Lookup(object.Name())
}

// Members expands the group into its methods' facts, for a dump.
func (fact *publishedMethods) Members(owner types.Object) []analysis.ObjectFact {
	return groupMembers(&fact.groupPublication, owner, nil)
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
