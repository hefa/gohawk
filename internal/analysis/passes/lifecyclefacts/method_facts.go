package lifecyclefacts

import (
	"errors"
	"go/types"
	"maps"
	"slices"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/kojah/gohawk/internal/analysis/factcodec"
	"golang.org/x/tools/go/analysis"
)

// A type's methods are most of a package's lifecycle facts, and x/tools
// carries every one of them, each with its package and object paths, to every
// importer down the build. The methods of one type are published together
// instead, as one fact on the type: x/tools carries a type's facts wherever it
// carries its methods', so the summaries are found wherever they were before.
// Each method's summary keeps its own encoding and is decoded only when that
// method is asked about, once, as an object fact of its own was.
//
// A package's functions are published together too, as one package fact.
// x/tools never carries a fact about a package-level function beyond the
// package's direct importers, and only a direct importer can call one, so
// the package fact reaches exactly the importers the functions' facts did.

// SummaryGroup is a type's method summaries, or a package's function
// summaries, sorted by name.
type SummaryGroup struct {
	_       struct{} `cbor:",toarray"` // published as a CBOR array; see factcodec
	Names   []string
	Summary []cbor.RawMessage
	// decoded holds each summary once decoded; copies of a value share it.
	decoded *methodDecodes
}

type methodDecodes struct {
	once  []sync.Once
	facts []Fact
	ok    []bool
}

// UnmarshalCBOR decodes the list and prepares its per-method decodes.
func (methods *SummaryGroup) UnmarshalCBOR(data []byte) error {
	type plain SummaryGroup
	var decoded plain
	if err := factcodec.UnmarshalPart(data, &decoded); err != nil {
		return err
	}
	if len(decoded.Names) != len(decoded.Summary) || !slices.IsSorted(decoded.Names) {
		return errSummaryGroup
	}
	*methods = SummaryGroup(decoded)
	methods.decoded = newMethodDecodes(len(methods.Names))
	return nil
}

func newMethodDecodes(count int) *methodDecodes {
	return &methodDecodes{once: make([]sync.Once, count), facts: make([]Fact, count), ok: make([]bool, count)}
}

var errSummaryGroup = errors.New("grouped summaries are not one sorted summary per name")

// publishedMethods and publishedFunctions hide the group's schema from gob,
// as publishedFact does: one is a type's fact, the other a package's.
type publishedMethods struct {
	publication[SummaryGroup]
}

type publishedFunctions struct {
	publication[SummaryGroup]
}

// fact returns the named method's summary.
func (methods *SummaryGroup) fact(name string) (Fact, bool) {
	index, found := slices.BinarySearch(methods.Names, name)
	if !found || methods.decoded == nil {
		return Fact{}, false
	}
	decodes := methods.decoded
	decodes.once[index].Do(func() {
		var fact Fact
		if err := factcodec.UnmarshalPart(methods.Summary[index], &fact); err == nil {
			decodes.facts[index], decodes.ok[index] = fact, true
		}
	})
	return decodes.facts[index], decodes.ok[index]
}

// summaryGroups gathers a package's summaries: methods by receiver type,
// package-level functions together.
type summaryGroups struct {
	methods   map[*types.TypeName]map[string]Fact
	functions map[string]Fact
}

// add records a summary, and reports false for a method of a type that is not
// declared, whose fact is published on its own.
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
	receiver := methodReceiver(object)
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
		methods, err := encodeMethods(facts)
		if err != nil {
			return err
		}
		pass.ExportObjectFact(receiver, &publishedMethods{factcodec.Wrap(methods)})
	}
	if len(groups.functions) != 0 {
		functions, err := encodeMethods(groups.functions)
		if err != nil {
			return err
		}
		pass.ExportPackageFact(&publishedFunctions{factcodec.Wrap(functions)})
	}
	return nil
}

// encodeMethods lists grouped summaries for publication.
func encodeMethods(facts map[string]Fact) (SummaryGroup, error) {
	names := slices.Sorted(maps.Keys(facts))
	summaries := make([]cbor.RawMessage, len(names))
	for index, name := range names {
		fact := facts[name]
		encoded, err := factcodec.MarshalPart(&fact)
		if err != nil {
			return SummaryGroup{}, err
		}
		summaries[index] = encoded
	}
	// A driver that passes facts in memory hands importers this very value,
	// never decoding it, so it carries its own per-summary decodes.
	return SummaryGroup{Names: names, Summary: summaries, decoded: newMethodDecodes(len(names))}, nil
}

// methodReceiver returns the declared type a method belongs to.
func methodReceiver(object *types.Func) *types.TypeName {
	signature, ok := object.Type().(*types.Signature)
	if !ok || signature.Recv() == nil {
		return nil
	}
	receiver := signature.Recv().Type()
	if pointer, ok := receiver.(*types.Pointer); ok {
		receiver = pointer.Elem()
	}
	named, ok := receiver.(*types.Named)
	if !ok {
		return nil
	}
	return named.Origin().Obj()
}

// importedGroupFact returns a function's summary from its group: its type's
// for a method, its package's otherwise.
func importedGroupFact(pass *analysis.Pass, object *types.Func) (Fact, bool) {
	signature, ok := object.Type().(*types.Signature)
	if !ok {
		return Fact{}, false
	}
	var group SummaryGroup
	var err error
	if signature.Recv() == nil {
		var published publishedFunctions
		if object.Pkg() == nil || pass.ImportPackageFact == nil || !pass.ImportPackageFact(object.Pkg(), &published) {
			return Fact{}, false
		}
		group, err = published.Value()
	} else {
		receiver := methodReceiver(object)
		var published publishedMethods
		if receiver == nil || !pass.ImportObjectFact(receiver, &published) {
			return Fact{}, false
		}
		group, err = published.Value()
	}
	if err != nil {
		return Fact{}, false
	}
	return group.fact(object.Name())
}
