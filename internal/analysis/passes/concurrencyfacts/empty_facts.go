package concurrencyfacts

import (
	"go/types"
	"slices"

	"github.com/kojah/gohawk/internal/analysis/factcodec"
	"golang.org/x/tools/go/analysis"
)

// Nearly every exported function's summary is empty: it performs no ordered
// operation, starts no worker and needs no cancellation input. An empty fact
// still says something, that the function was summarized and does nothing
// concurrent, so it cannot simply be left out; but one fact per function was
// most of what every importer down the build decoded. Empty summaries are
// published as lists instead: a package's functions in one package fact, and
// a type's methods in one fact on the type. A function is listed exactly when
// it would have had an empty fact, so an importer reads a listed function as
// that fact and an unlisted one, without a fact of its own, as unknown.
//
// The lists sit where the facts they replace could be found. A static call to
// a package-level function needs a direct import of its package, and package
// facts come from direct imports. A method can be reached through the API of
// a package that does not import the method's own, and x/tools carries a
// type's facts wherever it carries its methods'.

// EmptySummaries names the functions or methods whose summary is empty.
type EmptySummaries struct {
	_       struct{} `cbor:",toarray"` // published as a CBOR array; see factcodec
	Version int
	Names   []string
}

// publishedEmpty hides the list's schema from gob, as publishedFact does.
type publishedEmpty struct{ emptyPublication }

type emptyPublication = factcodec.Envelope[EmptySummaries]

// emptyFact reports whether a fact says only that its function does nothing.
func emptyFact(fact Fact) bool {
	return len(fact.Effects) == 0 && len(fact.Workers) == 0 && len(fact.CancellationInputs) == 0 && len(fact.Alternatives) == 0
}

// emptyCollector gathers a package's empty summaries for publication.
type emptyCollector struct {
	functions []string
	methods   map[*types.TypeName][]string
}

// add records an empty summary, and reports false when it has no list to go
// in, so its own fact must be published.
func (collector *emptyCollector) add(object *types.Func) bool {
	signature, ok := object.Type().(*types.Signature)
	if !ok {
		return false
	}
	if signature.Recv() == nil {
		collector.functions = append(collector.functions, object.Name())
		return true
	}
	receiver := receiverTypeName(signature.Recv().Type())
	if receiver == nil {
		return false
	}
	if collector.methods == nil {
		collector.methods = map[*types.TypeName][]string{}
	}
	collector.methods[receiver] = append(collector.methods[receiver], object.Name())
	return true
}

func (collector *emptyCollector) publish(pass *analysis.Pass) {
	if len(collector.functions) != 0 {
		slices.Sort(collector.functions)
		pass.ExportPackageFact(&publishedEmpty{factcodec.Wrap(EmptySummaries{Version: factVersion, Names: collector.functions})})
	}
	for receiver, names := range collector.methods {
		slices.Sort(names)
		pass.ExportObjectFact(receiver, &publishedEmpty{factcodec.Wrap(EmptySummaries{Version: factVersion, Names: names})})
	}
}

// receiverTypeName returns the declared type a method's receiver names.
func receiverTypeName(receiver types.Type) *types.TypeName {
	if pointer, ok := receiver.(*types.Pointer); ok {
		receiver = pointer.Elem()
	}
	named, ok := receiver.(*types.Named)
	if !ok {
		return nil
	}
	return named.Origin().Obj()
}

// emptyLists are the imported lists of empty summaries.
type emptyLists struct {
	packages map[*types.Package]*publishedEmpty
	types    map[*types.TypeName]*publishedEmpty
}

func importEmptyLists(pass *analysis.Pass) emptyLists {
	lists := emptyLists{packages: map[*types.Package]*publishedEmpty{}, types: map[*types.TypeName]*publishedEmpty{}}
	for _, imported := range pass.AllPackageFacts() {
		if published, ok := imported.Fact.(*publishedEmpty); ok {
			lists.packages[imported.Package] = published
		}
	}
	for _, imported := range pass.AllObjectFacts() {
		object, ok := imported.Object.(*types.TypeName)
		if published, valid := imported.Fact.(*publishedEmpty); ok && valid {
			lists.types[object] = published
		}
	}
	return lists
}

// listed reports whether object's summary was published as empty.
func (lists emptyLists) listed(object *types.Func) bool {
	signature, ok := object.Type().(*types.Signature)
	if !ok {
		return false
	}
	var published *publishedEmpty
	if signature.Recv() == nil {
		published = lists.packages[object.Pkg()]
	} else if receiver := receiverTypeName(signature.Recv().Type()); receiver != nil {
		published = lists.types[receiver]
	}
	if published == nil {
		return false
	}
	summaries, err := published.Value()
	if err != nil || summaries.Version != factVersion {
		return false
	}
	_, found := slices.BinarySearch(summaries.Names, object.Name())
	return found
}
