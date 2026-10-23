package lifecyclefacts

import (
	"errors"
	"go/types"
	"slices"

	"github.com/kojah/gohawk/internal/analysis/factcodec"
	"github.com/kojah/gohawk/internal/engine/heapmodel"
	"github.com/kojah/gohawk/internal/engine/ssaflow"
	ssacall "github.com/kojah/gohawk/internal/engine/ssaflow/calls"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/ssa"
)

// Publication is separate from the semantic summary. An opaque envelope keeps
// gob from recursively describing the heap schema in every inherited-fact stream.
// Domain validation and the distinction between missing and empty stay here.
// The unexported alias also hides the envelope's own type descriptor from gob.
type publication[T any] = factcodec.Envelope[T]

type publishedFact struct {
	publication[Fact]
}

type publishedCleanup struct {
	publication[CleanupFact]
}

type publishedPackage struct {
	publication[SummarizedPackage]
}

func publish(fact Fact) *publishedFact { return &publishedFact{factcodec.Wrap(fact)} }

func (fact *publishedFact) DescribeFact(object types.Object) []string {
	value, err := fact.Value()
	if err != nil {
		return []string{"undecodable fact: " + err.Error()}
	}
	return value.DescribeFact(object)
}

// DescribeHeap renders the published summary's heap projection for the dump.
func (fact *publishedFact) DescribeHeap(object types.Object) []string {
	value, err := fact.Value()
	if err != nil {
		return []string{"undecodable fact: " + err.Error()}
	}
	return value.DescribeHeap(object)
}

func (fact *publishedCleanup) DescribeFact(object types.Object) []string {
	value, err := fact.Value()
	if err != nil {
		return []string{"undecodable fact: " + err.Error()}
	}
	return value.DescribeFact(object)
}

// Imported lookup validates published lifecycle facts and attaches declaration
// signatures. A valid package marker distinguishes a known empty summary from
// an unavailable one; bodiless and incompatible declarations remain unknown.

// importFact imports the summary attached to a static callee.
func importFact(pass *analysis.Pass, instruction ssa.Instruction) (Fact, bool) {
	return factForFunction(pass, ssacall.ResolvedCallee(ssaflow.InstructionCall(instruction)))
}

// factForFunction returns the summary recorded for a function. It is the one
// place that reads an imported summary, so every proof asks the question the
// same way: a generic instantiation is answered by its origin, which is the
// object the summary was recorded against, and a function with no object,
// such as a literal, has no summary to find.
func factForFunction(pass *analysis.Pass, function *ssa.Function) (Fact, bool) {
	resolved := ssacall.ResolvedFunction(function)
	if pass == nil || resolved == nil {
		return Fact{}, false
	}
	object := resolved.Object()
	if object == nil {
		return Fact{}, false
	}
	var published publishedFact
	if pass.ImportObjectFact(object, &published) {
		fact, err := published.Value()
		if err != nil {
			return Fact{}, false
		}
		// An older heap fact may describe a returned field address as the
		// field's contents. None of its derived claims are safe to import
		// under the newer edge semantics.
		if fact.Heap != nil && fact.Heap.Version != heapmodel.SummaryVersion {
			return Fact{}, false
		}
		fact.signature = resolved.Signature
		return fact, true
	}
	// No summary of its own: proven to do nothing if its package was
	// summarized and the function was in scope for summarizing, which is
	// the same condition the pass applies before summarizing.
	var marker publishedPackage
	if object.Pkg() == nil || !object.Exported() || pass.ImportPackageFact == nil || !pass.ImportPackageFact(object.Pkg(), &marker) {
		return Fact{}, false
	}
	if signature, ok := object.Type().(*types.Signature); !ok || signature.Params().Len()+receiverCount(signature) > 64 {
		return Fact{}, false
	}
	summarized, err := marker.Value()
	if err != nil || slices.Contains(summarized.Bodiless, object.Name()) {
		return Fact{}, false
	}
	return Fact{}, true
}

func receiverCount(signature *types.Signature) int {
	if signature.Recv() != nil {
		return 1
	}
	return 0
}

// A lifecycle fact is published with its heap summary's strings in one table.
// Package paths, global names, access paths, origins and methods repeat
// across a summary's edges, effects and reads, and every importer of a
// package reads its facts again; strings were a third of the payload. Each
// string becomes an index, 0 for the empty string, and the table lists the
// others in the order the summary first uses them, so the encoding stays
// deterministic. A slot is flattened with its root. Decoding restores the
// summary exactly, nil and empty lists included.

func (fact *Fact) MarshalCBOR() ([]byte, error) {
	wire := wireFact{Must: fact.Must, May: fact.May, Discharges: fact.Discharges, ReturnedCleanup: fact.ReturnedCleanup}
	if fact.Heap != nil {
		wire.Heap = encodeHeap(fact.Heap)
	}
	return factcodec.MarshalPart(&wire)
}

func (fact *Fact) UnmarshalCBOR(data []byte) error {
	var wire wireFact
	if err := factcodec.UnmarshalPart(data, &wire); err != nil {
		return err
	}
	decoded := Fact{Must: wire.Must, May: wire.May, Discharges: wire.Discharges, ReturnedCleanup: wire.ReturnedCleanup}
	if wire.Heap != nil {
		heap, err := decodeHeap(wire.Heap)
		if err != nil {
			return err
		}
		decoded.Heap = heap
	}
	*fact = decoded
	return nil
}

type wireFact struct {
	_               struct{} `cbor:",toarray"`
	Must            MustClaims
	May             MayClaims
	Discharges      []Discharge
	Heap            *wireHeap
	ReturnedCleanup *ReturnedCleanupSummary
}

type wireHeap struct {
	_         struct{} `cbor:",toarray"`
	Version   int
	Strings   []string
	Edges     []wireEdge
	Effects   []wireEffect
	Holds     []heapmodel.HeapHold
	Reads     []wireSlot
	Requires  []wireRequirement
	Truncated []wireSlot
}

type wireSlot struct {
	_       struct{} `cbor:",toarray"`
	Kind    heapmodel.HeapRootKind
	Index   int
	Package int
	Name    int
	Path    int
}

type wireEdge struct {
	_      struct{} `cbor:",toarray"`
	From   wireSlot
	Kind   heapmodel.HeapTargetKind
	Slot   wireSlot
	Origin int
	Object int
	Must   bool
}

type wireEffect struct {
	_       struct{} `cbor:",toarray"`
	Slot    wireSlot
	Escape  heapmodel.HeapEscape
	Release int
	Every   bool
}

type wireRequirement struct {
	_      struct{} `cbor:",toarray"`
	Slot   wireSlot
	Kind   heapmodel.HeapRequirementKind
	Method int
}

// stringTable numbers strings in order of first use; 0 is the empty string.
type stringTable struct {
	index   map[string]int
	strings []string
}

func (table *stringTable) of(value string) int {
	if value == "" {
		return 0
	}
	if index, ok := table.index[value]; ok {
		return index
	}
	table.strings = append(table.strings, value)
	table.index[value] = len(table.strings)
	return len(table.strings)
}

func (table *stringTable) slot(at heapmodel.HeapSlot) wireSlot {
	return wireSlot{Kind: at.Root.Kind, Index: at.Root.Index, Package: table.of(at.Root.Package), Name: table.of(at.Root.Name), Path: table.of(at.Path)}
}

func encodeHeap(summary *heapmodel.HeapSummary) *wireHeap {
	table := &stringTable{index: map[string]int{}}
	wire := &wireHeap{Version: summary.Version, Holds: summary.Holds}
	wire.Edges = encodeList(summary.Edges, func(edge heapmodel.HeapEdge) wireEdge {
		return wireEdge{
			From: table.slot(edge.From), Kind: edge.To.Kind, Slot: table.slot(edge.To.Slot),
			Origin: table.of(edge.To.Origin), Object: edge.To.Object, Must: edge.Must,
		}
	})
	wire.Effects = encodeList(summary.Effects, func(effect heapmodel.HeapEffect) wireEffect {
		return wireEffect{Slot: table.slot(effect.Slot), Escape: effect.Escape, Release: table.of(effect.Release), Every: effect.Every}
	})
	wire.Reads = encodeList(summary.Reads, table.slot)
	wire.Requires = encodeList(summary.Requires, func(requirement heapmodel.HeapRequirement) wireRequirement {
		return wireRequirement{Slot: table.slot(requirement.Slot), Kind: requirement.Kind, Method: table.of(requirement.Method)}
	})
	wire.Truncated = encodeList(summary.Truncated, table.slot)
	wire.Strings = table.strings
	return wire
}

// encodeList converts each element, keeping a nil list nil.
func encodeList[From, To any](list []From, convert func(From) To) []To {
	if list == nil {
		return nil
	}
	converted := make([]To, len(list))
	for index, element := range list {
		converted[index] = convert(element)
	}
	return converted
}

var errStringIndex = errors.New("heap summary string index out of range")

func decodeHeap(wire *wireHeap) (*heapmodel.HeapSummary, error) {
	failed := false
	text := func(index int) string {
		switch {
		case index == 0:
			return ""
		case index < 0 || index > len(wire.Strings):
			failed = true
			return ""
		}
		return wire.Strings[index-1]
	}
	slot := func(at wireSlot) heapmodel.HeapSlot {
		return heapmodel.HeapSlot{Root: heapmodel.HeapRoot{Kind: at.Kind, Index: at.Index, Package: text(at.Package), Name: text(at.Name)}, Path: text(at.Path)}
	}
	summary := &heapmodel.HeapSummary{Version: wire.Version, Holds: wire.Holds}
	summary.Edges = encodeList(wire.Edges, func(edge wireEdge) heapmodel.HeapEdge {
		return heapmodel.HeapEdge{
			From: slot(edge.From), Must: edge.Must,
			To: heapmodel.HeapTarget{Kind: edge.Kind, Slot: slot(edge.Slot), Origin: text(edge.Origin), Object: edge.Object},
		}
	})
	summary.Effects = encodeList(wire.Effects, func(effect wireEffect) heapmodel.HeapEffect {
		return heapmodel.HeapEffect{Slot: slot(effect.Slot), Escape: effect.Escape, Release: text(effect.Release), Every: effect.Every}
	})
	summary.Reads = encodeList(wire.Reads, slot)
	summary.Requires = encodeList(wire.Requires, func(requirement wireRequirement) heapmodel.HeapRequirement {
		return heapmodel.HeapRequirement{Slot: slot(requirement.Slot), Kind: requirement.Kind, Method: text(requirement.Method)}
	})
	summary.Truncated = encodeList(wire.Truncated, slot)
	if failed {
		return nil, errStringIndex
	}
	return summary, nil
}
