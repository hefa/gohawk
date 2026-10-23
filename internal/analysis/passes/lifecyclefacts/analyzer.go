// Package lifecyclefacts resolves lifecycle evidence across source and package
// boundaries. It combines memoized local SSA proofs with conservative exported
// summaries, and keeps missing summaries distinct from disproved ownership.
package lifecyclefacts

import (
	"go/types"
	"maps"
	"reflect"
	"slices"

	"github.com/kojah/gohawk/internal/analysis/factcodec"
	"github.com/kojah/gohawk/internal/analysis/factscope"
	"github.com/kojah/gohawk/internal/engine/heapmodel"
	"github.com/kojah/gohawk/internal/engine/ssaflow"
	ssacall "github.com/kojah/gohawk/internal/engine/ssaflow/calls"
	analysisTrace "github.com/kojah/gohawk/internal/reporting/trace"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	ssa "golang.org/x/tools/go/ssa"
)

// Analyzer is an internal prerequisite shared by lifecycle analyzers.
var Analyzer = &analysis.Analyzer{
	Name:       "lifecyclefacts",
	Doc:        "exports internal lifecycle ownership summaries",
	Requires:   []*analysis.Analyzer{buildssa.Analyzer},
	FactTypes:  []analysis.Fact{new(publishedFact), new(publishedCleanup), new(publishedPackage), new(publishedFunctions), new(publishedTypes)},
	ResultType: reflect.TypeFor[Summaries](),
	Run:        run,
}

// traceAnalyzer names this prerequisite in a trace. It is not a catalog
// analyzer, but a reader selects its events the same way: -gohawk-trace=
// lifecyclefacts shows which function the fact pass is working on.
const traceAnalyzer = "lifecyclefacts"

func run(pass *analysis.Pass) (any, error) { return summarizePackage(pass, false) }

// RunForImporters is Run for a package analyzed only so its importers can read
// its facts, as go vet analyzes a dependency. It projects a private function's
// heap only when an exported function this pass summarizes can statically
// reach it. Every other projection was registered for the package's own
// diagnostics, which go vet discards for such a package; nothing reachable
// consults it, so the published facts are those Run publishes.
func RunForImporters(pass *analysis.Pass) (any, error) { return summarizePackage(pass, true) }

func summarizePackage(pass *analysis.Pass, importersOnly bool) (any, error) {
	functions, err := ssaflow.SourceSSAFunctions(pass)
	if err != nil {
		return nil, err
	}
	var reachable map[*ssa.Function]bool
	if importersOnly {
		reachable = reachableFromSummarized(functions)
	}
	summaries := make(Summaries, len(functions))
	callbacks := newCallbackInference(pass, summaries)
	marker := &SummarizedPackage{}
	// Import dependency summaries first, and hand their heap projections to
	// the graph, so every graph built for this package applies a summarized
	// callee by substitution instead of forgetting what the caller holds.
	// Facts belong to this prerequisite analyzer; siblings read them through
	// the result. A callee of this package has no fact yet and stays
	// unknown here; its own summary is registered once computed.
	importCalleeSummaries(pass, functions, summaries)
	var local []*ssa.Function
	// Callees before callers, so a function's projection is registered
	// before any caller in the package is summarized and the caller's graph
	// applies it. Every body's projection is registered, not only the
	// exported ones: a private helper that stores what it is handed is
	// exactly what a caller's graph must know about.
	for _, function := range calleesFirst(functions) {
		if object := function.Object(); object != nil && object.Exported() && len(function.Blocks) == 0 {
			marker.Bodiless = append(marker.Bodiless, object.Name())
		}
		object := function.Object()
		if projectsPrivately(function, reachable) {
			heapmodel.RegisterHeapSummary(function, *projectHeap(function))
		}
		// Only exported functions can be called from a package that imports this
		// fact. Skipping private dependency helpers keeps the prerequisite linear
		// in the externally visible API instead of every transitive SSA body.
		if object == nil || !object.Exported() || len(function.Params) > 64 || len(function.Blocks) == 0 {
			continue
		}
		// Summarizing walks the callee graph, so a pathological package can
		// spend a long time on one function. Announce the function before the
		// walk as well as after it: a run that stops making progress is then
		// located by its last candidate rather than by a stack dump.
		probe := analysisTrace.For(pass, traceAnalyzer, "", function.Pos())
		if probe.Enabled() {
			probe.Candidate(analysisTrace.Step{
				Reason:   reasonSummarizingFunction.String(),
				Outcome:  analysisTrace.OutcomeObserved,
				Pos:      function.Pos(),
				Function: function.String(),
			})
		}
		fact := callbacks.summarize(function)
		summaries[function] = fact
		local = append(local, function)
		if fact.Heap != nil {
			heapmodel.RegisterHeapSummary(function, *fact.Heap)
		}
		if probe.Enabled() {
			details := fact.traceDetails()
			maps.Copy(details, heapTraceDetails(function, fact.Heap))
			probe.Decision(analysisTrace.Step{
				Reason:   reasonFunctionSummarized.String(),
				Outcome:  analysisTrace.OutcomeAccepted,
				Pos:      function.Pos(),
				Function: function.String(),
				Details:  details,
			})
		}
	}
	// A returned view is decided once every method of this package is
	// summarized, because the releasing method usually lives beside the
	// constructor. Export afterwards. An importer must be able to tell a
	// callee proven to do nothing from one that was never summarized, and
	// only the latter is unknown; the package marker carries that
	// distinction, so an empty summary need not be serialized for every
	// function of every dependency.
	slices.Sort(marker.Bodiless)
	pass.ExportPackageFact(&publishedPackage{factcodec.Wrap(*marker)})
	if err := exportSummaries(pass, local, summaries); err != nil {
		return nil, err
	}
	// A type's contract needs its constructor and its methods, so it is joined
	// once both are summarized rather than while either is being proved.
	exportCleanupContracts(pass, summaries)
	return summaries, nil
}

// projectsPrivately reports whether a body the pass does not summarize is
// projected for its callers. reachable is nil when every such body is.
func projectsPrivately(function *ssa.Function, reachable map[*ssa.Function]bool) bool {
	if len(function.Blocks) == 0 || summarized(function) {
		return false
	}
	return reachable == nil || reachable[function]
}

// summarized reports whether the pass summarizes the function and may publish
// its fact: an exported function with a body and a bounded parameter list.
func summarized(function *ssa.Function) bool {
	object := function.Object()
	return object != nil && object.Exported() && len(function.Params) <= 64 && len(function.Blocks) != 0
}

// reachableFromSummarized returns the functions a summarized function names,
// directly or through functions it names: a static callee, a closure, or a
// function used as a value. A graph applies only the summaries of static
// callees, so a function outside this set is never consulted while the
// summarized functions are projected. An instantiation also reaches its origin.
func reachableFromSummarized(functions []*ssa.Function) map[*ssa.Function]bool {
	reachable := map[*ssa.Function]bool{}
	var work []*ssa.Function
	mark := func(function *ssa.Function) {
		for _, candidate := range []*ssa.Function{function, function.Origin()} {
			if candidate != nil && !reachable[candidate] {
				reachable[candidate] = true
				work = append(work, candidate)
			}
		}
	}
	for _, function := range functions {
		if summarized(function) {
			mark(function)
		}
	}
	var operands []*ssa.Value
	for len(work) > 0 {
		function := work[len(work)-1]
		work = work[:len(work)-1]
		for _, block := range function.Blocks {
			for _, instruction := range block.Instrs {
				operands = instruction.Operands(operands[:0])
				for _, operand := range operands {
					if operand == nil {
						continue
					}
					if named, ok := (*operand).(*ssa.Function); ok {
						mark(named)
					}
				}
			}
		}
		for _, anonymous := range function.AnonFuncs {
			mark(anonymous)
		}
	}
	return reachable
}

// calleesFirst orders the functions so that every static callee within the
// set precedes its callers, cycles broken where they close; a function's
// projection is then available to every caller summarized after it.
func calleesFirst(functions []*ssa.Function) []*ssa.Function {
	members := make(map[*ssa.Function]bool, len(functions))
	for _, function := range functions {
		members[function] = true
	}
	var ordered []*ssa.Function
	state := map[*ssa.Function]int{}
	var visit func(function *ssa.Function)
	visit = func(function *ssa.Function) {
		if state[function] != 0 {
			return
		}
		state[function] = 1
		for _, block := range function.Blocks {
			for _, instruction := range block.Instrs {
				if callee := ssacall.ResolvedCallee(ssaflow.InstructionCall(instruction)); callee != nil && members[callee] {
					visit(callee)
				}
			}
		}
		state[function] = 2
		ordered = append(ordered, function)
	}
	for _, function := range functions {
		visit(function)
	}
	return ordered
}

// importCalleeSummaries imports the fact of every static callee the package
// resolves and registers each callee's heap projection with the graph.
func importCalleeSummaries(pass *analysis.Pass, functions []*ssa.Function, summaries Summaries) {
	for _, function := range functions {
		for _, block := range function.Blocks {
			for _, instruction := range block.Instrs {
				common := ssaflow.InstructionCall(instruction)
				if common == nil || common.StaticCallee() == nil {
					continue
				}
				if _, seen := summaries[common.StaticCallee()]; seen {
					continue
				}
				if fact, ok := importFact(pass, instruction); ok {
					summaries[common.StaticCallee()] = fact
					if fact.Heap != nil {
						heapmodel.RegisterHeapSummary(common.StaticCallee(), *fact.Heap)
					}
					// A callee that returns an owned struct is only useful together
					// with the summaries of that struct's methods, which no sibling
					// analyzer can import itself.
					if fact.Must.OwnedFields != 0 {
						importResultMethods(pass, common.StaticCallee(), summaries)
					}
				}
			}
		}
	}
}

// factFor returns a memoized local or previously imported dependency summary.
func factFor(pass *analysis.Pass, instruction ssa.Instruction) (Fact, bool) {
	common := ssaflow.InstructionCall(instruction)
	if pass == nil || common == nil || common.StaticCallee() == nil {
		return Fact{}, false
	}
	if summaries, ok := pass.ResultOf[Analyzer].(Summaries); ok {
		if fact, found := summaries[common.StaticCallee()]; found {
			return fact, true
		}
	}
	return Fact{}, false
}

// exportSummaries publishes the package's summaries once every function is
// summarized: a function's own fact, or its method group's entry.
func exportSummaries(pass *analysis.Pass, local []*ssa.Function, summaries Summaries) error {
	// A method no importer can see is never an importer's callee, so its
	// fact, and the marker's reading of its absence, are never consulted.
	visible := factscope.API(pass.Pkg)
	var groups summaryGroups
	for _, function := range local {
		fact := summaries[function]
		fact.Must.ReturnedView = returnedViews(pass, function, fact, summaries)
		summaries[function] = fact
		if object, ok := function.Object().(*types.Func); ok && !fact.empty() && visible.Contains(object) && !groups.add(object, fact) {
			pass.ExportObjectFact(object, publish(fact))
		}
		if fact.Heap != nil {
			heapmodel.RegisterHeapSummary(function, *fact.Heap)
		}
	}
	return groups.publish(pass)
}
