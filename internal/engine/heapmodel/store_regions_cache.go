package heapmodel

import (
	"container/list"
	"slices"
	"sync"

	ssacall "github.com/kojah/gohawk/internal/engine/ssaflow/calls"
	"golang.org/x/tools/go/ssa"
)

// The graph cache keeps each function's points-to graph for the queries
// that follow, and keeps it only while it is still the graph a fresh build
// would produce. A graph applies the heap summaries of its callees, and a
// summary can be registered after the graph was built: the lifecycle pass
// registers imported summaries when it starts, but an analyzer that does not
// depend on it may already have built graphs of the same package. Such a
// graph forgot through a call it would now substitute, and serving it later
// made one run report what another did not. So every cached graph is
// indexed by the callee summaries it consulted, and registering a summary
// that differs from what a graph saw evicts the graph. Evicting a graph also
// drops the summary projected on demand from it, and so on up the callers.
// A caller already holding an evicted graph keeps its answers; the cache
// only guarantees that no one is handed a stale graph afterwards.

// regionGraphCache keeps a program's most recently built graphs. Analyzers
// ask many questions about one function in a row, and the graph is built
// once for all of them. The analyzers of a unit run at once and interleave
// their functions: a process-wide cache of 128 evicted graphs another
// analyzer was about to ask for again, and 512 rebuilt a tenth less on moby.
// Each program has its own cache, so the units analyzed at once each keep
// theirs; 256 apiece holds peak memory where one shared 512 did, at a tenth
// of a percent more allocation.
const regionGraphCache = 256

// A graphCache is one program's cached graphs, most recently used first.
type graphCache struct {
	sync.Mutex
	order   *list.List
	entries map[*ssa.Function]*list.Element
	// dependents indexes the cached graphs by the callee summaries they
	// consulted.
	dependents map[*ssa.Function]map[*regionGraphEntry]bool
}

// The heap model keeps its graphs, summaries and memos per SSA program: the
// package one unit analyzes, with its imports. Each is a view of functions
// of that program, so it is kept exactly as long as the program is
// analyzed. A process that analyzes many units forgets a unit's program
// with Release once the unit is done; one that analyzes a single unit and
// exits need not. One unit's state never counts against another's limits,
// and units analyzed at once do not contend for one another's locks.
type programState struct {
	graphs    graphCache
	summaries summaryRegistry
	cycles    cycleMemo
	// names keeps each function's name; see functionName.
	names sync.Map
}

func newProgramState() *programState {
	return &programState{
		graphs:    graphCache{order: list.New(), entries: map[*ssa.Function]*list.Element{}, dependents: map[*ssa.Function]map[*regionGraphEntry]bool{}},
		summaries: summaryRegistry{entries: map[*ssa.Function]heapEntry{}, generations: map[*ssa.Function]int{}},
		cycles:    cycleMemo{reach: map[*ssa.Function]map[*ssa.Function]bool{}, metadata: map[*ssa.Function]*callCycleMetadata{}},
	}
}

// programs maps each program the heap model has seen to its state.
var programs sync.Map

// stateOf returns the state the heap model keeps for the function's program.
func stateOf(function *ssa.Function) *programState {
	var program *ssa.Program
	if function != nil {
		program = function.Prog
	}
	if state, ok := programs.Load(program); ok {
		return state.(*programState) //nolint:forcetypeassert // The map holds only program states.
	}
	state, _ := programs.LoadOrStore(program, newProgramState())
	return state.(*programState) //nolint:forcetypeassert // The map holds only program states.
}

// Release forgets every graph, summary and memo kept for program.
func Release(program *ssa.Program) { programs.Delete(program) }

// graphsOf returns the graph cache of the function's program.
func graphsOf(function *ssa.Function) *graphCache { return &stateOf(function).graphs }

// regionGraphEntry is one cached graph. Its graph is nil while the build
// is in progress, and concurrent lookups wait for done before reading it.
// Graph construction cuts callee-summary call cycles before they can ask
// for the same graph. An evicted entry is stale, and a build that finishes
// after its eviction is not cached.
type regionGraphEntry struct {
	function *ssa.Function
	graph    *regionGraph
	stale    bool
	// done is closed once the build that created the entry finishes, whether
	// it was published or found stale.
	done chan struct{}
}

// finishLocked marks the entry's build finished, waking every lookup that is
// waiting for it. It runs under the cache lock.
func (entry *regionGraphEntry) finishLocked() {
	if entry.done == nil {
		return
	}
	select {
	case <-entry.done:
	default:
		close(entry.done)
	}
}

// regionsOf returns the points-to graph of the function that owns value,
// building it on first use. A value with no function, or a function with no
// body, has an unavailable graph.
func regionsOf(value ssa.Value) *regionGraph {
	return regionsOfFunction(valueFunction(value))
}

// regionsOfFunction returns the function's points-to graph, building it on
// first use.
func regionsOfFunction(function *ssa.Function) *regionGraph {
	if function == nil || len(function.Blocks) == 0 {
		return &regionGraph{}
	}
	graphs := graphsOf(function)
	for {
		graphs.Lock()
		element, ok := graphs.entries[function]
		if !ok {
			break
		}
		entry := element.Value.(*regionGraphEntry) //nolint:forcetypeassert // The list holds only entries.
		// Publication and eviction both update graph under this lock. Copy
		// the pointer before releasing it; reading entry.graph afterwards
		// races with another pass finishing the same function's build.
		graph, done := entry.graph, entry.done
		graphs.Unlock()
		if graph != nil {
			return graph
		}
		// Another analyzer is building this graph. Answering from an
		// unavailable placeholder meanwhile gave weaker, structural answers
		// whose presence depended on scheduling, so the same package could be
		// reported differently from run to run. Wait for that build instead:
		// a build never asks for its own function's graph, so the builder is
		// always another goroutine. A build found stale is not published, and
		// the loop then builds the graph here.
		if done == nil {
			return &regionGraph{building: true}
		}
		<-done
	}
	entry := &regionGraphEntry{function: function, done: make(chan struct{})}
	graphs.entries[function] = graphs.order.PushFront(entry)
	graphs.Unlock()
	graph := buildRegionGraph(function)
	cacheRegionGraph(entry, graph)
	return graph
}

// cacheRegionGraph stores a finished build unless it is already stale: its
// entry was evicted while it ran, or a summary it consulted has changed
// since. The check runs under the cache lock, and registration updates the
// registry before it takes that lock to evict, so a registration either
// happened before the check and is seen here, or finds the entry indexed
// and evicts it.
func cacheRegionGraph(entry *regionGraphEntry, graph *regionGraph) {
	graphs := graphsOf(entry.function)
	graphs.Lock()
	defer graphs.Unlock()
	defer entry.finishLocked()
	if entry.stale || !consultedStillCurrent(graph) {
		removeIndexedEntryLocked(entry)
		return
	}
	entry.graph = graph
	if element, ok := graphs.entries[entry.function]; ok {
		graphs.order.MoveToFront(element)
	} else {
		// The build outlived the cache's capacity; keep the graph anyway,
		// the caller is about to query it.
		graphs.entries[entry.function] = graphs.order.PushFront(entry)
	}
	for key := range graph.consulted {
		if graphs.dependents[key] == nil {
			graphs.dependents[key] = map[*regionGraphEntry]bool{}
		}
		graphs.dependents[key][entry] = true
	}
	for graphs.order.Len() > regionGraphCache {
		oldest := graphs.order.Back()
		if oldest.Value.(*regionGraphEntry).graph == nil { //nolint:forcetypeassert // The list holds only entries.
			break
		}
		evictLocked(oldest.Value.(*regionGraphEntry)) //nolint:forcetypeassert // The list holds only entries.
	}
}

// consultedStillCurrent reports whether no summary the build consulted has
// been replaced or dropped since.
func consultedStillCurrent(graph *regionGraph) bool {
	for callee, generation := range graph.consulted {
		if heapSummaryGeneration(callee) != generation {
			return false
		}
	}
	return true
}

// summaryKeys names the registry entries a lookup of the callee can read:
// the callee's own, and for a bodiless instantiation its origin's.
func summaryKeys(callee *ssa.Function) []*ssa.Function {
	keys := []*ssa.Function{callee}
	if resolved := ssacall.ResolvedFunction(callee); resolved != nil && resolved != callee {
		keys = append(keys, resolved)
	}
	return keys
}

// invalidateDependents evicts every cached graph that consulted the
// function's summary, then drops the summaries projected on demand from
// those graphs and evicts their dependents in turn.
func invalidateDependents(function *ssa.Function) {
	graphs := graphsOf(function)
	pending := []*ssa.Function{function}
	for len(pending) > 0 {
		next := pending[0]
		pending = pending[1:]
		graphs.Lock()
		var evicted []*ssa.Function
		for entry := range graphs.dependents[next] {
			evicted = append(evicted, entry.function)
			evictLocked(entry)
		}
		delete(graphs.dependents, next)
		graphs.Unlock()
		for _, caller := range evicted {
			if forgetOnDemandSummary(caller) {
				pending = append(pending, caller)
			}
		}
	}
}

// evictLocked removes an entry from the cache and its index. The caller
// holds the cache lock.
func evictLocked(entry *regionGraphEntry) {
	removeIndexedEntryLocked(entry)
	if entry.graph == nil {
		return
	}
	graphs := graphsOf(entry.function)
	for key := range entry.graph.consulted {
		delete(graphs.dependents[key], entry)
	}
}

// removeIndexedEntryLocked marks an entry stale and unlinks only its own
// cache slot. An older build must not remove its replacement. The caller holds
// the cache lock and separately owns dependency cleanup and build notification:
// eviction does not finish a build that is still running.
func removeIndexedEntryLocked(entry *regionGraphEntry) {
	entry.stale = true
	graphs := graphsOf(entry.function)
	if element, ok := graphs.entries[entry.function]; ok && element.Value == entry {
		delete(graphs.entries, entry.function)
		graphs.order.Remove(element)
	}
}

// heapSummariesEqual reports whether two summaries say the same thing.
func heapSummariesEqual(left, right HeapSummary) bool {
	return slices.Equal(left.Edges, right.Edges) && slices.Equal(left.Effects, right.Effects) &&
		slices.Equal(left.Holds, right.Holds) && slices.Equal(left.Reads, right.Reads) &&
		slices.Equal(left.Requires, right.Requires) && slices.Equal(left.Truncated, right.Truncated)
}

func valueFunction(value ssa.Value) *ssa.Function {
	switch typed := value.(type) {
	case nil:
		return nil
	case ssa.Instruction:
		// An instruction outside any block, such as one a test built by
		// hand, belongs to no function.
		if typed.Block() == nil {
			return nil
		}
		return typed.Parent()
	case *ssa.Parameter:
		return typed.Parent()
	case *ssa.FreeVar:
		return typed.Parent()
	}
	return nil
}
