package heapmodel

import (
	"iter"
	"strings"
	"sync"

	"github.com/kojah/gohawk/internal/engine/heapmodel/flagset"
	proofs "github.com/kojah/gohawk/internal/engine/proof"
	"golang.org/x/tools/go/ssa"
)

// A region graph is the one place the package models memory. It maps every
// pointer-valued expression of a function to the abstract objects it may
// refer to and records, at each program point, what those objects hold. The
// identity, containment, and storage questions the analyzers ask are then
// lookups in that structure rather than separate walks over the SSA value
// graph, so a copy, a merge, or a captured cell is understood once. The
// graph is flow-sensitive within one function and knows nothing about other
// functions beyond the call-effect proof it consults; a body it cannot finish
// within its budget is unavailable, and every answer about it is unknown.
// See docs/development/points-to-model.md for the model.

// regionKind classifies an abstract object by where the graph learned of it.
type regionKind uint8

const (
	// regionNil is the nil pointer.
	regionNil regionKind = iota
	// regionUnknown may be any object; it never supports a must-answer.
	regionUnknown
	// regionSite is a local allocation, one per Alloc instruction.
	regionSite
	// regionExternal is the object a parameter, free variable, or global
	// refers to, which existed before the function ran.
	regionExternal
	// regionOpaque is an object produced by an instruction the graph cannot
	// see through, such as a call result.
	regionOpaque
	// regionPlaceholder is the content of a slot the function never wrote,
	// identified by the slot and the write version of its region.
	regionPlaceholder
	// regionSnapshot is an aggregate value copied at one point.
	regionSnapshot
	// regionClosure holds the bindings of a function literal.
	regionClosure
)

// region is one abstract object. Regions are interned per graph, so identity
// is pointer identity.
type region struct {
	kind   regionKind
	origin ssa.Value
	// source and stamp identify a placeholder: the slot it stands for and
	// the write stamp of that slot when it was read. A snapshot keeps the
	// stamps of its source at the copy, so a sub-slot the copy did not list
	// resolves to the placeholder a load at that moment would have produced.
	source slot
	stamp  versionStamp
	stamps map[string]int
	// label distinguishes the objects one call created, by their origin
	// in the callee's summary.
	label string
	// serial is the region's creation order within its graph. It breaks a
	// tie in compareRegions only, because queries intern regions in the
	// order consumers ask them; order caches the region's ordering key.
	serial int
	order  string
	// whole is the read-only set holding just this object, for singleton.
	whole pointees
	// root and slots intern the region's slots; see at.
	root  slotNode
	slots map[string]slot
}

// versionStamp identifies the last unfollowed write that may have changed a
// slot: the epoch is the last call or write through an unknown pointer, the
// step the last write through a foreign pointer to a field or element with
// the same last step. Both are instruction or block identities, so a
// fixpoint that revisits a write produces the same stamp again.
type versionStamp struct {
	epoch int
	step  int
}

// slot is one abstract location: a region and an access path beneath it in
// JoinAccessPath form, empty for the object itself. A region interns its
// slots, so one location is one pointer: two slots are the same location
// exactly when they are equal, and the many maps and sets keyed by slot hash
// and hold a pointer rather than a region and a path. A nil slot is none.
type slot *slotNode

type slotNode struct {
	region *region
	path   string
}

// regionOf returns the slot's region, nil for no slot.
func regionOf(target slot) *region {
	if target == nil {
		return nil
	}
	return target.region
}

// at returns the region's slot at path.
func (object *region) at(path string) slot {
	if path == "" {
		if object.root.region == nil {
			object.root.region = object
		}
		return slot(&object.root)
	}
	if found, ok := object.slots[path]; ok {
		return found
	}
	if object.slots == nil {
		object.slots = map[string]slot{}
	}
	created := slot(&slotNode{region: object, path: path})
	object.slots[path] = created
	return created
}

// pathStar is the element step of an array or slice indexed dynamically; it
// overlaps every constant element step beneath the same prefix.
const pathStar = "index:*"

// pointees is the set of slots a value may refer to, or a slot may hold. A
// stale entry was carried around a back edge from an earlier iteration and
// supports may-answers only.
//
// A set has a map's reference semantics: copies share one set, and the zero
// value reads as empty and must not be written.
type pointees struct{ s *flagset.Set[slot] }

func newPointees() pointees { return pointees{s: &flagset.Set[slot]{}} }

// pointeesOf returns a new set holding member.
func pointeesOf(member slot, stale bool) pointees {
	set := newPointees()
	set.put(member, stale)
	return set
}

func (set pointees) isNil() bool { return set.s == nil }

// version changes whenever the set does.
func (set pointees) version() uint32 { return set.s.Version() }

func (set pointees) Len() int { return set.s.Len() }

// get returns member's stale bit, false when absent.
func (set pointees) get(member slot) bool {
	stale, _ := set.s.Lookup(member)
	return stale
}

func (set pointees) lookup(member slot) (stale, ok bool) { return set.s.Lookup(member) }

func (set pointees) put(member slot, stale bool) { set.s.Put(member, stale) }

func (set pointees) remove(member slot) { set.s.Remove(member) }

func (set pointees) clearAll() { set.s.Clear() }

// all yields each member and its stale bit.
func (set pointees) all() iter.Seq2[slot, bool] { return set.s.All() }

// equal reports whether both sets hold the same members with the same bits;
// a zero set equals an empty one.
func (set pointees) equal(other pointees) bool {
	if set.Len() != other.Len() {
		return false
	}
	for member, stale := range set.all() {
		if theirs, ok := other.lookup(member); !ok || theirs != stale {
			return false
		}
	}
	return true
}

// add records a slot, keeping an entry stale once any addition was. Unknown
// absorbs the set: a set that may be anything gains nothing from another
// member, and a set widened to unknown must stay unknown for the fixpoint
// to settle rather than grow, widen, and grow again on every round.
func (set pointees) add(target slot, stale bool) {
	if target.region.kind == regionUnknown {
		// Keep only the target, with its own stale bit if it was present.
		stale = set.get(target) || stale
		set.clearAll()
		set.put(target, stale)
		return
	}
	switch set.Len() {
	case 0:
		set.put(target, stale)
		return
	case 1:
		for previous, previousStale := range set.all() {
			if previous.region.kind == regionUnknown {
				return
			}
			// The sole member is known. Only that exact member can contribute
			// an existing stale bit; a different target is a new addition.
			if previous == target {
				stale = stale || previousStale
			}
			set.put(target, stale)
			return
		}
	}
	if set.unknown() {
		return
	}
	set.put(target, set.get(target) || stale)
}

func (set pointees) union(other pointees) {
	if other.Len() == 0 {
		return
	}
	// Known additions cannot change whether the destination is unknown. Keep
	// that answer for the merge instead of scanning the growing set each time.
	unknown := set.unknown()
	for target, stale := range other.all() {
		if target.region.kind == regionUnknown {
			set.add(target, stale)
			unknown = true
			continue
		}
		if !unknown {
			set.put(target, set.get(target) || stale)
		}
	}
}

// absorbs reports whether adding every member of other, each with the
// staleness stale gives it, would leave the set unchanged under add and
// union, so a shared set need not be copied first. stale may be nil for the
// member's own bit. Unknown absorbs a known member; an unknown member
// changes any set but itself.
func (set pointees) absorbs(other pointees, stale func(slot, bool) bool) bool {
	unknown := set.unknown()
	for target, targetStale := range other.all() {
		if stale != nil {
			targetStale = stale(target, targetStale)
		}
		old, ok := set.lookup(target)
		switch {
		case target.region.kind == regionUnknown:
			if !ok || set.Len() != 1 || targetStale && !old {
				return false
			}
		case unknown:
		case !ok || targetStale && !old:
			return false
		}
	}
	return true
}

func (set pointees) clone() pointees { return pointees{s: set.s.Clone()} }

// unknown reports whether the set admits any object.
func (set pointees) unknown() bool {
	for target := range set.all() {
		if target.region.kind == regionUnknown {
			return true
		}
	}
	return false
}

// regionKey interns regions.
type regionKey struct {
	kind   regionKind
	origin ssa.Value
	source slot
	stamp  versionStamp
	label  string
}

// regionGraph is the points-to graph of one function.
type regionGraph struct {
	// building marks the unavailable stand-in handed out while the real
	// graph is still being built.
	building  bool
	mu        sync.Mutex
	function  *ssa.Function
	available bool
	regions   map[regionKey]*region
	// values maps each pointer-valued expression to its pointees. SSA
	// values are immutable, so the map only grows during the fixpoint.
	values map[ssa.Value]pointees
	// views records constant slice windows over local arrays so an element
	// selected through a slice names the array's own element.
	views map[ssa.Value]sliceView
	// entry holds the state at the start of each block after the fixpoint,
	// and exit the state at its end.
	entry map[*ssa.BasicBlock]*regionState
	exit  map[*ssa.BasicBlock]*regionState
	// history unions, over the whole build, what each slot was ever given;
	// see slotsMayAlias. A later effect may forget a slot's content in the
	// state, but not that the function once put the object there.
	history map[slot]pointees
	// order is the reverse postorder the fixpoint used.
	order  []*ssa.BasicBlock
	budget *proofs.SearchBudget
	nilR   *region
	unkR   *region
	// ids number instructions and blocks so stamps are stable.
	ids map[ssa.Instruction]int
	// singletons holds the read-only one-object sets contentView answers.
	singletons map[singletonKey]pointees
	// disjoint records every disjointness answer for the heap dump, only
	// while RecordAliasDecisions is on.
	disjoint []AliasDecision
	// callResults holds the pointees a summarized multi-result call gave
	// each of its results, for the extracts that select them.
	callResults map[*ssa.Call][]pointees
	// applied records how the graph handled each call, for the dump and
	// for traces: whether a summary was substituted and, if not, why. A
	// call applied again on a later fixpoint pass keeps its latest record,
	// the one the final state reflects; recorded indexes it.
	applied  []appliedSummary
	recorded map[ssa.Instruction]int
	// consulted records the registry generation of each summary the build
	// looked up, read before the lookup, so the cache can tell when a later
	// registration made the graph stale.
	consulted map[*ssa.Function]int
	// runs lets a fixpoint round skip a block that would repeat its last
	// run; it is nil outside a build.
	runs *blockRuns
	// escapeOrigins records the first instruction that escaped each object
	// in each way, for the dump.
	escapeOrigins map[escapeOrigin]ssa.Instruction
	// widening holds the previous round's loop-header entries and phi values
	// while the fixpoint widens, and is nil otherwise.
	widening *loopSnapshot
	// widened records every slot whose pointees were collapsed to unknown
	// because they outgrew the bound, for the dump.
	widened []widening
	// buildReason classifies a failed build; buildDetail is explanatory text,
	// never a value used to branch on the failure's meaning.
	buildReason GraphBuildReason
	buildDetail string
}

// pointeeLimit bounds the objects one slot may be recorded as holding.
// Past it the slot holds unknown: the answer stays sound, may-answers say
// yes and must-answers say no, and the graph stays small. A set that
// large is not a set a diagnostic can be precise about anyway.
const pointeeLimit = 32

// widening is one slot collapsed to unknown, for the dump.
type widening struct {
	target slot
	at     ssa.Instruction
	size   int
}

// bound collapses the slot's contents to unknown when they outgrew the
// limit, and records that it did.
func (graph *regionGraph) bound(state *regionState, target slot, at ssa.Instruction) {
	set := state.contents[target]
	if set.Len() <= pointeeLimit {
		return
	}
	graph.widened = append(graph.widened, widening{target: target, at: at, size: set.Len()})
	state.mutableContents()[target] = pointeesOf(graph.unkR.at(""), false)
}

// boundValue collapses a value's pointees to unknown when they outgrew the
// limit.
func (graph *regionGraph) boundValue(value ssa.Value) {
	set := graph.values[value]
	if set.Len() <= pointeeLimit {
		return
	}
	if instruction, ok := value.(ssa.Instruction); ok {
		graph.widened = append(graph.widened, widening{target: graph.opaque(value).at(""), at: instruction, size: set.Len()})
	}
	graph.values[value] = pointeesOf(graph.unkR.at(""), false)
	graph.markChanged(value)
}

func buildRegionGraph(function *ssa.Function) *regionGraph {
	// A graph interns about one region per instruction and gives about half
	// its instructions pointees; sizing the maps for that up front spares
	// them most of their growth.
	instructions := 0
	for _, block := range function.Blocks {
		instructions += len(block.Instrs)
	}
	graph := &regionGraph{
		function:  function,
		regions:   make(map[regionKey]*region, instructions),
		values:    make(map[ssa.Value]pointees, instructions/2),
		views:     map[ssa.Value]sliceView{},
		entry:     make(map[*ssa.BasicBlock]*regionState, len(function.Blocks)),
		history:   map[slot]pointees{},
		budget:    proofs.NewSearchBudget(regionBuildBudget),
		ids:       map[ssa.Instruction]int{},
		recorded:  map[ssa.Instruction]int{},
		consulted: map[*ssa.Function]int{},
	}
	graph.nilR = graph.intern(regionKey{kind: regionNil})
	graph.unkR = graph.intern(regionKey{kind: regionUnknown})
	graph.order = reversePostorder(function)
	graph.buildReason, graph.buildDetail = graph.fixpoint()
	graph.available = graph.buildReason == GraphBuildComplete
	if !graph.available {
		graph.entry = nil
		graph.exit = nil
	}
	return graph
}

func (graph *regionGraph) intern(key regionKey) *region {
	if existing, ok := graph.regions[key]; ok {
		return existing
	}
	created := &region{kind: key.kind, origin: key.origin, source: key.source, stamp: key.stamp, label: key.label, serial: len(graph.regions)}
	graph.regions[key] = created
	return created
}

func (graph *regionGraph) site(origin ssa.Value) *region {
	return graph.intern(regionKey{kind: regionSite, origin: origin})
}

func (graph *regionGraph) external(origin ssa.Value) *region {
	return graph.intern(regionKey{kind: regionExternal, origin: origin})
}

func (graph *regionGraph) opaque(origin ssa.Value) *region {
	return graph.intern(regionKey{kind: regionOpaque, origin: origin})
}

func (graph *regionGraph) snapshot(origin ssa.Value) *region {
	return graph.intern(regionKey{kind: regionSnapshot, origin: origin})
}

func (graph *regionGraph) closure(origin ssa.Value) *region {
	return graph.intern(regionKey{kind: regionClosure, origin: origin})
}

func (graph *regionGraph) placeholder(source slot, stamp versionStamp) *region {
	return graph.intern(regionKey{kind: regionPlaceholder, source: source, stamp: stamp})
}

// id numbers an instruction stably for stamps.
func (graph *regionGraph) id(instruction ssa.Instruction) int {
	if id, ok := graph.ids[instruction]; ok {
		return id
	}
	id := len(graph.ids) + 1
	graph.ids[instruction] = id
	return id
}

// blockID numbers a join block for stamps, apart from instruction ids.
func (graph *regionGraph) blockID(block *ssa.BasicBlock) int {
	return -(block.Index + 1)
}

// stateAt replays the block's entry state up to, but not including, the
// instruction, so a query sees memory as it was when the instruction ran.
func (graph *regionGraph) stateAt(instruction ssa.Instruction) *regionState {
	if !graph.available || instruction == nil || instruction.Parent() != graph.function {
		return nil
	}
	entry, ok := graph.entry[instruction.Block()]
	if !ok {
		return nil
	}
	state := entry.clone()
	for _, candidate := range instruction.Block().Instrs {
		if candidate == instruction {
			return state
		}
		graph.transfer(state, candidate)
	}
	return nil
}

// joinSlotPath appends a step, or a whole path, to a slot path.
func joinSlotPath(path, step string) string {
	switch {
	case path == "":
		return step
	case step == "":
		return path
	}
	return path + "/" + step
}

// slotBeneath reports whether path lies beneath prefix, or is it.
func slotBeneath(path, prefix string) bool {
	return prefix == "" || path == prefix || strings.HasPrefix(path, prefix+"/")
}

// lastStep returns the final step of a path.
func lastStep(path string) string {
	// A missing slash gives -1, so the slice starts at zero and keeps the whole value.
	return path[strings.LastIndexByte(path, '/')+1:]
}

func isIndexStep(step string) bool {
	return strings.HasPrefix(step, "index:")
}
