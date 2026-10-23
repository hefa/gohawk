package heapmodel

import (
	"go/types"
	"strconv"
	"strings"

	"github.com/kojah/gohawk/internal/engine/heapmodel/operations"
	"github.com/kojah/gohawk/internal/engine/ssaflow"
	cfg "github.com/kojah/gohawk/internal/engine/ssaflow/cfg"
	"golang.org/x/tools/go/ssa"
)

// The transfer function moves the memory state across one instruction and
// records the pointees of the value it defines. It is the one place the
// graph decides what each SSA form does to memory; the queries only read
// what it recorded.

// transfer applies one instruction to the state: the instructions that
// touch memory are handled here, and every other instruction only defines a
// value whose pointees define records.
func (graph *regionGraph) transfer(state *regionState, instruction ssa.Instruction) {
	switch typed := instruction.(type) {
	case *ssa.Alloc:
		graph.allocate(state, typed)
	case *ssa.Store:
		graph.store(state, typed)
	case *ssa.Call:
		graph.call(state, typed.Common(), typed, false)
	case *ssa.Defer:
		graph.deferCall(state, typed)
	case *ssa.RunDefers:
		graph.runDefers(state, typed)
	case *ssa.Go:
		graph.call(state, typed.Common(), typed, true)
	case *ssa.Send:
		graph.escape(state, graph.pointees(typed.X), HeapEscapedSend, typed)
	case *ssa.MapUpdate:
		graph.mapUpdate(state, typed)
	case *ssa.Lookup:
		graph.lookup(state, typed)
	case *ssa.MakeClosure:
		graph.makeClosure(state, typed)
	case *ssa.Phi:
		graph.phi(typed)
	case *ssa.Extract:
		graph.extract(typed)
	default:
		graph.define(state, instruction)
	}
}

// define records the pointees of a value-defining instruction that does not
// change memory.
func (graph *regionGraph) define(state *regionState, instruction ssa.Instruction) {
	value, ok := instruction.(ssa.Value)
	if !ok {
		return
	}
	plan := operations.Define(value)
	switch plan.Kind {
	case operations.Alias:
		graph.setValue(plan.Value, graph.pointees(plan.Source))
	case operations.FieldAddress:
		graph.setValue(plan.Value, graph.selectStep(graph.pointees(plan.Source), "field:"+strconv.Itoa(plan.Field)))
	case operations.FieldLoad:
		graph.setValue(plan.Value, graph.loadView(state, graph.selectStep(graph.pointees(plan.Source), "field:"+strconv.Itoa(plan.Field)), plan.Value))
	case operations.IndexAddress:
		graph.setValue(plan.Value, graph.index(plan.Source, plan.Index))
	case operations.IndexLoad:
		graph.setValue(plan.Value, graph.loadView(state, graph.index(plan.Source, plan.Index), plan.Value))
	case operations.Sliced:
		graph.slice(plan.Slice)
	case operations.Load:
		graph.setValue(plan.Value, graph.loadView(state, graph.pointees(plan.Source), plan.Value))
	case operations.Opaque:
		graph.setValue(plan.Value, pointeesOf(graph.opaque(plan.Value).at(""), false))
	case operations.Ignored:
	}
}

// pointees returns the slots a value may refer to, deriving them for the
// values no instruction defines: parameters, free variables, globals,
// constants, and functions.
func (graph *regionGraph) pointees(value ssa.Value) pointees {
	if value == nil {
		return pointeesOf(graph.unkR.at(""), false)
	}
	graph.noteRead(value)
	if set, ok := graph.values[value]; ok {
		return set
	}
	if !tracked(value.Type()) {
		return newPointees()
	}
	if owner := valueFunction(value); owner != nil && owner != graph.function {
		// A value of another function, such as a closure's parameter or
		// free variable, may refer to anything this function holds.
		return pointeesOf(graph.unkR.at(""), false)
	}
	var set pointees
	switch operations.Leaf(value, graph.function) {
	case operations.LeafExternal:
		set = pointeesOf(graph.external(value).at(""), false)
	case operations.LeafNil:
		set = pointeesOf(graph.nilR.at(""), false)
	case operations.LeafOpaque:
		set = pointeesOf(graph.opaque(value).at(""), false)
	case operations.LeafPending:
		return newPointees()
	case operations.LeafUnknown:
		set = pointeesOf(graph.unkR.at(""), false)
	}
	graph.values[value] = set
	return set
}

// tracked reports whether values of the type can refer to or hold memory
// the graph models: a scalar cannot, and a function value is a closure
// object that can.
func tracked(typ types.Type) bool {
	switch typ.Underlying().(type) {
	case *types.Basic, *types.Tuple:
		return false
	}
	return true
}

// setValue records the pointees of a value, growing them across rounds.
func (graph *regionGraph) setValue(value ssa.Value, set pointees) {
	if !tracked(value.Type()) {
		return
	}
	// The bound applies to a value's first set as well as to later unions,
	// or the first round would see an overfull set every later round
	// collapses, and a loop-free body would need a second round only to
	// apply it.
	if existing, ok := graph.values[value]; ok {
		before := existing.version()
		existing.union(set)
		if existing.version() != before {
			graph.markChanged(value)
		}
	} else {
		graph.values[value] = set.clone()
		graph.markChanged(value)
	}
	graph.boundValue(value)
}

// allocate zeroes the site's storage. A site inside a loop is a fresh cell
// each iteration, but a pointer to the earlier cell may survive, so the
// zeroing is weak there.
func (graph *regionGraph) allocate(state *regionState, alloc *ssa.Alloc) {
	site := graph.site(alloc)
	graph.setValue(alloc, pointeesOf(site.at(""), false))
	if cfg.BlockInCycle(alloc.Block()) && state.escaped[site] {
		return
	}
	graph.clearSubtree(state, site.at(""))
}

// selectStep returns the slots one step beneath each of the bases. Its result
// is read-only: setValue copies a value's first set, and every other caller
// only reads. A single base, the usual case, is answered with the graph's
// singleton set rather than a new one on every transfer of every round.
func (graph *regionGraph) selectStep(bases pointees, step string) pointees {
	if bases.Len() == 1 {
		for base, stale := range bases.all() {
			switch base.region.kind {
			case regionUnknown:
				return graph.singleton(base, stale)
			case regionNil:
				return newPointees()
			case regionSite, regionExternal, regionOpaque, regionPlaceholder, regionSnapshot, regionClosure:
				return graph.singleton(base.region.at(joinSlotPath(base.path, step)), stale)
			}
		}
	}
	result := newPointees()
	for base, stale := range bases.all() {
		switch base.region.kind {
		case regionUnknown:
			result.add(base, stale)
		case regionNil:
			// Selecting through nil faults, so on the path where the base is
			// nil the selected address never reaches a use and names no slot.
			// Widening it to unknown instead would absorb the other bases'
			// real slots: a slice built by append from a nil start would
			// make every element alias every object in the function.
			// https://github.com/ipfs/boxo/blob/3d6ac39a0f76c824ffbb90e3a729e78f62bc2d12/routing/mock/centralized_server.go#L61-L77
		case regionSite, regionExternal, regionOpaque, regionPlaceholder, regionSnapshot, regionClosure:
			result.add(base.region.at(joinSlotPath(base.path, step)), stale)
		}
	}
	return result
}

// index returns the element slots selected from an array address, array
// value, or slice by the index, using the constant position when the
// window and index are both known and the element step otherwise.
func (graph *regionGraph) index(base, index ssa.Value) pointees {
	bases := graph.pointees(base)
	position, fixed := ssaflow.ConstantIndex(index)
	view, viewed := graph.view(base)
	step := pathStar
	if fixed && viewed {
		if offset, err := strconv.ParseInt(position, 10, 64); err == nil && offset >= 0 && offset < view.size {
			step = "index:" + strconv.FormatInt(view.offset+offset, 10)
		}
	}
	return graph.selectStep(bases, step)
}

// sliceView is a constant window over a local array.
type sliceView struct {
	offset, size, capacity int64
}

// view returns a recorded slice window or an array's full window. An
// unrecorded slice has unknown bounds; a zero-length array is still known.
// Callers decide whether the window and their selected index are usable.
func (graph *regionGraph) view(value ssa.Value) (sliceView, bool) {
	graph.noteRead(value)
	if view, known := graph.views[value]; known {
		return view, true
	}
	length, known := arrayLength(value.Type())
	return sliceView{size: length, capacity: length}, known
}

// arrayLength returns the length of an array type or a pointer to one.
func arrayLength(typ types.Type) (int64, bool) {
	if pointer, ok := typ.Underlying().(*types.Pointer); ok {
		typ = pointer.Elem()
	}
	array, ok := typ.Underlying().(*types.Array)
	if !ok {
		return 0, false
	}
	return array.Len(), true
}

// slice records a window over the sliced value's storage; a slice of a local
// array with constant bounds keeps naming the array's own elements.
func (graph *regionGraph) slice(sliced *ssa.Slice) {
	graph.setValue(sliced, graph.pointees(sliced.X))
	view, ok := graph.view(sliced.X)
	if !ok {
		return
	}
	low, lowOK := ssaflow.StorageInteger(sliced.Low, 0)
	high, highOK := ssaflow.StorageInteger(sliced.High, view.size)
	max, maxOK := ssaflow.StorageInteger(sliced.Max, view.capacity)
	if !lowOK || !highOK || !maxOK || low < 0 || low > high || high > max || max > view.capacity {
		return
	}
	window := sliceView{offset: view.offset + low, size: high - low, capacity: max - low}
	if old, ok := graph.views[sliced]; !ok || old != window {
		graph.views[sliced] = window
		graph.markChanged(sliced)
	}
}

// load returns what the slots hold. A whole-aggregate load makes a snapshot
// whose sub-slots are copied from the source.
// loadView is load for a caller that only reads the result, as setValue and
// the builtin element copies do. A scalar load through one address that is
// not stale answers exactly that slot's content, so it returns the content
// view instead of building a copy of it.
func (graph *regionGraph) loadView(state *regionState, addresses pointees, loaded ssa.Value) pointees {
	if addresses.Len() != 1 || isAggregate(loaded.Type()) {
		return graph.load(state, addresses, loaded)
	}
	for address, stale := range addresses.all() {
		if stale {
			break
		}
		view := graph.contentView(state, address)
		nameLoadedPlaceholders(view, loaded)
		return view
	}
	return graph.load(state, addresses, loaded)
}

// nameLoadedPlaceholders names each placeholder in set by the load that
// first produced it.
func nameLoadedPlaceholders(set pointees, loaded ssa.Value) {
	for pointee := range set.all() {
		if pointee.region.kind == regionPlaceholder && pointee.region.origin == nil {
			pointee.region.origin = loaded
		}
	}
}

func (graph *regionGraph) load(state *regionState, addresses pointees, loaded ssa.Value) pointees {
	if isAggregate(loaded.Type()) {
		// A slot written whole from an aggregate value holds that value: a
		// copy of a by-value parameter is the parameter. Otherwise the load
		// is a fresh copy of whatever the sub-slots hold.
		if address, ok := singleSlot(addresses); ok {
			if set, ok := state.contents[address]; ok && set.Len() > 0 {
				return set.clone()
			}
		}
		return graph.snapshotOf(state, addresses, loaded)
	}
	result := newPointees()
	for address, stale := range addresses.all() {
		for pointee, pointeeStale := range graph.contentView(state, address).all() {
			result.add(pointee, stale || pointeeStale)
			if pointee.region.kind == regionPlaceholder && pointee.region.origin == nil {
				// The first load that produced the placeholder names it.
				pointee.region.origin = loaded
			}
		}
	}
	return result
}

func isAggregate(typ types.Type) bool {
	switch typ.Underlying().(type) {
	case *types.Struct, *types.Array:
		return true
	}
	return false
}

// store writes the value into the addressed slots.
func (graph *regionGraph) phi(merged *ssa.Phi) {
	result := newPointees()
	block := merged.Block()
	for index, edge := range merged.Edges {
		predecessor := block.Preds[index]
		backEdge := block.Dominates(predecessor)
		for target, stale := range graph.pointees(edge).all() {
			result.add(target, stale || backEdge && createdInsideLoop(target.region, block))
		}
	}
	graph.setValue(merged, result)
	graph.widenPhi(merged)
}

func (graph *regionGraph) extract(extract *ssa.Extract) {
	if assertion, ok := extract.Tuple.(*ssa.TypeAssert); ok && extract.Index == 0 {
		graph.setValue(extract, graph.pointees(assertion.X))
		return
	}
	if call, ok := extract.Tuple.(*ssa.Call); ok {
		graph.noteRead(call)
		if results := graph.callResults[call]; extract.Index < len(results) && !results[extract.Index].isNil() {
			graph.setValue(extract, results[extract.Index])
			return
		}
	}
	graph.setValue(extract, pointeesOf(graph.opaque(extract).at(""), false))
}

func (graph *regionGraph) makeClosure(state *regionState, closure *ssa.MakeClosure) {
	object := graph.closure(closure)
	graph.setValue(closure, pointeesOf(object.at(""), false))
	for index, binding := range closure.Bindings {
		target := object.at("binding:" + strconv.Itoa(index))
		state.mutableContents()[target] = graph.pointees(binding).clone()
		graph.remember(target, state.contents[target])
	}
}

// Selected aggregate copies preserve the union of reference destinations in a
// known bounded array window. The snapshot remains clobbered outside those
// slots; an opaque window or element cannot establish a destination guarantee.
// https://github.com/ferro-labs/ai-gateway/blob/d025ca1a3c6e0c6a83ed7c93147e36f39a1e6cb4/internal/admin/repository/sql_store.go#L73-L99
func (graph *regionGraph) selectedSnapshot(state *regionState, address slot, stale bool, loaded ssa.Value, snapshot *region) {
	load, ok := loaded.(*ssa.UnOp)
	if !ok {
		return
	}
	index, ok := load.X.(*ssa.IndexAddr)
	if !ok {
		return
	}
	view, known := graph.view(index.X)
	if !known || view.size <= 0 || view.size > SummarySlots {
		return
	}
	// A wildcard write beneath an element is not an exact element update.
	// Until the content model propagates those writes through all descendant
	// slots, preserve the clobbered snapshot instead of reusing old fields.
	for target := range state.contents {
		if target.region == address.region && strings.Contains(target.path, pathStar) {
			return
		}
	}
	for target := range state.clobbered {
		if target.region == address.region && strings.Contains(target.path, pathStar) {
			return
		}
	}
	walkStructReferences(loaded.Type(), func(path string) {
		contents := newPointees()
		for offset := range view.size {
			element := joinSlotPath(parentPath(address.path), "index:"+strconv.FormatInt(view.offset+offset, 10))
			source := address.region.at(joinSlotPath(element, path))
			for target, old := range graph.contentView(state, source).all() {
				contents.add(target, stale || old)
			}
		}
		target := snapshot.at(path)
		state.mutableContents()[target] = contents
		graph.bound(state, target, load)
		graph.remember(target, state.contents[target])
	}, func(string) {})
}
