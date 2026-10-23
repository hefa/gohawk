package heapmodel

import (
	"cmp"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/kojah/gohawk/internal/engine/ssaflow"
	"golang.org/x/tools/go/ssa"
)

// recordAliasDecisions turns on the disjointness record RenderRegions prints.
// Nothing else reads it, and recording every answer was a large share of what
// graph queries allocated, so only a process that will dump graphs pays.
var recordAliasDecisions atomic.Bool

// RecordAliasDecisions makes every graph built afterwards keep its
// disjointness answers for RenderRegions. Call it before the analysis whose
// graphs will be dumped.
func RecordAliasDecisions() { recordAliasDecisions.Store(true) }

// RenderRegions prints the points-to graph of a function for the ssa
// subcommand: each tracked value with the slots it may refer to, then the
// disjointness answers the graph has given. Regions are named by kind and
// origin; a stale entry, carried around a loop's back edge, is marked.
func RenderRegions(function *ssa.Function) string {
	graph := regionsOfFunction(function)
	defer graph.lock()()
	var buffer strings.Builder
	if !graph.available {
		// The values the build assigned before it gave up are still the
		// evidence for why it gave up, so they are printed beneath the
		// reason.
		buffer.WriteString("// regions: unavailable (" + graph.buildFailureText() + ")\n")
	} else {
		buffer.WriteString("// regions:\n")
	}
	for _, parameter := range function.Params {
		graph.renderValue(&buffer, parameter)
	}
	for _, free := range function.FreeVars {
		graph.renderValue(&buffer, free)
	}
	for _, block := range function.Blocks {
		for _, instruction := range block.Instrs {
			if value, ok := instruction.(ssa.Value); ok {
				graph.renderValue(&buffer, value)
			}
		}
	}
	if graph.available {
		graph.renderStores(&buffer)
	}
	for _, entry := range graph.applied {
		if entry.reason != CallSummaryApplied {
			fmt.Fprintf(&buffer, "//   unsummarized %s: %s\n", entry.instruction.String(), entry.reason)
			continue
		}
		fmt.Fprintf(&buffer, "//   applied %s at %s: %d edges, %d effects, %d truncated\n",
			entry.callee.String(), entry.instruction.String(), entry.edges, entry.effects, entry.truncated)
	}
	for _, entry := range graph.widened {
		at := "join"
		if entry.at != nil {
			at = entry.at.String()
		}
		fmt.Fprintf(&buffer, "//   widened %s to unknown at %s: %d pointees\n", slotName(entry.target), at, entry.size)
	}
	origins := make([]escapeOrigin, 0, len(graph.escapeOrigins))
	for key := range graph.escapeOrigins {
		origins = append(origins, key)
	}
	sort.Slice(origins, func(i, j int) bool {
		left, right := graph.escapeOrigins[origins[i]], graph.escapeOrigins[origins[j]]
		if left.Pos() != right.Pos() {
			return left.Pos() < right.Pos()
		}
		if origins[i].kind != origins[j].kind {
			return origins[i].kind < origins[j].kind
		}
		return slotName(origins[i].target) < slotName(origins[j].target)
	})
	for _, key := range origins {
		fmt.Fprintf(&buffer, "//   escaped %s %s at %s\n", slotName(key.target), key.kind, graph.escapeOrigins[key])
	}
	for _, decision := range graph.disjoint {
		fmt.Fprintf(&buffer, "//   disjoint %s %s: %s\n", decision.Value.Name(), decision.Target.Name(), decision.Reason)
	}
	return buffer.String()
}

func (graph *regionGraph) renderValue(buffer *strings.Builder, value ssa.Value) {
	set, ok := graph.values[value]
	if !ok || len(set) == 0 {
		return
	}
	entries := make([]string, 0, len(set))
	for target, stale := range set {
		entry := regionName(target.region)
		if target.path != "" {
			entry += " " + target.path
		}
		if stale {
			entry += " (stale)"
		}
		entries = append(entries, entry)
	}
	sort.Strings(entries)
	fmt.Fprintf(buffer, "//   %s -> %s\n", value.Name(), strings.Join(entries, ", "))
}

// renderStores prints what each slot holds when the function returns: the
// object-to-object edges a value dump only shows once a later load reads
// them back. Contents are unioned over every normal return, and a slot that
// only some returns fill is marked, since a caller sees it only on those.
func (graph *regionGraph) renderStores(buffer *strings.Builder) {
	var states []*regionState
	for _, returned := range ssaflow.InstructionsOf[*ssa.Return](graph.function) {
		if state := graph.stateAt(returned); state != nil {
			states = append(states, state)
		}
	}
	if len(states) == 0 {
		buffer.WriteString("// stores at return: no normal return\n")
		return
	}
	union := map[slot]pointees{}
	filled := map[slot]int{}
	for _, state := range states {
		for target, set := range state.contents {
			if len(set) == 0 {
				continue
			}
			if union[target] == nil {
				union[target] = pointees{}
			}
			for pointee, stale := range set {
				union[target].add(pointee, stale)
			}
			filled[target]++
		}
	}
	buffer.WriteString("// stores at return:\n")
	lines := make([]string, 0, len(union))
	for target, set := range union {
		entries := make([]string, 0, len(set))
		for pointee, stale := range set {
			entry := slotName(pointee)
			if stale {
				entry += " (stale)"
			}
			entries = append(entries, entry)
		}
		sort.Strings(entries)
		line := fmt.Sprintf("//   %s -> %s", slotName(target), strings.Join(entries, ", "))
		if filled[target] < len(states) {
			line += " (some returns)"
		}
		lines = append(lines, line)
	}
	sort.Strings(lines)
	for _, line := range lines {
		buffer.WriteString(line + "\n")
	}
}

// slotName names a slot for the dump: its object, then its path.
func slotName(target slot) string {
	if target.path == "" {
		return regionName(target.region)
	}
	return regionName(target.region) + " " + target.path
}

func regionName(object *region) string {
	switch object.kind {
	case regionNil:
		return "nil"
	case regionUnknown:
		return "?"
	case regionSite:
		return "local:" + object.origin.Name()
	case regionExternal:
		if object.label != "" {
			return "foreign:" + object.label
		}
		switch object.origin.(type) {
		case *ssa.Global:
			return "global:" + object.origin.Name()
		case *ssa.FreeVar:
			return "free:" + object.origin.Name()
		}
		return "param:" + object.origin.Name()
	case regionOpaque:
		// An object a deferred call's summary created has no value to be
		// named by, only its label.
		name := "opaque:"
		if object.origin != nil {
			name += object.origin.Name()
		}
		if object.label != "" {
			return name + "[" + object.label + "]"
		}
		return name
	case regionPlaceholder:
		return fmt.Sprintf("content(%s %s @%d.%d)", regionName(object.source.region), object.source.path, object.stamp.epoch, object.stamp.step)
	case regionSnapshot:
		return "copy:" + object.origin.Name()
	case regionClosure:
		return "closure:" + object.origin.Name()
	}
	return "?"
}

// compareRegions orders regions by what they are rather than when they were
// created. A graph interns regions during its queries as well as during the
// fixpoint, and queries come in the order its consumers ask them, so a
// creation-order serial differed from run to run. Every ordered walk over
// slots, and with it the numbering of fresh objects in a projection and
// which slots a projection keeps within its bound, then did too. Distinct
// regions have distinct keys; serial breaks a tie only for an origin with no
// stable name.
func compareRegions(left, right *region) int {
	if left == right {
		return 0
	}
	if order := strings.Compare(left.orderKey(), right.orderKey()); order != 0 {
		return order
	}
	return cmp.Compare(left.serial, right.serial)
}

// orderKey is the region's identity as a string: its kind, origin, label,
// source slot and stamp, the fields that intern it. It is computed once.
func (object *region) orderKey() string {
	if object.order != "" {
		return object.order
	}
	var key strings.Builder
	key.WriteString(strconv.Itoa(int(object.kind)))
	key.WriteString("|")
	key.WriteString(valueOrderKey(object.origin))
	key.WriteString("|")
	key.WriteString(object.label)
	key.WriteString("|")
	if object.source.region != nil {
		key.WriteString("(")
		key.WriteString(object.source.region.orderKey())
		key.WriteString(")")
		key.WriteString(object.source.path)
	}
	key.WriteString("|")
	key.WriteString(strconv.Itoa(object.stamp.epoch))
	key.WriteString(".")
	key.WriteString(strconv.Itoa(object.stamp.step))
	object.order = key.String()
	return object.order
}

// valueOrderKey names an SSA value by its place in the program: an
// instruction by function, block and position in the block, a parameter or
// free variable by index, a global by package and name.
func valueOrderKey(value ssa.Value) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case *ssa.Parameter:
		return "param:" + typed.Parent().String() + "#" + strconv.Itoa(slices.Index(typed.Parent().Params, typed))
	case *ssa.FreeVar:
		return "free:" + typed.Parent().String() + "#" + strconv.Itoa(slices.Index(typed.Parent().FreeVars, typed))
	case *ssa.Global:
		return "global:" + typed.Pkg.Pkg.Path() + "." + typed.Name()
	case *ssa.Function:
		return "func:" + typed.String()
	case ssa.Instruction:
		block := typed.Block()
		if block == nil {
			return "value:" + value.String()
		}
		return "instr:" + block.Parent().String() + "#" + strconv.Itoa(block.Index) + "." + strconv.Itoa(slices.Index(block.Instrs, typed))
	}
	return "value:" + value.String()
}
