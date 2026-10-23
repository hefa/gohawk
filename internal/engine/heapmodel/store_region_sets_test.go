package heapmodel

import (
	"fmt"
	"strconv"
	"testing"
)

func TestPointeesAddPreservesUnknownAndStale(t *testing.T) {
	first := (&region{kind: regionSite}).at("")
	second := (&region{kind: regionSite}).at("")
	unknown := (&region{kind: regionUnknown}).at("")
	for _, test := range []struct {
		name    string
		initial pointees
		target  slot
		stale   bool
		want    pointees
	}{
		{"empty", newPointees(), first, false, pointeesOf(first, false)},
		{"same known", pointeesOf(first, false), first, true, pointeesOf(first, true)},
		{"retain stale", pointeesOf(first, true), first, false, pointeesOf(first, true)},
		{"different known", pointeesOf(first, false), second, true, setOf(map[slot]bool{first: false, second: true})},
		{"unknown absorbs", pointeesOf(unknown, true), first, true, pointeesOf(unknown, true)},
		{"mixed unknown absorbs duplicate", setOf(map[slot]bool{first: false, unknown: true}), first, true, setOf(map[slot]bool{first: false, unknown: true})},
		{"replace known with unknown", setOf(map[slot]bool{first: true, second: false}), unknown, true, pointeesOf(unknown, true)},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.initial.add(test.target, test.stale)
			if !test.initial.equal(test.want) {
				t.Fatalf("add changed evidence: got=%v want=%v", test.initial, test.want)
			}
		})
	}
}

func BenchmarkPointeesAdd(b *testing.B) {
	target := (&region{kind: regionSite}).at("")
	other := (&region{kind: regionSite}).at("")
	unknown := (&region{kind: regionUnknown}).at("")
	for _, name := range []string{"empty", "duplicate", "different", "unknown", "mixed"} {
		b.Run(name, func(b *testing.B) {
			set := newPointees()
			switch name {
			case "duplicate":
				set.put(target, false)
			case "different":
				set.put(other, false)
			case "unknown":
				set.put(unknown, true)
			case "mixed":
				set.put(unknown, true)
				set.put(target, false)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				switch name {
				case "empty":
					set.clearAll()
				case "different":
					set.remove(target)
				}
				set.add(target, true)
			}
		})
	}
}

func TestPointeesCloneIsIndependentAndWritable(t *testing.T) {
	first := (&region{kind: regionSite}).at("")
	second := (&region{kind: regionSite}).at("")
	original := pointeesOf(first, true)
	copied := original.clone()
	copied.put(first, false)
	copied.put(second, true)
	if !original.get(first) || original.Len() != 1 {
		t.Fatal("changing the copy changed the original pointee set")
	}
	var empty pointees
	copied = empty.clone()
	copied.put(first, false)
	if copied.Len() != 1 {
		t.Fatal("cloning a nil set must return a writable set")
	}
}

func BenchmarkPointeesClone(b *testing.B) {
	for _, size := range []int{0, 1, 16, 256} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			set := newPointees()
			for range size {
				set.put((&region{kind: regionSite}).at(""), false)
			}
			b.ReportAllocs()
			for b.Loop() {
				copy := set.clone()
				if copy.Len() != set.Len() {
					b.Fatal("clone lost a pointee")
				}
			}
		})
	}
}

func BenchmarkRegionStateClone(b *testing.B) {
	for _, size := range []int{0, 1, 16, 256} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			state := newRegionState()
			for index := range size {
				owner := &region{kind: regionSite}
				target := owner.at("")
				state.backing[target] = owner
				state.clobbered[target] = index
				state.escaped[owner] = true
				state.escapes[target] = HeapEscape(1)
				state.stepEpochs[strconv.Itoa(index)] = index
			}
			b.ReportAllocs()
			for b.Loop() {
				copy := state.clone()
				if len(copy.backing) != size {
					b.Fatal("clone lost backing evidence")
				}
			}
		})
	}
}

func TestRegionStateScalarCloneIsIndependentAndWritable(t *testing.T) {
	owner := &region{kind: regionSite}
	target := owner.at("")
	state := newRegionState()
	state.backing[target] = owner
	state.stepEpochs["field"] = 1
	state.clobbered[target] = 2
	state.escaped[owner] = true
	state.escapes[target] = HeapEscape(1)
	copy := state.clone()
	// The maps are shared after a clone; changes go through the mutable
	// accessors.
	delete(copy.mutableBacking(), target)
	copy.mutableStepEpochs()["field"] = 3
	copy.mutableClobbered()[target] = 4
	copy.mutableEscaped()[owner] = false
	// Escapes are shared after a clone; changes go through addEscape.
	copy.addEscape(target, HeapEscape(2))
	if state.backing[target] != owner || state.stepEpochs["field"] != 1 || state.clobbered[target] != 2 ||
		!state.escaped[owner] || state.escapes[target] != HeapEscape(1) {
		t.Fatal("changing scalar snapshot evidence changed the original state")
	}
	if copy.escapes[target] != HeapEscape(3) {
		t.Fatal("a clone lost its own escape")
	}
	state.addEscape(target, HeapEscape(4))
	if copy.escapes[target] != HeapEscape(3) {
		t.Fatal("an original's escape reached its clone")
	}
	copy = (&regionState{}).clone()
	copy.mutableBacking()[target] = owner
	copy.mutableStepEpochs()["field"] = 1
	copy.mutableClobbered()[target] = 2
	copy.mutableEscaped()[owner] = true
	copy.addEscape(target, HeapEscape(1))
}

func BenchmarkRegionStateContentsClone(b *testing.B) {
	for _, size := range []int{0, 1, 16, 32} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			state := newRegionState()
			for range 16 {
				set := newPointees()
				for range size {
					set.put((&region{kind: regionSite}).at(""), false)
				}
				state.contents[(&region{kind: regionSite}).at("")] = set
			}
			b.ReportAllocs()
			for b.Loop() {
				copy := state.clone()
				if len(copy.contents) != 16 {
					b.Fatal("clone lost stored contents")
				}
			}
		})
	}
}

func TestRegionStateContentsCloneIsIndependentAndWritable(t *testing.T) {
	owner := (&region{kind: regionSite}).at("")
	first := (&region{kind: regionSite}).at("")
	second := (&region{kind: regionSite}).at("")
	empty := (&region{kind: regionSite}).at("")
	state := newRegionState()
	state.contents[owner] = pointeesOf(first, true)
	state.contents[empty] = pointees{}
	state.deferred = pointeesOf(first, false)
	copy := state.clone()
	// Contents sets are shared after a clone; changes go through writable.
	copy.writable(owner).put(first, false)
	copy.writable(owner).put(second, true)
	copy.writable(empty).put(second, false)
	state.writable(owner).put(first, true)
	copy.mutableDeferred().put(first, true)
	copy.mutableDeferred().put(second, false)
	if !state.contents[owner].get(first) || state.contents[owner].Len() != 1 || !state.contents[empty].isNil() ||
		state.deferred.get(first) || state.deferred.Len() != 1 {
		t.Fatal("changing stored or deferred snapshot evidence changed the original state")
	}
	if copy.contents[owner].get(first) || !copy.contents[owner].get(second) || copy.contents[empty].Len() != 1 {
		t.Fatal("a writable set lost its change or took the original's")
	}
	copy = newRegionState().clone()
	copy.mutableDeferred().put(first, false)
}

func TestPointeesUnion(t *testing.T) {
	first := (&region{kind: regionSite}).at("")
	second := (&region{kind: regionSite}).at("")
	unknown := (&region{kind: regionUnknown}).at("")
	for _, test := range []struct {
		name        string
		destination pointees
		source      pointees
		want        pointees
	}{
		{"empty", newPointees(), newPointees(), newPointees()},
		{"known stale overlap", pointeesOf(first, false), setOf(map[slot]bool{first: true, second: false}), setOf(map[slot]bool{first: true, second: false})},
		{"retain stale", pointeesOf(first, true), pointeesOf(first, false), pointeesOf(first, true)},
		{"unknown destination", pointeesOf(unknown, false), pointeesOf(first, true), pointeesOf(unknown, false)},
		{"unknown source", pointeesOf(first, true), setOf(map[slot]bool{second: false, unknown: true}), pointeesOf(unknown, true)},
		{"retain unknown stale", pointeesOf(unknown, true), setOf(map[slot]bool{unknown: false, first: true}), pointeesOf(unknown, true)},
	} {
		t.Run(test.name, func(t *testing.T) {
			sourceBefore := test.source.clone()
			test.destination.union(test.source)
			if !test.destination.equal(test.want) {
				t.Fatalf("union = %v, want %v", test.destination, test.want)
			}
			if !test.source.equal(sourceBefore) {
				t.Fatal("union changed independent source evidence")
			}
		})
	}
}

func TestPointeesUnionWithSelf(t *testing.T) {
	for _, set := range []pointees{
		setOf(map[slot]bool{(&region{kind: regionSite}).at(""): true, (&region{kind: regionSite}).at(""): false}),
		pointeesOf((&region{kind: regionUnknown}).at(""), true),
	} {
		before := set.clone()
		set.union(set)
		if !set.equal(before) {
			t.Fatal("self union changed evidence")
		}
	}
}

func BenchmarkPointeesUnion(b *testing.B) {
	for _, size := range []int{0, 1, 8, 32} {
		b.Run(fmt.Sprintf("known/%d", size), func(b *testing.B) {
			source := newPointees()
			for range size {
				source.put((&region{kind: regionSite}).at(""), false)
			}
			destination := source.clone()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				destination.union(source)
			}
		})
	}
	b.Run("unknown", func(b *testing.B) {
		destination := pointeesOf((&region{kind: regionUnknown}).at(""), false)
		source := pointeesOf((&region{kind: regionSite}).at(""), false)
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			destination.union(source)
		}
	})
}

func TestMergeContentsReadsBeforeUpdates(t *testing.T) {
	for _, test := range []struct {
		name    string
		backing bool
	}{
		{"backing copy", true},
		{"wildcard element", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			graph := &regionGraph{nilR: &region{kind: regionNil}, unkR: &region{kind: regionUnknown}}
			source := (&region{kind: regionSite}).at("")
			copied := (&region{kind: regionSite}).at("")
			old := (&region{kind: regionSite}).at("")
			updated := (&region{kind: regionSite}).at("")
			incoming := (&region{kind: regionSite}).at("")
			state, other := newRegionState(), newRegionState()
			wanted := setOf(map[slot]bool{old: false, incoming: true})
			if test.backing {
				state.backing[copied] = source.region
			} else {
				source = source.region.at("index:0")
				copied = source.region.at(pathStar)
				wanted.put(graph.nilR.at(""), false)
			}
			state.contents[source] = pointeesOf(old, false)
			other.contents[source] = pointeesOf(updated, false)
			other.contents[copied] = pointeesOf(incoming, true)
			graph.mergeContents(state, other, false, nil)
			if !state.contents[copied].equal(wanted) {
				t.Fatalf("merged contents = %v, want original read plus incoming evidence %v", state.contents[copied], wanted)
			}
			if !other.contents[source].equal(pointeesOf(updated, false)) || !other.contents[copied].equal(pointeesOf(incoming, true)) {
				t.Fatal("merge changed incoming evidence")
			}
		})
	}
}

func BenchmarkRegionMergeContents(b *testing.B) {
	for _, test := range []struct {
		name    string
		size    int
		missing int
	}{
		{"shared/16", 16, 0},
		{"shared/128", 128, 0},
		{"disjoint/16", 16, 16},
		{"disjoint/128", 128, 128},
		{"mixed/16", 16, 1},
		{"mixed/128", 128, 1},
	} {
		b.Run(test.name, func(b *testing.B) {
			size := test.size
			wanted := size + test.missing
			graph := &regionGraph{nilR: &region{kind: regionNil}, unkR: &region{kind: regionUnknown}}
			base, other := newRegionState(), newRegionState()
			for index := range size {
				owner := &region{kind: regionSite}
				target := owner.at("")
				base.contents[target] = pointeesOf((&region{kind: regionSite}).at(""), false)
				base.backing[target] = owner
				base.escaped[owner] = true
				base.clobbered[target] = index
				incoming := target
				if index < test.missing {
					incoming = (&region{kind: regionSite}).at("")
				}
				other.contents[incoming] = pointeesOf((&region{kind: regionSite}).at(""), false)
			}
			b.ReportAllocs()
			for b.Loop() {
				state := base.clone()
				graph.mergeContents(state, other, false, nil)
				if len(state.contents) != wanted {
					b.Fatal("merge lost a slot")
				}
			}
		})
	}
}

func TestContentBackingCyclesAreUnknown(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*regionState, *region)
	}{
		{
			name: "self backing",
			setup: func(state *regionState, first *region) {
				state.backing[first.at("")] = first
			},
		},
		{
			name: "two backing regions",
			setup: func(state *regionState, first *region) {
				second := &region{kind: regionSite}
				state.backing[first.at("")] = second
				state.backing[second.at("")] = first
			},
		},
		{
			name: "snapshot source",
			setup: func(_ *regionState, first *region) {
				first.kind = regionSnapshot
				first.source = first.at("")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			graph := &regionGraph{nilR: &region{kind: regionNil}, unkR: &region{kind: regionUnknown}}
			state := newRegionState()
			first := &region{kind: regionSite}
			test.setup(state, first)
			got := graph.content(state, first.at(""))
			if !got.unknown() {
				t.Errorf("cyclic content = %v, want unknown", got)
			}
		})
	}
}

func TestContentBackingKnownAndDeepPaths(t *testing.T) {
	graph := &regionGraph{nilR: &region{kind: regionNil}, unkR: &region{kind: regionUnknown}}
	state := newRegionState()
	first := &region{kind: regionSite}
	second := &region{kind: regionSite}
	state.backing[first.at("")] = second
	got := graph.content(state, first.at(""))
	if _, ok := got.lookup(graph.nilR.at("")); !ok || got.Len() != 1 {
		t.Errorf("acyclic content = %v, want nil region", got)
	}

	known := &region{kind: regionExternal}
	state.contents[first.at("")] = pointeesOf(known.at(""), false)
	state.backing[first.at("")] = first
	if got := graph.content(state, first.at("")); got.Len() != 1 {
		t.Errorf("written content = %v, want exact content", got)
	} else if _, ok := got.lookup(known.at("")); !ok {
		t.Errorf("written content = %v, want exact content", got)
	}

	deep := newRegionState()
	chain := make([]*region, maxContentHops+2)
	for index := range chain {
		chain[index] = &region{kind: regionSite}
		if index > 0 {
			deep.backing[chain[index-1].at("")] = chain[index]
		}
	}
	if got := graph.content(deep, chain[0].at("")); !got.unknown() {
		t.Errorf("deep content = %v, want unknown", got)
	}
}

func TestContentQueriesReturnIndependentWritableSets(t *testing.T) {
	graph := &regionGraph{nilR: &region{kind: regionNil}, unkR: &region{kind: regionUnknown}}
	state := newRegionState()
	owner := (&region{kind: regionSite}).at("")
	first := (&region{kind: regionSite}).at("")
	second := (&region{kind: regionSite}).at("")
	state.contents[owner] = pointeesOf(first, true)
	read := graph.content(state, owner)
	read.put(first, false)
	read.put(second, false)
	if state.contents[owner].Len() != 1 || !state.contents[owner].get(first) {
		t.Fatal("changing query results changed stored evidence")
	}
	another := graph.content(state, owner)
	if another.Len() != 1 || !another.get(first) {
		t.Fatal("a later query reused the mutated result")
	}
	unwritten := (&region{kind: regionSite}).at("")
	read = graph.content(state, unwritten)
	read.put(second, true)
	if next := graph.content(state, unwritten); next.Len() != 1 || next.get(graph.nilR.at("")) {
		t.Fatal("a later implicit query reused a mutated result")
	}
}

func TestContentIndexQueriesReturnIndependentSets(t *testing.T) {
	graph := &regionGraph{nilR: &region{kind: regionNil}, unkR: &region{kind: regionUnknown}}
	owner := &region{kind: regionSite}
	value := (&region{kind: regionSite}).at("")
	zero := graph.nilR.at("")
	unknown := graph.unkR.at("")
	for _, test := range []struct {
		name   string
		path   string
		stored map[slot]pointees
		want   pointees
	}{
		{"constant from wildcard", "index:0", map[slot]pointees{owner.at(pathStar): pointeesOf(value, true)}, pointeesOf(value, true)},
		{
			"dynamic includes unwritten", pathStar,
			map[slot]pointees{owner.at("index:0"): pointeesOf(value, false)},
			setOf(map[slot]bool{value: false, zero: false}),
		},
		{"dynamic absorbs unknown", pathStar, map[slot]pointees{owner.at("index:0"): pointeesOf(unknown, true)}, pointeesOf(unknown, true)},
		{"empty stored set", "index:0", map[slot]pointees{owner.at(pathStar): newPointees()}, pointeesOf(zero, false)},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := newRegionState()
			state.contents = test.stored
			got := graph.content(state, owner.at(test.path))
			if !got.equal(test.want) {
				t.Fatalf("content = %v, want %v", got, test.want)
			}
			got.clearAll()
			got.put(value, true)
			if next := graph.content(state, owner.at(test.path)); !next.equal(test.want) {
				t.Fatal("mutating query result changed later content")
			}
		})
	}
}

func BenchmarkRegionContent(b *testing.B) {
	for _, written := range []bool{false, true} {
		name := "unwritten"
		if written {
			name = "written"
		}
		b.Run(name, func(b *testing.B) {
			graph := &regionGraph{nilR: &region{kind: regionNil}, unkR: &region{kind: regionUnknown}}
			state := newRegionState()
			owner := (&region{kind: regionSite}).at("")
			if written {
				state.contents[owner] = pointeesOf((&region{kind: regionSite}).at(""), false)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if got := graph.content(state, owner); got.Len() != 1 {
					b.Fatal("content query lost its single target")
				}
			}
		})
	}
}

// setOf builds a pointee set from a map literal, for tests.
func setOf(entries map[slot]bool) pointees {
	set := newPointees()
	for member, stale := range entries {
		set.put(member, stale)
	}
	return set
}
