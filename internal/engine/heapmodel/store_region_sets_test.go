package heapmodel

import (
	"fmt"
	"strconv"
	"testing"
)

func TestPointeesAddPreservesUnknownAndStale(t *testing.T) {
	first := slot{region: &region{kind: regionSite}}
	second := slot{region: &region{kind: regionSite}}
	unknown := slot{region: &region{kind: regionUnknown}}
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
	target := slot{region: &region{kind: regionSite}}
	other := slot{region: &region{kind: regionSite}}
	unknown := slot{region: &region{kind: regionUnknown}}
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
	first := slot{region: &region{kind: regionSite}}
	second := slot{region: &region{kind: regionSite}}
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
				set.put(slot{region: &region{kind: regionSite}}, false)
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
				target := slot{region: owner}
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
	target := slot{region: owner}
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
					set.put(slot{region: &region{kind: regionSite}}, false)
				}
				state.contents[slot{region: &region{kind: regionSite}}] = set
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
	owner := slot{region: &region{kind: regionSite}}
	first := slot{region: &region{kind: regionSite}}
	second := slot{region: &region{kind: regionSite}}
	empty := slot{region: &region{kind: regionSite}}
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
	first := slot{region: &region{kind: regionSite}}
	second := slot{region: &region{kind: regionSite}}
	unknown := slot{region: &region{kind: regionUnknown}}
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
		setOf(map[slot]bool{{region: &region{kind: regionSite}}: true, {region: &region{kind: regionSite}}: false}),
		pointeesOf(slot{region: &region{kind: regionUnknown}}, true),
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
				source.put(slot{region: &region{kind: regionSite}}, false)
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
		destination := pointeesOf(slot{region: &region{kind: regionUnknown}}, false)
		source := pointeesOf(slot{region: &region{kind: regionSite}}, false)
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
			source := slot{region: &region{kind: regionSite}}
			copied := slot{region: &region{kind: regionSite}}
			old := slot{region: &region{kind: regionSite}}
			updated := slot{region: &region{kind: regionSite}}
			incoming := slot{region: &region{kind: regionSite}}
			state, other := newRegionState(), newRegionState()
			wanted := setOf(map[slot]bool{old: false, incoming: true})
			if test.backing {
				state.backing[copied] = source.region
			} else {
				source.path = "index:0"
				copied = slot{region: source.region, path: pathStar}
				wanted.put(slot{region: graph.nilR}, false)
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
				target := slot{region: owner}
				base.contents[target] = pointeesOf(slot{region: &region{kind: regionSite}}, false)
				base.backing[target] = owner
				base.escaped[owner] = true
				base.clobbered[target] = index
				incoming := target
				if index < test.missing {
					incoming = slot{region: &region{kind: regionSite}}
				}
				other.contents[incoming] = pointeesOf(slot{region: &region{kind: regionSite}}, false)
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
				state.backing[slot{region: first}] = first
			},
		},
		{
			name: "two backing regions",
			setup: func(state *regionState, first *region) {
				second := &region{kind: regionSite}
				state.backing[slot{region: first}] = second
				state.backing[slot{region: second}] = first
			},
		},
		{
			name: "snapshot source",
			setup: func(_ *regionState, first *region) {
				first.kind = regionSnapshot
				first.source = slot{region: first}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			graph := &regionGraph{nilR: &region{kind: regionNil}, unkR: &region{kind: regionUnknown}}
			state := newRegionState()
			first := &region{kind: regionSite}
			test.setup(state, first)
			got := graph.content(state, slot{region: first})
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
	state.backing[slot{region: first}] = second
	got := graph.content(state, slot{region: first})
	if _, ok := got.lookup(slot{region: graph.nilR}); !ok || got.Len() != 1 {
		t.Errorf("acyclic content = %v, want nil region", got)
	}

	known := &region{kind: regionExternal}
	state.contents[slot{region: first}] = pointeesOf(slot{region: known}, false)
	state.backing[slot{region: first}] = first
	if got := graph.content(state, slot{region: first}); got.Len() != 1 {
		t.Errorf("written content = %v, want exact content", got)
	} else if _, ok := got.lookup(slot{region: known}); !ok {
		t.Errorf("written content = %v, want exact content", got)
	}

	deep := newRegionState()
	chain := make([]*region, maxContentHops+2)
	for index := range chain {
		chain[index] = &region{kind: regionSite}
		if index > 0 {
			deep.backing[slot{region: chain[index-1]}] = chain[index]
		}
	}
	if got := graph.content(deep, slot{region: chain[0]}); !got.unknown() {
		t.Errorf("deep content = %v, want unknown", got)
	}
}

func TestContentQueriesReturnIndependentWritableSets(t *testing.T) {
	graph := &regionGraph{nilR: &region{kind: regionNil}, unkR: &region{kind: regionUnknown}}
	state := newRegionState()
	owner := slot{region: &region{kind: regionSite}}
	first := slot{region: &region{kind: regionSite}}
	second := slot{region: &region{kind: regionSite}}
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
	unwritten := slot{region: &region{kind: regionSite}}
	read = graph.content(state, unwritten)
	read.put(second, true)
	if next := graph.content(state, unwritten); next.Len() != 1 || next.get(slot{region: graph.nilR}) {
		t.Fatal("a later implicit query reused a mutated result")
	}
}

func TestContentIndexQueriesReturnIndependentSets(t *testing.T) {
	graph := &regionGraph{nilR: &region{kind: regionNil}, unkR: &region{kind: regionUnknown}}
	owner := &region{kind: regionSite}
	value := slot{region: &region{kind: regionSite}}
	zero := slot{region: graph.nilR}
	unknown := slot{region: graph.unkR}
	for _, test := range []struct {
		name   string
		path   string
		stored map[slot]pointees
		want   pointees
	}{
		{"constant from wildcard", "index:0", map[slot]pointees{{region: owner, path: pathStar}: pointeesOf(value, true)}, pointeesOf(value, true)},
		{
			"dynamic includes unwritten", pathStar,
			map[slot]pointees{{region: owner, path: "index:0"}: pointeesOf(value, false)},
			setOf(map[slot]bool{value: false, zero: false}),
		},
		{"dynamic absorbs unknown", pathStar, map[slot]pointees{{region: owner, path: "index:0"}: pointeesOf(unknown, true)}, pointeesOf(unknown, true)},
		{"empty stored set", "index:0", map[slot]pointees{{region: owner, path: pathStar}: newPointees()}, pointeesOf(zero, false)},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := newRegionState()
			state.contents = test.stored
			got := graph.content(state, slot{region: owner, path: test.path})
			if !got.equal(test.want) {
				t.Fatalf("content = %v, want %v", got, test.want)
			}
			got.clearAll()
			got.put(value, true)
			if next := graph.content(state, slot{region: owner, path: test.path}); !next.equal(test.want) {
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
			owner := slot{region: &region{kind: regionSite}}
			if written {
				state.contents[owner] = pointeesOf(slot{region: &region{kind: regionSite}}, false)
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
