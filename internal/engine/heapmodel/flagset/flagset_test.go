package flagset_test

import (
	"maps"
	"math/rand/v2"
	"testing"

	"github.com/kojah/gohawk/internal/engine/heapmodel/flagset"
)

// A set must agree with a map under any sequence of changes, on both sides
// of the spill boundary, and a clone must stay independent of its source.
func TestSetMatchesMap(t *testing.T) {
	random := rand.New(rand.NewPCG(1, 2))
	for trial := range 200 {
		set, model := &flagset.Set[int]{}, map[int]bool{}
		var clone *flagset.Set[int]
		var cloned map[int]bool
		for range 64 {
			key, flag := random.IntN(2*flagset.Inline+2), random.IntN(2) == 0
			switch random.IntN(8) {
			case 0:
				set.Remove(key)
				delete(model, key)
			case 1:
				if random.IntN(4) == 0 {
					set.Clear()
					clear(model)
				}
			case 2:
				clone, cloned = set.Clone(), maps.Clone(model)
			default:
				set.Put(key, flag)
				model[key] = flag
			}
			requireEqual(t, trial, set, model)
		}
		if clone != nil {
			requireEqual(t, trial, clone, cloned)
		}
	}
}

func requireEqual(t *testing.T, trial int, set *flagset.Set[int], model map[int]bool) {
	t.Helper()
	got := maps.Collect(set.All())
	if set.Len() != len(model) || !maps.Equal(got, model) {
		t.Fatalf("trial %d: set = %v (len %d), want %v", trial, got, set.Len(), model)
	}
	for key := range 2*flagset.Inline + 2 {
		flag, ok := set.Lookup(key)
		if want, wantOK := model[key]; flag != want || ok != wantOK {
			t.Fatalf("trial %d: Lookup(%d) = %v, %v, want %v, %v", trial, key, flag, ok, want, wantOK)
		}
	}
}

func TestNilSetReadsEmpty(t *testing.T) {
	var set *flagset.Set[string]
	if _, ok := set.Lookup("a"); ok || set.Len() != 0 || len(maps.Collect(set.All())) != 0 {
		t.Fatal("a nil set must read as empty")
	}
	set.Remove("a")
	set.Clear()
	if clone := set.Clone(); clone.Len() != 0 {
		t.Fatal("cloning a nil set must return an empty set")
	}
}
