package resultfacts

import (
	"strings"
	"testing"

	proofs "github.com/kojah/gohawk/internal/engine/proof"
	"github.com/kojah/gohawk/internal/engine/ssaflow/ssaflowtest"
)

const storageResultsFixture = `package storedresults
type box struct { flag bool; err error; pointer *int }
type failure struct{}
func (*failure) Error() string { return "failure" }
var global box
func opaque(*box)
func literal() bool { return true }
func stable() bool { b := &box{flag: true}; return b.flag }
func typedNil() error { b := &box{err: (*failure)(nil)}; return b.err }
func nilError() error { b := &box{err: nil}; return b.err }
func freshPointer() *int { b := &box{pointer: new(int)}; return b.pointer }
func snapshot() bool { b := &box{flag: true}; saved := b.flag; b.flag = false; return saved }
func overwritten() bool { b := &box{flag: true}; b.flag = false; return b.flag }
func mixed(pick bool) bool { b := &box{flag: true}; if pick { b.flag = false }; return b.flag }
func escaped() bool { b := &box{flag: true}; opaque(b); return b.flag }
func deferred() (flag bool) { flag = true; defer func(){ flag = false }(); return }
func globalLoad() bool { return global.flag }
func forwarded() bool { return stable() }
func fieldAlias() bool { b := &box{flag: true}; alias := &b.flag; *alias = false; return b.flag }
func conditional(pick bool) bool { if pick { return stable() }; return false }
func mixedInterface(pick bool) error { b := &box{err: (*failure)(nil)}; if pick { b.err = nil }; return b.err }
func async() bool { b := &box{flag: true}; go func(){ b.flag = false }(); return b.flag }
func preservedSnapshot() error { b := &box{err: (*failure)(nil)}; saved := b.err; b.err = nil; return saved }
`

func TestStoredResultGuarantees(t *testing.T) {
	pkg := ssaflowtest.BuildPackage(t, "storedresults", storageResultsFixture)
	for name, want := range map[string]Guarantee{
		"stable": AlwaysTrue, "typedNil": AlwaysNonNil, "nilError": AlwaysNil,
		"freshPointer": AlwaysNonNil, "snapshot": AlwaysTrue, "overwritten": AlwaysFalse,
		"mixed": Unknown, "escaped": Unknown, "deferred": Unknown, "globalLoad": Unknown,
		"forwarded": AlwaysTrue, "fieldAlias": AlwaysFalse, "conditional": Unknown,
		"mixedInterface": Unknown, "async": Unknown, "preservedSnapshot": AlwaysNonNil,
	} {
		t.Run(name, func(t *testing.T) {
			got := NewEngine().Function(pkg.Func(name), proofs.NewSearchBudget(proofs.SummaryBudget))
			if got.Result(0) != want {
				var ir strings.Builder
				if _, err := pkg.Func(name).WriteTo(&ir); err != nil {
					t.Fatal(err)
				}
				t.Log(ir.String())
				t.Errorf("%s: got %v, want %v", name, got.Result(0), want)
			}
		})
	}
}

func TestStoredResultBudget(t *testing.T) {
	pkg := ssaflowtest.BuildPackage(t, "storedresults", `package storedresults
type box struct { flag bool }
func marker() {}
func stable() bool { b := &box{flag: true}; return b.flag }
func light() bool { b := &box{flag: true}; `+strings.Repeat("marker();", 10)+`return b.flag }
func heavy() bool { b := &box{flag: true}; `+strings.Repeat("marker();", 2100)+`return b.flag }
`)
	engine := NewEngine()
	// A caller that cannot pay for the lookup learns nothing, and its refusal
	// does not become the summary a later caller reads.
	if got := engine.Function(pkg.Func("stable"), proofs.NewSearchBudget(1)); got.Available || got.Result(0) != Unknown {
		t.Fatal("unaffordable lookup established a result guarantee")
	}
	// The summary has a budget of its own: paying for the lookup is enough.
	for _, name := range []string{"stable", "light"} {
		for _, limit := range []int{2, proofs.SummaryBudget} {
			if got := engine.Function(pkg.Func(name), proofs.NewSearchBudget(limit)); got.Result(0) != AlwaysTrue {
				t.Fatalf("%s: caller budget %d changed the summary to %v", name, limit, got.Result(0))
			}
		}
	}
	// A body larger than the summary's own budget is exhausted whoever asks.
	for _, limit := range []int{2, 4 * proofs.SummaryBudget} {
		if got := engine.Function(pkg.Func("heavy"), proofs.NewSearchBudget(limit)); got.Available || got.Result(0) != Unknown {
			t.Fatalf("exhausted summary established a result guarantee for caller budget %d", limit)
		}
	}
}

func BenchmarkStoredResultSummary(b *testing.B) {
	pkg := ssaflowtest.BuildPackage(b, "storedresults", storageResultsFixture)
	for _, name := range []string{"literal", "stable", "escaped", "mixed"} {
		b.Run(name, func(b *testing.B) {
			function := pkg.Func(name)
			b.ReportAllocs()
			for b.Loop() {
				NewEngine().Function(function, proofs.NewSearchBudget(proofs.SummaryBudget))
			}
		})
	}
}
