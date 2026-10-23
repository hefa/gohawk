package resultfacts

import (
	"strings"
	"testing"

	proofs "github.com/kojah/gohawk/internal/engine/proof"
	"github.com/kojah/gohawk/internal/engine/ssaflow/ssaflowtest"
)

func TestTerminationReachabilityCutoffClaimsNothing(t *testing.T) {
	// The padding fits the summary's own budget for the result census but
	// not for the reachability proof, which also looks up every callee.
	padding := strings.Repeat("marker();", 800)
	pkg := ssaflowtest.BuildPackage(t, "results", `package results
import "os"
func marker() {}
func Die() { os.Exit(0) }
func Loop() { for {} }
func Returns() {}
func HeavyDie() { `+padding+`os.Exit(0) }
func HeavyLoop() { for { `+padding+`} }
func HeavyReturns() { `+padding+`}
func Deferred() { defer os.Exit(0) }
func Conditional(flag bool) { if flag { defer os.Exit(0) } }
`)
	engine := NewEngine()
	for _, test := range []struct {
		name  string
		never bool
	}{{"Die", true}, {"Loop", true}, {"Returns", false}} {
		function := pkg.Func(test.name)
		// A caller that cannot pay for the lookup learns nothing, and that
		// refusal does not become the summary a later caller reads.
		if got := engine.Function(function, proofs.NewSearchBudget(1)); got.Available || got.NeverReturns() {
			t.Fatalf("%s admitted a summary the caller could not pay for: %+v", test.name, got)
		}
		if got := engine.Function(function, proofs.NewSearchBudget(2)); !got.Available || got.NeverReturns() != test.never {
			t.Fatalf("%s refused lookup poisoned inference: %+v", test.name, got)
		}
		// An incomplete reachability proof makes no termination claim, and
		// since the summary's budget is its own, no caller sees another answer.
		heavy := pkg.Func("Heavy" + test.name)
		for _, limit := range []int{2, 4 * proofs.SummaryBudget} {
			if got := engine.Function(heavy, proofs.NewSearchBudget(limit)); got.Available || got.NeverReturns() {
				t.Fatalf("Heavy%s admitted an incomplete termination summary for caller budget %d: %+v", test.name, limit, got)
			}
		}
	}
	for _, name := range []string{"Deferred", "Conditional"} {
		function := pkg.Func(name)
		if function.Recover == nil {
			t.Fatal("expected actual SSA recovery entry for deferred execution")
		}
		if got := NewEngine().Function(function, proofs.NewSearchBudget(proofs.SummaryBudget)); !got.Available || got.NeverReturns() {
			t.Fatal("recovery entry must retain the existing no-termination-claim boundary")
		}
	}
}
