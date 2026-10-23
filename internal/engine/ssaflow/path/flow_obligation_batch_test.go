package path_test

import (
	"testing"

	"github.com/kojah/gohawk/internal/engine/ssaflow"
	ssapath "github.com/kojah/gohawk/internal/engine/ssaflow/path"
	"github.com/kojah/gohawk/internal/engine/ssaflow/ssaflowtest"
	"golang.org/x/tools/go/ssa"
)

// Without a cutoff, a batch answers each candidate as its own walk does.
func TestObligationBatchMatchesSeparateWalks(t *testing.T) {
	pkg := ssaflowtest.BuildPackage(t, "batch", `package batch
func a() {}
func b() {}
func c() {}
func every(flag bool) { if flag { a(); b(); return }; a(); c() }
func early(flag bool) { a(); if flag { return }; b() }
func loop(n int) { for i := 0; i < n; i++ { b() }; a() }
func never(flag bool) { if flag { panic(0) }; c() }
func none() {}
`)
	names := []string{"a", "b", "c"}
	calls := func(name string) func(ssa.Instruction) bool {
		return func(instruction ssa.Instruction) bool {
			common := ssaflow.InstructionCall(instruction)
			return common != nil && ssaflow.CallName(common) == name
		}
	}
	for _, function := range []string{"every", "early", "loop", "never", "none"} {
		fn := pkg.Func(function)
		batch := ssapath.EvaluateObligationsFromEntry(fn, ssapath.ObligationBatch{
			Count: len(names),
			Instruction: func(instruction ssa.Instruction) (ssapath.ObligationMask, ssapath.ObligationMask) {
				var exact ssapath.ObligationMask
				for index, name := range names {
					if calls(name)(instruction) {
						exact |= 1 << index
					}
				}
				return exact, 0
			},
		})
		for index, name := range names {
			single := ssapath.EvaluateObligationFromEntry(fn, ssapath.ObligationFlow{Instruction: ssapath.ExactOrNone(calls(name))})
			if batch[index] != single {
				t.Errorf("%s/%s: batch %v, separate walk %v", function, name, batch[index], single)
			}
		}
	}
}
