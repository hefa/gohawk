package path

import (
	proofs "github.com/kojah/gohawk/internal/engine/proof"
	cfg "github.com/kojah/gohawk/internal/engine/ssaflow/cfg"
	"golang.org/x/tools/go/ssa"
)

// A function is often asked many every-return questions at once: one per
// heap requirement, per field it might release, per parameter it might hand
// back. Each was its own obligation walk over the same paths and guards. A
// batch answers them in one walk. A path state carries, per candidate, the
// strongest action seen on it, as two masks; the path, its guards and the
// opaque actions of edges and contradictions are shared, since they do not
// depend on the candidate. Every candidate's states are then exactly the
// states its own walk would visit, so without a cutoff each outcome is the
// one its own walk returns. The batch spends one budget: a cutoff leaves
// every unsettled candidate uncertain.

// MaxObligationCandidates bounds a batch by the width of its masks.
const MaxObligationCandidates = 64

// ObligationMask holds one bit per candidate of a batch.
type ObligationMask uint64

// ObligationBatch is ObligationFlow for count candidates. Instruction and
// Return label each candidate at once: exact holds the candidates the
// instruction or return settles exactly, unknown those it consumes opaquely.
// Flow's own Instruction and Return are ignored; its Edge applies to every
// candidate alike.
type ObligationBatch struct {
	Flow        ObligationFlow
	Count       int
	Instruction func(ssa.Instruction) (exact, unknown ObligationMask)
	Return      func(*ssa.Return) (exact, unknown ObligationMask)
}

// EvaluateObligationsFromEntry is EvaluateObligationFromEntry for each
// candidate of batch, in one walk. Count must not exceed
// MaxObligationCandidates.
func EvaluateObligationsFromEntry(function *ssa.Function, batch ObligationBatch) []ObligationOutcome {
	outcomes := make([]ObligationOutcome, batch.Count)
	if batch.Count == 0 {
		return outcomes
	}
	for index := range outcomes {
		outcomes[index] = ObligationHonored
	}
	if function == nil || len(function.Blocks) == 0 {
		return outcomes
	}
	walk := batchWalk{batch: batch, policy: batch.Flow.successorPolicy(), all: ObligationMask(1)<<batch.Count - 1}
	if batch.Count == MaxObligationCandidates {
		walk.all = ^ObligationMask(0)
	}
	cfg.WalkStatesWithin([]batchState{{block: function.Blocks[0]}}, func(state batchState) batchKey {
		return state.keyWithin(batch.Flow.Budget, &walk.ids)
	}, walk.step, batch.Flow.Budget)
	walk.stopAtCutoff()
	for index := range outcomes {
		bit := ObligationMask(1) << index
		switch {
		case walk.violated&bit != 0:
			outcomes[index] = ObligationViolated
		case walk.uncertain&bit != 0:
			outcomes[index] = ObligationUncertain
		}
	}
	return outcomes
}

// batchState is obligationState with coverage per candidate.
type batchState struct {
	block, predecessor *ssa.BasicBlock
	index              int
	exact, unknown     ObligationMask
	guards             PathGuards
}

type batchKey struct {
	block, predecessor, index int
	guards                    guardKeyID
	exact, unknown            ObligationMask
}

func (state batchState) keyWithin(budget *proofs.SearchBudget, ids *guardIDs) batchKey {
	predecessor := -1
	if state.predecessor != nil {
		predecessor = state.predecessor.Index
	}
	return batchKey{
		block: state.block.Index, predecessor: predecessor, index: state.index,
		guards: ids.within(state.guards, budget), exact: state.exact, unknown: state.unknown,
	}
}

// batchWalk is obligationWalk for a batch. violated and uncertain gather the
// candidates some return left unsettled or only opaquely settled.
type batchWalk struct {
	ids                 guardIDs
	formats             guardFormats
	batch               ObligationBatch
	policy              SuccessorPolicy
	all                 ObligationMask
	violated, uncertain ObligationMask
	edges               []SuccessorEdge
	next                []batchState
}

// stopAtCutoff leaves every candidate not yet violated uncertain.
func (walk *batchWalk) stopAtCutoff() bool {
	if !walk.batch.Flow.Budget.Exhausted() {
		return false
	}
	walk.uncertain |= walk.all &^ walk.violated
	return true
}

func (walk *batchWalk) step(state batchState) ([]batchState, bool) {
	flow := walk.batch.Flow
	for _, instruction := range state.block.Instrs[state.index:] {
		if !flow.Budget.Spend() {
			return nil, false
		}
		if !walk.instruction(&state, instruction) {
			return nil, false
		}
		if walk.violated == walk.all {
			return nil, false
		}
		if InstructionTerminatesWithin(instruction, flow.Terminates, flow.Budget) {
			return nil, !walk.stopAtCutoff()
		}
		if walk.stopAtCutoff() {
			return nil, false
		}
	}
	edges := walk.policy.appendEdgesWithFormats(walk.edges[:0], state.block, state.predecessor, state.guards, flow.Budget, &walk.formats)
	walk.edges = edges
	if walk.stopAtCutoff() {
		return nil, false
	}
	next := walk.next[:0]
	for _, edge := range edges {
		exact, unknown := state.exact, state.unknown
		if flow.Edge != nil {
			exact, unknown = raise(exact, unknown, flow.Edge(state.block, edge.To), walk.all)
			if walk.stopAtCutoff() {
				return nil, false
			}
		}
		switch edge.Contradiction {
		case GuardStableContradiction:
			continue
		case GuardLoadedContradiction:
			exact, unknown = raise(exact, unknown, ObligationUnknown, walk.all)
		case GuardConsistent:
		}
		next = append(next, batchState{block: edge.To, predecessor: state.block, exact: exact, unknown: unknown, guards: edge.Guards})
	}
	walk.next = next
	return next, true
}

// raise applies one action to every candidate, as max does for one.
func raise(exact, unknown ObligationMask, action ObligationAction, all ObligationMask) (ObligationMask, ObligationMask) {
	switch action {
	case ObligationExact:
		return all, 0
	case ObligationUnknown:
		return exact, unknown | all&^exact
	case ObligationNone:
	}
	return exact, unknown
}

// cover adds labels to the masks; an exact label supersedes an opaque one.
func cover(exact, unknown, addExact, addUnknown ObligationMask) (ObligationMask, ObligationMask) {
	exact |= addExact
	return exact, (unknown | addUnknown) &^ exact
}

func (walk *batchWalk) instruction(state *batchState, instruction ssa.Instruction) bool {
	flow := walk.batch.Flow
	state.guards = state.guards.afterWithFormats(instruction, flow.Budget, &walk.formats)
	if walk.stopAtCutoff() {
		return false
	}
	if walk.batch.Instruction != nil {
		addExact, addUnknown := walk.batch.Instruction(instruction)
		state.exact, state.unknown = cover(state.exact, state.unknown, addExact, addUnknown)
		if walk.stopAtCutoff() {
			return false
		}
	}
	returned, ok := instruction.(*ssa.Return)
	if !ok {
		return true
	}
	exact, unknown := state.exact, state.unknown
	if walk.batch.Return != nil {
		addExact, addUnknown := walk.batch.Return(returned)
		exact, unknown = cover(exact, unknown, addExact, addUnknown)
		if walk.stopAtCutoff() {
			return false
		}
	}
	walk.violated |= walk.all &^ (exact | unknown)
	walk.uncertain |= unknown &^ exact
	return true
}
