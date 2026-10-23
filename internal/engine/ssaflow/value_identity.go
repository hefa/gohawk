package ssaflow

import (
	proofs "github.com/kojah/gohawk/internal/engine/proof"
	"golang.org/x/tools/go/ssa"
	// StructurallyIdentical proves value identity from the value graph alone:
	// one SSA value seen through wrappers, a phi whose alternatives all agree,
	// or equal address selections. Distinct loads stay unknown here, even from
	// the same address.
)

func StructurallyIdentical(left, right ssa.Value) bool {
	return StructurallyIdenticalWithin(left, right, nil)
}

// StructurallyIdenticalWithin charges structural comparisons and reaching-value
// visits to budget. A cutoff supplies no identity evidence; false remains
// unproved, never inequality. A nil budget retains the default structural policy.
func StructurallyIdenticalWithin(left, right ssa.Value, budget *proofs.SearchBudget) bool {
	if !budget.Spend() {
		return false
	}
	if left == nil || right == nil {
		return false
	}
	if left == right {
		return true
	}
	forms := TransparentChangeInterface | TransparentChangeType | TransparentConvert | TransparentMakeInterface
	if structuralLeaf(left) && structuralLeaf(right) {
		// Each walk below would spend one visit and fold only its value.
		// Most comparisons are of two such leaves; answer them without the
		// walks, which were most of what reaching folds allocated.
		for range 2 {
			if !budget.Spend() {
				return false
			}
		}
		return identicalLeaves(left, right, budget) && !budget.Exhausted()
	}
	return NewReachingWalk(forms).Within(budget).Every(left, func(_ ReachingWalk, left ssa.Value) bool {
		return NewReachingWalk(forms).Within(budget).Every(right, func(_ ReachingWalk, right ssa.Value) bool {
			return identicalLeaves(left, right, budget)
		})
	})
}

// structuralLeaf reports whether StructurallyIdenticalWithin's walk visits
// only value itself: it is neither a phi nor a form the walk looks through.
func structuralLeaf(value ssa.Value) bool {
	forms := TransparentChangeInterface | TransparentChangeType | TransparentConvert | TransparentMakeInterface
	if _, wrapped := UnwrapTransparentValue(value, forms); wrapped {
		return false
	}
	_, phi := value.(*ssa.Phi)
	return !phi
}

// identicalLeaves compares two values a structural identity walk reached.
func identicalLeaves(left, right ssa.Value, budget *proofs.SearchBudget) bool {
	if left == right {
		return true
	}
	switch left := left.(type) {
	case *ssa.FieldAddr:
		other, ok := right.(*ssa.FieldAddr)
		return ok && left.Field == other.Field && StructurallyIdenticalWithin(left.X, other.X, budget)
	case *ssa.IndexAddr:
		other, ok := right.(*ssa.IndexAddr)
		if !ok || !StructurallyIdenticalWithin(left.X, other.X, budget) {
			return false
		}
		a, aOK := ConstantIndex(left.Index)
		b, bOK := ConstantIndex(other.Index)
		return aOK && bOK && a == b || left.Index == other.Index
	}
	return false
}

type identitySteps = []string

// identitySignature keeps ProveIdentityWithin's native inputs and proof. Roots
// must already be equivalent. Structural identity, both path searches and step
// comparison share budget; cutoff is unknown, never differing-path evidence.
// Traversal remains native; identity.rules owns its order and proof selection.
type identitySignature func(AccessPath, AccessPath, *proofs.SearchBudget) proofs.IdentityProof

var _ identitySignature = ProveIdentityWithin

func unknownIdentity(budget *proofs.SearchBudget) proofs.IdentityProof {
	reason := proofs.EvidenceUnavailable
	if budget.Exhausted() {
		reason = proofs.EvidenceBudgetExhausted
	}
	return identityEvidence(proofs.EvidenceUnknown, reason, 0)
}

func identityEvidence(state proofs.EvidenceState, reason proofs.EvidenceReason, provenance proofs.EvidenceProvenance) proofs.IdentityProof {
	return proofs.IdentityProof{Proof: proofs.Proof{State: state, Reason: reason, Provenance: provenance}}
}

func identityBudgetExhausted(budget *proofs.SearchBudget) bool { return budget.Exhausted() }

const (
	identityProven    = proofs.EvidenceProven
	identityDisproven = proofs.EvidenceDisproven
	identitySameValue = proofs.EvidenceSameValue
	identitySamePath  = proofs.EvidenceSameAccessPath
	identityNotFound  = proofs.EvidenceNotFound
	identityLocalSSA  = proofs.EvidenceFromLocalSSA
)
