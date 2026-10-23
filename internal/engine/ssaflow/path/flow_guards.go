package path

import (
	"fmt"
	"go/token"
	"go/types"
	"slices"
	"strings"

	proofs "github.com/kojah/gohawk/internal/engine/proof"
	ssaflow "github.com/kojah/gohawk/internal/engine/ssaflow"
	cfg "github.com/kojah/gohawk/internal/engine/ssaflow/cfg"
	"golang.org/x/tools/go/ssa"
)

// Path guards remember which way a branch went on the path being walked, so
// that a later branch on the same condition can be related to it. Two kinds
// of condition have an identity. A stable one compares parameters and
// constants, or is a Boolean computed once outside any cycle: its value
// cannot change within the invocation, so a path that takes the other arm
// later is infeasible. A loaded one reads a cell through an address path:
// a store the analysis does not see could change it, so a later
// contradiction is uncertainty, never proof that the path cannot run. The
// engine records both kinds and reports which kind a contradiction is; each
// walk decides what to do with it, because pruning a path and calling it
// unknown are different claims with different risks.
//
// Two representative shapes, from opposite sides of the same policy:
// mutagen guards a profiler's creation and its finalization on one
// address-taken flag, and geesefs locks and unlocks under one five-way
// disjunction of pointer parameters.
// https://github.com/mutagen-io/mutagen/blob/6ccfeaaf4dfd261e59ef9aac56e3c157b62e605b/tools/scan_bench/main.go#L140-L172
// https://github.com/yandex-cloud/geesefs/blob/dd847771b29b26f3246edaf3227acbc430f4548d/core/file.go#L1901-L1972

// GuardLimit bounds the guards one path carries so the state space stays
// small; a guard beyond the limit is simply not remembered, which loses a
// correlation but never invents one.
const GuardLimit = 8

// PathGuard is one branch outcome the path established.
type PathGuard struct {
	Identity string
	Value    bool
	// Stable is true for a guard whose value cannot change within the
	// invocation; false for one read from a cell.
	Stable bool
}

// PathGuards is the sorted, bounded set of guards a path carries.
type PathGuards []PathGuard

// GuardContradiction is how an edge relates to the guards already held.
type GuardContradiction uint8

const (
	// GuardConsistent: the edge agrees with, or is unrelated to, every guard.
	GuardConsistent GuardContradiction = iota
	// GuardStableContradiction: the edge takes the other arm of a stable
	// guard, so no execution reaches it on this path.
	GuardStableContradiction
	// GuardLoadedContradiction: the edge takes the other arm of a loaded
	// guard, which a hidden store could explain; the edge is uncertain.
	GuardLoadedContradiction
)

// guardConditionWithin decodes condition identity, polarity and stability.
// An interrupted decode supplies no identity or path-pruning evidence.
func guardConditionWithin(condition ssa.Value, budget *proofs.SearchBudget) (identity string, negated, stable, ok bool) {
	return guardConditionWithFormats(condition, budget, nil)
}

func guardConditionWithFormats(condition ssa.Value, budget *proofs.SearchBudget, formats *guardFormats) (identity string, negated, stable, ok bool) {
	condition, inverted := ssaflow.BooleanNegationSourceWithin(condition, budget)
	if budget.Exhausted() {
		return "", false, false, false
	}
	identity, negated, stable, ok = guardConditionSource(condition, budget, formats)
	if budget.Exhausted() {
		return "", false, false, false
	}
	return identity, negated != inverted, stable, ok
}

func guardConditionSource(condition ssa.Value, budget *proofs.SearchBudget, formats *guardFormats) (identity string, negated, stable, ok bool) {
	if identity, negated, ok := loadedGuard(condition, budget, formats); ok {
		return identity, negated, false, true
	}
	return decideStableGuard(condition, budget)
}

// Computed stability is one bounded cycle query. Keep it separate from the
// ordered operand proof: failed left evidence must not query the right operand.
func computedGuard(condition ssa.Value, budget *proofs.SearchBudget) (string, bool) {
	// A computed Boolean outside a cycle is evaluated once, so repeating that
	// exact SSA value cannot change its truth, including a short-circuit phi.
	// A loop instruction is not correlated across iterations: its next
	// evaluation may differ even though its SSA node is the same.
	// https://github.com/pb33f/libopenapi/blob/07795ddc2c097af8581138ef290d6cf964110d74/index/extract_refs_lookup.go#L199-L220
	if instruction, ok := condition.(ssa.Instruction); ok && booleanValue(condition) {
		cyclic := cfg.BlockInCycleWithin(instruction.Block(), budget)
		if !cyclic && !budget.Exhausted() {
			return guardValueIdentity(condition), true
		}
	}
	return "", false
}

func stableEquality(left, right ssa.Value) string {
	first, second := guardOperandIdentity(left), guardOperandIdentity(right)
	if second < first {
		first, second = second, first
	}
	return "eq(" + first + "," + second + ")"
}

type (
	stableGuardSignature  func(ssa.Value, *proofs.SearchBudget) (string, bool, bool, bool)
	loadedGuardSignature  func(ssa.Value, *proofs.SearchBudget, *guardFormats) (string, bool, bool)
	addressGuardSignature func(ssa.Value) (guardAddressKind, ssa.Value)
)

var (
	_ stableGuardSignature  = decideStableGuard
	_ loadedGuardSignature  = loadedGuard
	_ addressGuardSignature = recognizeGuardAddress
)

// guardAddressKind selects the structural step; traversal and memo writes are
// applied afterward so recognition never spends or mutates formatting state.
type guardAddressKind uint8

const (
	guardAddressAbsent guardAddressKind = iota
	guardAddressRoot
	guardAddressProjection
)

const (
	guardLoadToken     = token.MUL
	guardEqualToken    = token.EQL
	guardNotEqualToken = token.NEQ
)

func guardValueIdentity(value ssa.Value) string { return fmt.Sprintf("value:%p", value) }

func guardNegated(op token.Token) bool { return op == token.NEQ }

// guardAddressIdentityWithin names a cell by its selected address/load path.
func guardAddressIdentityWithin(address ssa.Value, budget *proofs.SearchBudget) (string, bool) {
	return guardAddressIdentityWithFormats(address, budget, nil)
}

func guardAddressIdentityWithFormats(address ssa.Value, budget *proofs.SearchBudget, formats *guardFormats) (string, bool) {
	if !budget.Spend() {
		return "", false
	}
	kind, source := recognizeGuardAddress(address)
	switch kind {
	case guardAddressRoot:
		return formats.addressIdentity(address, "", true), true
	case guardAddressProjection:
		inner, ok := guardAddressIdentityWithFormats(source, budget, formats)
		return formats.addressIdentity(address, inner, ok), ok
	case guardAddressAbsent:
	}
	return "", false
}

// A call result outside a cycle is computed once per invocation, like a
// parameter, so comparing it twice compares the same value: two checks of one
// err agree.
func stableOperandWithin(value ssa.Value, budget *proofs.SearchBudget) bool {
	if !budget.Spend() {
		return false
	}
	switch value := value.(type) {
	case *ssa.Parameter, *ssa.Const:
		return true
	case *ssa.Call:
		return !cfg.BlockInCycleWithin(value.Block(), budget) && !budget.Exhausted()
	case *ssa.Extract:
		call, ok := value.Tuple.(*ssa.Call)
		return ok && !cfg.BlockInCycleWithin(call.Block(), budget) && !budget.Exhausted()
	}
	return false
}

func guardOperandIdentity(value ssa.Value) string {
	switch typed := value.(type) {
	case *ssa.Parameter:
		return fmt.Sprintf("param:%p", typed)
	case *ssa.Call, *ssa.Extract:
		return fmt.Sprintf("result:%p", typed)
	case *ssa.Const:
		if typed.Value == nil {
			return "nil:" + types.TypeString(typed.Type(), nil)
		}
		return typed.Value.ExactString()
	}
	return fmt.Sprintf("%T:%p", value, value)
}

func booleanValue(value ssa.Value) bool {
	basic, ok := value.Type().Underlying().(*types.Basic)
	return ok && basic.Info()&types.IsBoolean != 0
}

// ExtendWithin shares guard decoding and comparison with budget. Incomplete
// guards or contradictions are unavailable; callers must check exhaustion.
func (guards PathGuards) ExtendWithin(
	block, successor *ssa.BasicBlock, keep func(PathGuard) bool, budget *proofs.SearchBudget,
) (PathGuards, GuardContradiction) {
	return guards.extendWithFormats(block, successor, keep, budget, nil)
}

func (guards PathGuards) extendWithFormats(
	block, successor *ssa.BasicBlock, keep func(PathGuard) bool, budget *proofs.SearchBudget, formats *guardFormats,
) (PathGuards, GuardContradiction) {
	if len(block.Succs) != 2 || len(block.Instrs) == 0 {
		return guards, GuardConsistent
	}
	branch, ok := block.Instrs[len(block.Instrs)-1].(*ssa.If)
	if !ok {
		return guards, GuardConsistent
	}
	identity, negated, stable, ok := guardConditionWithFormats(branch.Cond, budget, formats)
	if budget.Exhausted() {
		return nil, GuardConsistent
	}
	if !ok {
		return guards, GuardConsistent
	}
	guard := PathGuard{Identity: identity, Value: (successor == block.Succs[0]) != negated, Stable: stable}
	if keep != nil && !keep(guard) {
		return guards, GuardConsistent
	}
	for _, held := range guards {
		if !budget.Spend() {
			return nil, GuardConsistent
		}
		if held.Identity != identity {
			continue
		}
		if held.Value == guard.Value {
			return guards, GuardConsistent
		}
		if stable {
			return guards, GuardStableContradiction
		}
		return guards, GuardLoadedContradiction
	}
	if len(guards) >= GuardLimit {
		return guards, GuardConsistent
	}
	// Guards stay sorted by identity and the new one is absent, so it goes
	// in at its place in one exact allocation.
	at, _ := slices.BinarySearchFunc(guards, identity, func(held PathGuard, identity string) int { return strings.Compare(held.Identity, identity) })
	next := make(PathGuards, len(guards)+1)
	copy(next, guards[:at])
	next[at] = guard
	copy(next[at+1:], guards[at:])
	return next, GuardConsistent
}

// forgetWithin drops guards about the stored cell and paths above/beneath it.
func (guards PathGuards) forgetWithin(store *ssa.Store, budget *proofs.SearchBudget, formats *guardFormats) PathGuards {
	address, ok := guardAddressIdentityWithFormats(store.Addr, budget, formats)
	if budget.Exhausted() {
		return nil
	}
	if !ok {
		return guards
	}
	return guards.withoutIdentityWithin(address, budget)
}

// Store invalidation and rerun-result invalidation share the same exact
// identity filtering; neither may keep a partial guard list at cutoff.
func (guards PathGuards) withoutIdentityWithin(identity string, budget *proofs.SearchBudget) PathGuards {
	if len(guards) > GuardLimit {
		return guards.withoutIdentityInto(nil, identity, budget)
	}
	// Collect the bounded list on the stack, then detach the retained
	// entries. Guard lists are never written in place, and every extension
	// clones first, so an unchanged list is returned itself, clipped so an
	// append to it reallocates; copying it was most of what a store's guard
	// invalidation allocated.
	var buffer [GuardLimit]PathGuard
	kept := guards.withoutIdentityInto(buffer[:0], identity, budget)
	if len(kept) == 0 {
		return nil
	}
	if len(kept) == len(guards) {
		return slices.Clip(guards)
	}
	result := make(PathGuards, len(kept))
	copy(result, kept)
	return result
}

// withoutIdentityInto owns filtering and its charges for both bounded and
// oversized inputs. A cutoff never publishes the partially collected guards.
func (guards PathGuards) withoutIdentityInto(kept PathGuards, identity string, budget *proofs.SearchBudget) PathGuards {
	for _, guard := range guards {
		if !budget.Spend() {
			return nil
		}
		if !strings.Contains(guard.Identity, identity) {
			kept = append(kept, guard)
		}
	}
	return kept
}

// AfterWithin shares guard invalidation with budget. A cutoff cannot establish
// that the remaining guards hold; callers must check exhaustion.
func (guards PathGuards) AfterWithin(instruction ssa.Instruction, budget *proofs.SearchBudget) PathGuards {
	return guards.afterWithFormats(instruction, budget, nil)
}

func (guards PathGuards) afterWithFormats(instruction ssa.Instruction, budget *proofs.SearchBudget, formats *guardFormats) PathGuards {
	switch typed := instruction.(type) {
	case *ssa.Store:
		return guards.forgetWithin(typed, budget, formats)
	case *ssa.Call, *ssa.Extract:
		if len(guards) == 0 {
			return nil
		}
		identity := formats.addressIdentity(typed.(ssa.Value), "", true)
		return guards.withoutIdentityWithin(identity, budget)
	}
	return guards
}

// KeyWithin charges guard entries before rendering. An exhausted partial key
// must not enter a visited set; a nil budget retains the default policy.
func (guards PathGuards) KeyWithin(budget *proofs.SearchBudget) string {
	if len(guards) == 0 {
		return ""
	}
	capacity := 0
	for index, guard := range guards {
		if !budget.Spend() {
			return ""
		}
		capacity = pathGuardKeyCapacity(capacity, len(guard.Identity), guard.Value, index > 0)
	}
	var key strings.Builder
	if capacity > 0 {
		key.Grow(capacity)
	}
	for index, guard := range guards {
		if index > 0 {
			key.WriteByte(';')
		}
		key.WriteString(guard.Identity)
		key.WriteByte('=')
		if guard.Value {
			key.WriteString("true")
		} else {
			key.WriteString("false")
		}
	}
	return key.String()
}

// An oversized key disables the allocation hint; it must never wrap into a
// negative Grow argument or an incorrectly small positive capacity.
func pathGuardKeyCapacity(size, identityBytes int, value, separator bool) int {
	if size < 0 {
		return -1
	}
	suffix := len("=false")
	if value {
		suffix = len("=true")
	}
	if separator {
		suffix++
	}
	maxInt := int(^uint(0) >> 1)
	if identityBytes > maxInt-size-suffix {
		return -1
	}
	return size + identityBytes + suffix
}
