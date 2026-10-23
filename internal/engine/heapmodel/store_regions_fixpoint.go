package heapmodel

import (
	"slices"
	"strconv"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// The fixpoint runs the transfer over a function's blocks in reverse
// postorder, round after round, until no block's out state changes, widening
// loop headers once the plain rounds have not settled.

// regionBuildBudget bounds the instruction transfers one graph may spend,
// across every fixpoint round. A function past it is unavailable rather
// than half-modeled.
const regionBuildBudget = 200_000

// regionFixpointRounds bounds the plain rounds over the blocks. Ordinary
// loops settle in two or three. A body that has not settled by then is
// widened; one that has settled is never widened, so its graph is exactly
// the least fixpoint the plain rounds compute.
const regionFixpointRounds = 6

// regionWideningRounds bounds the rounds after widening starts. Widening
// only coarsens a loop header's entry, so a body settles within a few more
// rounds or is unavailable. Escapes are left to grow: they accumulate over
// finitely many slots, but can take a step a round to cross nested maps, as
// caddy's httpcaddyfile mapAddressToProtocolToServerBlocks needs eight.
const regionWideningRounds = 8

// fixpoint runs the transfer over the blocks in reverse postorder until the
// entry states settle, and reports whether they did within the bounds.
func (graph *regionGraph) fixpoint() (GraphBuildReason, string) {
	function := graph.function
	if len(function.Blocks) == 0 {
		return GraphBuildNoBody, ""
	}
	graph.entry[function.Blocks[0]] = newRegionState()
	graph.runs = newBlockRuns()
	defer func() { graph.runs = nil }()
	out := map[*ssa.BasicBlock]*regionState{}
	headers := loopHeaders(function)
	acyclic := !hasRetreatingEdge(graph.order, len(function.Blocks))
	// unsettled explains a body that never settles: the blocks that still
	// changed in the last round. Earlier rounds change on every ordinary
	// loop, and describing those differences cost more than the transfers.
	var unsettled []string
	var previous *loopSnapshot
	rounds := regionFixpointRounds + regionWideningRounds
	unspent := graph.budget.Remaining()
	for round := range rounds {
		last := round == rounds-1
		graph.widening = previous
		// Snapshots start one round before widening, so the first widened
		// round can tell what the last plain round still changed.
		var current *loopSnapshot
		if round >= regionFixpointRounds-1 {
			current = newLoopSnapshot()
		}
		changed := false
		for _, block := range graph.order {
			in := graph.entryState(block, out)
			if in == nil {
				continue
			}
			if headers[block] {
				if previous != nil {
					graph.widen(in, previous.entries[block], block)
				}
				if current != nil {
					current.recordEntry(block, in)
				}
			}
			state, ok := graph.runBlock(block, in, headers[block])
			if !ok {
				return GraphBuildBudgetExhausted, ""
			}
			if previous, ok := out[block]; !ok || !previous.equal(state) {
				changed = true
				if ok && last {
					unsettled = append(unsettled, "block "+strconv.Itoa(block.Index)+": "+previous.difference(state))
				}
			}
			out[block] = state
		}
		if !changed || round == 0 && acyclic {
			return graph.settle(out, changed, unspent-graph.budget.Remaining())
		}
		if current != nil {
			current.recordPhis(graph, headers)
		}
		previous = current
	}
	graph.widening = nil
	return GraphBuildFixpointLimit, "in " + strconv.Itoa(rounds) + " rounds; changes: " + strings.Join(unsettled, " | ")
}

// entryState merges the predecessors' out states into the block's entry
// state, marking back edges, and returns nil for a block nothing reaches yet.
func (graph *regionGraph) entryState(block *ssa.BasicBlock, out map[*ssa.BasicBlock]*regionState) *regionState {
	if block == graph.function.Blocks[0] {
		return graph.entry[block]
	}
	if shared := soleForwardEntry(block, out); shared != nil {
		graph.entry[block] = shared
		return shared
	}
	var merged *regionState
	for _, predecessor := range block.Preds {
		state, ok := out[predecessor]
		if !ok {
			continue
		}
		if merged == nil {
			merged = state.clone()
			if block.Dominates(predecessor) {
				graph.merge(merged, state, true, block)
			}
			continue
		}
		graph.merge(merged, state, block.Dominates(predecessor), block)
	}
	if merged == nil {
		return nil
	}
	graph.entry[block] = merged
	return merged
}

// soleForwardEntry returns the out state of a block's only reached
// predecessor when no back edge enters the block. Its entry is then that
// state unchanged, so it is shared rather than cloned: nothing writes an out
// state once stored, the transfer works on its own clone, and a block a back
// edge enters, whose entry widening may change, never shares.
func soleForwardEntry(block *ssa.BasicBlock, out map[*ssa.BasicBlock]*regionState) *regionState {
	var sole *regionState
	for _, predecessor := range block.Preds {
		if block.Dominates(predecessor) {
			return nil
		}
		state, ok := out[predecessor]
		if !ok {
			continue
		}
		if sole != nil {
			return nil
		}
		sole = state
	}
	return sole
}

func reversePostorder(function *ssa.Function) []*ssa.BasicBlock {
	seen := map[*ssa.BasicBlock]bool{}
	var order []*ssa.BasicBlock
	var visit func(block *ssa.BasicBlock)
	visit = func(block *ssa.BasicBlock) {
		if seen[block] {
			return
		}
		seen[block] = true
		for _, successor := range block.Succs {
			visit(successor)
		}
		order = append(order, block)
	}
	visit(function.Blocks[0])
	for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
		order[i], order[j] = order[j], order[i]
	}
	return order
}

// Loop widening. A loop that walks a structure reads one more unwritten
// level each round, minting a placeholder for content(content(…)); a loop
// whose effects carry different stamps reads the same slot as a new object
// each round. The plain rounds then grow until pointeeLimit collapses each
// set on its own, and large functions did not settle within the bound and
// were unavailable. Once the plain rounds have not settled, every part of a
// loop header's entry, and of its phis, that still changed since the previous
// round takes a value that cannot change again: a pointee set becomes
// unknown, which answers may-queries yes and must-queries no, and a stamp
// becomes the header's own, as a join already stamps disagreeing effects.
// Parts that only grow within finite bounds, such as escapes, settle
// without help.

// loopSnapshot is one round's loop-header entries and phi values, compared
// against in the next widened round.
type loopSnapshot struct {
	entries map[*ssa.BasicBlock]*regionState
	phis    map[*ssa.Phi]pointees
}

func newLoopSnapshot() *loopSnapshot {
	return &loopSnapshot{entries: map[*ssa.BasicBlock]*regionState{}, phis: map[*ssa.Phi]pointees{}}
}

func (snapshot *loopSnapshot) recordEntry(header *ssa.BasicBlock, entry *regionState) {
	snapshot.entries[header] = entry.clone()
}

func (snapshot *loopSnapshot) recordPhis(graph *regionGraph, headers map[*ssa.BasicBlock]bool) {
	for header := range headers {
		for _, instruction := range header.Instrs {
			phi, ok := instruction.(*ssa.Phi)
			if !ok {
				break
			}
			if set, ok := graph.values[phi]; ok {
				snapshot.phis[phi] = set.clone()
			}
		}
	}
}

// loopHeaders returns the blocks a back edge enters: a predecessor the block
// dominates. The entry block has no predecessors, so it is never one.
func loopHeaders(function *ssa.Function) map[*ssa.BasicBlock]bool {
	headers := map[*ssa.BasicBlock]bool{}
	for _, block := range function.Blocks {
		for _, predecessor := range block.Preds {
			if block.Dominates(predecessor) {
				headers[block] = true
			}
		}
	}
	return headers
}

// widen coarsens a loop header's entry wherever it differs from the previous
// round's widened entry, so the next round cannot change it again.
func (graph *regionGraph) widen(state, previous *regionState, header *ssa.BasicBlock) {
	if previous == nil {
		return
	}
	stamp := graph.blockID(header)
	for target, set := range state.contents {
		if old, ok := previous.contents[target]; ok && old.equal(set) || set.unknown() {
			continue
		}
		graph.widened = append(graph.widened, widening{target: target, size: set.Len()})
		state.contents[target] = pointeesOf(graph.unkR.at(""), false)
		state.own(target)
	}
	if state.epoch != previous.epoch {
		state.epoch = stamp
	}
	if state.reachEpoch != previous.reachEpoch {
		state.reachEpoch = stamp
	}
	for step, epoch := range state.stepEpochs {
		if old, ok := previous.stepEpochs[step]; !ok || old != epoch {
			state.mutableStepEpochs()[step] = stamp
		}
	}
	for target, snapshot := range state.backing {
		if previous.backing[target] != snapshot {
			delete(state.mutableBacking(), target)
			if _, ok := state.clobbered[target]; !ok {
				state.mutableClobbered()[target] = stamp
			}
		}
	}
	for target, epoch := range state.clobbered {
		if old, ok := previous.clobbered[target]; !ok || old != epoch {
			state.mutableClobbered()[target] = stamp
		}
	}
	if !state.deferred.equal(previous.deferred) && !state.deferred.unknown() {
		state.deferred = pointeesOf(graph.unkR.at(""), false)
	}
}

// widenPhi coarsens a loop-header phi whose pointees grew since the previous
// round. SSA values are graph-wide, not part of the block states, so a value
// carried around a loop would otherwise keep growing however the states are
// widened.
func (graph *regionGraph) widenPhi(phi *ssa.Phi) {
	if graph.widening == nil {
		return
	}
	old, ok := graph.widening.phis[phi]
	set := graph.values[phi]
	if !ok || old.equal(set) || set.unknown() {
		return
	}
	graph.widened = append(graph.widened, widening{target: graph.opaque(phi).at(""), at: phi, size: set.Len()})
	graph.values[phi] = pointeesOf(graph.unkR.at(""), false)
	graph.markChanged(phi)
}

// Without a retreating edge every block follows all its predecessors in
// reverse postorder, and every value it reads is defined before it, so the
// first round computes each out state from final inputs and a second round
// could only confirm them. It was half of all region graph work. The skipped
// round is still charged to the build budget, so which functions build does
// not change. A transfer's call-effect proofs spend that budget too, so the
// charge is what the first round spent, not one unit per instruction.

// hasRetreatingEdge reports whether an edge leads to a block no later in
// order than its source: a loop, reducible or not.
func hasRetreatingEdge(order []*ssa.BasicBlock, blocks int) bool {
	position := make([]int, blocks)
	for index, block := range order {
		position[block.Index] = index + 1
	}
	for _, block := range order {
		for _, successor := range block.Succs {
			if position[successor.Index] <= position[block.Index] {
				return true
			}
		}
	}
	return false
}

// runBlock transfers a block's instructions over its own copy of in, and
// reports false when the build budget runs out.
func (graph *regionGraph) runBlock(block *ssa.BasicBlock, in *regionState, header bool) (*regionState, bool) {
	runs := graph.runs
	if out, cost, ok := runs.repeat(graph, block, in, header); ok {
		for range cost {
			if !graph.budget.Spend() {
				return nil, false
			}
		}
		return out, true
	}
	runs.seq++
	seq, before := runs.seq, graph.budget.Remaining()
	state := in.clone()
	runs.read, runs.reading = runs.read[:0], true
	for _, instruction := range block.Instrs {
		if !graph.budget.Spend() {
			return nil, false
		}
		graph.transfer(state, instruction)
	}
	runs.reading = false
	runs.last[block] = blockRun{
		in: in, out: state, seq: seq, cost: before - graph.budget.Remaining(), widening: graph.widening != nil, reads: runs.distinctReads(),
	}
	return state, true
}

// A round re-runs every block, but most blocks of a function still settling
// see nothing new: their entry state is the one they last ran from, and no
// value they read from another block has changed since. Their transfer would
// then repeat itself exactly, producing the same out state and adding nothing
// to any value, so the round reuses the last out state instead. It still
// charges what the transfer cost, so the build budget, and with it which
// functions build, does not change. A loop header is always re-run: widening
// changes its entry and phis. So is any block when the round's widening mode
// differs from its last run's, since widening changes how a store through the
// unknown pointer is modeled.
//
// A block's inputs beyond its entry state are the values its transfer looks
// up, which need not be its operands: running defers reads the arguments the
// defer statements bound. So a run records the values it read, and every
// write that changes a value marks it with the sequence number of the run
// that made it; a later run repeats the last one when none of the values it
// read was marked after it.

// blockRuns records each block's last run and when each value last changed;
// read gathers the values the current run looks up while reading is set.
type blockRuns struct {
	seq     int
	changed map[ssa.Value]int
	last    map[*ssa.BasicBlock]blockRun
	read    []ssa.Value
	reading bool
}

// blockRun is a block's last run: what it ran from and produced, the
// sequence number it ran at, what it cost, and whether widening was on.
type blockRun struct {
	in, out  *regionState
	seq      int
	cost     int
	widening bool
	reads    []ssa.Value
}

func newBlockRuns() *blockRuns {
	return &blockRuns{changed: map[ssa.Value]int{}, last: map[*ssa.BasicBlock]blockRun{}}
}

// noteRead records that the current run looked a value up.
func (graph *regionGraph) noteRead(value ssa.Value) {
	if runs := graph.runs; runs != nil && runs.reading {
		runs.read = append(runs.read, value)
	}
}

// distinctReads returns the current run's reads, each once. A block reads
// few values, so a short list is deduplicated in place of a set.
func (runs *blockRuns) distinctReads() []ssa.Value {
	reads := make([]ssa.Value, 0, len(runs.read))
	if len(runs.read) <= distinctReadScan {
		for _, value := range runs.read {
			if !slices.Contains(reads, value) {
				reads = append(reads, value)
			}
		}
		return reads
	}
	seen := make(map[ssa.Value]bool, len(runs.read))
	for _, value := range runs.read {
		if !seen[value] {
			seen[value] = true
			reads = append(reads, value)
		}
	}
	return reads
}

// distinctReadScan bounds the reads deduplicated by scanning.
const distinctReadScan = 32

// markChanged records that a value's pointees, or its slice window or call
// results, just changed. Outside a fixpoint, as when a query replays a block,
// nothing is recorded.
func (graph *regionGraph) markChanged(value ssa.Value) {
	if graph.runs != nil {
		graph.runs.changed[value] = graph.runs.seq
	}
}

// repeat returns the out state and cost of the block's last run when a run
// now would repeat it exactly.
func (runs *blockRuns) repeat(graph *regionGraph, block *ssa.BasicBlock, in *regionState, header bool) (*regionState, int, bool) {
	run, ok := runs.last[block]
	if header || !ok || run.widening != (graph.widening != nil) {
		return nil, 0, false
	}
	for _, value := range run.reads {
		if runs.changed[value] > run.seq {
			return nil, 0, false
		}
	}
	if run.in != in && !run.in.equal(in) {
		return nil, 0, false
	}
	return run.out, run.cost, true
}

// settle accepts the out states. A round that still changed them is the
// first round of a loop-free function, and the confirming round it skips is
// charged as if it ran: that round would repeat the first round's transfers
// from the same states, call-effect proofs included, so it would spend what
// the first round spent.
func (graph *regionGraph) settle(out map[*ssa.BasicBlock]*regionState, changed bool, spent int) (GraphBuildReason, string) {
	graph.widening = nil
	if changed {
		for range spent {
			if !graph.budget.Spend() {
				return GraphBuildBudgetExhausted, ""
			}
		}
	}
	graph.exit = out
	return GraphBuildComplete, ""
}
