package calls

import "golang.org/x/tools/go/ssa"

// A summary cut short by recursion depends on the route that reached the
// cycle, so a memo cannot keep it, and a densely recursive package is then
// re-walked once per route. Summaries with budgets of their own cannot rely
// on a shared allowance to stop that, so they treat recursion by component
// instead: a call into a function whose strongly connected component of the
// static call graph is already being summarized gets the recursive answer
// whatever route reached it. Each member's summary then depends only on its
// body and the summaries of other components, and is kept like any other.
//
// The graph's edges are the function values a body names: static callees,
// closures, method values and callbacks passed as arguments. A cycle through
// an edge it cannot see, such as a call resolved through an interface, is
// still caught by the route guard and is not kept.

// components numbers the strongly connected components of the static call
// graph, computing each function's component when it is first asked about.
type components struct {
	of    map[*ssa.Function]int
	count int
}

// component returns function's component.
func (graph *components) component(function *ssa.Function) int {
	if id, ok := graph.of[function]; ok {
		return id
	}
	if graph.of == nil {
		graph.of = map[*ssa.Function]int{}
	}
	search := tarjan{graph: graph, index: map[*ssa.Function]int{}, low: map[*ssa.Function]int{}}
	search.visit(function)
	return graph.of[function]
}

// tarjan is one depth-first search for components not numbered yet. A
// function it has seen but not yet numbered is on its stack: the search
// numbers a function exactly when it pops it.
type tarjan struct {
	graph *components
	index map[*ssa.Function]int
	low   map[*ssa.Function]int
	stack []*ssa.Function
}

func (search *tarjan) visit(function *ssa.Function) {
	search.index[function] = len(search.index)
	search.low[function] = search.index[function]
	search.stack = append(search.stack, function)
	for _, callee := range staticReferences(function) {
		if _, numbered := search.graph.of[callee]; numbered {
			continue
		}
		if seen, ok := search.index[callee]; ok {
			search.low[function] = min(search.low[function], seen)
			continue
		}
		search.visit(callee)
		search.low[function] = min(search.low[function], search.low[callee])
	}
	if search.low[function] != search.index[function] {
		return
	}
	id := search.graph.count
	search.graph.count++
	for {
		member := search.stack[len(search.stack)-1]
		search.stack = search.stack[:len(search.stack)-1]
		search.graph.of[member] = id
		if member == function {
			return
		}
	}
}

// staticReferences returns the bodies function names as values, each once,
// in instruction order.
func staticReferences(function *ssa.Function) []*ssa.Function {
	var references []*ssa.Function
	seen := map[*ssa.Function]bool{}
	var operands []*ssa.Value
	for _, block := range function.Blocks {
		for _, instruction := range block.Instrs {
			operands = instruction.Operands(operands[:0])
			for _, operand := range operands {
				callee, ok := (*operand).(*ssa.Function)
				if !ok {
					continue
				}
				callee = ResolvedFunction(callee)
				if callee == nil || len(callee.Blocks) == 0 || seen[callee] {
					continue
				}
				seen[callee] = true
				references = append(references, callee)
			}
		}
	}
	return references
}
