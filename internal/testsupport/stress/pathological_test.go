//go:build stress && linux

package stress

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestGoJSON analyzes goccy/go-json, whose generated encoders are single
// functions with thousands of blocks. Before the points-to graph build was
// bounded by the state it copies, this run held 17 to 20 GB
// (https://github.com/kojah/gohawk/issues/51); it now needs a few hundred MB.
func TestGoJSON(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod":  moduleHeader + "\nrequire github.com/goccy/go-json v0.10.5\n",
		"main.go": "package main\n\nimport _ \"github.com/goccy/go-json\"\n\nfunc main() {}\n",
	})
	runGohawk(t, t.TempDir(), dir, limits{memory: 3 << 30, wall: 20 * time.Minute}, "github.com/goccy/go-json/...")
}

// TestGeneratedShapes analyzes programs built to be far larger along one
// axis than ordinary code. Each must finish within a fixed memory limit:
// when a shape outgrows a proof budget, the analysis must give up on it
// rather than grow with it.
func TestGeneratedShapes(t *testing.T) {
	cache := t.TempDir()
	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			dir := writeModule(t, map[string]string{
				"go.mod":   moduleHeader,
				"shape.go": shape.source(),
			})
			runGohawk(t, cache, dir, limits{memory: 2 << 30, wall: 10 * time.Minute}, "./...")
		})
	}
}

type shape struct {
	name   string
	source func() string
}

var shapes = []shape{
	{"opcode switch", func() string { return opcodeSwitch(3000) }},
	{"package initializer", func() string { return packageInitializer(4000) }},
	{"deep nesting", func() string { return deepNesting(300) }},
	{"call chain", func() string { return callChain(3000) }},
	{"goroutine fan-out", func() string { return goroutineFanOut(800) }},
	{"wide struct copies", func() string { return wideStruct(1500) }},
	{"deferred closures", func() string { return deferredClosures(600) }},
}

// opcodeSwitch is the go-json encoder shape: one loop around a switch whose
// every case stores to a different field, so each block's memory state
// differs from its neighbours'.
func opcodeSwitch(cases int) string {
	var b strings.Builder
	b.WriteString("package shape\n\ntype node struct {\n\tnext *node\n")
	for i := range cases {
		fmt.Fprintf(&b, "\tf%d *node\n", i)
	}
	b.WriteString("}\n\nfunc run(code []int, c, value *node) *node {\n\tfor _, op := range code {\n\t\tswitch op {\n")
	for i := range cases {
		fmt.Fprintf(&b, "\t\tcase %d:\n\t\t\tvalue = value.next\n\t\t\tc.f%d = value\n", i, i)
	}
	b.WriteString("\t\t}\n\t}\n\treturn c\n}\n")
	return b.String()
}

// packageInitializer puts thousands of allocations and stores into the
// package's init function, as generated tables and registries do.
func packageInitializer(entries int) string {
	var b strings.Builder
	b.WriteString("package shape\n\ntype node struct {\n\tname string\n\tnext *node\n\tkids map[string]*node\n}\n\n")
	b.WriteString("var table = map[string]*node{\n")
	for i := range entries {
		fmt.Fprintf(&b, "\t\"k%d\": {name: \"n%d\", next: &node{name: \"m%d\"}},\n", i, i, i)
	}
	b.WriteString("}\n\nvar registry = map[int]*node{}\n\nfunc init() {\n")
	for i := range entries {
		fmt.Fprintf(&b, "\tregistry[%d] = &node{next: table[\"k%d\"], kids: map[string]*node{\"x\": table[\"k%d\"]}}\n", i, i, (i+1)%entries)
	}
	b.WriteString("}\n")
	return b.String()
}

// deepNesting alternates conditionals and loops to a great depth. Go's own
// parser stops resolving scopes not far past this depth, so it stays at a
// few hundred levels.
func deepNesting(depth int) string {
	var b strings.Builder
	b.WriteString("package shape\n\ntype node struct{ next *node }\n\nfunc walk(n *node, x int) *node {\n")
	for i := range depth {
		if i%2 == 0 {
			fmt.Fprintf(&b, "if x > %d {\n", i)
		} else {
			fmt.Fprintf(&b, "for range x {\nn = n.next\n")
		}
		b.WriteString("n = &node{next: n}\n")
	}
	for range depth {
		b.WriteString("}\n")
	}
	b.WriteString("return n\n}\n")
	return b.String()
}

// callChain links thousands of functions that pass pointers and channels
// down the chain and back around, so every summary depends on the next.
func callChain(length int) string {
	var b strings.Builder
	b.WriteString("package shape\n\ntype node struct {\n\tnext *node\n\tdone chan struct{}\n}\n\n")
	for i := range length {
		next := (i + 1) % length
		fmt.Fprintf(&b, "func f%d(n *node, depth int) *node {\n\tif depth == 0 {\n\t\treturn n\n\t}\n", i)
		fmt.Fprintf(&b, "\tm := &node{next: n, done: make(chan struct{})}\n\tclose(m.done)\n\treturn f%d(m, depth-1)\n}\n\n", next)
	}
	return b.String()
}

// goroutineFanOut starts hundreds of goroutines in one function, each joined
// through a wait group and a channel and touching shared state under a lock.
func goroutineFanOut(workers int) string {
	var b strings.Builder
	b.WriteString("package shape\n\nimport \"sync\"\n\ntype state struct {\n\tmu sync.Mutex\n\tn  int\n}\n\n")
	b.WriteString("func fan(s *state) int {\n\tvar wg sync.WaitGroup\n\tresults := make(chan int, 1)\n")
	for i := range workers {
		fmt.Fprintf(&b, "\twg.Add(1)\n\tgo func() {\n\t\tdefer wg.Done()\n\t\ts.mu.Lock()\n\t\ts.n += %d\n\t\ts.mu.Unlock()\n", i)
		b.WriteString("\t\tselect {\n\t\tcase results <- s.n:\n\t\tdefault:\n\t\t}\n\t}()\n")
	}
	b.WriteString("\twg.Wait()\n\tclose(results)\n\ttotal := 0\n\tfor value := range results {\n\t\ttotal += value\n\t}\n\treturn total\n}\n")
	return b.String()
}

// wideStruct copies a struct with many pointer fields through a loop, so
// every copy carries a large memory state.
func wideStruct(fields int) string {
	var b strings.Builder
	b.WriteString("package shape\n\ntype node struct{ next *node }\n\ntype wide struct {\n")
	for i := range fields {
		fmt.Fprintf(&b, "\tf%d *node\n", i)
	}
	b.WriteString("}\n\nfunc fill(n *node, rounds int) wide {\n\tvar w wide\n")
	for i := range fields {
		fmt.Fprintf(&b, "\tw.f%d = &node{next: n}\n", i)
	}
	b.WriteString("\tcopies := make([]wide, 0, rounds)\n\tfor range rounds {\n\t\tcurrent := w\n\t\tcopies = append(copies, current)\n")
	b.WriteString("\t\tw.f0, w.f1 = w.f1, w.f0\n\t}\n\treturn copies[len(copies)-1]\n}\n")
	return b.String()
}

// deferredClosures defers hundreds of closures that capture and rewrite the
// same variables, so every return carries a long chain of pending effects.
func deferredClosures(count int) string {
	var b strings.Builder
	b.WriteString("package shape\n\ntype node struct{ next *node }\n\nfunc unwind(n *node) (result *node) {\n\tcurrent := n\n")
	for i := range count {
		b.WriteString("\tdefer func() {\n\t\tif recover() != nil || current == nil {\n")
		b.WriteString("\t\t\tresult = &node{next: current}\n\t\t}\n\t\tcurrent = current.next\n\t}()\n")
		if i%50 == 0 {
			b.WriteString("\tif current == nil {\n\t\treturn nil\n\t}\n")
		}
	}
	b.WriteString("\treturn current\n}\n")
	return b.String()
}
