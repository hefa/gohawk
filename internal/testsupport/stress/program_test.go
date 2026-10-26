//go:build stress

package stress

import (
	"fmt"
	"strings"
)

// A program generator for the fuzz target. The fuzzer's bytes are read as a
// sequence of choices, and every sequence produces a package that type
// checks: the generator declares its variables up front, gives each
// statement only the context it is valid in (break inside a loop, a result
// in a function that has one), and never declares a name it does not use.
//
// The package imports nothing, so an iteration analyzes only itself, but it
// uses the constructs the analyzers reason about: pointers and fields,
// closures, goroutines, channels, select, defers, recover, maps, slices,
// function values and recursion.

const (
	maxFunctions  = 4
	maxStatements = 300
	maxDepth      = 8
	maxExprDepth  = 3
	variables     = 4
)

const programHeader = `package fuzz

type T struct {
	a, b *T
	c    chan *T
	f    func(*T) *T
	m    map[int]*T
	s    []*T
	n    int
}

var global *T

`

type generator struct {
	data       []byte
	pos        int
	out        strings.Builder
	functions  int
	statements int
}

// frame is what a statement may use where it is emitted.
type frame struct {
	depth     int
	breakable bool // inside a loop, switch or select
	loop      bool // inside a loop, so continue is valid
	result    bool // the enclosing function returns *T
}

// generateProgram turns fuzz bytes into a type-correct Go package.
func generateProgram(data []byte) string {
	g := &generator{data: data}
	g.functions = 1 + g.choose(maxFunctions)
	g.out.WriteString(programHeader)
	for index := range g.functions {
		fmt.Fprintf(&g.out, "func g%d(x, y *T, n int) *T {\n", index)
		g.linef(1, "v0, v1, v2, v3 := x, y, (*T)(nil), &T{}")
		g.linef(1, "ch := make(chan *T, 1)")
		g.linef(1, "done := make(chan struct{})")
		g.linef(1, "_, _, _, _, _, _ = v0, v1, v2, v3, ch, done")
		g.block(frame{depth: 1, result: true})
		g.linef(1, "return v0")
		g.out.WriteString("}\n\n")
	}
	return g.out.String()
}

// choose reads the next choice in [0, n); exhausted input reads as zero.
func (g *generator) choose(n int) int {
	if g.pos >= len(g.data) {
		return 0
	}
	value := int(g.data[g.pos]) % n
	g.pos++
	return value
}

func (g *generator) exhausted() bool {
	return g.pos >= len(g.data) || g.statements >= maxStatements
}

func (g *generator) linef(depth int, format string, arguments ...any) {
	g.out.WriteString(strings.Repeat("\t", depth))
	fmt.Fprintf(&g.out, format, arguments...)
	g.out.WriteByte('\n')
}

func (g *generator) variable() string {
	return fmt.Sprintf("v%d", g.choose(variables))
}

// block emits statements until the input says to close the block. A nested
// block closes on one choice in eight, so depth stays modest.
func (g *generator) block(at frame) {
	for !g.exhausted() {
		if at.depth > 1 && g.choose(8) == 0 {
			return
		}
		g.statement(at)
	}
}

// pointer emits an expression of type *T.
func (g *generator) pointer(depth int) string {
	choices := 6
	if depth < maxExprDepth {
		choices = 12
	}
	switch g.choose(choices) {
	case 0, 1:
		return g.variable()
	case 2:
		return g.variable() + ".a"
	case 3:
		return g.variable() + ".b"
	case 4:
		return "global"
	case 5:
		return "new(T)"
	case 6:
		return fmt.Sprintf("&T{a: %s, n: n}", g.pointer(depth+1))
	case 7:
		return fmt.Sprintf("g%d(%s, %s, n-1)", g.choose(g.functions), g.pointer(depth+1), g.pointer(depth+1))
	case 8:
		return fmt.Sprintf("%s.f(%s)", g.variable(), g.pointer(depth+1))
	case 9:
		return "<-ch"
	case 10:
		return g.variable() + ".m[n]"
	default:
		return g.variable() + ".s[n]"
	}
}

func (g *generator) statement(at frame) {
	g.statements++
	d := at.depth
	kinds := 16
	if at.depth < maxDepth {
		kinds = 26
	}
	switch g.choose(kinds) {
	case 0, 1:
		g.linef(d, "%s = %s", g.variable(), g.pointer(0))
	case 2:
		g.linef(d, "%s.%s = %s", g.variable(), []string{"a", "b"}[g.choose(2)], g.pointer(0))
	case 3:
		g.linef(d, "global = %s", g.pointer(0))
	case 4:
		g.linef(d, "ch <- %s", g.pointer(0))
	case 5:
		g.linef(d, "%s.c <- %s", g.variable(), g.variable())
	case 6:
		g.linef(d, "%s = <-%s.c", g.variable(), g.variable())
	case 7:
		g.linef(d, "%s.m = map[int]*T{n: %s}", g.variable(), g.pointer(0))
	case 8:
		g.linef(d, "%s.m[n] = %s", g.variable(), g.pointer(0))
	case 9:
		g.linef(d, "%s.s = append(%s.s, %s)", g.variable(), g.variable(), g.pointer(0))
	case 10:
		g.linef(d, "%s.c = make(chan *T, n)", g.variable())
	case 11:
		g.linef(d, "%s", []string{"close(ch)", "close(done)", "<-done", "n++"}[g.choose(4)])
	case 12:
		g.linef(d, "_ = g%d(%s, %s, n-1)", g.choose(g.functions), g.pointer(0), g.pointer(0))
	case 13:
		g.linef(d, "n = %s.n", g.variable())
	case 14:
		g.jump(at)
	case 15:
		g.linef(d, "if %s == nil {", g.variable())
		g.linef(d+1, `panic("nil")`)
		g.linef(d, "}")
	default:
		g.compound(at)
	}
}

// jump emits a statement that leaves the current block, if one is valid.
func (g *generator) jump(at frame) {
	switch {
	case at.loop && g.choose(2) == 0:
		g.linef(at.depth, "continue")
	case at.breakable && g.choose(2) == 0:
		g.linef(at.depth, "break")
	case at.result:
		g.linef(at.depth, "return %s", g.pointer(0))
	default:
		g.linef(at.depth, "return")
	}
}

// loop emits one of the loop forms, whose body may break and continue.
func (g *generator) loop(at frame) {
	d := at.depth
	body := frame{depth: d + 1, breakable: true, loop: true, result: at.result}
	switch g.choose(3) {
	case 0:
		g.linef(d, "for range n {")
	case 1:
		variable := g.variable()
		g.linef(d, "for %s != nil {", variable)
		g.linef(d+1, "%s = %s.a", variable, variable)
	default:
		g.linef(d, "for _, e := range %s.s {", g.variable())
		g.linef(d+1, "%s = e", g.variable())
	}
	g.block(body)
	g.linef(d, "}")
}

// compound emits a statement with nested blocks.
func (g *generator) compound(at frame) {
	d := at.depth
	inner := frame{depth: d + 1, breakable: at.breakable, loop: at.loop, result: at.result}
	closure := frame{depth: d + 1}
	switch g.choose(8) {
	case 0:
		g.linef(d, "if %s == (%s) {", g.variable(), g.pointer(0))
		g.block(inner)
		g.linef(d, "} else {")
		g.block(inner)
		g.linef(d, "}")
	case 1:
		g.loop(at)
	case 2:
		g.linef(d, "switch n %% 3 {")
		for _, label := range []string{"case 0:", "case 1:", "default:"} {
			g.linef(d, "%s", label)
			g.block(frame{depth: d + 1, breakable: true, loop: at.loop, result: at.result})
		}
		g.linef(d, "}")
	case 3:
		g.linef(d, "select {")
		g.linef(d, "case %s = <-ch:", g.variable())
		g.block(frame{depth: d + 1, breakable: true, loop: at.loop, result: at.result})
		g.linef(d, "case ch <- %s:", g.variable())
		g.block(frame{depth: d + 1, breakable: true, loop: at.loop, result: at.result})
		g.linef(d, "default:")
		g.block(frame{depth: d + 1, breakable: true, loop: at.loop, result: at.result})
		g.linef(d, "}")
	case 4:
		g.linef(d, "go func() {")
		g.block(closure)
		g.linef(d, "}()")
	case 5:
		g.linef(d, "defer func() {")
		if g.choose(2) == 0 {
			g.linef(d+1, "_ = recover()")
		}
		g.block(closure)
		g.linef(d, "}()")
	case 6:
		g.linef(d, "%s.f = func(p *T) *T {", g.variable())
		g.block(frame{depth: d + 1, result: true})
		g.linef(d+1, "return p")
		g.linef(d, "}")
	default:
		g.linef(d, "{")
		g.linef(d+1, "w := *%s", g.variable())
		g.linef(d+1, "w.b = %s", g.pointer(0))
		g.linef(d+1, "%s = &w", g.variable())
		g.block(inner)
		g.linef(d, "}")
	}
}
