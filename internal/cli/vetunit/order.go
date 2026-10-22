package vetunit

import (
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// Sequence makes the passes that will run in this unit run one after another,
// in the given order, by making each require the previous one that runs.
//
// unitchecker runs analyzers whose requirements are met concurrently. Passes
// that share process-wide state, such as the heap model's summary registry and
// graph cache, can then publish facts that depend on goroutine scheduling.
// Requirements order them without any waiting of gohawk's own, so a pass that
// does not run cannot leave another waiting.
//
// An edge is added only between passes that will run anyway, so selecting a
// subset never pays for a pass it did not ask for. The selection mirrors
// unitchecker's: if any analyzer flag is true only those roots run, otherwise
// roots set false are dropped. Were the mirror ever wrong, an extra pass would
// run; nothing would wait forever. Call it before unitchecker parses its
// flags, while the analyzer graph can still change.
func Sequence(arguments []string, roots, passes []*analysis.Analyzer) {
	running := closure(selectedRoots(arguments, roots))
	var previous *analysis.Analyzer
	for _, pass := range passes {
		if !running[pass] {
			continue
		}
		if previous != nil && !requires(pass, previous) {
			pass.Requires = append(pass.Requires, previous)
		}
		previous = pass
	}
}

// selectedRoots applies unitchecker's analyzer flags, -NAME and -NAME=BOOL,
// to the roots. Flags that do not name a root are ignored.
func selectedRoots(arguments []string, roots []*analysis.Analyzer) []*analysis.Analyzer {
	byName := make(map[string]*analysis.Analyzer, len(roots))
	for _, root := range roots {
		byName[root.Name] = root
	}
	enabled := map[*analysis.Analyzer]bool{}
	disabled := map[*analysis.Analyzer]bool{}
	for _, argument := range arguments {
		if argument == "--" {
			break
		}
		if !strings.HasPrefix(argument, "-") {
			continue
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(argument, "-"), "=")
		root, ok := byName[name]
		if !ok {
			continue
		}
		on := true
		if hasValue {
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				continue
			}
			on = parsed
		}
		if on {
			enabled[root] = true
		} else {
			disabled[root] = true
		}
	}
	var selected []*analysis.Analyzer
	for _, root := range roots {
		if len(enabled) > 0 && !enabled[root] || len(enabled) == 0 && disabled[root] {
			continue
		}
		selected = append(selected, root)
	}
	return selected
}

func closure(roots []*analysis.Analyzer) map[*analysis.Analyzer]bool {
	seen := map[*analysis.Analyzer]bool{}
	var visit func(*analysis.Analyzer)
	visit = func(analyzer *analysis.Analyzer) {
		if seen[analyzer] {
			return
		}
		seen[analyzer] = true
		for _, required := range analyzer.Requires {
			visit(required)
		}
	}
	for _, root := range roots {
		visit(root)
	}
	return seen
}

// requires reports whether analyzer already depends on other, directly or
// through its own requirements.
func requires(analyzer, other *analysis.Analyzer) bool {
	return closure([]*analysis.Analyzer{analyzer})[other] && analyzer != other
}
