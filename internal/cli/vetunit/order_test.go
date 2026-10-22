package vetunit

import (
	"slices"
	"testing"

	"golang.org/x/tools/go/analysis"
)

func TestSequenceOrdersOnlyPassesThatRun(t *testing.T) {
	chained := map[string]string{"first": "", "second": "first", "third": "second"}
	withoutFirst := map[string]string{"first": "", "second": "", "third": "second"}
	for _, test := range []struct {
		name      string
		arguments []string
		// want lists each pass's added requirement, "" for none.
		want map[string]string
	}{
		{"every root", []string{"gohawk", "unit.cfg"}, chained},
		{"enabled root without the first pass", []string{"gohawk", "-concurrent=true", "unit.cfg"}, withoutFirst},
		{"disabled root", []string{"gohawk", "-lifecycle=false", "unit.cfg"}, withoutFirst},
		{"enabled roots spanning all passes", []string{"gohawk", "-lifecycle", "-concurrent", "unit.cfg"}, chained},
	} {
		t.Run(test.name, func(t *testing.T) {
			first := &analysis.Analyzer{Name: "first"}
			second := &analysis.Analyzer{Name: "second"}
			third := &analysis.Analyzer{Name: "third"}
			roots := []*analysis.Analyzer{
				{Name: "lifecycle", Requires: []*analysis.Analyzer{first}},
				{Name: "concurrent", Requires: []*analysis.Analyzer{second, third}},
			}
			passes := []*analysis.Analyzer{first, second, third}
			Sequence(test.arguments, roots, passes)
			for _, pass := range passes {
				var added string
				if len(pass.Requires) > 0 {
					added = pass.Requires[len(pass.Requires)-1].Name
				}
				if added != test.want[pass.Name] {
					t.Errorf("%s requires %q, want %q", pass.Name, added, test.want[pass.Name])
				}
			}
			if slices.Contains(third.Requires, first) {
				t.Error("a pass skipped its predecessor and required an earlier one")
			}
		})
	}
}
