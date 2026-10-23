package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	gohawk "github.com/kojah/gohawk/analyzers"
	"github.com/kojah/gohawk/internal/analysis/passes/concurrencyfacts"
	"github.com/kojah/gohawk/internal/analysis/passes/lifecyclefacts"
	"github.com/kojah/gohawk/internal/analysis/passes/resultfacts"
	"github.com/kojah/gohawk/internal/cli/runner"
	"github.com/kojah/gohawk/internal/cli/vetunit"
	"github.com/kojah/gohawk/internal/engine/heapmodel"
	analysisTrace "github.com/kojah/gohawk/internal/reporting/trace"
	"golang.org/x/tools/go/analysis"
)

// inProcessVariable selects the in-process runner instead of go vet. Both
// analyze the same units the same way; the runner does it in one process.
const inProcessVariable = "GOHAWK_IN_PROCESS"

// runInProcess analyzes the requested packages with the in-process runner
// and presents the findings as runViaGoVet presents go vet's.
func runInProcess(invocation *analysisInvocation, runtime cliRuntime) int {
	analyzers := gohawk.Analyzers()
	arguments := append([]string{"gohawk"}, invocation.arguments...)
	plan, err := buildExecutionPlan(arguments, analyzers, gohawk.AnalyzerGroups(), gohawk.AnalyzerMetadata(), false)
	if err != nil {
		writeLine(runtime.errorsOutput, "gohawk:", err)
		return 2
	}
	request, err := parseToolArguments(plan.arguments[1:], plan.analyzers)
	if err != nil {
		writeLine(runtime.errorsOutput, "gohawk:", err)
		return 2
	}
	// The fact passes run one after another in each unit, as go vet's tool
	// runs them; see prepareUnit.
	vetunit.Sequence(plan.arguments, plan.analyzers, []*analysis.Analyzer{lifecyclefacts.Analyzer, resultfacts.Analyzer, concurrencyfacts.Analyzer})
	output, failures := runner.Run(context.Background(), runner.Options{
		Dir:          ".",
		Patterns:     request.patterns,
		BuildFlags:   request.buildFlags,
		Analyzers:    request.analyzers,
		FactsOnlyRun: map[*analysis.Analyzer]func(*analysis.Pass) (any, error){lifecyclefacts.Analyzer: lifecyclefacts.RunForImporters},
		Release:      heapmodel.Release,
	})
	for _, failure := range failures {
		writeLine(runtime.errorsOutput, "gohawk:", failure)
	}
	merged, err := mergeVetOutput(output)
	if err != nil {
		writeLine(runtime.errorsOutput, "gohawk:", err)
		return 1
	}
	var code int
	switch invocation.render {
	case renderJSON:
		_, _ = runtime.output.Write(merged)
		code = jsonDiagnosticExitCode(merged)
	default:
		code = renderDelegatedDiagnostics(merged, invocation.contextLines, runtime.output)
	}
	if len(failures) > 0 {
		return max(1, code)
	}
	return code
}

// toolRequest is what go vet would have made of the arguments: the build
// flags it keeps for itself, the packages, and the analyzers its tool runs
// once the tool has parsed its flags.
type toolRequest struct {
	buildFlags []string
	patterns   []string
	analyzers  []*analysis.Analyzer
}

// parseToolArguments parses the arguments as go vet and its tool would
// together: go build flags go to go list, and the rest are the tool's, which
// x/tools parses into -NAME switches that select analyzers and -NAME.FLAG
// analyzer flags.
func parseToolArguments(arguments []string, analyzers []*analysis.Analyzer) (toolRequest, error) {
	flags := flag.NewFlagSet("gohawk", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var request toolRequest
	for name, takesValue := range goBuildFlags {
		flags.Var(&buildFlag{name: name, takesValue: takesValue, collected: &request.buildFlags}, name, "")
	}
	enabled := map[*analysis.Analyzer]*triState{}
	for _, analyzer := range analyzers {
		state := new(triState)
		enabled[analyzer] = state
		flags.Var(state, analyzer.Name, "")
		analyzer.Flags.VisitAll(func(option *flag.Flag) {
			flags.Var(option.Value, analyzer.Name+"."+option.Name, option.Usage)
		})
	}
	for _, name := range []string{"enable-all", "json", "fix", "diff", "source", "v", "all"} {
		flags.Bool(name, false, "")
	}
	for _, name := range []string{"tier", "enable", "disable", "enable-checks", "disable-checks", "enable-groups", "disable-groups"} {
		flags.String(name, "", "")
	}
	flags.Int("c", -1, "")
	analysisTrace.RegisterFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return toolRequest{}, err
	}
	request.patterns = flags.Args()
	if len(request.patterns) == 0 {
		request.patterns = []string{"."}
	}
	// If any -NAME is true, run only those analyzers; otherwise, if any is
	// false, run all but those.
	var anyTrue, anyFalse bool
	for _, state := range enabled {
		anyTrue = anyTrue || *state == setTrue
		anyFalse = anyFalse || *state == setFalse
	}
	for _, analyzer := range analyzers {
		switch state := *enabled[analyzer]; {
		case anyTrue && state != setTrue, !anyTrue && anyFalse && state == setFalse:
			continue
		}
		request.analyzers = append(request.analyzers, analyzer)
	}
	return request, nil
}

// goBuildFlags are the go command's build flags go vet accepts, by whether
// each takes a value.
var goBuildFlags = map[string]bool{
	"tags": true, "mod": true, "modfile": true, "overlay": true, "pgo": true, "gcflags": true, "ldflags": true,
	"asmflags": true, "gccgoflags": true, "compiler": true, "installsuffix": true, "toolexec": true, "p": true,
	"race": false, "msan": false, "asan": false, "cover": false, "trimpath": false, "buildvcs": true, "a": false,
	"n": false, "x": false, "work": false, "linkshared": false,
}

// buildFlag collects a go build flag as it was given, to pass to go list.
type buildFlag struct {
	name       string
	takesValue bool
	collected  *[]string
}

func (value *buildFlag) String() string { return "" }

func (value *buildFlag) Set(text string) error {
	*value.collected = append(*value.collected, "-"+value.name+"="+text)
	return nil
}

func (value *buildFlag) IsBoolFlag() bool { return !value.takesValue }

// triState is an analyzer's -NAME switch: unset, true or false.
type triState int

const (
	unset triState = iota
	setTrue
	setFalse
)

func (state *triState) String() string {
	switch *state {
	case setTrue:
		return "true"
	case setFalse:
		return "false"
	case unset:
	}
	return ""
}

func (state *triState) Set(text string) error {
	switch strings.ToLower(text) {
	case "true", "1", "t":
		*state = setTrue
	case "false", "0", "f":
		*state = setFalse
	default:
		return fmt.Errorf("invalid boolean %q", text)
	}
	return nil
}

func (state *triState) IsBoolFlag() bool { return true }
