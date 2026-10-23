package goroutineownership

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kojah/gohawk/internal/analysis/passes/concurrencyfacts"
	proofs "github.com/kojah/gohawk/internal/engine/proof"
	"github.com/kojah/gohawk/internal/engine/ssaflow"
	"github.com/kojah/gohawk/internal/engine/ssaflow/ssaflowtest"
	"github.com/kojah/gohawk/internal/reporting/check"
	analysisTrace "github.com/kojah/gohawk/internal/reporting/trace"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/ssa"
)

func TestConcurrencyJoinProofs(t *testing.T) {
	tracePath := enableSummaryJoinTrace(t)
	want := map[string]GoroutineOutcome{
		"importedReceive":     GoroutineLifecycleHonored,
		"importedWait":        GoroutineLifecycleHonored,
		"deferredReceive":     GoroutineLifecycleHonored,
		"branchAwareJoin":     GoroutineLifecycleHonored,
		"opaqueReceive":       GoroutineUnknown,
		"conditionalReceive":  GoroutineUnknown,
		"asynchronousReceive": GoroutineUnknown,
		"differentSignal":     GoroutineLifecycleViolated,
		"differentArgument":   GoroutineUnknown,
		"missingPath":         GoroutineLifecycleViolated,
		"returnedWaiter":      GoroutineLifecycleHonored,
		"otherReturnedWaiter": GoroutineLifecycleViolated,
		"uninvokedWaiter":     GoroutineUnknown,
		"asynchronousWaiter":  GoroutineUnknown,
	}
	assertSpawnProofs(t, want, "summaryjoins")
	assertSummaryJoinTrace(t, tracePath)
}

func enableSummaryJoinTrace(t *testing.T) string {
	t.Helper()
	flags := flag.NewFlagSet("summary-joins", flag.ContinueOnError)
	analysisTrace.RegisterFlags(flags)
	path := filepath.Join(t.TempDir(), "trace.jsonl")
	for name, value := range map[string]string{"gohawk-trace": "goroutineownership", "gohawk-trace-file": path} {
		previous := flags.Lookup(name).Value.String()
		if previous == "" {
			previous = "none"
			if name == "gohawk-trace-file" {
				previous = os.DevNull
			}
		}
		if err := flags.Set(name, value); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := flags.Set(name, previous); err != nil {
				t.Error(err)
			}
		})
	}
	return path
}

func assertSummaryJoinTrace(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		var event struct {
			Reason    string `json:"reason"`
			Phase     string `json:"phase"`
			Outcome   string `json:"outcome"`
			Candidate string `json:"candidate"`
			Position  string `json:"position"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		if event.Reason != "concurrency-summary-join" {
			continue
		}
		found = true
		if event.Phase != "evidence" || event.Outcome != "accepted" || event.Candidate == "" || event.Position == "" {
			t.Errorf("invalid summary join event: %+v", event)
		}
	}
	if !found {
		t.Error("missing concurrency-summary-join evidence")
	}
}

func TestSummaryJoinSharesCandidateAllowance(t *testing.T) {
	path := enableSummaryJoinTrace(t)
	pkg := ssaflowtest.BuildPackage(t, "summarybudget", "package summarybudget; func wait(done chan int)int{n:=0;"+
		strings.Repeat("n++;", 32)+"<-done;return n};func subject(){done:=make(chan int);go func(){done<-1}();wait(done)}")
	function := pkg.Func("subject")
	var dump bytes.Buffer
	if _, err := pkg.Func("wait").WriteTo(&dump); err != nil {
		t.Fatal(err)
	}
	t.Log(dump.String())
	spawn := ssaflow.InstructionsOf[*ssa.Go](function)[0]
	call := ssaflow.InstructionsOf[*ssa.Call](function)[0]
	target := ssaflow.InstructionsOf[*ssa.MakeChan](function)[0]
	engine := concurrencyfacts.NewEngine()
	pass := &analysis.Pass{Fset: pkg.Prog.Fset, Pkg: pkg.Pkg, ResultOf: map[*analysis.Analyzer]any{concurrencyfacts.Analyzer: engine}}
	probe := analysisTrace.For(pass, "goroutineownership", string(check.GoroutineJoin), spawn.Pos())
	query := func(limit int) helperCallProof {
		candidate := &spawnAnalysis{
			pass: pass, function: function, spawn: spawn, probe: probe,
			pool: proofs.NewSearchBudget(limit).Observed(probe.Observer()), tracked: []trackedValue{{value: target, kind: trackedSignal}},
		}
		label, decided := candidate.summarizedJoin(call)
		if !decided {
			t.Fatal("summary did not recognize completion or cutoff")
		}
		return label
	}
	for _, limit := range []int{0, 1, 32} {
		if got := query(limit); got.action != actionUnknown || got.reason != reasonSummaryJoinBudgetExhausted {
			t.Fatalf("limit%d returned %+v; want unavailable summary", limit, got)
		}
	}
	if got := query(spawnPoolBudget); got.action != actionJoin || got.reason != reasonLabelSummaryJoin {
		t.Fatalf("fresh query=%+v", got)
	}
	// Reusing a completed summary still requires admission to this candidate's
	// allowance; a cached join must not bypass an exhausted outer pool.
	if got := query(0); got.action != actionUnknown {
		t.Fatalf("cached join bypassed cutoff: %+v", got)
	}
	assertCandidateCutoffTrace(t, path, pass.Fset.Position(spawn.Pos()).String(), func(event followupTraceEvent) bool {
		return event.Details["phase"] == "summary-join"
	})
}

func TestSummaryJoinChildCutoffAndOwnedSummary(t *testing.T) {
	subject := func(helper string) string {
		return "func " + helper + "Subject(){done,other:=make(chan int),make(chan int);go func(){done<-1}();" + helper + "(done,other)};"
	}
	pkg := ssaflowtest.BuildPackage(t, "summarychild", "package summarychild;"+
		"func wait(done,other chan int)int{n:=0;"+strings.Repeat("n++;", helperUseBudget+32)+"<-done;return n};"+
		"func heavy(done,other chan int)int{n:=0;"+strings.Repeat("n++;", 2*proofs.SummaryBudget)+"<-done;return n};"+
		subject("wait")+subject("heavy"))
	engine := concurrencyfacts.NewEngine()
	pass := &analysis.Pass{Fset: pkg.Prog.Fset, Pkg: pkg.Pkg, ResultOf: map[*analysis.Analyzer]any{concurrencyfacts.Analyzer: engine}}
	// decoys tracked values the helper never joins are examined before done.
	query := func(helper string, decoys int) (*spawnAnalysis, helperCallProof, bool) {
		fn := pkg.Func(helper + "Subject")
		channels := ssaflow.InstructionsOf[*ssa.MakeChan](fn)
		tracked := make([]trackedValue, 0, decoys+1)
		for range decoys {
			tracked = append(tracked, trackedValue{value: channels[1], kind: trackedSignal})
		}
		candidate := &spawnAnalysis{
			pass: pass, function: fn, spawn: ssaflow.InstructionsOf[*ssa.Go](fn)[0],
			pool: proofs.NewSearchBudget(spawnPoolBudget), tracked: append(tracked, trackedValue{value: channels[0], kind: trackedSignal}),
		}
		got, decided := candidate.summarizedJoin(ssaflow.InstructionsOf[*ssa.Call](fn)[0])
		return candidate, got, decided
	}
	// The summary spends a budget of its own, so a helper body larger than the
	// child allowance costs the candidate one lookup and still joins.
	if _, got, decided := query("wait", 0); !decided || got.action != actionJoin {
		t.Fatalf("owned summary lookup returned %+v", got)
	}
	// Matching the summary against each tracked value is the child's own
	// work: running out of it leaves the instruction unknown without draining
	// the candidate pool.
	candidate, cutoff, decided := query("wait", helperUseBudget)
	if !decided || cutoff.action != actionUnknown || cutoff.reason != reasonSummaryJoinBudgetExhausted || candidate.pool.Exhausted() {
		t.Fatalf("child cutoff with live pool returned %+v, pool exhausted=%v", cutoff, candidate.pool.Exhausted())
	}
	// A summary that exhausts its own budget never proves a join, and a
	// generous engine query does not see a different answer.
	if _, got, _ := query("heavy", 0); got.action == actionJoin {
		t.Fatalf("exhausted summary proved a join: %+v", got)
	}
	heavy := ssaflow.InstructionsOf[*ssa.Call](pkg.Func("heavySubject"))[0]
	if summary := engine.AtCall(heavy, proofs.NewSearchBudget(4*proofs.SummaryBudget)); summary.Complete() {
		t.Fatalf("exhausted summary completed for a larger caller: %+v", summary)
	}
}

func TestWorkerCompletionSuffixesAndAllowance(t *testing.T) {
	pkg := ssaflowtest.BuildPackage(t, "completiontails", `package completiontails
 import "sync"
 func opaque(){}
 func terminal(done chan int){close(done)}
 func early(done chan int){close(done);println("work")}
 func groupFinal(group *sync.WaitGroup,other chan int){defer close(other);group.Done()}
 func channelFinal(done,other chan int){defer close(other);close(done)}
 func tail(done chan int,value *int)int{opaque();close(done);return *value}
 func send(done chan int){opaque();done<-1}
 func deferred(done chan int){defer close(done);opaque()}
 func badDeferred(clean func()){defer clean();opaque()}
 func cycle(){opaque();for{}}
 `)
	for _, test := range []struct {
		name     string
		terminal bool
		want     bool
	}{
		{"terminal", true, true},
		{"early", true, false},
		{"groupFinal", true, true},
		{"channelFinal", true, false},
		{"tail", false, true},
		{"send", false, false},
		{"deferred", false, true},
		{"badDeferred", false, false},
		{"cycle", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			function := pkg.Func(test.name)
			calls := ssaflow.InstructionsOf[*ssa.Call](function)
			if len(calls) == 0 {
				t.Fatal("missing call under test")
			}
			for _, limit := range []int{0, proofs.QueryBudget} {
				budget := proofs.NewSearchBudget(limit)
				var got bool
				if test.terminal {
					got = terminalCompletion(calls[0], budget)
				} else {
					got = opaqueCallEndsWorkerWork(calls[0], budget)
				}
				want := test.want && limit != 0
				if got != want || budget.Exhausted() != (limit == 0) {
					t.Fatalf("limit=%d result=%v exhausted=%v, want %v", limit, got, budget.Exhausted(), want)
				}
			}
		})
	}
}
