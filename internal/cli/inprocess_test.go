package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The in-process runner analyzes the same units as go vet, so every
// invocation must print the same findings and exit the same way.
func TestInProcessRunnerMatchesGoVet(t *testing.T) {
	binary := buildTestBinary(t)
	modules := map[string]string{"sample": writeTestModule(t), "capture tests": writeCaptureTestModule(t)}
	invocations := [][]string{
		{"./..."},
		{"-json", "-enable=concurrentcapture", "./..."},
		{"-json", "-enable-all", "./..."},
	}
	for name, module := range modules {
		for _, arguments := range invocations {
			delegated, delegatedCode := runCommandWithEnv(t, module, []string{goVetVariable + "=1"}, binary, arguments...)
			inProcess, inProcessCode := runCommandWithEnv(t, module, nil, binary, arguments...)
			if inProcess != delegated || inProcessCode != delegatedCode {
				t.Errorf("%s %v: in process exited %d with\n%s\ngo vet exited %d with\n%s",
					name, arguments, inProcessCode, inProcess, delegatedCode, delegated)
			}
		}
	}
}

// A cached unit result stands for the unit only while its inputs are
// unchanged: a rerun repeats the first run, and an edit is analyzed afresh.
func TestInProcessCacheFollowsEdits(t *testing.T) {
	binary := buildTestBinary(t)
	module := writeTestModule(t)
	cached := []string{cacheVariable + "=" + t.TempDir()}
	arguments := []string{"-json", "-enable=concurrentcapture", "./..."}
	first, firstCode := runCommandWithEnv(t, module, cached, binary, arguments...)
	again, againCode := runCommandWithEnv(t, module, cached, binary, arguments...)
	if again != first || againCode != firstCode {
		t.Fatalf("rerun from the cache exited %d with\n%s\nfirst run exited %d with\n%s", againCode, again, firstCode, first)
	}
	// Same imports, a different body: only the contents distinguish it.
	writeTestFile(t, filepath.Join(module, "sample", "sample.go"),
		"package sample\n\nimport \"sync\"\n\nfunc Quiet() {\n\tvar mu sync.Mutex\n\tmu.Lock()\n\tmu.Unlock()\n}\n")
	edited, editedCode := runCommandWithEnv(t, module, cached, binary, arguments...)
	fresh, freshCode := runCommandWithEnv(t, module, nil, binary, arguments...)
	if edited != fresh || editedCode != freshCode || edited == first {
		t.Fatalf("run after an edit exited %d with\n%s\nan uncached run exited %d with\n%s", editedCode, edited, freshCode, fresh)
	}
}

func runCommandWithEnv(t *testing.T, directory string, environment []string, name string, arguments ...string) (string, int) {
	t.Helper()
	command := exec.CommandContext(t.Context(), name, arguments...)
	command.Dir = directory
	command.Env = append(append(os.Environ(), "GOWORK=off", cacheVariable+"=off"), environment...)
	output, err := command.Output()
	if err == nil {
		return string(output), 0
	}
	if exitError, ok := errors.AsType[*exec.ExitError](err); ok {
		return string(output), exitError.ExitCode()
	}
	t.Fatalf("run %s: %v", name, err)
	return "", -1
}
