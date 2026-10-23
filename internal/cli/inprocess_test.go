package cli

import (
	"errors"
	"os"
	"os/exec"
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
			delegated, delegatedCode := runCommandWithEnv(t, module, nil, binary, arguments...)
			inProcess, inProcessCode := runCommandWithEnv(t, module, []string{inProcessVariable + "=1"}, binary, arguments...)
			if inProcess != delegated || inProcessCode != delegatedCode {
				t.Errorf("%s %v: in process exited %d with\n%s\ngo vet exited %d with\n%s",
					name, arguments, inProcessCode, inProcess, delegatedCode, delegated)
			}
		}
	}
}

func runCommandWithEnv(t *testing.T, directory string, environment []string, name string, arguments ...string) (string, int) {
	t.Helper()
	command := exec.CommandContext(t.Context(), name, arguments...)
	command.Dir = directory
	command.Env = append(append(os.Environ(), "GOWORK=off"), environment...)
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
