//go:build stress && linux

package stress

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The pathological cases run the real command, `gohawk -enable-all ./...`,
// because that is how a user meets them: go vet fans the work out over
// several gohawk processes, and the memory that matters is their sum. A
// watcher samples the resident memory of the whole process tree and stops
// the run when it crosses the case's limit, so a regression fails the test
// instead of taking the machine down with it.

// gohawkBinary builds the command into the test's temporary directory. The
// build cache makes every build after the first cheap.
func gohawkBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "gohawk")
	output, err := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "github.com/kojah/gohawk").CombinedOutput()
	if err != nil {
		t.Fatalf("build gohawk: %v\n%s", err, output)
	}
	return binary
}

// writeModule writes the files of a throwaway module and returns its root.
func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const moduleHeader = "module example.com/stress\n\ngo 1.26.0\n"

// limits bound one run of the command.
type limits struct {
	// memory is the most resident memory the whole process tree may hold.
	memory uint64
	// wall is how long the run may take before it is stopped. It is a
	// backstop against hangs, not a performance assertion: shared runners
	// are too noisy for that.
	wall time.Duration
}

// runGohawk analyzes the packages in dir and fails the test when the run
// crashes, exceeds its limits, or exits with a status other than "clean" (0)
// or "findings" (3). Each test passes its own fresh build cache, so go vet
// cannot replay a result cached by an earlier run.
func runGohawk(t *testing.T, cache, dir string, bound limits, patterns ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), bound.wall)
	defer cancel()
	arguments := append([]string{"-enable-all", "-json"}, patterns...)
	command := exec.CommandContext(ctx, gohawkBinary(t), arguments...)
	command.Dir = dir
	command.Env = append(os.Environ(),
		"GOCACHE="+cache,
		"GOFLAGS=-mod=mod", "GOWORK=off", "GOTOOLCHAIN=local")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output

	start := time.Now()
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	peak, exceeded := watchMemory(command.Process.Pid, bound.memory, func() {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	})
	err := command.Wait()
	exceeded()
	t.Logf("peak tree memory %d MiB, wall %s", *peak>>20, time.Since(start).Round(time.Millisecond))

	switch {
	case *peak > bound.memory:
		t.Fatalf("process tree reached %d MiB, over the %d MiB limit", *peak>>20, bound.memory>>20)
	case ctx.Err() != nil:
		t.Fatalf("run did not finish within %s", bound.wall)
	case err != nil && !reportedFindings(err):
		t.Fatalf("gohawk failed: %v\n%s", err, tail(output.String(), 4000))
	}
}

// reportedFindings reports whether the command exited with status 3, which
// means it ran to completion and found something.
func reportedFindings(err error) bool {
	var exit *exec.ExitError
	return errors.As(err, &exit) && exit.ExitCode() == 3
}

// watchMemory samples the process tree rooted at pid until stop is called,
// recording the peak and calling kill once the sum crosses limit.
func watchMemory(pid int, limit uint64, kill func()) (*uint64, func()) {
	var peak uint64
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			if resident := treeResident(pid); resident > peak {
				peak = resident
				if peak > limit {
					kill()
				}
			}
			select {
			case <-done:
				return
			case <-ticker.C:
			}
		}
	}()
	return &peak, func() { close(done); <-finished }
}

// treeResident sums the resident memory of pid and all its descendants.
func treeResident(root int) uint64 {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	parents := map[int]int{}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		if parent, ok := parentOf(pid); ok {
			parents[pid] = parent
		}
	}
	var total uint64
	for pid := range parents {
		if descends(pid, root, parents) {
			total += resident(pid)
		}
	}
	return total
}

func descends(pid, root int, parents map[int]int) bool {
	for range len(parents) + 1 {
		if pid == root {
			return true
		}
		parent, ok := parents[pid]
		if !ok || parent == pid {
			return false
		}
		pid = parent
	}
	return false
}

// parentOf reads the parent field of /proc/<pid>/stat. The command name
// before it may contain spaces, so the fields start after its closing paren.
func parentOf(pid int) (int, bool) {
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(stat[bytes.LastIndexByte(stat, ')')+1:]))
	if len(fields) < 2 {
		return 0, false
	}
	parent, err := strconv.Atoi(fields[1])
	return parent, err == nil
}

func resident(pid int) uint64 {
	statm, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/statm")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(statm))
	if len(fields) < 2 {
		return 0
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return pages * uint64(os.Getpagesize())
}

func tail(text string, size int) string {
	if len(text) <= size {
		return text
	}
	return "..." + text[len(text)-size:]
}
