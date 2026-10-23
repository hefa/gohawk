// Package vetprofile records where one go vet analysis unit spends its time
// and what it allocates.
//
// gohawk analyzes each package in its own vet-tool process, so a whole-run
// profile is the union of per-unit records. When the profile directory is set,
// Instrument starts a CPU profile labelled by analyzer and times every
// analyzer's Run. When the last selected root analyzer returns, it stops the
// profile and writes the unit's record. unitchecker calls os.Exit itself, so
// a deferred stop would never run; the last root's return is the final point
// the tool controls before results are printed.
//
// go vet caches unit results by tool identity and inputs, not by environment,
// so a cached unit runs nothing and records nothing. Profile with a binary
// whose build ID go vet has not seen, or with a cleared cache.
package vetprofile

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime/pprof"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kojah/gohawk/internal/cli/vetunit"
	"golang.org/x/tools/go/analysis"
)

// DirectoryVariable names the environment variable that enables profiling.
// Its value is the directory that receives one record and one CPU profile per
// analyzed unit.
const DirectoryVariable = "GOHAWK_PROFILE_DIR"

// Record is the timing of one vet-tool unit, written as name.json beside the
// unit's CPU profile name.pprof.
type Record struct {
	Package   string `json:"package"`
	ID        string `json:"id"`
	FactsOnly bool   `json:"facts_only"`
	// SetupSeconds covers parsing, type checking and fact decoding: the time
	// from process start until the first analyzer runs.
	SetupSeconds    float64 `json:"setup_seconds"`
	AnalysisSeconds float64 `json:"analysis_seconds"`
	// ImportedFactBytes is the total size of the imported packages' fact
	// files, which unitchecker decodes before the first analyzer runs.
	ImportedFactBytes int64 `json:"imported_fact_bytes"`
	// ImportedFactCount is the number of facts in those files.
	ImportedFactCount int `json:"imported_fact_count"`
	// ImportedFacts maps each import path to a fingerprint of its facts.
	// Across a run's records it covers every package's exported facts except
	// those no other unit imports, so an optimization can be checked for
	// unchanged facts as well as unchanged diagnostics.
	ImportedFacts map[string]string `json:"imported_facts"`
	// ImportedFactTypes splits each fingerprint by fact type, naming which
	// family changed when a fingerprint differs.
	ImportedFactTypes map[string]map[string]string `json:"imported_fact_types"`
	// ImportedFactTypeBytes totals the imported payload bytes by fact type:
	// every importer reads and decodes them, so the largest types are where
	// a smaller fact saves the most.
	ImportedFactTypeBytes map[string]int64 `json:"imported_fact_type_bytes"`
	// PeakRSSKiB is the process high-water mark when analysis finished, or
	// nil when the platform does not report it.
	PeakRSSKiB *int64 `json:"peak_rss_kib"`
	// Analyzers maps each analyzer to the wall time of its own Run, which
	// excludes its prerequisites. Analyzers run in parallel within a unit, so
	// these can sum past AnalysisSeconds.
	Analyzers map[string]float64 `json:"analyzers"`
}

type session struct {
	started  time.Time
	unit     vetunit.Config
	name     string
	dir      string
	roots    []*analysis.Analyzer
	profile  *os.File
	mu       sync.Mutex
	first    time.Time
	pending  map[*analysis.Analyzer]bool
	analyzer map[string]float64
}

// Instrument prepares analyzers for profiling unit. It does nothing when
// directory is empty.
//
// Run is replaced on the shared analyzer values rather than on copies:
// passes look up prerequisite results by the original analyzer pointers, so
// a cloned graph would break every ResultOf lookup. This is safe only because
// a vet-tool process analyzes exactly one unit.
func Instrument(directory string, unit vetunit.Config, analyzers []*analysis.Analyzer) error {
	if directory == "" {
		return nil
	}
	started := time.Now()
	// go vet can analyze one unit ID twice, once for facts as a dependency and
	// once in full as a root, so the process ID keeps their records apart.
	digest := sha256.Sum256([]byte(unit.ID))
	current := &session{
		started:  started,
		unit:     unit,
		name:     hex.EncodeToString(digest[:12]) + "-" + strconv.Itoa(os.Getpid()),
		dir:      directory,
		roots:    analyzers,
		analyzer: make(map[string]float64),
	}
	if err := current.startProfile(); err != nil {
		return err
	}
	wrapped := make(map[*analysis.Analyzer]bool)
	for _, analyzer := range analyzers {
		current.wrap(analyzer, wrapped)
	}
	return nil
}

// writeAllocations records every sampled allocation since the process
// started as name.allocs, for go tool pprof -sample_index=alloc_space. Garbage
// collection is a large share of a unit's CPU, and this names the code that
// makes the garbage. It is taken before fingerprinting allocates.
func (s *session) writeAllocations() error {
	file, err := os.Create(filepath.Join(s.dir, s.name+".allocs"))
	if err != nil {
		return fmt.Errorf("create allocation profile: %w", err)
	}
	writeErr := pprof.Lookup("allocs").WriteTo(file, 0)
	if writeErr != nil {
		writeErr = fmt.Errorf("write allocation profile: %w", writeErr)
	}
	return errors.Join(writeErr, file.Close())
}

// importedFacts sizes, counts and fingerprints the unit's imported fact
// files. unitchecker has already read every one of them before analysis
// starts, and has registered every fact type with gob.
func importedFacts(unit vetunit.Config) (int64, int, map[string]string, map[string]map[string]string, map[string]int64, error) {
	var total int64
	var count int
	typeBytes := map[string]int64{}
	digests := make(map[string]string, len(unit.PackageVetx))
	byType := make(map[string]map[string]string, len(unit.PackageVetx))
	for importPath, file := range unit.PackageVetx {
		data, err := os.ReadFile(file) //nolint:gosec // go vet names the imported fact files.
		if err != nil {
			return 0, 0, nil, nil, nil, fmt.Errorf("read imported facts of %s: %w", importPath, err)
		}
		digest, types, facts, err := factDigest(data, typeBytes)
		if err != nil {
			return 0, 0, nil, nil, nil, fmt.Errorf("fingerprint imported facts of %s: %w", importPath, err)
		}
		total += int64(len(data))
		count += facts
		digests[importPath] = digest
		byType[importPath] = types
	}
	return total, count, digests, byType, typeBytes, nil
}

// wireFact mirrors the gob record x/tools writes for each fact; gob matches
// it by field name.
type wireFact struct {
	PkgPath string
	Object  string
	Fact    analysis.Fact
}

// factDigest fingerprints a fact file's content rather than its bytes. Gob
// numbers types in registration order, and unitchecker registers some fact
// types in map order, so equal facts can produce different files. The
// digest covers each fact's package, object, type and payload encoding,
// sorted.
func factDigest(data []byte, typeBytes map[string]int64) (string, map[string]string, int, error) {
	if len(data) == 0 {
		return "empty", nil, 0, nil
	}
	var facts []wireFact
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&facts); err != nil {
		return "", nil, 0, fmt.Errorf("decode fact file: %w", err)
	}
	entries := make([]string, 0, len(facts))
	entriesByType := map[string][]string{}
	for _, fact := range facts {
		payload, err := factPayload(fact.Fact)
		if err != nil {
			return "", nil, 0, err
		}
		factType := fmt.Sprintf("%T", fact.Fact)
		typeBytes[factType] += int64(len(payload))
		// x/tools repeats the package path with every fact it writes.
		typeBytes["(package and object paths)"] += int64(len(fact.PkgPath) + len(fact.Object))
		entry := fmt.Sprintf("%q %q %s %x", fact.PkgPath, fact.Object, factType, payload)
		entries = append(entries, entry)
		entriesByType[factType] = append(entriesByType[factType], entry)
	}
	byType := make(map[string]string, len(entriesByType))
	for factType, list := range entriesByType {
		byType[factType] = digestOf(list)
	}
	return digestOf(entries), byType, len(facts), nil
}

func digestOf(entries []string) string {
	slices.Sort(entries)
	digest := sha256.Sum256([]byte(strings.Join(entries, "\n")))
	return hex.EncodeToString(digest[:])
}

func factPayload(fact analysis.Fact) ([]byte, error) {
	if encoder, ok := fact.(gob.GobEncoder); ok {
		payload, err := encoder.GobEncode()
		if err != nil {
			return nil, fmt.Errorf("encode %T: %w", fact, err)
		}
		return payload, nil
	}
	var buffer bytes.Buffer
	if err := gob.NewEncoder(&buffer).Encode(fact); err != nil {
		return nil, fmt.Errorf("encode %T: %w", fact, err)
	}
	return buffer.Bytes(), nil
}

func (s *session) startProfile() error {
	if err := os.MkdirAll(s.dir, 0o750); err != nil {
		return fmt.Errorf("create profile directory: %w", err)
	}
	file, err := os.Create(filepath.Join(s.dir, s.name+".pprof"))
	if err != nil {
		return fmt.Errorf("create CPU profile: %w", err)
	}
	if err := pprof.StartCPUProfile(file); err != nil {
		closeErr := file.Close()
		return errors.Join(fmt.Errorf("start CPU profile: %w", err), closeErr)
	}
	s.profile = file
	return nil
}

// wrap times analyzer and its prerequisites and labels their CPU samples.
// Labels set by pprof.Do are inherited by goroutines the analyzer starts.
func (s *session) wrap(analyzer *analysis.Analyzer, wrapped map[*analysis.Analyzer]bool) {
	if wrapped[analyzer] {
		return
	}
	wrapped[analyzer] = true
	for _, required := range analyzer.Requires {
		s.wrap(required, wrapped)
	}
	run := analyzer.Run
	name := analyzer.Name
	analyzer.Run = func(pass *analysis.Pass) (result any, err error) {
		began := s.begin()
		pprof.Do(context.Background(), pprof.Labels("analyzer", name), func(context.Context) {
			result, err = run(pass)
		})
		if s.finish(analyzer, time.Since(began)) {
			err = errors.Join(err, s.write())
		}
		return result, err
	}
}

// begin records the start of analysis. The first call happens after
// unitchecker has parsed its flags, so the selected roots are known here.
func (s *session) begin() time.Time {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.first.IsZero() {
		s.first = now
		s.pending = s.selectedRoots()
	}
	return now
}

// finish accumulates an analyzer's time and reports whether it was the last
// selected root to return. Prerequisites finish before the roots that need
// them, so the last root marks the end of the unit's analysis.
func (s *session) finish(analyzer *analysis.Analyzer, elapsed time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.analyzer[analyzer.Name] += elapsed.Seconds()
	if !s.pending[analyzer] {
		return false
	}
	delete(s.pending, analyzer)
	return len(s.pending) == 0
}

// selectedRoots mirrors unitchecker's selection: if any analyzer flag is set
// true, only those run; otherwise any set false are dropped. A facts-only unit
// further skips analyzers that neither produce nor require facts.
// flag.Visit sees only flags set on the command line, which distinguishes an
// explicit -NAME=true from the default.
func (s *session) selectedRoots() map[*analysis.Analyzer]bool {
	explicit := make(map[string]string)
	flag.Visit(func(f *flag.Flag) { explicit[f.Name] = f.Value.String() })
	anyTrue := false
	for _, root := range s.roots {
		if explicit[root.Name] == "true" {
			anyTrue = true
		}
	}
	selected := make(map[*analysis.Analyzer]bool)
	for _, root := range s.roots {
		value, set := explicit[root.Name]
		switch {
		case anyTrue && value != "true", !anyTrue && set && value == "false":
			continue
		case s.unit.VetxOnly && !usesFacts(root, make(map[*analysis.Analyzer]bool)):
			continue
		}
		selected[root] = true
	}
	return selected
}

func usesFacts(analyzer *analysis.Analyzer, seen map[*analysis.Analyzer]bool) bool {
	if seen[analyzer] {
		return false
	}
	seen[analyzer] = true
	if len(analyzer.FactTypes) > 0 {
		return true
	}
	for _, required := range analyzer.Requires {
		if usesFacts(required, seen) {
			return true
		}
	}
	return false
}

func (s *session) write() error {
	finished := time.Now()
	pprof.StopCPUProfile()
	closeErr := errors.Join(s.profile.Close(), s.writeAllocations())
	factBytes, factCount, factDigests, factTypes, factTypeBytes, factErr := importedFacts(s.unit)
	if factErr != nil {
		return errors.Join(closeErr, factErr)
	}
	s.mu.Lock()
	first := s.first
	record := Record{
		Package:               s.unit.ImportPath,
		ID:                    s.unit.ID,
		FactsOnly:             s.unit.VetxOnly,
		SetupSeconds:          first.Sub(s.started).Seconds(),
		AnalysisSeconds:       finished.Sub(first).Seconds(),
		ImportedFactBytes:     factBytes,
		ImportedFactCount:     factCount,
		ImportedFacts:         factDigests,
		ImportedFactTypes:     factTypes,
		ImportedFactTypeBytes: factTypeBytes,
		PeakRSSKiB:            peakRSSKiB(),
		Analyzers:             s.analyzer,
	}
	data, err := json.Marshal(record)
	s.mu.Unlock()
	if err != nil {
		return errors.Join(fmt.Errorf("encode profile record: %w", err), closeErr)
	}
	writeErr := os.WriteFile(filepath.Join(s.dir, s.name+".json"), data, 0o600)
	if writeErr != nil {
		writeErr = fmt.Errorf("write profile record: %w", writeErr)
	}
	return errors.Join(closeErr, writeErr)
}

// peakRSSKiB reads the Linux high-water mark. Other platforms report nil,
// which consumers must treat as unknown rather than zero.
func peakRSSKiB() *int64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		value, found := strings.CutPrefix(scanner.Text(), "VmHWM:")
		if !found {
			continue
		}
		kib, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(value), " kB"), 10, 64)
		if err != nil {
			return nil
		}
		return &kib
	}
	return nil
}
