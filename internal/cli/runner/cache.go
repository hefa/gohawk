package runner

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/types/objectpath"
)

// go vet keeps each unit's findings and facts in the build cache, so a
// rerun analyzes only the units whose inputs changed. The runner keeps its
// own cache the same way. A unit's key covers everything its result depends
// on: this binary, the analyzers and their flags, the unit's own files and
// the compiler's export data for it, and the keys of its imports, so a
// changed dependency invalidates its importers as it would under go vet.

// A cache stores unit results under their keys, one file each, all within
// its root directory.
type cache struct {
	root *os.Root
	base []byte
	// partial numbers this run's files being written.
	partial atomic.Uint64
}

// openCache returns the cache in dir for results of the analyzers built
// into the executable, or nil when either is unavailable.
func openCache(dir string, analyzers []*analysis.Analyzer) *cache {
	if dir == "" {
		return nil
	}
	executable, err := os.Executable()
	if err != nil {
		return nil
	}
	binary, err := hashFile(executable)
	if err != nil {
		return nil
	}
	hash := sha256.New()
	hash.Write(binary)
	for _, analyzer := range analyzers {
		_, _ = fmt.Fprintf(hash, "analyzer %s\n", analyzer.Name)
	}
	for _, analyzer := range everyAnalyzer(analyzers) {
		analyzer.Flags.VisitAll(func(option *flag.Flag) {
			_, _ = fmt.Fprintf(hash, "flag %s.%s=%s\n", analyzer.Name, option.Name, option.Value)
		})
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil
	}
	// Facts are decoded from a cached result by their gob names.
	for _, analyzer := range everyAnalyzer(analyzers) {
		for _, fact := range analyzer.FactTypes {
			gob.Register(fact)
		}
	}
	store := &cache{root: root, base: hash.Sum(nil)}
	store.trim()
	return store
}

// key returns the unit's key, given the keys of its imports.
func (store *cache) key(target *unit, imports map[string][]byte) ([]byte, error) {
	hash := sha256.New()
	hash.Write(store.base)
	_, _ = fmt.Fprintf(hash, "unit %s\ndeponly %t\nexport %s\n", target.id(), target.DepOnly, target.Export)
	for _, name := range target.CompiledGoFiles {
		if !filepath.IsAbs(name) {
			name = filepath.Join(target.Dir, name)
		}
		contents, err := hashFile(name)
		if err != nil {
			return nil, err
		}
		_, _ = fmt.Fprintf(hash, "file %s %x\n", name, contents)
	}
	ids := slices.Sorted(slices.Values(target.Imports))
	for _, id := range ids {
		_, _ = fmt.Fprintf(hash, "import %s %x\n", id, imports[id])
	}
	return hash.Sum(nil), nil
}

// path names the key's file within the cache's root.
func (store *cache) path(key []byte) string {
	name := hex.EncodeToString(key)
	return filepath.Join(name[:2], name)
}

// cachedResult is a unit's result as the cache holds it: its reports as
// JSON, and its published facts, decoded only when an importer needs them.
type cachedResult struct {
	Reports map[string]json.RawMessage
	Facts   []byte
}

type gobFact struct {
	PkgPath string
	Object  string
	Fact    analysis.Fact
}

// load returns the cached result under key, if any, and marks it used.
func (store *cache) load(key []byte) (unitResult, bool) {
	path := store.path(key)
	data, err := store.root.ReadFile(path)
	if err != nil {
		return unitResult{}, false
	}
	if info, err := store.root.Stat(path); err == nil && time.Since(info.ModTime()) > time.Hour {
		now := time.Now()
		_ = store.root.Chtimes(path, now, now)
	}
	var cached cachedResult
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&cached); err != nil {
		return unitResult{}, false
	}
	result := unitResult{reports: map[string]any{}}
	for name, report := range cached.Reports {
		result.reports[name] = report
	}
	result.lazyFacts = sync.OnceValue(func() []publishedFact {
		var facts []gobFact
		if err := gob.NewDecoder(bytes.NewReader(cached.Facts)).Decode(&facts); err != nil {
			return nil
		}
		published := make([]publishedFact, len(facts))
		for index, fact := range facts {
			published[index] = publishedFact{pkgPath: fact.PkgPath, object: objectpath.Path(fact.Object), fact: fact.Fact}
		}
		return published
	})
	return result, true
}

// save stores the unit's result under key. A result that does not encode
// is not cached; the next run analyzes the unit again.
func (store *cache) save(key []byte, result unitResult) {
	facts := make([]gobFact, len(result.published))
	for index, fact := range result.published {
		facts[index] = gobFact{PkgPath: fact.pkgPath, Object: string(fact.object), Fact: fact.fact}
	}
	var encodedFacts bytes.Buffer
	if err := gob.NewEncoder(&encodedFacts).Encode(facts); err != nil {
		return
	}
	cached := cachedResult{Reports: map[string]json.RawMessage{}, Facts: encodedFacts.Bytes()}
	for name, report := range result.reports {
		encoded, err := json.Marshal(report)
		if err != nil {
			return
		}
		cached.Reports[name] = encoded
	}
	var data bytes.Buffer
	if err := gob.NewEncoder(&data).Encode(cached); err != nil {
		return
	}
	path := store.path(key)
	if err := store.root.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return
	}
	// Write aside and rename, so a reader never sees a partial result.
	partial := fmt.Sprintf("%s.partial-%d-%d", path, os.Getpid(), store.partial.Add(1))
	if err := store.root.WriteFile(partial, data.Bytes(), 0o600); err != nil {
		_ = store.root.Remove(partial)
		return
	}
	if err := store.root.Rename(partial, path); err != nil {
		_ = store.root.Remove(partial)
	}
}

// As Go's build cache does, the cache forgets results no run has used for
// five days, looking at most once a day.
const (
	unusedFor = 5 * 24 * time.Hour
	trimEvery = 24 * time.Hour
)

// trim removes results unused for unusedFor, unless a run trimmed within
// trimEvery.
func (store *cache) trim() {
	const marker = "trimmed"
	if info, err := store.root.Stat(marker); err == nil && time.Since(info.ModTime()) < trimEvery {
		return
	}
	_ = store.root.WriteFile(marker, nil, 0o600)
	cutoff := time.Now().Add(-unusedFor)
	_ = fs.WalkDir(store.root.FS(), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || path == marker {
			return nil
		}
		if info, err := entry.Info(); err == nil && info.ModTime().Before(cutoff) {
			_ = store.root.Remove(path)
		}
		return nil
	})
}

func hashFile(path string) ([]byte, error) {
	file, err := os.Open(path) //nolint:gosec // The run reads its own executable and the units' sources by design.
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

// everyAnalyzer returns the analyzers and all they require.
func everyAnalyzer(analyzers []*analysis.Analyzer) []*analysis.Analyzer {
	var all []*analysis.Analyzer
	seen := map[*analysis.Analyzer]bool{}
	var visit func(*analysis.Analyzer)
	visit = func(analyzer *analysis.Analyzer) {
		if seen[analyzer] {
			return
		}
		seen[analyzer] = true
		all = append(all, analyzer)
		for _, required := range analyzer.Requires {
			visit(required)
		}
	}
	for _, analyzer := range analyzers {
		visit(analyzer)
	}
	return all
}
