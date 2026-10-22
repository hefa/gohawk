// Package vetunit describes the single go vet unit a vet-tool process analyzes.
//
// go vet invokes gohawk once per package with a .cfg file naming the unit. A
// dependency is analyzed only for the facts its importers need.
package vetunit

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Config is the part of unitchecker's .cfg file that identifies the unit.
type Config struct {
	ID         string `json:"ID"`
	ImportPath string `json:"ImportPath"`
	// VetxOnly reports that the unit runs only to compute facts for
	// importers; its diagnostics are discarded.
	VetxOnly bool `json:"VetxOnly"`
	// PackageVetx maps each import path to the fact file go vet wrote for it.
	PackageVetx map[string]string `json:"PackageVetx"`
}

// ConfigPath returns the .cfg file that ends a vet-tool unit invocation, or
// "" for a handshake such as -flags or -V=full.
func ConfigPath(arguments []string) string {
	if len(arguments) == 0 || !strings.HasSuffix(arguments[len(arguments)-1], ".cfg") {
		return ""
	}
	return arguments[len(arguments)-1]
}

// ReadConfig reads the unit configuration at path.
func ReadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // go vet names the unit's config file.
	if err != nil {
		return Config{}, fmt.Errorf("read vet unit config: %w", err)
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, fmt.Errorf("decode vet unit config %s: %w", path, err)
	}
	return config, nil
}
