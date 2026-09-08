package snmpdiscovery

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadRunConfig builds a DiscoveryFile from --config or legacy --cidrs/--auths flags.
func LoadRunConfig(configPath, cidrsCSV, authsCSV string, port uint16, allowLarge bool, fp string) (DiscoveryFile, error) {
	configPath = strings.TrimSpace(configPath)
	if configPath != "" {
		return LoadDiscoveryFile(configPath)
	}
	cidrList := splitCSV(cidrsCSV)
	if len(cidrList) == 0 {
		return DiscoveryFile{}, fmt.Errorf("provide --config or --cidrs")
	}
	authNames := splitCSV(authsCSV)
	if len(authNames) == 0 {
		return DiscoveryFile{}, fmt.Errorf("--auths required with --cidrs")
	}
	return cliGroup("cli", cidrList, authNames, port, allowLarge, fp), nil
}

// MergeOverridesFile merges an optional overrides YAML into cfg.
// Missing path is a no-op. Only Overrides are appended (groups in the
// overrides file are ignored — match the historic CLI behaviour).
func MergeOverridesFile(cfg *DiscoveryFile, path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var extra DiscoveryFile
	if err := yaml.Unmarshal(b, &extra); err != nil {
		return fmt.Errorf("overrides %s: %w", path, err)
	}
	cfg.Overrides = append(cfg.Overrides, extra.Overrides...)
	return nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
