package snmpdiscovery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// AlloyTarget is what prometheus.exporter.snmp targets = encoding.from_yaml(...) expects.
type AlloyTarget struct {
	Name           string `yaml:"name" json:"name"`
	Address        string `yaml:"address" json:"address"`
	Module         string `yaml:"module" json:"module"` // hot tier (60s)
	ModuleCold     string `yaml:"module_cold,omitempty" json:"module_cold,omitempty"`
	ModuleTopology string `yaml:"module_topology,omitempty" json:"module_topology,omitempty"`
	Auth           string `yaml:"auth" json:"auth"`
	DeviceName     string `yaml:"device_name" json:"device_name"`
	SysObjectID    string `yaml:"sysObjectID,omitempty" json:"sysObjectID,omitempty"`
	SnmpGroup      string `yaml:"snmp_group,omitempty" json:"snmp_group,omitempty"`
	// SnmpTier is set when this row is a projected scrape (hot/cold/topology).
	SnmpTier string `yaml:"snmp_tier,omitempty" json:"snmp_tier,omitempty"`
	// Aliases are extra SNMP-reachable IPs collapsed into this identity.
	// Not scraped; used to join traps/syslog/flow from those addresses.
	Aliases []string `yaml:"aliases,omitempty" json:"aliases,omitempty"`
}

// FileSDGroup is Prometheus file_sd / HTTP SD.
type FileSDGroup struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

// writeFileAtomic writes b to path via a same-dir temp file + rename so
// Alloy/local.file never observes a truncated catalog mid-write.
func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("writeFileAtomic: empty path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	base := filepath.Base(path)
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func WriteAlloyYAML(path string, targets []AlloyTarget) error {
	if targets == nil {
		targets = []AlloyTarget{}
	}
	b, err := yaml.Marshal(targets)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, b, 0o644)
}

func ReadAlloyYAML(path string) ([]AlloyTarget, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var targets []AlloyTarget
	if err := yaml.Unmarshal(b, &targets); err != nil {
		return nil, err
	}
	return targets, nil
}

// httpSDGroups is Prometheus HTTP/file SD. prometheusParams=true writes
// __param_module / __param_auth (classic snmp_exporter). false writes
// name / module / auth / address for Alloy prometheus.exporter.snmp.
// Community is never written. Do not mix the two: __param_* on the Alloy
// path is not in ignoredLabels and would leak onto series.
func httpSDGroups(targets []AlloyTarget, prometheusParams bool) []FileSDGroup {
	groups := make([]FileSDGroup, 0, len(targets))
	for _, t := range targets {
		labels := map[string]string{}
		if prometheusParams {
			labels["__param_module"] = t.Module
			labels["__param_auth"] = t.Auth
			labels["device_name"] = t.DeviceName
		} else {
			labels["name"] = t.Name
			labels["module"] = t.Module
			labels["auth"] = t.Auth
			labels["address"] = t.Address
			labels["device_name"] = t.DeviceName
		}
		if t.SysObjectID != "" {
			labels["sysObjectID"] = t.SysObjectID
		}
		if t.SnmpGroup != "" {
			labels["snmp_group"] = t.SnmpGroup
		}
		if t.SnmpTier != "" {
			labels["snmp_tier"] = t.SnmpTier
		}
		if len(t.Aliases) > 0 {
			labels["snmp_aliases"] = strings.Join(t.Aliases, ",")
		}
		groups = append(groups, FileSDGroup{
			Targets: []string{t.Address},
			Labels:  labels,
		})
	}
	if groups == nil {
		groups = []FileSDGroup{}
	}
	return groups
}

func writeFileSD(path string, targets []AlloyTarget) error {
	groups := httpSDGroups(targets, true)
	b, err := json.MarshalIndent(groups, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return writeFileAtomic(path, b, 0o644)
}

// targetNames returns Alloy name and device_name (human/sysName for joins).
// Same-sysName addresses are collapsed later unless AllowDuplicateSysName.
func targetNames(sysName, addr string) (name, deviceName string) {
	addr = mustCanonIP(addr)
	n := strings.TrimSpace(sysName)
	if n == "" || n == addr {
		return nameAddrSuffix(addr), addr
	}
	if i := strings.IndexByte(n, '.'); i > 0 {
		n = n[:i]
	}
	return n, n
}

// uniquifyNames ensures prometheus.exporter.snmp `name` is unique. On collision,
// suffixes with -<address>. device_name is left as the friendly sysName.
func uniquifyNames(targets []AlloyTarget) {
	used := map[string]string{} // name -> address that owns it
	for i := range targets {
		name := strings.TrimSpace(targets[i].Name)
		if name == "" {
			name = targets[i].Address
		}
		if owner, ok := used[name]; ok && owner != targets[i].Address {
			name = name + "-" + nameAddrSuffix(targets[i].Address)
		}
		if owner, ok := used[name]; ok && owner != targets[i].Address {
			name = nameAddrSuffix(targets[i].Address)
		}
		used[name] = targets[i].Address
		targets[i].Name = name
	}
}

func joinModules(mods []string) string {
	return strings.Join(mods, ",")
}

func fmtDiscovered(n int) string {
	return fmt.Sprintf("%d SNMP targets", n)
}
