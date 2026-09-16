package snmpdiscovery

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func repoPath(t *testing.T, rel string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	p := filepath.Join(filepath.Dir(file), "..", rel)
	if _, err := os.Stat(p); err != nil {
		t.Fatal(p, err)
	}
	return p
}

func loadNetworkFingerprinter(t *testing.T) Fingerprinter {
	t.Helper()
	fps, err := LoadFingerprinters(repoPath(t, "snmp/fingerprinters.yml"))
	if err != nil {
		t.Fatal(err)
	}
	fp, ok := fps.Fingerprinters["network"]
	if !ok {
		t.Fatal("missing fingerprinter network")
	}
	if err := fp.compile(); err != nil {
		t.Fatal(err)
	}
	return fp
}

func containsModule(list []string, name string) bool {
	for _, m := range list {
		if m == name {
			return true
		}
	}
	return false
}

func TestShippedCatalogNokiaClos(t *testing.T) {
	fp := loadNetworkFingerprinter(t)
	tiers := fp.MatchTiers(map[string]string{"sysObjectID": "1.3.6.1.4.1.6527.1.20.26"})
	wantHot := []string{"if_mib", "nokia_srlinux"}
	wantCold := []string{"if_mib_meta", "ip_addr", "nokia_srlinux_sensors", "nokia_srlinux_ext"}
	wantTopo := []string{"nokia_srlinux_topo", "lldp_mib"}
	if !reflect.DeepEqual(tiers.Hot, wantHot) {
		t.Fatalf("hot: %v", tiers.Hot)
	}
	if !reflect.DeepEqual(tiers.Cold, wantCold) {
		t.Fatalf("cold: %v", tiers.Cold)
	}
	if !reflect.DeepEqual(tiers.Topology, wantTopo) {
		t.Fatalf("topology: %v", tiers.Topology)
	}
	if containsModule(tiers.Topology, "cdp_mib") {
		t.Fatalf("nokia must not get cdp_mib: %v", tiers.Topology)
	}

	for _, rel := range []string{
		"snmp/modules/_general/if_mib.yml",
		"snmp/modules/_general/if_mib_meta.yml",
		"snmp/modules/_general/ip_addr.yml",
		"snmp/modules/_general/lldp_mib.yml",
		"snmp/modules/nokia/nokia_srlinux.yml",
		"snmp/modules/nokia/nokia_srlinux_sensors.yml",
		"snmp/modules/nokia/nokia_srlinux_ext.yml",
		"snmp/modules/nokia/nokia_srlinux_topo.yml",
	} {
		_ = repoPath(t, rel)
	}
}

func TestShippedCatalogCiscoGetsCDP(t *testing.T) {
	fp := loadNetworkFingerprinter(t)
	tiers := fp.MatchTiers(map[string]string{"sysObjectID": "1.3.6.1.4.1.9.6.1.23.3.13.0.4"})
	if !containsModule(tiers.Topology, "lldp_mib") || !containsModule(tiers.Topology, "cdp_mib") {
		t.Fatalf("cisco_asr topology: %v", tiers.Topology)
	}
}

var ciscoRelatedName = regexp.MustCompile(`(^|_)(cisco|meraki)(_|$)`)

func matcherCiscoRelated(m Matcher) bool {
	var names []string
	names = append(names, m.Modules...)
	names = append(names, m.ModulesHot...)
	names = append(names, m.ModulesCold...)
	names = append(names, m.ModulesTopology...)
	for _, n := range names {
		if ciscoRelatedName.MatchString(strings.ToLower(n)) {
			return true
		}
	}
	return false
}

func TestShippedTopologyCoverage(t *testing.T) {
	fp := loadNetworkFingerprinter(t)
	if !containsModule(fp.DefaultModulesTopology, "lldp_mib") {
		t.Fatalf("default_modules_topology: %v", fp.DefaultModulesTopology)
	}

	known := shippedModuleNames(t)
	var missingLLDP, missingCDP, missingMod []string
	for _, m := range fp.Matchers {
		if !m.hasTier() {
			continue
		}
		if !containsModule(m.ModulesTopology, "lldp_mib") {
			missingLLDP = append(missingLLDP, m.Comment)
		}
		if matcherCiscoRelated(m) && !containsModule(m.ModulesTopology, "cdp_mib") {
			missingCDP = append(missingCDP, m.Comment)
		}
		for _, name := range uniqueModules(append(append(m.ModulesHot, m.ModulesCold...), m.ModulesTopology...)) {
			if _, ok := known[name]; !ok {
				missingMod = append(missingMod, name+" ("+m.Comment+")")
			}
		}
	}
	if len(missingLLDP) > 0 {
		t.Fatalf("matchers missing lldp_mib (%d): %v", len(missingLLDP), missingLLDP[:min(5, len(missingLLDP))])
	}
	if len(missingCDP) > 0 {
		t.Fatalf("cisco/meraki matchers missing cdp_mib (%d): %v", len(missingCDP), missingCDP[:min(5, len(missingCDP))])
	}
	if len(missingMod) > 0 {
		t.Fatalf("fingerprinter names missing from snmp/modules (%d): %v", len(missingMod), missingMod[:min(5, len(missingMod))])
	}
}

func shippedModuleNames(t *testing.T) map[string]struct{} {
	t.Helper()
	root := repoPath(t, "snmp/modules")
	out := map[string]struct{}{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yml") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var doc struct {
			Modules map[string]any `yaml:"modules"`
		}
		if err := yaml.Unmarshal(b, &doc); err != nil {
			return err
		}
		for name := range doc.Modules {
			out[name] = struct{}{}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("no modules under snmp/modules")
	}
	return out
}
