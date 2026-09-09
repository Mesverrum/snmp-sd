package snmpdiscovery

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
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

func TestShippedCatalogNokiaClos(t *testing.T) {
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

	tiers := fp.MatchTiers(map[string]string{"sysObjectID": "1.3.6.1.4.1.6527.1.20.26"})
	wantHot := []string{"if_mib", "nokia_srlinux"}
	wantCold := []string{"if_mib_meta", "ip_addr", "nokia_srlinux_sensors", "nokia_srlinux_ext"}
	wantTopo := []string{"nokia_srlinux_topo"}
	if !reflect.DeepEqual(tiers.Hot, wantHot) {
		t.Fatalf("hot: %v", tiers.Hot)
	}
	if !reflect.DeepEqual(tiers.Cold, wantCold) {
		t.Fatalf("cold: %v", tiers.Cold)
	}
	if !reflect.DeepEqual(tiers.Topology, wantTopo) {
		t.Fatalf("topology: %v", tiers.Topology)
	}

	for _, rel := range []string{
		"snmp/modules/_general/if_mib.yml",
		"snmp/modules/_general/if_mib_meta.yml",
		"snmp/modules/_general/ip_addr.yml",
		"snmp/modules/nokia/nokia_srlinux.yml",
		"snmp/modules/nokia/nokia_srlinux_sensors.yml",
		"snmp/modules/nokia/nokia_srlinux_ext.yml",
		"snmp/modules/nokia/nokia_srlinux_topo.yml",
	} {
		_ = repoPath(t, rel)
	}
}
