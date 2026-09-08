package snmpdiscovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDiscoveryFileRequiresScopedAuths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "d.yml")
	if err := os.WriteFile(path, []byte(`
groups:
  - name: hq
    cidrs: ["172.20.20.0/24"]
    auths: ["public_v2"]
overrides:
  - address: 172.20.20.9
    ignore: true
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadDiscoveryFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Groups) != 1 || cfg.Groups[0].Auths[0] != "public_v2" {
		t.Fatalf("%+v", cfg)
	}
}

func TestLoadDiscoveryFileRejectsAuthlessGroup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "d.yml")
	if err := os.WriteFile(path, []byte(`
groups:
  - name: hq
    cidrs: ["172.20.20.0/24"]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDiscoveryFile(path); err == nil {
		t.Fatal("expected error")
	}
}

func TestApplyOverrideIgnoreAndPin(t *testing.T) {
	in := []AlloyTarget{
		{Name: "a", Address: "10.0.0.1", Module: "system_mib,if_mib", Auth: "public_v2", DeviceName: "a"},
		{Name: "b", Address: "10.0.0.2", Module: "system_mib,if_mib", Auth: "public_v2", DeviceName: "b", SnmpGroup: "hq"},
	}
	out := applyOverrides(in, []Override{
		{Address: "10.0.0.1", Ignore: true},
		{Address: "10.0.0.2", Name: "spine1", Module: "system_mib,if_mib,nokia_srlinux"},
	})
	if len(out) != 1 {
		t.Fatalf("len=%d", len(out))
	}
	if out[0].Name != "spine1" || out[0].DeviceName != "spine1" {
		t.Fatalf("name=%s", out[0].Name)
	}
	// Legacy module pin is partitioned into hot/cold (not stuffed entirely into hot).
	if out[0].Module != "if_mib" {
		t.Fatalf("module(hot)=%s", out[0].Module)
	}
	if out[0].ModuleCold != "system_mib,if_mib_meta,nokia_srlinux" {
		t.Fatalf("module_cold=%s", out[0].ModuleCold)
	}
	if out[0].SnmpGroup != "hq" {
		t.Fatalf("group=%s", out[0].SnmpGroup)
	}
}

func TestIgnoreDropsFromCatalog(t *testing.T) {
	c := NewCatalog()
	c.Replace([]AlloyTarget{
		{Name: "a", Address: "10.0.0.1", Auth: "public_v2"},
		{Name: "b", Address: "10.0.0.2", Auth: "public_v2"},
	})
	if n := c.DropAddresses([]string{"10.0.0.1"}); n != 1 {
		t.Fatalf("dropped=%d", n)
	}
	out, _ := c.Snapshot()
	if len(out) != 1 || out[0].Address != "10.0.0.2" {
		t.Fatalf("%+v", out)
	}
}

func TestSweepKeepsCatalogWhenPingMisses(t *testing.T) {
	fps := FingerprintersFile{Fingerprinters: map[string]Fingerprinter{
		"network": {DefaultModules: []string{"system_mib", "if_mib"}},
	}}
	cfg := DiscoveryFile{Groups: []DiscoveryGroup{{
		Name:          "hq",
		CIDRs:         []string{"10.9.9.0/30"},
		Auths:         []string{"public_v2"},
		Fingerprinter: "network",
		Mode:          modeSweep,
	}}}
	dir := t.TempDir()
	snmp := filepath.Join(dir, "snmp.yml")
	if err := os.WriteFile(snmp, []byte("auths:\n  public_v2: {community: public, version: 2}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rts, err := loadGroupRuntimes(cfg, ScanParams{SnmpCfg: snmp, DefaultFP: "network", DefaultPort: 161}, fps)
	if err != nil {
		t.Fatal(err)
	}
	prev := []AlloyTarget{{Address: "10.9.9.1", SnmpGroup: "hq", Auth: "public_v2"}}
	// Ping returns nobody — catalog IP must still be scheduled.
	jobs, _, _, _, err := planInitialJobs(rts, ScanParams{
		Ping: true,
		PingFilter: func(ips []string) ([]string, error) {
			return nil, nil
		},
	}, prev)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, j := range jobs {
		if j.ip == "10.9.9.1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("catalog IP missing from jobs: %+v", jobs)
	}
}

func TestFirstGroupClaimsIP(t *testing.T) {
	fps := FingerprintersFile{Fingerprinters: map[string]Fingerprinter{
		"network": {DefaultModules: []string{"system_mib", "if_mib"}},
	}}
	cfg := DiscoveryFile{Groups: []DiscoveryGroup{
		{Name: "hq", CIDRs: []string{"10.1.1.8/32"}, Auths: []string{"hq_v2"}, Fingerprinter: "network"},
		{Name: "dc", CIDRs: []string{"10.1.1.8/32"}, Auths: []string{"dc_v2"}, Fingerprinter: "network"},
	}}
	dir := t.TempDir()
	snmp := filepath.Join(dir, "snmp.yml")
	if err := os.WriteFile(snmp, []byte(`
auths:
  hq_v2: {community: public, version: 2}
  dc_v2: {community: private, version: 2}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	jobs, err := expandJobs(cfg, ScanParams{SnmpCfg: snmp, FpPath: "x", DefaultFP: "network", DefaultPort: 161}, fps)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 {
		t.Fatalf("jobs=%d", len(jobs))
	}
	if jobs[0].group.Name != "hq" || jobs[0].auths[0].Name != "hq_v2" {
		t.Fatalf("%+v %+v", jobs[0].group, jobs[0].auths)
	}
}
