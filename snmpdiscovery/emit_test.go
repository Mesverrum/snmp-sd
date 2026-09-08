package snmpdiscovery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileSDUsesParamLabelsNotCommunity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sd.json")
	err := writeFileSD(path, []AlloyTarget{{
		Name:        "spine1",
		Address:     "172.20.20.2",
		Module:      "system_mib,if_mib,nokia_srlinux",
		Auth:        "public_v2",
		DeviceName:  "spine1",
		SysObjectID: "1.3.6.1.4.1.6527.1.20.26",
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "community") {
		t.Fatalf("community must never appear in file_sd: %s", raw)
	}
	var groups []FileSDGroup
	if err := json.Unmarshal(raw, &groups); err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 {
		t.Fatalf("groups=%d", len(groups))
	}
	l := groups[0].Labels
	if l["__param_module"] != "system_mib,if_mib,nokia_srlinux" || l["__param_auth"] != "public_v2" {
		t.Fatalf("labels=%v", l)
	}
	if _, ok := l["module"]; ok {
		t.Fatal("module should be __param_module only")
	}
	if l["device_name"] != "spine1" {
		t.Fatalf("device_name=%s", l["device_name"])
	}
}

func TestAlloyYAMLHasNamedAuthNoCommunity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.yml")
	err := WriteAlloyYAML(path, []AlloyTarget{{
		Name:       "leaf1",
		Address:    "172.20.20.3",
		Module:     "system_mib,if_mib,nokia_srlinux",
		Auth:       "public_v2",
		DeviceName: "leaf1",
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if strings.Contains(s, "community") {
		t.Fatalf("community leaked: %s", s)
	}
	for _, want := range []string{"name: leaf1", "address: 172.20.20.3", "module: system_mib,if_mib,nokia_srlinux", "auth: public_v2"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in %s", want, s)
		}
	}
}

func TestAtomicWriteNoPartialFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.yml")
	if err := WriteAlloyYAML(path, []AlloyTarget{{Name: "a", Address: "10.0.0.1", Auth: "public_v2"}}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "name: a") {
		t.Fatalf("%s", raw)
	}
	// No leftover temps
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("leftover temp %s", e.Name())
		}
	}
}

func TestUniquifyNames(t *testing.T) {
	in := []AlloyTarget{
		{Name: "spine", Address: "10.0.0.1", DeviceName: "spine"},
		{Name: "spine", Address: "10.0.0.2", DeviceName: "spine"},
	}
	uniquifyNames(in)
	if in[0].Name != "spine" {
		t.Fatalf("first keeps name: %s", in[0].Name)
	}
	if in[1].Name != "spine-10.0.0.2" {
		t.Fatalf("second uniquified: %s", in[1].Name)
	}
	if in[1].DeviceName != "spine" {
		t.Fatalf("device_name should stay friendly: %s", in[1].DeviceName)
	}
}
