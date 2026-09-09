package snmpdiscovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func sampleLib(t *testing.T) LibraryOIDs {
	t.Helper()
	lib, err := LoadLibraryOIDs(filepath.Join("..", "snmp", "modules", "_general"))
	if err != nil {
		t.Fatal(err)
	}
	return lib
}

func TestDraftPickSkipsLibraryAndKeepsVendor(t *testing.T) {
	vars := sampleVars(t)
	vars = append(vars, WalkVar{OID: "1.3.6.1.2.1.1.2.0", Type: "OID", Value: "1.3.6.1.4.1.99999.1"})
	cat := ClusterWalk(vars)
	p := DraftPick(cat, sampleLib(t), vars)
	if p.Module != "local_99999" {
		t.Fatalf("module=%s", p.Module)
	}
	if p.SysObjectID != "1.3.6.1.4.1.99999.1" {
		t.Fatalf("sysObjectID=%s", p.SysObjectID)
	}
	if len(p.Scalars) != 1 || p.Scalars[0].OID != "1.3.6.1.4.1.99999.1.1.0" {
		t.Fatalf("scalars=%+v", p.Scalars)
	}
	if !strings.HasPrefix(p.Scalars[0].Name, "snmp_") {
		t.Fatalf("scalar name should be snmp_*: %s", p.Scalars[0].Name)
	}
	if len(p.Tables) != 1 || p.Tables[0].Entry != "1.3.6.1.4.1.99999.2.1" {
		t.Fatalf("tables=%+v", p.Tables)
	}
	if len(p.Tables[0].Metrics) != 1 || p.Tables[0].Metrics[0].Column != 1 {
		t.Fatalf("metrics=%+v", p.Tables[0].Metrics)
	}
	if len(p.Tables[0].Labels) != 1 || p.Tables[0].Labels[0].Column != 2 {
		t.Fatalf("labels=%+v", p.Tables[0].Labels)
	}
	if p.Tables[0].Labels[0].Type != "DisplayString" {
		t.Fatalf("label type=%s", p.Tables[0].Labels[0].Type)
	}
	if p.Tables[0].IndexLabels[0] != "index" {
		t.Fatalf("index_labels=%v", p.Tables[0].IndexLabels)
	}
}

func TestEmitPickModuleShape(t *testing.T) {
	vars := sampleVars(t)
	p := DraftPick(ClusterWalk(vars), sampleLib(t), vars)
	p.Tables[0].Labels[0].Name = "slot"
	body, err := EmitPickModule(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "modules:") || !strings.Contains(body, "local_99999:") {
		t.Fatalf("missing module:\n%s", body)
	}
	if !strings.Contains(body, "1.3.6.1.4.1.99999.1.1.0") {
		t.Fatalf("scalar get missing:\n%s", body)
	}
	if !strings.Contains(body, "oid: 1.3.6.1.4.1.99999.1.1\n") && !strings.Contains(body, "oid: 1.3.6.1.4.1.99999.1.1\r\n") {
		t.Fatalf("scalar metric oid should drop .0:\n%s", body)
	}
	if !strings.Contains(body, "1.3.6.1.4.1.99999.2.1.1") || !strings.Contains(body, "1.3.6.1.4.1.99999.2.1.2") {
		t.Fatalf("table columns should be walked:\n%s", body)
	}
	if strings.Contains(body, "walk:\n    - 1.3.6.1.4.1.99999.2.1\n") {
		t.Fatal("must walk columns, not the parent table")
	}
	if !strings.Contains(body, "labelname: index") || !strings.Contains(body, "labelname: slot") {
		t.Fatalf("indexes/lookups:\n%s", body)
	}
	var decoded map[string]any
	if err := yaml.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("yaml: %v\n%s", err, body)
	}
}

func TestPickRoundTripFile(t *testing.T) {
	dir := t.TempDir()
	vars := sampleVars(t)
	p := DraftPick(ClusterWalk(vars), sampleLib(t), vars)
	path := filepath.Join(dir, "pick.yml")
	if err := WritePickFile(path, p, false); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPickFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Module != p.Module || len(got.Scalars) != 1 || len(got.Tables) != 1 {
		t.Fatalf("roundtrip %+v", got)
	}
	if err := WritePickFile(path, p, false); err == nil {
		t.Fatal("expected exists error without overwrite")
	}
	body, err := EmitPickModule(got)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "mod.yml")
	if err := WriteEmitFile(out, body, false); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "snmp_") {
		t.Fatalf("emit:\n%s", raw)
	}
}

func TestPickCoveredNamesWarns(t *testing.T) {
	p := PickFile{
		Module: "dup",
		Scalars: []PickScalar{{
			OID:  "1.3.6.1.2.1.1.3.0",
			Name: "snmp_Uptime",
			Type: "gauge",
		}},
	}
	hits := PickCoveredNames(p, sampleLib(t))
	if len(hits) == 0 || !strings.Contains(hits[0], "snmp_Uptime") {
		t.Fatalf("hits=%v", hits)
	}
}

func TestEmitRejectsLabelsOnlyTable(t *testing.T) {
	_, err := EmitPickModule(PickFile{
		Module: "x",
		Tables: []PickTable{{
			Entry:       "1.3.6.1.4.1.1.1",
			IndexLabels: []string{"index"},
			Labels:      []PickCol{{Column: 1, Name: "name", Type: "DisplayString"}},
		}},
	})
	if err == nil {
		t.Fatal("expected labels-only error")
	}
}
