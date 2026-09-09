package snmpdiscovery

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleVars(t *testing.T) []WalkVar {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "sample.walk"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	vars, err := ParseWalkText(f)
	if err != nil {
		t.Fatal(err)
	}
	return vars
}

func TestParseWalkNumeric(t *testing.T) {
	vars := sampleVars(t)
	if len(vars) < 10 {
		t.Fatalf("vars=%d", len(vars))
	}
	if vars[0].OID != "1.3.6.1.2.1.1.5.0" || vars[0].Value != "leaf1" {
		t.Fatalf("%+v", vars[0])
	}
}

func TestClusterIFAndVendor(t *testing.T) {
	cat := ClusterWalk(sampleVars(t))
	if len(cat.Scalars) != 3 {
		t.Fatalf("scalars=%d %+v", len(cat.Scalars), cat.Scalars)
	}
	var ifTable, vendor, ip *WalkTable
	for i := range cat.Tables {
		t := &cat.Tables[i]
		switch {
		case strings.HasPrefix(t.EntryOID, "1.3.6.1.2.1.31.1.1.1"):
			ifTable = t
		case strings.HasPrefix(t.EntryOID, "1.3.6.1.4.1.99999.2.1"):
			vendor = t
		case strings.HasPrefix(t.EntryOID, "1.3.6.1.2.1.4.20.1"):
			ip = t
		}
	}
	if ifTable == nil || ifTable.IndexPieces != 1 || ifTable.Rows != 2 || len(ifTable.Columns) < 2 {
		t.Fatalf("if table: %+v", ifTable)
	}
	if vendor == nil || vendor.IndexPieces != 1 || vendor.Rows != 2 {
		t.Fatalf("vendor: %+v", vendor)
	}
	if ip == nil || ip.IndexPieces != 4 {
		t.Fatalf("ip table index pieces: %+v", ip)
	}
}

func TestCoveredIFMIB(t *testing.T) {
	lib, err := LoadLibraryOIDs(filepath.Join("..", "snmp", "modules", "_general"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := lib.Lookup("1.3.6.1.2.1.31.1.1.1.6.1"); !ok {
		t.Fatal("ifHCInOctets instance should match if_mib column")
	}
	h, ok := lib.Lookup("1.3.6.1.2.1.31.1.1.1.6")
	if !ok || h.Name != "snmp_ifHCInOctets" {
		t.Fatalf("column hit %+v ok=%v", h, ok)
	}
	up, ok := lib.Lookup("1.3.6.1.2.1.1.3.0")
	if !ok || up.Name != "snmp_Uptime" {
		t.Fatalf("sysUpTime should be snmp_Uptime, got %+v ok=%v", up, ok)
	}
	if _, ok := lib.Lookup("1.3.6.1.4.1.99999.1.1.0"); ok {
		t.Fatal("fake vendor oid should not be covered")
	}

	cat := ClusterWalk(sampleVars(t))
	var buf bytes.Buffer
	WriteWalkCatalog(&buf, cat, lib, false)
	out := buf.String()
	if !strings.Contains(out, "99999") {
		t.Fatalf("new vendor missing:\n%s", out)
	}
	if strings.Contains(out, "already snmp_ifHCInOctets") && !strings.Contains(out, "--show-covered") {
		// default hides fully covered if table; mention should be in the hidden count
	}
	if !strings.Contains(out, "already in the library") && !strings.Contains(out, "hidden") {
		t.Fatalf("expected a covered summary:\n%s", out)
	}
	if strings.Contains(out, "table 1.3.6.1.2.1.31.1.1.1") {
		t.Fatalf("fully covered IF-MIB table should be hidden by default:\n%s", out)
	}

	buf.Reset()
	WriteWalkCatalog(&buf, cat, lib, true)
	shown := buf.String()
	if !strings.Contains(shown, "snmp_ifHCInOctets") {
		t.Fatalf("show-covered should name ifHCInOctets:\n%s", shown)
	}
}

func TestParseWalkRejectsNamedOIDs(t *testing.T) {
	_, err := ParseWalkText(strings.NewReader("SNMPv2-MIB::sysName.0 = STRING: leaf1\n"))
	if err == nil {
		t.Fatal("expected error for named walk")
	}
}
