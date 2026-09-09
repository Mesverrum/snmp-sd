package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWalkPickAndEmitCLI(t *testing.T) {
	dir := t.TempDir()
	walk := filepath.Join("..", "..", "snmpdiscovery", "testdata", "sample.walk")
	mods := filepath.Join("..", "..", "snmp", "modules", "_general")
	pick := filepath.Join(dir, "pick.yml")
	mod := filepath.Join(dir, "mod.yml")
	if err := runWalkPick([]string{
		"--file", walk,
		"--modules", mods,
		"--out", pick,
	}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(pick)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "local_99999") || !strings.Contains(string(body), "1.3.6.1.4.1.99999") {
		t.Fatalf("pick:\n%s", body)
	}
	if strings.Contains(string(body), "1.3.6.1.2.1.31.1.1.1.6") {
		t.Fatalf("IF-MIB should not be in the draft:\n%s", body)
	}
	if err := runWalkEmit([]string{"--pick", pick, "--out", mod, "--modules", mods}); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(mod)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "modules:") || !strings.Contains(s, "local_99999") {
		t.Fatalf("emit:\n%s", s)
	}
	if !strings.Contains(s, "1.3.6.1.4.1.99999.2.1.1") {
		t.Fatalf("column walk missing:\n%s", s)
	}
}

func TestWalkCatalogWritePick(t *testing.T) {
	dir := t.TempDir()
	walk := filepath.Join("..", "..", "snmpdiscovery", "testdata", "sample.walk")
	mods := filepath.Join("..", "..", "snmp", "modules", "_general")
	pick := filepath.Join(dir, "pick.yml")
	if err := runWalkCatalog([]string{
		"--file", walk,
		"--modules", mods,
		"--write-pick", pick,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pick); err != nil {
		t.Fatal(err)
	}
}
