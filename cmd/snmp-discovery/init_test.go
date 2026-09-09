package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitNonInteractive(t *testing.T) {
	dir := t.TempDir()
	ap := filepath.Join(dir, "auths.yml")
	dp := filepath.Join(dir, "discovery.yml")
	err := runInit([]string{
		"--out-auths", ap,
		"--out-discovery", dp,
		"--auth-v2", "public_v2=public",
		"--group", "lab,cidrs=172.20.20.0/24,auths=public_v2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runInit([]string{"--check", "--auths", ap, "--discovery", dp}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(ap)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "public_v2") || !strings.Contains(string(body), "community: public") {
		t.Fatalf("auths: %s", body)
	}
}

func TestInitWizard(t *testing.T) {
	in := strings.NewReader(strings.Join([]string{
		"", // name default public_v2
		"", // version 2
		"labnet",
		"n", // no more auths
		"",  // group lab
		"10.1.2.0/24",
		"",  // auth default public_v2
		"",  // sweep
		"",  // port
		"",  // ping Y
		"n", // no more groups
		"",
	}, "\n"))
	var out strings.Builder
	p, err := runInitWizard(in, &out)
	if err != nil {
		t.Fatal(err, out.String())
	}
	if len(p.Auths) != 1 || p.Auths[0].Community != "labnet" {
		t.Fatalf("%+v", p.Auths)
	}
	if len(p.Groups) != 1 || p.Groups[0].Name != "lab" || p.Groups[0].Auths[0] != "public_v2" {
		t.Fatalf("%+v", p.Groups)
	}
}
