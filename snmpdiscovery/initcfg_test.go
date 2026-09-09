package snmpdiscovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func samplePlan() InitPlan {
	return InitPlan{
		Auths: []InitAuth{
			{Name: "public_v2", Version: 2, Community: "public"},
			{Name: "dc_v3", Version: 3, SecurityLevel: "authPriv", Username: "netops", Password: "auth", PrivPassword: "priv"},
		},
		Groups: []InitGroup{
			{Name: "lab", CIDRs: []string{"172.20.20.0/24"}, Auths: []string{"public_v2"}, Mode: "sweep", Port: 161, Ping: true, Fingerprinter: "network"},
		},
	}
}

func TestValidateInitPlanRejectsUnknownAuth(t *testing.T) {
	p := samplePlan()
	p.Groups[0].Auths = []string{"typo_v2"}
	if err := ValidateInitPlan(p); err == nil || !strings.Contains(err.Error(), "typo_v2") {
		t.Fatalf("want unknown auth, got %v", err)
	}
}

func TestValidateInitPlanRejectsWideCIDR(t *testing.T) {
	p := samplePlan()
	p.Groups[0].CIDRs = []string{"10.0.0.0/16"}
	if err := ValidateInitPlan(p); err == nil || !strings.Contains(err.Error(), "allow_large") {
		t.Fatalf("want wide CIDR, got %v", err)
	}
	p.Groups[0].AllowLarge = true
	if err := ValidateInitPlan(p); err != nil {
		t.Fatal(err)
	}
}

func TestRenderRoundTrip(t *testing.T) {
	p := samplePlan()
	if err := ValidateInitPlan(p); err != nil {
		t.Fatal(err)
	}
	ay, err := RenderAuthsYAML(p.Auths)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ay, "typo") {
		t.Fatal(ay)
	}
	dir := t.TempDir()
	ap := filepath.Join(dir, "auths.yml")
	if err := os.WriteFile(ap, []byte(ay), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadAuths(ap, []string{"public_v2", "dc_v3"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Community != "public" || got[1].Username != "netops" {
		t.Fatalf("%+v", got)
	}

	dy, err := RenderDiscoveryYAML(p.Groups)
	if err != nil {
		t.Fatal(err)
	}
	dp := filepath.Join(dir, "discovery.yml")
	if err := os.WriteFile(dp, []byte(dy), 0o644); err != nil {
		t.Fatal(err)
	}
	disc, err := LoadDiscoveryFile(dp)
	if err != nil {
		t.Fatal(err)
	}
	if len(disc.Groups) != 1 || disc.Groups[0].Auths[0] != "public_v2" {
		t.Fatalf("%+v", disc)
	}
	if err := CheckAuthDiscovery(ap, dp, ""); err != nil {
		t.Fatal(err)
	}
}

func TestCheckAuthDiscoveryReportsTypo(t *testing.T) {
	dir := t.TempDir()
	ap := filepath.Join(dir, "auths.yml")
	dp := filepath.Join(dir, "discovery.yml")
	if err := os.WriteFile(ap, []byte("auths:\n  public_v2:\n    version: 2\n    community: public\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dp, []byte("groups:\n  - name: lab\n    cidrs: [10.0.0.0/24]\n    auths: [pubic_v2]\n    mode: sweep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := CheckAuthDiscovery(ap, dp, "")
	if err == nil || !strings.Contains(err.Error(), "pubic_v2") {
		t.Fatalf("got %v", err)
	}
}

func TestParseFlags(t *testing.T) {
	a, err := ParseAuthV2Flag("public_v2=secret", 2)
	if err != nil || a.Name != "public_v2" || a.Community != "secret" {
		t.Fatalf("%+v %v", a, err)
	}
	v3, err := ParseAuthV3Flag("dc_v3,user=netops,auth=a,priv=p")
	if err != nil || v3.Name != "dc_v3" || v3.Username != "netops" || v3.SecurityLevel != "authPriv" {
		t.Fatalf("%+v %v", v3, err)
	}
	g, err := ParseGroupFlag("lab,cidrs=10.0.0.0/24;10.0.1.0/24,auths=public_v2")
	if err != nil || g.Name != "lab" || len(g.CIDRs) != 2 || g.Auths[0] != "public_v2" {
		t.Fatalf("%+v %v", g, err)
	}
}

func TestWriteInitFilesRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	ap := filepath.Join(dir, "auths.yml")
	dp := filepath.Join(dir, "discovery.yml")
	p := samplePlan()
	if err := WriteInitFiles(ap, dp, p, false); err != nil {
		t.Fatal(err)
	}
	if err := WriteInitFiles(ap, dp, p, false); err == nil {
		t.Fatal("expected exists")
	}
	if err := WriteInitFiles(ap, dp, p, true); err != nil {
		t.Fatal(err)
	}
}
