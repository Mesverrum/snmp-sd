package snmpdiscovery

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

func TestCrawlModeDoesNotSweep24(t *testing.T) {
	fps := FingerprintersFile{Fingerprinters: map[string]Fingerprinter{
		"network": {DefaultModules: []string{"system_mib", "if_mib"}},
	}}
	cfg := DiscoveryFile{Groups: []DiscoveryGroup{{
		Name:          "hq",
		CIDRs:         []string{"10.9.9.0/24"},
		Seeds:         []string{"10.9.9.10"},
		Auths:         []string{"public_v2"},
		Fingerprinter: "network",
		Mode:          modeCrawl,
	}}}
	dir := t.TempDir()
	snmp := dir + "/snmp.yml"
	if err := os.WriteFile(snmp, []byte("auths:\n  public_v2: {community: public, version: 2}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rts, err := loadGroupRuntimes(cfg, ScanParams{SnmpCfg: snmp, DefaultFP: "network", DefaultPort: 161}, fps)
	if err != nil {
		t.Fatal(err)
	}
	jobs, _, sweepN, _, err := planInitialJobs(rts, ScanParams{Ping: false}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sweepN != 0 {
		t.Fatalf("crawl must not expand CIDR, sweepN=%d", sweepN)
	}
	if len(jobs) != 1 || jobs[0].ip != "10.9.9.10" {
		t.Fatalf("jobs=%v", jobs)
	}
}

func TestAllowNeighborRespectsNetsAndExclude(t *testing.T) {
	cidrs := []string{"10.12.0.0/22"}
	excl := []string{"10.12.0.1/32"}
	if !allowNeighbor("10.12.1.8", cidrs, excl) {
		t.Fatal("in-net neighbor should be allowed")
	}
	if allowNeighbor("10.12.0.1", cidrs, excl) {
		t.Fatal("excluded")
	}
	if allowNeighbor("8.8.8.8", cidrs, excl) {
		t.Fatal("outside nets")
	}
}

func TestIPv4FromLLDPOID(t *testing.T) {
	oid := ".1.0.8802.1.1.2.1.4.2.1.4.0.2.1.1.4.10.12.0.9"
	if ip := neighborFromOID(oid); ip != "10.12.0.9" {
		t.Fatalf("got %q", ip)
	}
	if ip := neighborFromPDU(gosnmp.SnmpPDU{Value: []byte{10, 0, 0, 1}}); ip != "10.0.0.1" {
		t.Fatalf("bytes %q", ip)
	}
}

func TestIPv6FromLLDPOID(t *testing.T) {
	// subtype 2, length 16, then 2001:db8::1
	oid := ".1.0.8802.1.1.2.1.4.2.1.4.0.2.1.2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1"
	if ip := neighborFromOID(oid); ip != "2001:db8::1" {
		t.Fatalf("got %q", ip)
	}
	b := net.ParseIP("2001:db8::2").To16()
	if ip := neighborFromPDU(gosnmp.SnmpPDU{Value: []byte(b)}); ip != "2001:db8::2" {
		t.Fatalf("bytes %q", ip)
	}
}

func TestAllowNeighborIPv6(t *testing.T) {
	cidrs := []string{"2001:db8::/64"}
	excl := []string{"2001:db8::1/128"}
	if !allowNeighbor("2001:db8::10", cidrs, excl) {
		t.Fatal("in-net v6 neighbor should be allowed")
	}
	if allowNeighbor("2001:db8::1", cidrs, excl) {
		t.Fatal("excluded")
	}
	if allowNeighbor("2001:db9::1", cidrs, excl) {
		t.Fatal("outside nets")
	}
}

func TestStickyCatalogMissCycles(t *testing.T) {
	c := NewCatalog()
	c.Replace([]AlloyTarget{{Name: "spine1", Address: "10.0.0.1", Auth: "public_v2"}})
	now := time.Now().UTC()

	// misses=3 → keep through miss 1 and 2, drop on miss 3
	out := c.MergeFound(nil, now, 3)
	if len(out) != 1 {
		t.Fatalf("miss 1 should keep: %+v", out)
	}
	out = c.MergeFound(nil, now.Add(24*time.Hour), 3)
	if len(out) != 1 {
		t.Fatalf("miss 2 should keep: %+v", out)
	}
	out = c.MergeFound(nil, now.Add(48*time.Hour), 3)
	if len(out) != 0 {
		t.Fatalf("miss 3 should drop: %+v", out)
	}
}

func TestMissesZeroNeverPurges(t *testing.T) {
	c := NewCatalog()
	c.Replace([]AlloyTarget{{Name: "spine1", Address: "10.0.0.1", Auth: "public_v2"}})
	now := time.Now().UTC()
	for i := 0; i < 10; i++ {
		out := c.MergeFound(nil, now.Add(time.Duration(i)*24*time.Hour), 0)
		if len(out) != 1 {
			t.Fatalf("misses=0 must never purge (i=%d): %+v", i, out)
		}
	}
}

func TestFoundResetsMissCounter(t *testing.T) {
	c := NewCatalog()
	c.Replace([]AlloyTarget{{Name: "spine1", Address: "10.0.0.1", Auth: "public_v2"}})
	now := time.Now().UTC()
	_ = c.MergeFound(nil, now, 3)
	_ = c.MergeFound(nil, now.Add(time.Hour), 3)
	out := c.MergeFound([]AlloyTarget{{Name: "spine1", Address: "10.0.0.1", Auth: "public_v2"}}, now.Add(2*time.Hour), 3)
	if len(out) != 1 {
		t.Fatalf("found should keep: %+v", out)
	}
	entries := c.SnapshotEntries()
	if len(entries) != 1 || entries[0].Misses != 0 {
		t.Fatalf("found must reset Misses: %+v", entries)
	}
	// two more misses after reset should still keep (need 3)
	_ = c.MergeFound(nil, now.Add(3*time.Hour), 3)
	out = c.MergeFound(nil, now.Add(4*time.Hour), 3)
	if len(out) != 1 {
		t.Fatalf("after reset, miss 2 should keep: %+v", out)
	}
}

func TestPlanCrawlAddsNeighborNotSeed(t *testing.T) {
	fps := FingerprintersFile{Fingerprinters: map[string]Fingerprinter{
		"network": {DefaultModules: []string{"system_mib", "if_mib"}},
	}}
	cfg := DiscoveryFile{Groups: []DiscoveryGroup{{
		Name:          "hq",
		CIDRs:         []string{"10.12.0.0/22"},
		Seeds:         []string{"10.12.0.10"},
		Auths:         []string{"public_v2"},
		Fingerprinter: "network",
		Mode:          modeCrawl,
	}}}
	dir := t.TempDir()
	snmp := dir + "/snmp.yml"
	if err := os.WriteFile(snmp, []byte("auths:\n  public_v2: {community: public, version: 2}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rts, err := loadGroupRuntimes(cfg, ScanParams{SnmpCfg: snmp, DefaultFP: "network", DefaultPort: 161}, fps)
	if err != nil {
		t.Fatal(err)
	}
	jobs, claimed, _, _, err := planInitialJobs(rts, ScanParams{Ping: false}, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := []AlloyTarget{{Address: "10.12.0.10", SnmpGroup: "hq", Auth: "public_v2"}}
	extra := planCrawlJobs(rts, ScanParams{
		WalkNeighbor: func(addr string, port uint16, auths []snmpAuth) []string {
			if addr != "10.12.0.10" {
				return nil
			}
			return []string{"10.12.0.11", "8.8.8.8", "10.12.0.10"}
		},
	}, nil, found, claimed)
	if len(extra) != 1 || extra[0].ip != "10.12.0.11" {
		t.Fatalf("crawl jobs=%+v (initial jobs=%d)", extra, len(jobs))
	}
}
