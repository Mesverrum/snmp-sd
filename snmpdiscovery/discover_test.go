package snmpdiscovery

import (
	"strings"
	"testing"
)

func TestParseEnabledTiers(t *testing.T) {
	all, err := ParseEnabledTiers("")
	if err != nil || len(all) != 3 {
		t.Fatalf("empty: %v %v", all, err)
	}
	hot, err := ParseEnabledTiers("hot")
	if err != nil || len(hot) != 1 || hot[0] != "hot" {
		t.Fatalf("hot: %v %v", hot, err)
	}
	pair, err := ParseEnabledTiers("cold,hot")
	if err != nil || len(pair) != 2 || pair[0] != "hot" || pair[1] != "cold" {
		t.Fatalf("order: %v %v", pair, err)
	}
	if _, err := ParseEnabledTiers("warm"); err == nil {
		t.Fatal("expected error for warm")
	}
}

func TestTargetsForTiersHotOnly(t *testing.T) {
	cat := []AlloyTarget{{
		Name: "spine1", Address: "10.0.0.1", Module: "if_mib",
		ModuleCold: "if_mib_meta", ModuleTopology: "lldp_mib",
		Auth: "public_v2", DeviceName: "spine1",
	}}
	got := TargetsForTiers(cat, []string{"hot"})
	if len(got) != 1 || got[0].Module != "if_mib" || !strings.HasSuffix(got[0].Name, "-hot") {
		t.Fatalf("hot-only: %+v", got)
	}
	if n := len(TargetsForTiers(cat, []string{"hot", "cold"})); n != 2 {
		t.Fatalf("hot+cold: %d", n)
	}
}
