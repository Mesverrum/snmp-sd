package snmpdiscovery

import "testing"

func TestFilterTiersToKnownDropsMissingSidecar(t *testing.T) {
	in := ModuleTiers{
		Hot:  []string{"if_mib", "nokia_srlinux_hot", "nokia_srlinux"},
		Cold: []string{"if_mib_meta", "ip_addr"},
	}
	known := map[string]struct{}{
		"if_mib":        {},
		"if_mib_meta":   {},
		"nokia_srlinux": {},
	}
	got, dropped := filterTiersToKnown(in, known)
	if len(got.Hot) != 2 || got.Hot[0] != "if_mib" || got.Hot[1] != "nokia_srlinux" {
		t.Fatalf("hot: %v", got.Hot)
	}
	if len(got.Cold) != 1 || got.Cold[0] != "if_mib_meta" {
		t.Fatalf("cold: %v", got.Cold)
	}
	if len(dropped) != 2 {
		t.Fatalf("dropped: %v", dropped)
	}
}

func TestFilterTiersToKnownSkipsEmptyCatalog(t *testing.T) {
	in := ModuleTiers{Hot: []string{"nokia_srlinux_hot"}}
	got, dropped := filterTiersToKnown(in, nil)
	if len(got.Hot) != 1 || got.Hot[0] != "nokia_srlinux_hot" || len(dropped) != 0 {
		t.Fatalf("got=%v dropped=%v", got, dropped)
	}
}

func TestMatchTiersNokia(t *testing.T) {
	fp := Fingerprinter{
		DefaultModules: []string{"system_mib", "if_mib"},
		Matchers: []Matcher{
			{
				Label:   "sysObjectID",
				Regex:   `^\.?1\.3\.6\.1\.4\.1\.6527\.1\.20(\.[0-9]+)+$`,
				Modules: []string{"system_mib", "if_mib", "nokia_srlinux"},
			},
		},
	}
	if err := fp.compile(); err != nil {
		t.Fatal(err)
	}
	tiers := fp.MatchTiers(map[string]string{"sysObjectID": "1.3.6.1.4.1.6527.1.20.26"})
	if len(tiers.Hot) != 1 || tiers.Hot[0] != "if_mib" {
		t.Fatalf("hot: %v", tiers.Hot)
	}
	if len(tiers.Cold) < 2 {
		t.Fatalf("cold: %v", tiers.Cold)
	}
}
