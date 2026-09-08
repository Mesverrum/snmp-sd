package snmpdiscovery

import "testing"

func TestMatchNokiaSysObjectID(t *testing.T) {
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
	// Match expands legacy modules into hot+cold (if_mib → if_mib + if_mib_meta).
	got := fp.Match(map[string]string{"sysObjectID": "1.3.6.1.4.1.6527.1.20.26"})
	want := []string{"if_mib", "system_mib", "if_mib_meta", "nokia_srlinux"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	got = fp.Match(map[string]string{"sysObjectID": ".1.3.6.1.4.1.6527.1.20.26"})
	if len(got) != 4 || got[3] != "nokia_srlinux" {
		t.Fatalf("leading-dot: %v", got)
	}
	got = fp.Match(map[string]string{"sysObjectID": "1.3.6.1.4.1.9.1.1"})
	wantDef := []string{"if_mib", "system_mib", "if_mib_meta"}
	if len(got) != len(wantDef) || got[0] != "if_mib" {
		t.Fatalf("default: %v", got)
	}
}
