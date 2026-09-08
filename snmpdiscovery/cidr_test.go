package snmpdiscovery

import "testing"

func TestExpandCIDR32KeepsHost(t *testing.T) {
	ips, err := expandCIDRs([]string{"172.20.20.2/32"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "172.20.20.2" {
		t.Fatalf(" /32 must keep the host, got %v", ips)
	}
}

func TestExpandBareIP(t *testing.T) {
	ips, err := expandCIDRs([]string{"172.20.20.3"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "172.20.20.3" {
		t.Fatalf("got %v", ips)
	}
}

func TestExpandCIDR24SkipsNetworkBroadcast(t *testing.T) {
	ips, err := expandCIDRs([]string{"10.1.2.0/30"}, false)
	if err != nil {
		t.Fatal(err)
	}
	// /30 has 2 host bits (< 8) so network/broadcast are kept — that is
	// intentional so tiny lab CIDRs are not emptied. /24+ skip them.
	if len(ips) != 4 {
		t.Fatalf("got %v", ips)
	}
	ips, err = expandCIDRs([]string{"10.9.9.0/24"}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range ips {
		if ip == "10.9.9.0" || ip == "10.9.9.255" {
			t.Fatalf("network/broadcast leaked: %s", ip)
		}
	}
	if len(ips) != 254 {
		t.Fatalf("want 254 hosts, got %d", len(ips))
	}
}

func TestExpandAllows22Rejects21(t *testing.T) {
	if _, err := expandCIDRs([]string{"10.0.0.0/22"}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := expandCIDRs([]string{"10.0.0.0/21"}, false); err == nil {
		t.Fatal("expected /21 to require allow_large")
	}
}

func TestExpandRejectsLargeCIDR(t *testing.T) {
	_, err := expandCIDRs([]string{"10.0.0.0/16"}, false)
	if err == nil {
		t.Fatal("expected --allow-large error")
	}
}

func TestCanonIPAcceptsBracketsAndPort(t *testing.T) {
	got, err := canonIP("[2001:db8::1]:161")
	if err != nil || got != "2001:db8::1" {
		t.Fatalf("got %q err=%v", got, err)
	}
	got, err = canonIP("2001:db8::1")
	if err != nil || got != "2001:db8::1" {
		t.Fatalf("got %q err=%v", got, err)
	}
}

func TestExpandIPv6BareAnd128(t *testing.T) {
	ips, err := expandCIDRs([]string{"2001:db8::5"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "2001:db8::5" {
		t.Fatalf("got %v", ips)
	}
	ips, err = expandCIDRs([]string{"2001:db8::a/128"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "2001:db8::a" {
		t.Fatalf("got %v", ips)
	}
}

func TestExpandIPv6Allows118Rejects117(t *testing.T) {
	if _, err := expandCIDRs([]string{"2001:db8::/118"}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := expandCIDRs([]string{"2001:db8::/117"}, false); err == nil {
		t.Fatal("expected /117 to require allow_large")
	}
}

func TestParseIPNetsBareIPv6Is128(t *testing.T) {
	nets, err := parseIPNets([]string{"2001:db8::1"})
	if err != nil {
		t.Fatal(err)
	}
	ones, bits := nets[0].Mask.Size()
	if bits != 128 || ones != 128 {
		t.Fatalf("want /128, got /%d bits=%d", ones, bits)
	}
	if !ipInNets("2001:db8::1", nets) {
		t.Fatal("should contain")
	}
	if ipInNets("2001:db8::2", nets) {
		t.Fatal("should not contain sibling")
	}
}

func TestNameAddrSuffixStripsColons(t *testing.T) {
	if s := nameAddrSuffix("2001:db8::1"); s != "2001-db8--1" {
		t.Fatalf("got %q", s)
	}
}

