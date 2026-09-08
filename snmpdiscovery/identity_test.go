package snmpdiscovery

import (
	"io"
	"log/slog"
	"testing"
)

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestCollapseSameHostnameKeepsLowestIP(t *testing.T) {
	in := []AlloyTarget{
		{Name: "spine1", Address: "10.0.0.10", DeviceName: "spine1"},
		{Name: "spine1", Address: "10.0.0.2", DeviceName: "Spine1"},
		{Name: "leaf1", Address: "10.0.0.3", DeviceName: "leaf1"},
	}
	out, dropped := collapseSameHostname(in, false, discardLog())
	if len(out) != 2 {
		t.Fatalf("got %d targets: %+v", len(out), out)
	}
	if out[0].Address != "10.0.0.2" || out[0].DeviceName != "Spine1" {
		t.Fatalf("lowest IP should win with its labels: %+v", out[0])
	}
	if len(out[0].Aliases) != 1 || out[0].Aliases[0] != "10.0.0.10" {
		t.Fatalf("collapsed IP must stay as alias: %+v", out[0].Aliases)
	}
	if len(dropped) != 1 || dropped[0] != "10.0.0.10" {
		t.Fatalf("dropped=%v", dropped)
	}
}

func TestCollapseSameHostnameAllowDuplicates(t *testing.T) {
	in := []AlloyTarget{
		{Name: "cam", Address: "10.0.0.8", DeviceName: "camera"},
		{Name: "cam", Address: "10.0.0.9", DeviceName: "camera"},
	}
	out, dropped := collapseSameHostname(in, true, discardLog())
	if len(out) != 2 || len(dropped) != 0 {
		t.Fatalf("allowDup should keep both: out=%d dropped=%v", len(out), dropped)
	}
}

func TestCollapseSameHostnameSkipsIPIdentity(t *testing.T) {
	in := []AlloyTarget{
		{Name: "a", Address: "10.0.0.1", DeviceName: "10.0.0.1"},
		{Name: "b", Address: "10.0.0.2", DeviceName: "10.0.0.2"},
	}
	out, dropped := collapseSameHostname(in, false, discardLog())
	if len(out) != 2 || len(dropped) != 0 {
		t.Fatalf("IP-as-sysName must not collapse: out=%d dropped=%v", len(out), dropped)
	}
}

func TestCompareProbeAddrNumericNotLexical(t *testing.T) {
	if compareProbeAddr("10.0.0.2", "10.0.0.10") >= 0 {
		t.Fatal("10.0.0.2 must sort before 10.0.0.10")
	}
}
