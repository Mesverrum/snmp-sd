package snmpdiscovery

import (
	"errors"
	"testing"
	"time"
)

func TestClassifyProbeError(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, ProbeReasonOK},
		{errors.New("i/o timeout"), ProbeReasonTimeout},
		{errors.New("context deadline exceeded"), ProbeReasonTimeout},
		{errors.New("read udp: connection refused"), ProbeReasonRefused},
		{errors.New("empty SNMP response"), ProbeReasonEmpty},
		{errors.New("no sys* fields"), ProbeReasonNoSys},
		{errors.New("no auth succeeded"), ProbeReasonNoAuth},
		{errors.New("dial tcp: connect: network is unreachable"), ProbeReasonConnect},
		{errors.New("something weird"), ProbeReasonOther},
	}
	for _, tc := range cases {
		if got := classifyProbeError(tc.err); got != tc.want {
			t.Fatalf("%v: got %s want %s", tc.err, got, tc.want)
		}
	}
}

func TestProbeEmptyAuths(t *testing.T) {
	res, d := probe("10.0.0.1", 161, time.Millisecond, 0, nil, nil)
	if res != nil {
		t.Fatalf("expected nil result: %+v", res)
	}
	if d.Success || d.Reason != ProbeReasonNoAuth {
		t.Fatalf("detail=%+v", d)
	}
}
