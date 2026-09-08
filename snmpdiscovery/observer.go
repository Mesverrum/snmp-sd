package snmpdiscovery

import (
	"strings"
	"time"
)

const (
	ProbeReasonOK      = "ok"
	ProbeReasonTimeout = "timeout"
	ProbeReasonRefused = "refused"
	ProbeReasonConnect = "connect"
	ProbeReasonEmpty   = "empty"
	ProbeReasonNoSys   = "no_sys"
	ProbeReasonNoAuth  = "no_auth"
	ProbeReasonOther   = "other"
)

// ProbeObserver is notified around each SNMP identity probe. The component
// uses this to emit health metrics without importing Prometheus here.
type ProbeObserver interface {
	ProbeBegin()
	ProbeEnd(ProbeDetail)
}

// ProbeDetail is one address probe (all auths + retries).
type ProbeDetail struct {
	Duration  time.Duration
	Success   bool
	Reason    string
	FirstAuth bool
	AuthFails int
	Retries   int
}

func classifyProbeError(err error) string {
	if err == nil {
		return ProbeReasonOK
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "timeout") || strings.Contains(s, "deadline"):
		return ProbeReasonTimeout
	case strings.Contains(s, "connection refused") || strings.Contains(s, "refused"):
		return ProbeReasonRefused
	case strings.Contains(s, "empty snmp"):
		return ProbeReasonEmpty
	case strings.Contains(s, "no sys"):
		return ProbeReasonNoSys
	case strings.Contains(s, "no auth"):
		return ProbeReasonNoAuth
	case strings.Contains(s, "connect") || strings.Contains(s, "unreachable") ||
		strings.Contains(s, "no route") || strings.Contains(s, "network is down"):
		return ProbeReasonConnect
	default:
		return ProbeReasonOther
	}
}
