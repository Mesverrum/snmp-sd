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

	// FingerprintKnown is a sysObjectID that hit a fingerprinter matcher.
	FingerprintKnown = "known"
	// FingerprintUnknown uses the fingerprinter default chain (device_base / if_mib).
	FingerprintUnknown = "unknown"
)

// ProbeObserver is notified around each SNMP identity probe. The Alloy
// component and the CLI /metrics handler implement this without the library
// importing Prometheus.
type ProbeObserver interface {
	ProbeBegin()
	ProbeEnd(ProbeDetail)
}

// DeviceObserver is optional. Implement it on the same value as ProbeObserver
// to receive fingerprint / module-drop events after a successful identity Get.
type DeviceObserver interface {
	DeviceFound(DeviceFoundDetail)
}

// ProbeDetail is one address probe (all auths + retries).
type ProbeDetail struct {
	Duration  time.Duration
	Success   bool
	Reason    string
	FirstAuth bool
	AuthFails int
	Retries   int
	Address   string
	Group     string
	Auth      string // winning auth name, or last attempted
}

// DeviceFoundDetail is a successful identity probe after fingerprinting.
type DeviceFoundDetail struct {
	Address        string
	Group          string
	DeviceName     string
	SysObjectID    string
	Auth           string
	Fingerprint    string // FingerprintKnown or FingerprintUnknown
	DroppedModules []string
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

func probeReasonActionable(reason string) bool {
	switch reason {
	case ProbeReasonNoAuth, ProbeReasonNoSys, ProbeReasonEmpty:
		return true
	default:
		return false
	}
}
