package snmpdiscovery

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"testing"
)

func TestDiscoverMissingFingerprinters(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := DiscoveryFile{
		Groups: []DiscoveryGroup{{
			Name:  "hq",
			CIDRs: []string{"10.0.0.0/30"},
			Auths: []string{"public_v2"},
		}},
	}
	_, stats, err := Discover(cfg, ScanParams{
		SnmpCfg:     filepath.Join(t.TempDir(), "missing-snmp.yml"),
		FpPath:      filepath.Join(t.TempDir(), "missing-fp.yml"),
		DefaultFP:   "network",
		Concurrency: 1,
		Timeout:     1,
		Ping:        false,
		Logger:      log,
	})
	if err == nil {
		t.Fatal("expected error for missing fingerprinters")
	}
	if stats != (ScanStats{}) {
		t.Fatalf("failed scan should return zero stats, got %+v", stats)
	}
}

func TestScanParamsLoggerNilSafe(t *testing.T) {
	p := ScanParams{}
	if p.logger() == nil {
		t.Fatal("logger() must not return nil")
	}
}
