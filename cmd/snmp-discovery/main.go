// Command snmp-discovery — CLI wrapper around snmpdiscovery.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Mesverrum/snmp-sd/snmpdiscovery"
)

func main() {
	log.SetFlags(0)
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(argv []string) error {
	fs := flag.NewFlagSet("snmp-discovery", flag.ContinueOnError)
	configPath := fs.String("config", "", "discovery groups YAML")
	cidrs := fs.String("cidrs", "", "comma-separated CIDRs (legacy)")
	port := fs.Uint("port", 161, "default SNMP UDP port")
	snmpCfg := fs.String("snmp-config", "snmp/snmp-network.yml", "snmp.yml (modules + default auths)")
	fpPath := fs.String("fingerprinters", "snmp/fingerprinters.yml", "fingerprinters")
	fpName := fs.String("fingerprinter", "network", "default fingerprinter name")
	authsFlag := fs.String("auths", "", "comma-separated auth names for --cidrs")
	outAlloy := fs.String("out-alloy", "snmp-targets.yml", "Alloy targets YAML")
	outSD := fs.String("out-file-sd", "snmp-file-sd.json", "Prometheus file_sd")
	listen := fs.String("listen", "", "HTTP SD listen (e.g. :9780)")
	concurrency := fs.Int("concurrency", 8, "parallel probes")
	timeout := fs.Duration("timeout", 2*time.Second, "SNMP timeout")
	retries := fs.Int("retries", 0, "SNMP retries")
	allowLarge := fs.Bool("allow-large", false, "allow CIDR wider than /22")
	interval := fs.Duration("interval", 0, "rescan period (0 = one-shot)")
	overridesPath := fs.String("overrides", "", "overrides YAML")
	ping := fs.Bool("ping", true, "ICMP filter sweeps")
	pingTimeout := fs.Duration("ping-timeout", 400*time.Millisecond, "ICMP wait")
	misses := fs.Int("misses", 3, "misses before drop")
	statePath := fs.String("state", "", "state path")
	allowDupSys := fs.Bool("allow-duplicate-sysname", false, "do not collapse same sysName on multiple IPs")
	tiersFlag := fs.String("tiers", "hot,cold", "scrape tiers to publish: hot, cold, topology, or all")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	enabledTiers, err := snmpdiscovery.ParseEnabledTiers(*tiersFlag)
	if err != nil {
		return err
	}

	state := strings.TrimSpace(*statePath)
	if state == "" && strings.TrimSpace(*outAlloy) != "" {
		state = *outAlloy + ".state.json"
	}

	cat := snmpdiscovery.NewCatalog()
	p := snmpdiscovery.ScanParams{
		SnmpCfg:               *snmpCfg,
		FpPath:                *fpPath,
		DefaultFP:             *fpName,
		OutAlloy:              *outAlloy,
		OutSD:                 *outSD,
		Concurrency:           *concurrency,
		Timeout:               *timeout,
		Retries:               *retries,
		DefaultPort:           uint16(*port),
		Catalog:               cat,
		Ping:                  *ping,
		PingTimeout:           *pingTimeout,
		Misses:                *misses,
		StatePath:             state,
		AllowDuplicateSysName: *allowDupSys,
		EnabledTiers:          enabledTiers,
	}

	if entries, err := snmpdiscovery.ReadCatalogState(state); err == nil && len(entries) > 0 {
		cat.LoadEntries(entries)
		log.Printf("loaded %d catalog entries from %s", len(entries), state)
	} else if prev, err := snmpdiscovery.ReadAlloyYAML(*outAlloy); err == nil && len(prev) > 0 {
		cat.Replace(prev)
		log.Printf("seeded catalog from %s (%d targets)", *outAlloy, len(prev))
	}

	var scanMu sync.Mutex
	scanOnce := func() error {
		if !scanMu.TryLock() {
			log.Printf("previous scan still running; skip")
			return nil
		}
		defer scanMu.Unlock()
		cfg, err := snmpdiscovery.LoadRunConfig(*configPath, *cidrs, *authsFlag, uint16(*port), *allowLarge, *fpName)
		if err != nil {
			return err
		}
		if err := snmpdiscovery.MergeOverridesFile(&cfg, *overridesPath); err != nil {
			return err
		}
		_, err = snmpdiscovery.RunScan(cfg, p)
		return err
	}

	if err := scanOnce(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if addr := strings.TrimSpace(*listen); addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", addr, err)
		}
		srv := &http.Server{Handler: snmpdiscovery.NewDiscoveryMux(cat), ReadHeaderTimeout: 5 * time.Second}
		go func() {
			log.Printf("HTTP SD on %s", addr)
			_ = srv.Serve(ln)
		}()
		defer func() {
			shctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = srv.Shutdown(shctx)
		}()
	}

	if *interval <= 0 {
		if strings.TrimSpace(*listen) == "" {
			return nil
		}
		<-ctx.Done()
		return nil
	}
	log.Printf("rescanning every %s", *interval)
	t := time.NewTicker(*interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := scanOnce(); err != nil {
				log.Printf("scan error: %v", err)
			}
		}
	}
}
