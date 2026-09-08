package snmpdiscovery

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ScanParams struct {
	SnmpCfg      string
	FpPath       string
	DefaultFP    string
	OutAlloy     string
	OutSD        string
	Concurrency  int
	Timeout      time.Duration
	Retries      int
	DefaultPort  uint16
	Catalog      *Catalog
	Ping         bool
	PingTimeout  time.Duration
	Misses       int // consecutive discovery cycles with no response before drop; <=0 = never
	StatePath    string
	PingFilter   func([]string) ([]string, error)
	WalkNeighbor func(addr string, port uint16, auths []snmpAuth) []string
	Logger       *slog.Logger
	// AllowDuplicateSysName keeps every SNMP address even when several
	// share a sysName (IoT fleets that clone hostnames). Default false:
	// one identity per hostname, lowest IP wins.
	AllowDuplicateSysName bool
	Observer              ProbeObserver
	// KnownModules, when set, is the snmp.yml module catalog used to drop
	// fingerprinter names that do not exist. RunScan loads it from SnmpCfg
	// when this field is nil.
	KnownModules map[string]struct{}
	// AuthsOverlay is optional snmp_exporter `auths:` YAML. Named keys
	// replace the same names from SnmpCfg; modules stay on the library file.
	AuthsOverlay []byte
}

// ScanStats is filled by a successful RunScan (and zero on error).
type ScanStats struct {
	Duration     time.Duration
	Sweep        int
	PingUp       int
	Found        int
	Catalog      int
	Dropped      int
	Dedupes      int // extra IPs folded into an existing sysName this scan
	ProbeErrors  int
	ProbeSuccess int
	FirstAuth    int
	AuthFallback int
	ProbeRetries int
}

func (p ScanParams) logger() *slog.Logger {
	if p.Logger != nil {
		return p.Logger
	}
	return slog.Default()
}

type probeJob struct {
	ip    string
	group DiscoveryGroup
	auths []snmpAuth
	fp    Fingerprinter
	port  uint16
}

type groupRuntime struct {
	group DiscoveryGroup
	auths []snmpAuth
	fp    Fingerprinter
	port  uint16
}

func RunScan(cfg DiscoveryFile, p ScanParams) (ScanStats, error) {
	start := time.Now()
	fpRaw, err := LoadFingerprinters(p.FpPath)
	if err != nil {
		return ScanStats{}, err
	}
	if p.KnownModules == nil && strings.TrimSpace(p.SnmpCfg) != "" {
		names, err := loadModuleNames(p.SnmpCfg)
		if err != nil {
			p.logger().Warn("snmp.yml module catalog unavailable; emitting fingerprinter names unchecked",
				"path", p.SnmpCfg, "err", err)
		} else if len(names) > 0 {
			p.KnownModules = names
			p.logger().Debug("loaded snmp.yml modules", "count", len(names), "path", p.SnmpCfg)
		}
	}

	prev := []AlloyTarget{}
	if p.Catalog != nil {
		prev, _ = p.Catalog.Snapshot()
	}

	rts, err := loadGroupRuntimes(cfg, p, fpRaw)
	if err != nil {
		// Failed before probes — do not touch catalog / miss counters / on-disk SD.
		return ScanStats{}, err
	}

	jobs, claimed, sweepN, pingN, err := planInitialJobs(rts, p, prev)
	if err != nil {
		return ScanStats{}, err
	}
	found, probeStats := probeAll(jobs, p)

	crawlJobs := planCrawlJobs(rts, p, prev, found, claimed)
	if len(crawlJobs) > 0 {
		more, crawlStats := probeAll(crawlJobs, p)
		found = append(found, more...)
		probeStats.add(crawlStats)
	}

	ignoreAddrs := ignoredAddresses(cfg.Overrides)
	found = applyOverrides(found, cfg.Overrides)
	found = dedupeTargets(found)
	var collapsedAddrs []string
	found, collapsedAddrs = collapseSameHostname(found, p.AllowDuplicateSysName, p.logger())
	uniquifyNames(found)
	sort.Slice(found, func(i, k int) bool {
		return found[i].Address < found[k].Address
	})

	// Successful complete pass only — merge misses + publish atomically.
	published := found
	dropped := 0
	if p.Catalog != nil {
		beforeAddrs := map[string]struct{}{}
		for _, e := range p.Catalog.SnapshotEntries() {
			beforeAddrs[e.Target.Address] = struct{}{}
		}
		published = p.Catalog.MergeFound(found, time.Now().UTC(), p.Misses)
		if n := p.Catalog.DropAddresses(collapsedAddrs); n > 0 {
			p.logger().Debug("removed collapsed sysName aliases from catalog", "count", n)
			published, _ = p.Catalog.Snapshot()
		}
		if n := p.Catalog.DropAddresses(ignoreAddrs); n > 0 {
			p.logger().Info("ignore override removed catalog entries", "count", n)
			published, _ = p.Catalog.Snapshot()
		}
		for addr := range beforeAddrs {
			still := false
			for _, t := range published {
				if t.Address == addr {
					still = true
					break
				}
			}
			if !still {
				dropped++
			}
		}
		sort.Slice(published, func(i, k int) bool {
			return published[i].Address < published[k].Address
		})
		uniquifyNames(published)
	}

	if err := publishCatalog(p, published); err != nil {
		return ScanStats{}, err
	}
	stats := ScanStats{
		Duration:     time.Since(start).Truncate(time.Millisecond),
		Sweep:        sweepN,
		PingUp:       pingN,
		Found:        len(found),
		Catalog:      len(published),
		Dropped:      dropped,
		Dedupes:      len(collapsedAddrs),
		ProbeErrors:  probeStats.errors,
		ProbeSuccess: probeStats.success,
		FirstAuth:    probeStats.firstAuth,
		AuthFallback: probeStats.fallback,
		ProbeRetries: probeStats.retries,
	}
	p.logger().Info("SNMP discovery scan complete",
		"found", stats.Found,
		"duration", stats.Duration,
		"sweep", stats.Sweep,
		"ping_up", stats.PingUp,
		"catalog", stats.Catalog,
		"dropped", stats.Dropped,
		"dedupes", stats.Dedupes,
		"probe_success", stats.ProbeSuccess,
		"probe_errors", stats.ProbeErrors,
		"first_auth", stats.FirstAuth,
		"retries", stats.ProbeRetries,
	)
	return stats, nil
}

// publishCatalog writes YAML + file_sd + state via temp+rename. Call only after
// a complete successful probe pass (never on partial/error paths).
//
// Alloy staggered scrapes: --out-alloy is the hot catalog; siblings
// *-cold.yml and *-topology.yml are written beside it (empty list when no modules).
func publishCatalog(p ScanParams, published []AlloyTarget) error {
	if p.OutAlloy != "" {
		if err := WriteAlloyYAML(p.OutAlloy, TierTargets(published, "hot")); err != nil {
			return err
		}
		if err := WriteAlloyYAML(tierSiblingPath(p.OutAlloy, "-cold"), TierTargets(published, "cold")); err != nil {
			return err
		}
		if err := WriteAlloyYAML(tierSiblingPath(p.OutAlloy, "-topology"), TierTargets(published, "topology")); err != nil {
			return err
		}
	}
	if p.OutSD != "" {
		if err := writeFileSD(p.OutSD, published); err != nil {
			return err
		}
	}
	if p.Catalog != nil && p.StatePath != "" {
		if err := WriteCatalogState(p.StatePath, p.Catalog); err != nil {
			return err
		}
	}
	return nil
}

func tierSiblingPath(path, suffix string) string {
	switch {
	case strings.HasSuffix(path, ".yml"):
		return strings.TrimSuffix(path, ".yml") + suffix + ".yml"
	case strings.HasSuffix(path, ".yaml"):
		return strings.TrimSuffix(path, ".yaml") + suffix + ".yaml"
	default:
		return path + suffix
	}
}

// TierTargets projects a catalog into a single-module YAML list for one scrape tier.
// Target names are suffixed (-hot/-cold/-topology) so concurrent prometheus.exporter.snmp
// instances do not collide on the same `name` (device_name stays the friendly sysName).
func TierTargets(in []AlloyTarget, tier string) []AlloyTarget {
	out := make([]AlloyTarget, 0, len(in))
	for _, t := range in {
		mod := t.Module
		switch tier {
		case "cold":
			mod = t.ModuleCold
		case "topology":
			mod = t.ModuleTopology
		}
		if strings.TrimSpace(mod) == "" {
			continue
		}
		name := strings.TrimSpace(t.Name)
		if name == "" {
			name = t.Address
		}
		out = append(out, AlloyTarget{
			Name:        name + "-" + tier,
			Address:     t.Address,
			Module:      mod,
			Auth:        t.Auth,
			DeviceName:  t.DeviceName,
			SysObjectID: t.SysObjectID,
			SnmpGroup:   t.SnmpGroup,
		})
	}
	return out
}

func loadGroupRuntimes(cfg DiscoveryFile, p ScanParams, fps FingerprintersFile) ([]groupRuntime, error) {
	var rts []groupRuntime
	for _, g := range cfg.Groups {
		fpName := g.Fingerprinter
		if fpName == "" {
			fpName = p.DefaultFP
		}
		fp, ok := fps.Fingerprinters[fpName]
		if !ok {
			return nil, fmt.Errorf("group %q: fingerprinter %q not in %s", g.Name, fpName, p.FpPath)
		}
		if err := fp.compile(); err != nil {
			return nil, fmt.Errorf("group %q fingerprinter: %w", g.Name, err)
		}
		auths, err := loadAuthsOverlay(p.SnmpCfg, p.AuthsOverlay, g.Auths)
		if err != nil {
			return nil, fmt.Errorf("group %q: %w", g.Name, err)
		}
		port := g.Port
		if port == 0 {
			port = p.DefaultPort
		}
		rts = append(rts, groupRuntime{group: g, auths: auths, fp: fp, port: port})
	}
	return rts, nil
}

func planInitialJobs(rts []groupRuntime, p ScanParams, prev []AlloyTarget) ([]probeJob, map[string]string, int, int, error) {
	claimed := map[string]string{}
	var jobs []probeJob
	sweepN, pingN := 0, 0
	for _, rt := range rts {
		g := rt.group
		mode := groupMode(g)
		var ips []string
		if mode == modeSweep || mode == modeBoth {
			raw, err := expandCIDRs(g.CIDRs, g.AllowLarge)
			if err != nil {
				return nil, nil, 0, 0, fmt.Errorf("group %q: %w", g.Name, err)
			}
			raw, err = filterExcluded(raw, g.Exclude)
			if err != nil {
				return nil, nil, 0, 0, fmt.Errorf("group %q exclude: %w", g.Name, err)
			}
			sweepN += len(raw)
			if groupUsesPing(g, p.Ping) {
				alive, err := filterPing(p, raw)
				if err != nil {
					return nil, nil, 0, 0, fmt.Errorf("group %q ping: %w", g.Name, err)
				}
				pingN += len(alive)
				ips = append(ips, alive...)
			} else {
				pingN += len(raw)
				ips = append(ips, raw...)
			}
		}
		// Always re-probe seeds + catalog for this group (Zabbix-style: ICMP
		// does not gate known inventory). Ping only filters *new* CIDR candidates.
		ips = append(ips, seedIPs(g, prev)...)
		for _, ip := range uniqueStrings(ips) {
			if owner, ok := claimed[ip]; ok {
				p.logger().Debug("skip address claimed by another group",
					"address", ip, "owner", owner, "group", g.Name)
				continue
			}
			claimed[ip] = g.Name
			jobs = append(jobs, probeJob{ip: ip, group: g, auths: rt.auths, fp: rt.fp, port: rt.port})
		}
	}
	return jobs, claimed, sweepN, pingN, nil
}

func seedIPs(g DiscoveryGroup, prev []AlloyTarget) []string {
	var ips []string
	for _, s := range g.Seeds {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		ips = append(ips, mustCanonIP(s))
	}
	for _, t := range prev {
		if t.SnmpGroup == g.Name && t.Address != "" {
			ips = append(ips, mustCanonIP(t.Address))
		}
	}
	return ips
}

func planCrawlJobs(rts []groupRuntime, p ScanParams, prev, found []AlloyTarget, claimed map[string]string) []probeJob {
	walk := p.WalkNeighbor
	if walk == nil {
		walk = func(addr string, port uint16, auths []snmpAuth) []string {
			return walkNeighbors(addr, port, auths, p.Timeout)
		}
	}
	seeds := append([]AlloyTarget{}, found...)
	seeds = append(seeds, prev...)
	var jobs []probeJob
	for _, rt := range rts {
		g := rt.group
		mode := groupMode(g)
		if mode != modeCrawl && mode != modeBoth {
			continue
		}
		var walkFrom []string
		for _, s := range g.Seeds {
			s = strings.TrimSpace(s)
			if s != "" {
				walkFrom = append(walkFrom, s)
			}
		}
		for _, t := range seeds {
			if t.SnmpGroup != "" && t.SnmpGroup != g.Name {
				continue
			}
			if t.Address != "" {
				walkFrom = append(walkFrom, t.Address)
			}
		}
		for _, addr := range uniqueStrings(walkFrom) {
			addr = mustCanonIP(addr)
			for _, ip := range walk(addr, rt.port, rt.auths) {
				ip = mustCanonIP(ip)
				if ip == addr {
					continue
				}
				if !allowNeighbor(ip, g.CIDRs, g.Exclude) {
					continue
				}
				if _, ok := claimed[ip]; ok {
					continue
				}
				claimed[ip] = g.Name
				jobs = append(jobs, probeJob{ip: ip, group: g, auths: rt.auths, fp: rt.fp, port: rt.port})
			}
		}
	}
	return jobs
}

func filterPing(p ScanParams, ips []string) ([]string, error) {
	if len(ips) == 0 {
		return ips, nil
	}
	if p.PingFilter != nil {
		return p.PingFilter(ips)
	}
	if !p.Ping {
		return ips, nil
	}
	return icmpAlive(ips, p.PingTimeout)
}

type probeBatchStats struct {
	errors, success, firstAuth, fallback, retries int
}

func (s *probeBatchStats) add(o probeBatchStats) {
	s.errors += o.errors
	s.success += o.success
	s.firstAuth += o.firstAuth
	s.fallback += o.fallback
	s.retries += o.retries
}

func probeAll(jobs []probeJob, p ScanParams) ([]AlloyTarget, probeBatchStats) {
	if len(jobs) == 0 {
		return nil, probeBatchStats{}
	}
	workers := p.Concurrency
	if workers < 1 {
		workers = 1
	}
	ch := make(chan probeJob)
	var mu sync.Mutex
	var targets []AlloyTarget
	var errors, success, firstAuth, fallback, retries atomic.Int64
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := range ch {
				if p.Observer != nil {
					p.Observer.ProbeBegin()
				}
				res, detail := probe(j.ip, j.port, p.Timeout, p.Retries, j.auths, j.fp.ProbeOIDs)
				if p.Observer != nil {
					p.Observer.ProbeEnd(detail)
				}
				retries.Add(int64(detail.Retries))
				if !detail.Success || res == nil {
					errors.Add(1)
					p.logger().Debug("SNMP probe failed", "address", j.ip, "group", j.group.Name, "reason", detail.Reason)
					continue
				}
				success.Add(1)
				if detail.FirstAuth {
					firstAuth.Add(1)
				} else {
					fallback.Add(1)
				}
				labels := map[string]string{
					"sysObjectID": res.SysObjectID,
					"sysName":     res.SysName,
					"sysDescr":    res.SysDescr,
				}
				tiers, dropped := filterTiersToKnown(j.fp.MatchTiers(labels), p.KnownModules)
				if len(dropped) > 0 {
					p.logger().Warn("dropping fingerprinter modules missing from snmp.yml",
						"address", j.ip,
						"dropped", dropped,
					)
				}
				name, deviceName := targetNames(res.SysName, res.Addr)
				t := AlloyTarget{
					Name:           name,
					Address:        mustCanonIP(res.Addr),
					Module:         joinModules(tiers.Hot),
					ModuleCold:     joinModules(tiers.Cold),
					ModuleTopology: joinModules(tiers.Topology),
					Auth:           res.AuthName,
					DeviceName:     deviceName,
					SysObjectID:    res.SysObjectID,
					SnmpGroup:      j.group.Name,
				}
				mu.Lock()
				targets = append(targets, t)
				mu.Unlock()
				p.logger().Debug("SNMP device found",
					"address", t.Address,
					"group", t.SnmpGroup,
					"auth", t.Auth,
					"device_name", t.DeviceName,
					"hot", t.Module,
					"cold", t.ModuleCold,
					"topology", t.ModuleTopology,
					"sysObjectID", t.SysObjectID,
				)
			}
		}()
	}
	for _, j := range jobs {
		ch <- j
	}
	close(ch)
	wg.Wait()
	return targets, probeBatchStats{
		errors:    int(errors.Load()),
		success:   int(success.Load()),
		firstAuth: int(firstAuth.Load()),
		fallback:  int(fallback.Load()),
		retries:   int(retries.Load()),
	}
}

func dedupeTargets(in []AlloyTarget) []AlloyTarget {
	seen := map[string]struct{}{}
	out := make([]AlloyTarget, 0, len(in))
	for _, t := range in {
		if _, ok := seen[t.Address]; ok {
			continue
		}
		seen[t.Address] = struct{}{}
		out = append(out, t)
	}
	return out
}

// expandJobs is the sweep-only planner used by tests (first-group-wins).
func expandJobs(cfg DiscoveryFile, p ScanParams, fps FingerprintersFile) ([]probeJob, error) {
	rts, err := loadGroupRuntimes(cfg, p, fps)
	if err != nil {
		return nil, err
	}
	p.Ping = false
	p.PingFilter = func(ips []string) ([]string, error) { return ips, nil }
	jobs, _, _, _, err := planInitialJobs(rts, p, nil)
	return jobs, err
}
