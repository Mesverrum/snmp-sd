package snmpdiscovery

import (
	"fmt"
	"strings"
)

// AllTiers is the scrape-tier order: alerting, inventory, neighbor graphs.
var AllTiers = []string{"hot", "cold", "topology"}

// Discover runs one probe pass and returns the published catalog (after
// sticky-miss merge). When OutAlloy/OutSD/StatePath are set it still writes
// files — same side effects as RunScan.
func Discover(cfg DiscoveryFile, p ScanParams) ([]AlloyTarget, ScanStats, error) {
	if p.Catalog == nil {
		p.Catalog = NewCatalog()
	}
	stats, err := RunScan(cfg, p)
	if err != nil {
		return nil, stats, err
	}
	published, _ := p.Catalog.Snapshot()
	return published, stats, nil
}

// ParseEnabledTiers accepts "hot", "hot,cold", "all", or empty (all three).
// Order is always hot, cold, topology. At least one valid name is required
// when the string is non-empty and not "all".
func ParseEnabledTiers(s string) ([]string, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "all" {
		return append([]string{}, AllTiers...), nil
	}
	want := map[string]struct{}{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if p == "all" {
			return append([]string{}, AllTiers...), nil
		}
		switch p {
		case "hot", "cold", "topology":
			want[p] = struct{}{}
		default:
			return nil, fmt.Errorf("unknown scrape tier %q (hot, cold, topology, or all)", p)
		}
	}
	if len(want) == 0 {
		return nil, fmt.Errorf("tiers is empty (use hot, cold, topology, or all)")
	}
	out := make([]string, 0, len(want))
	for _, t := range AllTiers {
		if _, ok := want[t]; ok {
			out = append(out, t)
		}
	}
	return out, nil
}

// NormalizeTiers validates a list. Empty means all three (library default).
func NormalizeTiers(in []string) ([]string, error) {
	if len(in) == 0 {
		return append([]string{}, AllTiers...), nil
	}
	return ParseEnabledTiers(strings.Join(in, ","))
}

// TierEnabled reports whether name is in tiers. Empty tiers means all.
func TierEnabled(tiers []string, name string) bool {
	if len(tiers) == 0 {
		return true
	}
	for _, t := range tiers {
		if t == name {
			return true
		}
	}
	return false
}

// TargetsForTier projects the catalog into one scrape tier. Empty/"all"
// emits every non-empty tier.
func TargetsForTier(catalog []AlloyTarget, tier string) []AlloyTarget {
	list, err := ParseEnabledTiers(tier)
	if err != nil {
		return nil
	}
	return TargetsForTiers(catalog, list)
}

// TargetsForTiers projects the catalog into the enabled scrape tiers.
func TargetsForTiers(catalog []AlloyTarget, tiers []string) []AlloyTarget {
	list, err := NormalizeTiers(tiers)
	if err != nil {
		return nil
	}
	var out []AlloyTarget
	for _, t := range list {
		out = append(out, TierTargets(catalog, t)...)
	}
	return out
}
