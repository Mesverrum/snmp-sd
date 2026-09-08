package snmpdiscovery

import "strings"

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

// TargetsForTier projects the full catalog into a single-module list for one
// scrape tier (hot|cold|topology). Empty tier or "all" emits every non-empty tier.
func TargetsForTier(catalog []AlloyTarget, tier string) []AlloyTarget {
	tier = strings.TrimSpace(strings.ToLower(tier))
	if tier == "" || tier == "all" {
		var out []AlloyTarget
		for _, t := range []string{"hot", "cold", "topology"} {
			out = append(out, TierTargets(catalog, t)...)
		}
		return out
	}
	return TierTargets(catalog, tier)
}
