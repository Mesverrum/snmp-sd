package snmpdiscovery

import (
	"log/slog"
	"net/netip"
	"sort"
	"strings"
)

// collapseSameHostname keeps one catalog identity per sysName within a single
// scan. The lowest address wins (netip.Addr order: IPv4 before IPv6, then
// numeric). Addresses whose device_name is empty or is the IP itself are left
// alone. allowDup skips the merge (cloned IoT hostnames).
func collapseSameHostname(in []AlloyTarget, allowDup bool, log *slog.Logger) ([]AlloyTarget, []string) {
	if allowDup || len(in) < 2 {
		return in, nil
	}
	if log == nil {
		log = slog.Default()
	}

	byKey := map[string][]int{}
	for i, t := range in {
		if k := hostnameCollapseKey(t.DeviceName, t.Address); k != "" {
			byKey[k] = append(byKey[k], i)
		}
	}

	dropIdx := map[int]struct{}{}
	var dropped []string
	for _, idxs := range byKey {
		if len(idxs) < 2 {
			continue
		}
		win := idxs[0]
		for _, i := range idxs[1:] {
			if compareProbeAddr(in[i].Address, in[win].Address) < 0 {
				win = i
			}
		}
		lost := make([]string, 0, len(idxs)-1)
		var inherit []string
		for _, i := range idxs {
			if i == win {
				continue
			}
			dropIdx[i] = struct{}{}
			lost = append(lost, in[i].Address)
			dropped = append(dropped, in[i].Address)
			inherit = append(inherit, in[i].Aliases...)
		}
		sort.Strings(lost)
		in[win].Aliases = mergeAliases(in[win].Aliases, lost, inherit)
		log.Info("collapsed duplicate sysName into one identity",
			"device_name", in[win].DeviceName,
			"kept", in[win].Address,
			"aliases", in[win].Aliases,
		)
	}
	if len(dropIdx) == 0 {
		return in, nil
	}
	out := make([]AlloyTarget, 0, len(in)-len(dropIdx))
	for i, t := range in {
		if _, ok := dropIdx[i]; ok {
			continue
		}
		out = append(out, t)
	}
	return out, dropped
}

func hostnameCollapseKey(deviceName, addr string) string {
	n := strings.ToLower(strings.TrimSpace(deviceName))
	if n == "" {
		return ""
	}
	addr = strings.ToLower(mustCanonIP(addr))
	if n == addr {
		return ""
	}
	if _, err := netip.ParseAddr(n); err == nil {
		return ""
	}
	return n
}

func compareProbeAddr(a, b string) int {
	pa, ea := netip.ParseAddr(mustCanonIP(a))
	pb, eb := netip.ParseAddr(mustCanonIP(b))
	if ea == nil && eb == nil {
		return pa.Compare(pb)
	}
	if ea != nil && eb != nil {
		return strings.Compare(a, b)
	}
	if ea != nil {
		return 1
	}
	return -1
}

func mergeAliases(parts ...[]string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, p := range parts {
		for _, a := range p {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			a = mustCanonIP(a)
			if _, ok := seen[a]; ok {
				continue
			}
			seen[a] = struct{}{}
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}
