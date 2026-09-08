package snmpdiscovery

import (
	"fmt"
	"net"
	"strings"
)

// maxSweepHostBits caps CIDR expansion without allow_large (~1024 addresses).
// IPv4 /22 and IPv6 /118 both have 10 host bits.
const maxSweepHostBits = 10

// canonIP normalizes an IP for catalog keys and snmp_exporter targets:
// compressed string, no brackets, no port. Accepts "1.2.3.4", "2001:db8::1",
// and "[2001:db8::1]" / "[2001:db8::1]:161" (port discarded — use group port).
func canonIP(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("empty address")
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	} else if strings.HasPrefix(s, "[") {
		if i := strings.LastIndex(s, "]"); i > 1 {
			s = s[1:i]
		}
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", fmt.Errorf("invalid IP: %s", raw)
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), nil
	}
	return ip.String(), nil
}

func mustCanonIP(raw string) string {
	s, err := canonIP(raw)
	if err != nil {
		return strings.TrimSpace(raw)
	}
	return s
}

// nameAddrSuffix is safe to append to Alloy target names (no ':').
func nameAddrSuffix(addr string) string {
	return strings.ReplaceAll(mustCanonIP(addr), ":", "-")
}

func expandCIDRs(cidrs []string, allowLarge bool) ([]string, error) {
	var ips []string
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "/") {
			ip, err := canonIP(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid IP or CIDR: %s", raw)
			}
			ips = append(ips, ip)
			continue
		}
		_, ipnet, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, err
		}
		ones, bits := ipnet.Mask.Size()
		hostBits := bits - ones
		if hostBits > maxSweepHostBits && !allowLarge {
			family := "IPv4"
			maxPrefix := bits - maxSweepHostBits
			if bits == 128 {
				family = "IPv6"
			}
			return nil, fmt.Errorf("CIDR %s is %s /%d (%d host bits); max without allow_large is /%d (~1024). Do not sweep wider without allow_large",
				raw, family, ones, hostBits, maxPrefix)
		}
		for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
			addr := append(net.IP(nil), ip...)
			canon, err := canonIP(addr.String())
			if err != nil {
				continue
			}
			// Skip network / IPv4 broadcast on larger prefixes. IPv6 has no broadcast.
			if hostBits >= 8 {
				if isNetwork(ipnet, addr) {
					continue
				}
				if addr.To4() != nil && isBroadcast(ipnet, addr) {
					continue
				}
			}
			ips = append(ips, canon)
		}
	}
	return uniqueStrings(ips), nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isNetwork(n *net.IPNet, ip net.IP) bool {
	return n.IP.Equal(ip)
}

func isBroadcast(n *net.IPNet, ip net.IP) bool {
	bcast := make(net.IP, len(n.IP))
	copy(bcast, n.IP)
	for i := range bcast {
		bcast[i] |= ^n.Mask[i]
	}
	return bcast.Equal(ip)
}

func parseIPNets(cidrs []string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "/") {
			ip, err := canonIP(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %s: %w", raw, err)
			}
			parsed := net.ParseIP(ip)
			if parsed.To4() != nil {
				raw = ip + "/32"
			} else {
				raw = ip + "/128"
			}
		}
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %s: %w", raw, err)
		}
		nets = append(nets, n)
	}
	return nets, nil
}

func ipInNets(ip string, nets []*net.IPNet) bool {
	parsed, err := canonIP(ip)
	if err != nil {
		return false
	}
	addr := net.ParseIP(parsed)
	if addr == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

func filterExcluded(ips []string, exclude []string) ([]string, error) {
	nets, err := parseIPNets(exclude)
	if err != nil {
		return nil, err
	}
	if len(nets) == 0 {
		return ips, nil
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if !ipInNets(ip, nets) {
			out = append(out, ip)
		}
	}
	return out, nil
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if c, err := canonIP(s); err == nil {
			s = c
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
