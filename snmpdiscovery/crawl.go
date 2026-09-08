package snmpdiscovery

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

const (
	oidLLDPRemManAddr = "1.0.8802.1.1.2.1.4.2.1.4"
	oidCDPCacheAddr   = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
)

// snmpWalkXDP returns neighbors advertised via LLDP management address
// and Cisco CDP (IPv4 and IPv6). Failures are empty, not fatal.
func snmpWalkXDP(addr string, port uint16, auth snmpAuth, timeout time.Duration) []string {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	g := newGoSNMP(addr, port, timeout, 0, auth)
	if err := g.Connect(); err != nil {
		return nil
	}
	defer g.Conn.Close()

	seen := map[string]struct{}{}
	cb := func(pdu gosnmp.SnmpPDU) error {
		if ip := neighborFromPDU(pdu); ip != "" && usableNeighborIP(ip) {
			seen[ip] = struct{}{}
		}
		return nil
	}
	_ = g.BulkWalk(oidLLDPRemManAddr, cb)
	_ = g.BulkWalk(oidCDPCacheAddr, cb)
	out := make([]string, 0, len(seen))
	for ip := range seen {
		out = append(out, ip)
	}
	return out
}

func walkNeighbors(addr string, port uint16, auths []snmpAuth, timeout time.Duration) []string {
	for _, a := range auths {
		if ips := snmpWalkXDP(addr, port, a, timeout); len(ips) > 0 {
			return ips
		}
	}
	return nil
}

func neighborFromPDU(pdu gosnmp.SnmpPDU) string {
	switch v := pdu.Value.(type) {
	case []byte:
		if ip := ipFromBytes(v); ip != "" {
			return ip
		}
	case string:
		if c, err := canonIP(strings.TrimSpace(v)); err == nil {
			return c
		}
	}
	return neighborFromOID(pdu.Name)
}

func ipFromBytes(v []byte) string {
	switch len(v) {
	case 4:
		ip := net.IP(v).To4()
		if ip != nil {
			return ip.String()
		}
	case 16:
		ip := net.IP(v)
		if ip.To16() != nil && ip.To4() == nil {
			return mustCanonIP(ip.String())
		}
		// Some stacks store IPv4-mapped in 16 bytes
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ""
}

// neighborFromOID parses LLDP Rem Man Addr indexes:
// ...<timeMark>.<port>.<remIndex>.<subtype>.[<length>.]<addr-octets>
// subtype 1 = IPv4, 2 = IPv6. Length is often present (4 or 16).
func neighborFromOID(oid string) string {
	oid = strings.TrimPrefix(oid, ".")
	const prefix = "1.0.8802.1.1.2.1.4.2.1.4."
	if !strings.HasPrefix(oid, prefix) && !strings.Contains(oid, "1.0.8802.1.1.2.1.4.2.1.4.") {
		// CDP cache address OID may embed type+len+octets at the end
		return neighborFromCDPOID(oid)
	}
	idx := strings.Index(oid, "1.0.8802.1.1.2.1.4.2.1.4.")
	if idx < 0 {
		return ""
	}
	rest := oid[idx+len("1.0.8802.1.1.2.1.4.2.1.4."):]
	parts := strings.Split(rest, ".")
	if len(parts) < 5 {
		return ""
	}
	// Skip timeMark, localPort, remIndex
	subtype, err := strconv.Atoi(parts[3])
	if err != nil {
		return ""
	}
	octets := parts[4:]
	return ipFromOIDOctets(subtype, octets)
}

func neighborFromCDPOID(oid string) string {
	// cdpCacheAddress: often ...<type>.<len>.<octets> at end of index.
	// Prefer PDU value; OID fallback takes trailing length-prefixed octets.
	parts := strings.Split(strings.TrimPrefix(oid, "."), ".")
	if len(parts) < 6 {
		return ""
	}
	// Try last: length then N octets (type may be just before length)
	for _, take := range []int{4, 16} {
		if len(parts) < take+1 {
			continue
		}
		n, err := strconv.Atoi(parts[len(parts)-take-1])
		if err != nil || n != take {
			continue
		}
		octets := parts[len(parts)-take:]
		subtype := 1
		if take == 16 {
			subtype = 2
		}
		if ip := ipFromOIDOctets(subtype, octets); ip != "" {
			return ip
		}
	}
	return ""
}

func ipFromOIDOctets(subtype int, octets []string) string {
	need := 0
	switch subtype {
	case 1: // IPv4
		need = 4
	case 2: // IPv6
		need = 16
	default:
		return ""
	}
	if len(octets) == need+1 {
		// length-prefixed
		if n, err := strconv.Atoi(octets[0]); err == nil && n == need {
			octets = octets[1:]
		}
	}
	if len(octets) < need {
		return ""
	}
	if len(octets) > need {
		octets = octets[len(octets)-need:]
	}
	b := make([]byte, need)
	for i := 0; i < need; i++ {
		n, err := strconv.Atoi(octets[i])
		if err != nil || n < 0 || n > 255 {
			return ""
		}
		b[i] = byte(n)
	}
	return ipFromBytes(b)
}

func usableNeighborIP(ip string) bool {
	c, err := canonIP(ip)
	if err != nil {
		return false
	}
	p := net.ParseIP(c)
	if p == nil {
		return false
	}
	if p.IsUnspecified() || p.IsLoopback() || p.IsMulticast() || p.IsLinkLocalUnicast() {
		return false
	}
	if v4 := p.To4(); v4 != nil && v4[0] == 255 {
		return false
	}
	return true
}

func allowNeighbor(ip string, cidrs, exclude []string) bool {
	nets, err := parseIPNets(cidrs)
	if err != nil || len(nets) == 0 {
		return false
	}
	if !ipInNets(ip, nets) {
		return false
	}
	excl, err := parseIPNets(exclude)
	if err != nil {
		return false
	}
	return !ipInNets(ip, excl)
}
