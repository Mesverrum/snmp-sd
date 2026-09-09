package snmpdiscovery

import (
	"fmt"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// WalkTarget runs a live walk and returns snmpwalk-shaped varbinds.
// Empty oid means 1.3.6.1 (mib-2 + enterprises — the whole useful tree).
func WalkTarget(addr string, port uint16, authName, snmpConfig string, oid string, timeout time.Duration, retries int) ([]WalkVar, error) {
	if strings.TrimSpace(oid) == "" {
		oid = "1.3.6.1"
	}
	if port == 0 {
		port = 161
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	auths, err := loadAuths(snmpConfig, []string{authName})
	if err != nil {
		return nil, err
	}
	g := newGoSNMP(addr, port, timeout, retries, auths[0])
	if err := g.Connect(); err != nil {
		return nil, err
	}
	defer func() { _ = g.Conn.Close() }()

	var out []WalkVar
	fn := func(pdu gosnmp.SnmpPDU) error {
		out = append(out, WalkVar{
			OID:   walkOID(pdu.Name),
			Type:  pduTypeName(pdu.Type),
			Value: fmt.Sprint(pdu.Value),
		})
		return nil
	}
	if err := g.BulkWalk(walkOID(oid), fn); err != nil {
		if err2 := g.Walk(walkOID(oid), fn); err2 != nil {
			return nil, fmt.Errorf("walk %s: %v (getnext: %v)", oid, err, err2)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("walk %s: no variables", oid)
	}
	return out, nil
}

func pduTypeName(t gosnmp.Asn1BER) string {
	switch t {
	case gosnmp.OctetString:
		return "STRING"
	case gosnmp.Integer:
		return "INTEGER"
	case gosnmp.Counter32:
		return "Counter32"
	case gosnmp.Counter64:
		return "Counter64"
	case gosnmp.Gauge32:
		return "Gauge32"
	case gosnmp.TimeTicks:
		return "Timeticks"
	case gosnmp.IPAddress:
		return "IpAddress"
	case gosnmp.ObjectIdentifier:
		return "OID"
	default:
		return ""
	}
}
