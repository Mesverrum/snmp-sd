package snmpdiscovery

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// WalkVar is one line from snmpwalk -On (numeric OIDs).
type WalkVar struct {
	OID   string // 1.3.6… no leading dot
	Type  string // STRING, INTEGER, Counter64, …
	Value string
}

func walkOID(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, ".") && strings.HasPrefix(s[1:], "iso.") {
		s = s[1:]
	}
	if strings.HasPrefix(s, "iso.") {
		return "1." + strings.TrimPrefix(s, "iso.")
	}
	return normalizeOID(s)
}

func oidParts(oid string) []int {
	oid = walkOID(oid)
	if oid == "" {
		return nil
	}
	bits := strings.Split(oid, ".")
	out := make([]int, 0, len(bits))
	for _, b := range bits {
		n, err := strconv.Atoi(b)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}

func joinParts(p []int) string {
	if len(p) == 0 {
		return ""
	}
	var b strings.Builder
	for i, n := range p {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.Itoa(n))
	}
	return b.String()
}

// ParseWalkText reads net-snmp `snmpwalk -On` / `snmpbulkwalk -On` output.
func ParseWalkText(r io.Reader) ([]WalkVar, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var out []WalkVar
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "End of MIB") || strings.Contains(line, "No more variables") {
			continue
		}
		v, ok := parseWalkLine(line)
		if !ok {
			continue
		}
		out = append(out, v)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("walk: line %d: %w", lineNo, err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("walk: no numeric OIDs (use snmpwalk -On so OIDs are numbers, not names)")
	}
	return out, nil
}

func parseWalkLine(line string) (WalkVar, bool) {
	oid, rest, ok := strings.Cut(line, " = ")
	if !ok {
		oid, rest, ok = strings.Cut(line, "=")
		if !ok {
			return WalkVar{}, false
		}
		oid = strings.TrimSpace(oid)
		rest = strings.TrimSpace(rest)
	}
	oid = walkOID(oid)
	if oidParts(oid) == nil {
		return WalkVar{}, false
	}
	typ, val := "", rest
	if i := strings.Index(rest, ": "); i > 0 {
		head := rest[:i]
		if isWalkType(head) {
			typ = head
			val = rest[i+2:]
		}
	}
	val = strings.TrimSpace(val)
	val = strings.Trim(val, `"`)
	return WalkVar{OID: oid, Type: typ, Value: val}, true
}

func isWalkType(s string) bool {
	switch s {
	case "STRING", "Hex-STRING", "INTEGER", "Integer32", "Gauge32", "Gauge",
		"Counter32", "Counter64", "Counter", "Timeticks", "OID", "IpAddress",
		"Network Address", "BITS", "Opaque", "Float", "Double", "NULL",
		"NoSuchObject", "NoSuchInstance", "EndOfMibView":
		return true
	default:
		return false
	}
}

func oidHasPrefix(oid, prefix string) bool {
	oid = walkOID(oid)
	prefix = walkOID(prefix)
	if prefix == "" {
		return true
	}
	return oid == prefix || strings.HasPrefix(oid, prefix+".")
}
