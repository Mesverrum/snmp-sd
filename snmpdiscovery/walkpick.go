package snmpdiscovery

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// PickFile is the shopping list: what to turn into an snmp_exporter module.
type PickFile struct {
	Module      string       `yaml:"module"`
	SysObjectID string       `yaml:"sysobjectid,omitempty"`
	Scalars     []PickScalar `yaml:"scalars,omitempty"`
	Tables      []PickTable  `yaml:"tables,omitempty"`
}

type PickScalar struct {
	OID  string `yaml:"oid"`
	Name string `yaml:"name"`
	Type string `yaml:"type,omitempty"` // gauge, counter, DisplayString
}

type PickTable struct {
	Entry        string      `yaml:"entry"`
	IndexLabels  []string    `yaml:"index_labels"`
	Metrics      []PickCol   `yaml:"metrics,omitempty"`
	Labels       []PickCol   `yaml:"labels,omitempty"`
}

type PickCol struct {
	Column int    `yaml:"column"`
	Name   string `yaml:"name"`
	Type   string `yaml:"type,omitempty"`
}

func metricOID(instance string) string {
	instance = walkOID(instance)
	return strings.TrimSuffix(instance, ".0")
}

func guessExporterType(walkType string) string {
	t := strings.ToLower(walkType)
	switch {
	case strings.Contains(t, "counter"):
		return "counter"
	case t == "string" || t == "hex-string" || t == "displaystring":
		return "DisplayString"
	default:
		return "gauge"
	}
}

func sanitizeIdent(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "unnamed"
	}
	var b strings.Builder
	for _, r := range name {
		ok := r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			b.WriteByte('_')
			continue
		}
		b.WriteRune(r)
	}
	s := strings.Trim(b.String(), "_")
	if s == "" {
		return "unnamed"
	}
	return s
}

func sanitizeMetricName(name string) string {
	s := sanitizeIdent(name)
	if strings.HasPrefix(s, "snmp_") {
		return s
	}
	return "snmp_" + s
}

func sanitizeLabelName(name string) string {
	s := sanitizeIdent(name)
	if s == "" {
		return "unnamed"
	}
	if s[0] >= '0' && s[0] <= '9' {
		return "n" + s
	}
	return s
}

func guessNameFromOID(oid string) string {
	p := oidParts(metricOID(oid))
	if len(p) == 0 {
		return "snmp_value"
	}
	n := 3
	if len(p) < n {
		n = len(p)
	}
	parts := p[len(p)-n:]
	var b strings.Builder
	for i, x := range parts {
		if i > 0 {
			b.WriteByte('_')
		}
		b.WriteString(strconv.Itoa(x))
	}
	return sanitizeIdent(b.String())
}

func guessModuleName(cat WalkCatalog) string {
	for _, s := range cat.Scalars {
		if n := enterpriseID(s.OID); n != "" {
			return "local_" + n
		}
	}
	for _, t := range cat.Tables {
		if n := enterpriseID(t.EntryOID); n != "" {
			return "local_" + n
		}
	}
	return "local_walk"
}

func enterpriseID(oid string) string {
	const prefix = "1.3.6.1.4.1."
	oid = walkOID(oid)
	if !strings.HasPrefix(oid, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(oid, prefix)
	id, _, _ := strings.Cut(rest, ".")
	return id
}

func sysObjectIDFromWalk(vars []WalkVar) string {
	for _, v := range vars {
		if walkOID(v.OID) == "1.3.6.1.2.1.1.2.0" && v.Value != "" {
			return walkOID(strings.TrimSpace(v.Value))
		}
	}
	return ""
}

func defaultIndexLabels(n int) []string {
	if n <= 1 {
		return []string{"index"}
	}
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = fmt.Sprintf("index_%d", i+1)
	}
	return out
}

func isStringType(walkType string) bool {
	t := strings.ToLower(walkType)
	return t == "string" || t == "hex-string" || t == "displaystring" || t == "oid"
}

// DraftPick builds a shopping list from OIDs the library does not already scrape.
func DraftPick(cat WalkCatalog, lib LibraryOIDs, vars []WalkVar) PickFile {
	p := PickFile{
		Module:      guessModuleName(cat),
		SysObjectID: sysObjectIDFromWalk(vars),
	}
	for _, s := range cat.Scalars {
		if _, ok := lib.Lookup(s.OID); ok {
			continue
		}
		if isStringType(s.Type) {
			continue
		}
		p.Scalars = append(p.Scalars, PickScalar{
			OID:  s.OID,
			Name: sanitizeMetricName(guessNameFromOID(s.OID)),
			Type: guessExporterType(s.Type),
		})
	}
	for _, t := range cat.Tables {
		pt := PickTable{Entry: t.EntryOID, IndexLabels: defaultIndexLabels(t.IndexPieces)}
		for _, c := range t.Columns {
			if _, ok := lib.Lookup(c.OID); ok {
				continue
			}
			col, _ := strconv.Atoi(c.Col)
			stem := guessNameFromOID(c.OID)
			pc := PickCol{Column: col, Name: sanitizeMetricName(stem), Type: guessExporterType(c.Type)}
			if isStringType(c.Type) || c.Type == "IpAddress" {
				if pc.Type == "gauge" {
					pc.Type = "DisplayString"
				}
				if c.Type == "IpAddress" {
					pc.Type = "InetAddressIPv4"
				}
				pc.Name = sanitizeLabelName(stem)
				pt.Labels = append(pt.Labels, pc)
				continue
			}
			pt.Metrics = append(pt.Metrics, pc)
		}
		if len(pt.Metrics) == 0 {
			continue
		}
		p.Tables = append(p.Tables, pt)
	}
	return p
}

func RenderPickYAML(p PickFile) (string, error) {
	var b strings.Builder
	b.WriteString("# Shopping list for snmp-discovery walk-emit.\n")
	b.WriteString("# Delete anything you do not want. Rename `name` fields — those become snmp_*.\n")
	b.WriteString("# Then: snmp-discovery walk-emit --pick pick.yml --out mymodule.yml\n")
	enc, err := yaml.Marshal(p)
	if err != nil {
		return "", err
	}
	b.Write(enc)
	return b.String(), nil
}

func LoadPickFile(path string) (PickFile, error) {
	var p PickFile
	b, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	if err := yaml.Unmarshal(b, &p); err != nil {
		return p, err
	}
	p.Module = strings.TrimSpace(p.Module)
	if p.Module == "" {
		return p, fmt.Errorf("pick: module name is required")
	}
	if len(p.Scalars) == 0 && len(p.Tables) == 0 {
		return p, fmt.Errorf("pick: nothing to emit (no scalars or tables)")
	}
	return p, nil
}

func WritePickFile(path string, p PickFile, overwrite bool) error {
	s, err := RenderPickYAML(p)
	if err != nil {
		return err
	}
	return writeNewFile(path, []byte(s), 0o644, overwrite)
}

type emitLookup struct {
	Labels    []string `yaml:"labels"`
	Labelname string   `yaml:"labelname"`
	OID       string   `yaml:"oid"`
	Type      string   `yaml:"type"`
}

type emitIndex struct {
	Labelname string `yaml:"labelname"`
	Type      string `yaml:"type"`
}

type emitMetric struct {
	Name    string       `yaml:"name"`
	OID     string       `yaml:"oid"`
	Type    string       `yaml:"type"`
	Help    string       `yaml:"help"`
	Indexes []emitIndex  `yaml:"indexes,omitempty"`
	Lookups []emitLookup `yaml:"lookups,omitempty"`
}

type emitBody struct {
	Walk    []string     `yaml:"walk,omitempty"`
	Get     []string     `yaml:"get,omitempty"`
	Metrics []emitMetric `yaml:"metrics"`
}

// EmitPickModule writes a one-module snmp_exporter overlay (not the full library).
func EmitPickModule(p PickFile) (string, error) {
	if strings.TrimSpace(p.Module) == "" {
		return "", fmt.Errorf("pick: module name is required")
	}
	body := emitBody{}

	for _, s := range p.Scalars {
		oid := metricOID(s.OID)
		inst := s.OID
		if !strings.HasSuffix(inst, ".0") {
			inst = oid + ".0"
		}
		typ := s.Type
		if typ == "" {
			typ = "gauge"
		}
		name := sanitizeMetricName(s.Name)
		body.Metrics = append(body.Metrics, emitMetric{
			Name: name,
			OID:  oid,
			Type: typ,
			Help: "from walk-emit " + inst,
		})
		body.Get = append(body.Get, inst)
	}

	for _, t := range p.Tables {
		if len(t.Metrics) == 0 {
			return "", fmt.Errorf("pick: table %s has no metrics (labels-only tables need at least one numeric column)", t.Entry)
		}
		if len(t.IndexLabels) == 0 {
			t.IndexLabels = []string{"index"}
		}
		idxs := make([]emitIndex, 0, len(t.IndexLabels))
		for _, lab := range t.IndexLabels {
			idxs = append(idxs, emitIndex{Labelname: lab, Type: "gauge"})
		}
		lookups := make([]emitLookup, 0, len(t.Labels))
		for _, lab := range t.Labels {
			loid := tableColumnOID(t.Entry, lab.Column)
			typ := lab.Type
			if typ == "" {
				typ = "DisplayString"
			}
			lookups = append(lookups, emitLookup{
				Labels:    append([]string{}, t.IndexLabels...),
				Labelname: sanitizeLabelName(lab.Name),
				OID:       loid,
				Type:      typ,
			})
			body.Walk = append(body.Walk, loid)
		}
		for _, m := range t.Metrics {
			moid := tableColumnOID(t.Entry, m.Column)
			typ := m.Type
			if typ == "" {
				typ = "gauge"
			}
			body.Metrics = append(body.Metrics, emitMetric{
				Name:    sanitizeMetricName(m.Name),
				OID:     moid,
				Type:    typ,
				Help:    "from walk-emit column " + strconv.Itoa(m.Column) + " of " + t.Entry,
				Indexes: idxs,
				Lookups: lookups,
			})
			body.Walk = append(body.Walk, moid)
		}
	}

	raw, err := yaml.Marshal(map[string]any{
		"modules": map[string]emitBody{p.Module: body},
	})
	if err != nil {
		return "", err
	}
	head := "# Generated by snmp-discovery walk-emit. Overlay — do not replace the shipped library.\n"
	if p.SysObjectID != "" {
		head += "# sysObjectID from the walk: " + p.SysObjectID + " (pin with a discovery override if you want it auto-mapped)\n"
	}
	return head + string(raw), nil
}

func tableColumnOID(entry string, column int) string {
	return walkOID(entry) + "." + strconv.Itoa(column)
}

// PickCoveredNames lists library hits for OIDs the pick is about to emit.
func PickCoveredNames(p PickFile, lib LibraryOIDs) []string {
	var out []string
	seen := map[string]struct{}{}
	add := func(oid string) {
		h, ok := lib.Lookup(oid)
		if !ok {
			return
		}
		s := formatHit(h)
		if _, dup := seen[s]; dup {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s+" ["+oid+"]")
	}
	for _, s := range p.Scalars {
		add(s.OID)
	}
	for _, t := range p.Tables {
		for _, m := range t.Metrics {
			add(tableColumnOID(t.Entry, m.Column))
		}
		for _, lab := range t.Labels {
			add(tableColumnOID(t.Entry, lab.Column))
		}
	}
	return out
}

func WriteEmitFile(path, body string, overwrite bool) error {
	return writeNewFile(path, []byte(body), 0o644, overwrite)
}
