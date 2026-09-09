package snmpdiscovery

import (
	"fmt"
	"io"
	"strings"
)

func countNoun(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func describeIndex(pieces int, samples []string) string {
	shown := samples
	if len(shown) > 3 {
		shown = append(append([]string{}, samples[:3]...), "…")
	}
	sample := ""
	if len(shown) > 0 {
		sample = " (" + strings.Join(shown, ", ") + ")"
	}
	switch pieces {
	case 1:
		return "index is 1 number" + sample
	default:
		return fmt.Sprintf("index is %d numbers%s", pieces, sample)
	}
}

func describeColumn(c WalkColumn) string {
	hint := ""
	switch {
	case strings.Contains(strings.ToLower(c.Type), "counter"):
		hint = "looks like a counter"
	case c.Type == "STRING" || c.Type == "DisplayString" || c.Type == "Hex-STRING":
		hint = "looks like a name label"
	case c.Type == "IpAddress":
		hint = "looks like an address"
	case c.Type == "INTEGER" || c.Type == "Gauge32" || c.Type == "Gauge":
		hint = "looks like a gauge"
	}
	samples := strings.Join(c.Samples, ", ")
	if len(c.Samples) >= 4 {
		samples += ", …"
	}
	var b strings.Builder
	fmt.Fprintf(&b, ".%s  %s", c.Col, c.Type)
	if samples != "" {
		fmt.Fprintf(&b, "  %s", samples)
	}
	if hint != "" {
		fmt.Fprintf(&b, "  (%s)", hint)
	}
	return b.String()
}

func tableFullyCovered(t WalkTable, lib LibraryOIDs) bool {
	if len(t.Columns) == 0 {
		return false
	}
	for _, c := range t.Columns {
		if _, ok := lib.Lookup(c.OID); !ok {
			return false
		}
	}
	return true
}

func scalarCovered(s WalkScalar, lib LibraryOIDs) bool {
	_, ok := lib.Lookup(s.OID)
	return ok
}

// WriteWalkCatalog prints the clustered walk. Covered OIDs (already in the
// shipped library) are hidden unless showCovered is true.
func WriteWalkCatalog(w io.Writer, cat WalkCatalog, lib LibraryOIDs, showCovered bool) {
	hiddenTables, hiddenScalars := 0, 0
	var newTables, covTables []WalkTable
	for _, t := range cat.Tables {
		if tableFullyCovered(t, lib) {
			hiddenTables++
			covTables = append(covTables, t)
			continue
		}
		newTables = append(newTables, t)
	}
	var newScalars, covScalars []WalkScalar
	for _, s := range cat.Scalars {
		if scalarCovered(s, lib) {
			hiddenScalars++
			covScalars = append(covScalars, s)
			continue
		}
		newScalars = append(newScalars, s)
	}

	fmt.Fprintf(w, "walk catalog: %d scalars, %d tables\n", len(cat.Scalars), len(cat.Tables))
	if hiddenTables+hiddenScalars > 0 && !showCovered {
		fmt.Fprintf(w, "%s and %s already in the library (hidden; --show-covered to list)\n",
			countNoun(hiddenScalars, "scalar", "scalars"),
			countNoun(hiddenTables, "table", "tables"))
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "not in the library")
	if len(newScalars) == 0 && len(newTables) == 0 {
		fmt.Fprintln(w, "  (nothing new — this walk is already covered)")
	}
	for _, s := range newScalars {
		fmt.Fprintf(w, "  %s\n", s.OID)
		fmt.Fprintf(w, "    one value: %s  %s\n", s.Value, s.Type)
	}
	for _, t := range newTables {
		writeTable(w, t, lib, "  ")
	}

	if showCovered && (len(covScalars) > 0 || len(covTables) > 0) {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "already in the library")
		for _, s := range covScalars {
			h, _ := lib.Lookup(s.OID)
			fmt.Fprintf(w, "  %s\n", s.OID)
			fmt.Fprintf(w, "    one value: %s  %s  already %s\n", s.Value, s.Type, formatHit(h))
		}
		for _, t := range covTables {
			writeTable(w, t, lib, "  ")
		}
	}
}

func writeTable(w io.Writer, t WalkTable, lib LibraryOIDs, pad string) {
	fmt.Fprintf(w, "%stable %s   %d rows, %s\n", pad, t.EntryOID, t.Rows, describeIndex(t.IndexPieces, t.IndexSamples))
	for _, c := range t.Columns {
		line := describeColumn(c)
		if h, ok := lib.Lookup(c.OID); ok {
			fmt.Fprintf(w, "%s  %s  already %s\n", pad, line, formatHit(h))
			continue
		}
		fmt.Fprintf(w, "%s  %s\n", pad, line)
	}
}

// FilterWalk keeps varbinds under prefix (empty = all).
func FilterWalk(vars []WalkVar, prefix string) []WalkVar {
	if strings.TrimSpace(prefix) == "" {
		return vars
	}
	var out []WalkVar
	for _, v := range vars {
		if oidHasPrefix(v.OID, prefix) {
			out = append(out, v)
		}
	}
	return out
}
