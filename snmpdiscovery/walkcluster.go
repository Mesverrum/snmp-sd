package snmpdiscovery

import (
	"sort"
	"strconv"
	"strings"
)

// WalkColumn is one column under a table (or a lone column).
type WalkColumn struct {
	OID       string
	Col       string // last part of the column OID, e.g. "6"
	Type      string
	Samples   []string
	Instances int
}

// WalkTable is a set of columns that share the same index pieces.
type WalkTable struct {
	EntryOID     string
	IndexPieces  int
	IndexSamples []string
	Rows         int
	Columns      []WalkColumn
}

// WalkScalar is a single-instance object (usually ending in .0).
type WalkScalar struct {
	OID   string
	Type  string
	Value string
}

// WalkCatalog is the clustered walk.
type WalkCatalog struct {
	Scalars []WalkScalar
	Tables  []WalkTable
}

type oidTrie struct {
	kids map[int]*oidTrie
	leaf *WalkVar
}

func buildTrie(vars []WalkVar) *oidTrie {
	root := &oidTrie{kids: map[int]*oidTrie{}}
	for i := range vars {
		p := oidParts(vars[i].OID)
		if p == nil {
			continue
		}
		n := root
		for _, part := range p {
			if n.kids[part] == nil {
				n.kids[part] = &oidTrie{kids: map[int]*oidTrie{}}
			}
			n = n.kids[part]
		}
		n.leaf = &vars[i]
	}
	return root
}

func (n *oidTrie) childKeys() []int {
	keys := make([]int, 0, len(n.kids))
	for k := range n.kids {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

// instanceSuffixes returns dotted suffixes from this node to each leaf.
func (n *oidTrie) instanceSuffixes() []string {
	var out []string
	var walk func(*oidTrie, []int)
	walk = func(cur *oidTrie, path []int) {
		if cur.leaf != nil && len(cur.kids) == 0 {
			out = append(out, joinParts(path))
			return
		}
		for _, k := range cur.childKeys() {
			walk(cur.kids[k], append(path, k))
		}
	}
	walk(n, nil)
	return out
}

func suffixSet(ss []string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, s := range ss {
		m[s] = struct{}{}
	}
	return m
}

func suffixPieceCount(s string) int {
	if s == "" {
		return 0
	}
	return strings.Count(s, ".") + 1
}

func sameSuffixLen(ss []string) (int, bool) {
	if len(ss) == 0 {
		return 0, false
	}
	n := suffixPieceCount(ss[0])
	for _, s := range ss[1:] {
		if suffixPieceCount(s) != n {
			return 0, false
		}
	}
	return n, true
}

func overlapCount(a, b map[string]struct{}) int {
	n := 0
	for k := range a {
		if _, ok := b[k]; ok {
			n++
		}
	}
	return n
}

// ClusterWalk groups scalars vs tables. Index piece count comes from the walk
// (how many IDs sit after each column), not from a MIB.
func ClusterWalk(vars []WalkVar) WalkCatalog {
	byOID := map[string]WalkVar{}
	for _, v := range vars {
		byOID[v.OID] = v
	}
	root := buildTrie(vars)
	used := map[string]struct{}{}
	var tables []WalkTable

	var visit func(n *oidTrie, path []int)
	visit = func(n *oidTrie, path []int) {
		keys := n.childKeys()
		if len(keys) >= 2 {
			infos := make([]colInfo, 0, len(keys))
			for _, k := range keys {
				ch := n.kids[k]
				if ch.leaf != nil && len(ch.kids) == 0 {
					continue
				}
				suf := ch.instanceSuffixes()
				ln, ok := sameSuffixLen(suf)
				infos = append(infos, colInfo{part: k, suf: suf, set: suffixSet(suf), ln: ln, ok: ok && ln >= 1 && len(suf) >= 1})
			}
			// Need at least two children that look like columns with the same index length
			// and overlapping instance suffixes.
			for i := 0; i < len(infos); i++ {
				if !infos[i].ok {
					continue
				}
				group := []colInfo{infos[i]}
				for j := i + 1; j < len(infos); j++ {
					if !infos[j].ok || infos[j].ln != infos[i].ln {
						continue
					}
					if overlapCount(infos[i].set, infos[j].set) == 0 {
						continue
					}
					group = append(group, infos[j])
				}
				if len(group) < 2 {
					continue
				}
				t := tableFromColumns(path, group[0].ln, group, byOID)
				if t.Rows == 0 || isScalarDotZeroTable(t) {
					continue
				}
				for _, c := range t.Columns {
					markSubtree(used, c.OID, byOID)
				}
				tables = append(tables, t)
				break
			}
		}
		for _, k := range keys {
			visit(n.kids[k], append(append([]int{}, path...), k))
		}
	}
	visit(root, nil)

	// Single-column leftovers: longest common prefix, constant remaining length.
	var leftover []WalkVar
	for _, v := range vars {
		if _, ok := used[v.OID]; ok {
			continue
		}
		leftover = append(leftover, v)
	}
	tables = append(tables, clusterSingleColumns(leftover, used)...)

	var scalars []WalkScalar
	for _, v := range vars {
		if _, ok := used[v.OID]; ok {
			continue
		}
		scalars = append(scalars, WalkScalar{OID: v.OID, Type: v.Type, Value: v.Value})
		used[v.OID] = struct{}{}
	}
	sort.Slice(scalars, func(i, j int) bool { return oidLess(scalars[i].OID, scalars[j].OID) })
	sort.Slice(tables, func(i, j int) bool { return oidLess(tables[i].EntryOID, tables[j].EntryOID) })
	return WalkCatalog{Scalars: scalars, Tables: tables}
}

type colInfo struct {
	part int
	suf  []string
	set  map[string]struct{}
	ln   int
	ok   bool
}

func tableFromColumns(entry []int, indexPieces int, group []colInfo, byOID map[string]WalkVar) WalkTable {
	entryOID := joinParts(entry)
	var cols []WalkColumn
	rowSet := map[string]struct{}{}
	for _, g := range group {
		colOID := joinParts(append(append([]int{}, entry...), g.part))
		samples, typ := columnSamples(colOID, byOID)
		for _, s := range g.suf {
			rowSet[s] = struct{}{}
		}
		cols = append(cols, WalkColumn{
			OID:       colOID,
			Col:       strconv.Itoa(g.part),
			Type:      typ,
			Samples:   samples,
			Instances: len(g.suf),
		})
	}
	sort.Slice(cols, func(i, j int) bool { return oidLess(cols[i].OID, cols[j].OID) })
	idxSamples := make([]string, 0, len(rowSet))
	for s := range rowSet {
		idxSamples = append(idxSamples, s)
	}
	sort.Strings(idxSamples)
	return WalkTable{
		EntryOID:     entryOID,
		IndexPieces:  indexPieces,
		IndexSamples: idxSamples,
		Rows:         len(rowSet),
		Columns:      cols,
	}
}

// colInfoCompat is the grouping record used by tableFromColumns.
type colInfoCompat struct {
	part int
	suf  []string
	set  map[string]struct{}
	ln   int
	ok   bool
}

func isScalarDotZeroTable(t WalkTable) bool {
	if t.Rows > 1 {
		return false
	}
	return len(t.IndexSamples) == 1 && t.IndexSamples[0] == "0"
}

func markSubtree(used map[string]struct{}, colOID string, byOID map[string]WalkVar) {
	for oid := range byOID {
		if oidHasPrefix(oid, colOID) {
			used[oid] = struct{}{}
		}
	}
}

func columnSamples(colOID string, byOID map[string]WalkVar) ([]string, string) {
	var oids []string
	for oid := range byOID {
		if oid == colOID || strings.HasPrefix(oid, colOID+".") {
			oids = append(oids, oid)
		}
	}
	sort.Slice(oids, func(i, j int) bool { return oidLess(oids[i], oids[j]) })
	typ := ""
	var samples []string
	for _, oid := range oids {
		v := byOID[oid]
		if typ == "" {
			typ = v.Type
		}
		if v.Value != "" {
			samples = append(samples, v.Value)
		}
		if len(samples) >= 4 {
			break
		}
	}
	return samples, typ
}

func clusterSingleColumns(leftover []WalkVar, used map[string]struct{}) []WalkTable {
	// Group by all-but-last-N, preferring N where remaining length is constant
	// and we get the most instances. Skip .0-only singles (those stay scalars).
	type key struct {
		col string
		n   int
	}
	best := map[string]WalkTable{}
	for n := 1; n <= 8; n++ {
		groups := map[string][]WalkVar{}
		for _, v := range leftover {
			if _, ok := used[v.OID]; ok {
				continue
			}
			p := oidParts(v.OID)
			if len(p) <= n {
				continue
			}
			col := joinParts(p[:len(p)-n])
			groups[col] = append(groups[col], v)
		}
		for col, vs := range groups {
			if len(vs) < 2 {
				continue
			}
			allEndZero := true
			for _, v := range vs {
				if !strings.HasSuffix(v.OID, ".0") {
					allEndZero = false
					break
				}
			}
			if allEndZero {
				continue
			}
			ok := true
			for _, v := range vs {
				p := oidParts(v.OID)
				if len(p) != len(oidParts(col))+n {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
			// Prefer a more specific column (longer OID) over a parent.
			if existing, exists := best[col]; exists && existing.Rows >= len(vs) {
				continue
			}
			byOID := map[string]WalkVar{}
			for _, v := range vs {
				byOID[v.OID] = v
			}
			samples, typ := columnSamples(col, byOID)
			idx := []string{}
			seen := map[string]struct{}{}
			for _, v := range vs {
				suf := strings.TrimPrefix(v.OID, col+".")
				if _, ok := seen[suf]; ok {
					continue
				}
				seen[suf] = struct{}{}
				idx = append(idx, suf)
			}
			sort.Strings(idx)
			p := oidParts(col)
			colNum := ""
			if len(p) > 0 {
				colNum = strconv.Itoa(p[len(p)-1])
			}
			parent := joinParts(p[:len(p)-1])
			t := WalkTable{
				EntryOID:     parent,
				IndexPieces:  n,
				IndexSamples: idx,
				Rows:         len(idx),
				Columns: []WalkColumn{{
					OID:       col,
					Col:       colNum,
					Type:      typ,
					Samples:   samples,
					Instances: len(vs),
				}},
			}
			// If we already have this parent with more columns, skip adding a 1-col duplicate.
			best[col] = t
		}
	}
	// Drop a candidate if a longer column OID (more specific) already covers the same vars.
	cols := make([]string, 0, len(best))
	for c := range best {
		cols = append(cols, c)
	}
	sort.Slice(cols, func(i, j int) bool { return len(oidParts(cols[i])) > len(oidParts(cols[j])) })
	var out []WalkTable
	claimed := map[string]struct{}{}
	for _, c := range cols {
		t := best[c]
		skip := false
		for oid := range claimed {
			if oidHasPrefix(oid, c) || oidHasPrefix(c, oid) && len(oidParts(oid)) > len(oidParts(c)) {
				// a more specific column already claimed these instances
				if oidHasPrefix(c, oid) && len(oidParts(oid)) > len(oidParts(c)) {
					skip = true
				}
			}
		}
		if skip {
			continue
		}
		// Don't turn a pile of unrelated scalars that share 1.3.6.1.2.1 into a table.
		if t.IndexPieces >= 6 && t.Rows < 3 {
			continue
		}
		for _, v := range leftover {
			if oidHasPrefix(v.OID, c) {
				claimed[v.OID] = struct{}{}
				used[v.OID] = struct{}{}
			}
		}
		out = append(out, t)
	}
	return out
}

func oidLess(a, b string) bool {
	pa, pb := oidParts(a), oidParts(b)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return len(pa) < len(pb)
}
