package snmpdiscovery

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// LibraryHit is one shipped metric/lookup that owns a column OID.
type LibraryHit struct {
	Module string
	Name   string // snmp_ifHCInOctets or lookup label
	Kind   string // metric, lookup, walk
	OID    string
}

// LibraryOIDs indexes column OIDs from the shipped module library.
type LibraryOIDs struct {
	// longest prefix first when matching
	oids []LibraryHit
}

type libModuleFile struct {
	Modules map[string]libModule `yaml:"modules"`
}

type libModule struct {
	Metrics []libMetric `yaml:"metrics"`
	Walk    []string    `yaml:"walk"`
	Get     []string    `yaml:"get"`
}

type libMetric struct {
	Name    string      `yaml:"name"`
	OID     string      `yaml:"oid"`
	Lookups []libLookup `yaml:"lookups"`
}

type libLookup struct {
	OID       string `yaml:"oid"`
	Labelname string `yaml:"labelname"`
}

// LoadLibraryOIDs reads module YAML from a directory or a single concat file.
func LoadLibraryOIDs(path string) (LibraryOIDs, error) {
	st, err := os.Stat(path)
	if err != nil {
		return LibraryOIDs{}, err
	}
	var hits []LibraryHit
	if st.IsDir() {
		err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".yml") {
				return nil
			}
			more, err := loadLibraryFile(p)
			if err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			hits = append(hits, more...)
			return nil
		})
		if err != nil {
			return LibraryOIDs{}, err
		}
	} else {
		hits, err = loadLibraryFile(path)
		if err != nil {
			return LibraryOIDs{}, err
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		// Longer OIDs first so instance matching prefers the column over a parent walk.
		li, lj := len(oidParts(hits[i].OID)), len(oidParts(hits[j].OID))
		if li != lj {
			return li > lj
		}
		return hits[i].OID < hits[j].OID
	})
	return LibraryOIDs{oids: hits}, nil
}

func loadLibraryFile(path string) ([]LibraryHit, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f libModuleFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	var hits []LibraryHit
	for mod, m := range f.Modules {
		for _, met := range m.Metrics {
			if oid := walkOID(met.OID); oid != "" {
				hits = append(hits, LibraryHit{Module: mod, Name: met.Name, Kind: "metric", OID: oid})
			}
			for _, lu := range met.Lookups {
				if oid := walkOID(lu.OID); oid != "" {
					name := lu.Labelname
					if name == "" {
						name = met.Name + " lookup"
					}
					hits = append(hits, LibraryHit{Module: mod, Name: name, Kind: "lookup", OID: oid})
				}
			}
		}
		for _, oid := range append(append([]string{}, m.Walk...), m.Get...) {
			oid = walkOID(oid)
			if oid == "" {
				continue
			}
			hits = append(hits, LibraryHit{Module: mod, Name: "", Kind: "walk", OID: oid})
		}
	}
	return hits, nil
}

func hitScore(h LibraryHit) int {
	kind := 1
	switch h.Kind {
	case "metric":
		kind = 3
	case "lookup":
		kind = 2
	}
	mod := 0
	switch h.Module {
	case "if_mib", "if32_mib", "device_base", "ip_addr":
		mod = 2
	case "if_mib_meta", "if32_mib_meta":
		mod = 1
	}
	return kind*1000 + len(oidParts(h.OID))*10 + mod
}

// Lookup returns the best library hit for a walk instance or column.
// Metrics and lookups beat bare walk/get lists (those often include the .0 instance).
func (lib LibraryOIDs) Lookup(oid string) (LibraryHit, bool) {
	oid = walkOID(oid)
	var best LibraryHit
	found := false
	bestScore := -1
	for _, h := range lib.oids {
		if oid == h.OID || strings.HasPrefix(oid, h.OID+".") {
			s := hitScore(h)
			if s > bestScore {
				best = h
				bestScore = s
				found = true
			}
		}
	}
	return best, found
}

func formatHit(h LibraryHit) string {
	name := h.Name
	if name == "" {
		name = h.Kind
	}
	if h.Module == "" {
		return name
	}
	return name + " (" + h.Module + ")"
}
