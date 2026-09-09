package snmpdiscovery

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type CatalogEntry struct {
	Target   AlloyTarget `json:"target"`
	LastSeen time.Time   `json:"last_seen"`
	Misses   int         `json:"misses"`
}

type Catalog struct {
	mu      sync.RWMutex
	entries []CatalogEntry
	updated time.Time
}

func NewCatalog() *Catalog {
	return &Catalog{entries: []CatalogEntry{}}
}

func (c *Catalog) Replace(targets []AlloyTarget) {
	now := time.Now().UTC()
	if targets == nil {
		targets = []AlloyTarget{}
	}
	entries := make([]CatalogEntry, 0, len(targets))
	for _, t := range targets {
		entries = append(entries, CatalogEntry{Target: t, LastSeen: now, Misses: 0})
	}
	c.mu.Lock()
	c.entries = entries
	c.updated = now
	c.mu.Unlock()
}

func (c *Catalog) LoadEntries(entries []CatalogEntry) {
	if entries == nil {
		entries = []CatalogEntry{}
	}
	c.mu.Lock()
	c.entries = append([]CatalogEntry(nil), entries...)
	c.updated = time.Now().UTC()
	c.mu.Unlock()
}

func (c *Catalog) Snapshot() ([]AlloyTarget, time.Time) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]AlloyTarget, 0, len(c.entries))
	for _, e := range c.entries {
		out = append(out, e.Target)
	}
	return out, c.updated
}

func (c *Catalog) SnapshotEntries() []CatalogEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]CatalogEntry(nil), c.entries...)
}

func (c *Catalog) DropAddresses(addrs []string) int {
	if len(addrs) == 0 {
		return 0
	}
	drop := map[string]struct{}{}
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a != "" {
			drop[a] = struct{}{}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	kept := make([]CatalogEntry, 0, len(c.entries))
	n := 0
	for _, e := range c.entries {
		if _, ok := drop[e.Target.Address]; ok {
			n++
			continue
		}
		kept = append(kept, e)
	}
	c.entries = kept
	return n
}

// mergeFound is ktranslate-style housekeeping: found resets the miss counter;
// unseen targets increment Misses and drop once Misses >= maxMisses.
// maxMisses <= 0 means never purge (LibreNMS-sticky).
func (c *Catalog) MergeFound(found []AlloyTarget, now time.Time, maxMisses int) []AlloyTarget {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	byAddr := map[string]CatalogEntry{}
	for _, e := range c.entries {
		byAddr[e.Target.Address] = e
	}
	seen := map[string]struct{}{}
	for _, t := range found {
		seen[t.Address] = struct{}{}
		byAddr[t.Address] = CatalogEntry{Target: t, LastSeen: now, Misses: 0}
	}
	keep := make([]CatalogEntry, 0, len(byAddr))
	out := make([]AlloyTarget, 0, len(byAddr))
	for addr, e := range byAddr {
		if _, ok := seen[addr]; !ok {
			e.Misses++
			if maxMisses > 0 && e.Misses >= maxMisses {
				continue
			}
			byAddr[addr] = e
		}
		keep = append(keep, byAddr[addr])
		out = append(out, byAddr[addr].Target)
	}
	c.entries = keep
	c.updated = now
	return out
}

type catalogStateFile struct {
	Updated time.Time      `json:"updated"`
	Entries []CatalogEntry `json:"entries"`
}

func WriteCatalogState(path string, c *Catalog) error {
	if path == "" {
		return nil
	}
	c.mu.RLock()
	st := catalogStateFile{Updated: c.updated, Entries: append([]CatalogEntry(nil), c.entries...)}
	c.mu.RUnlock()
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return writeFileAtomic(path, b, 0o644)
}

func ReadCatalogState(path string) ([]CatalogEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st catalogStateFile
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return st.Entries, nil
}

func applyShardQuery(r *http.Request, targets []AlloyTarget) ([]AlloyTarget, error) {
	shard, shards, filter, err := parseShardQuery(r.URL.Query().Get("shard"), r.URL.Query().Get("shards"))
	if err != nil {
		return nil, err
	}
	if !filter {
		return targets, nil
	}
	return filterShard(targets, shard, shards), nil
}

func httpSDHandler(c *Catalog, prometheusParams bool, tiers []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		targets, updated := c.Snapshot()
		targets, err := applyShardQuery(r, targets)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if prometheusParams {
			targets = TargetsForTiers(targets, tiers)
		}
		body, err := json.MarshalIndent(httpSDGroups(targets, prometheusParams), "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		body = append(body, '\n')
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Snmp-Discovery-Count", strconv.Itoa(len(targets)))
		if !updated.IsZero() {
			w.Header().Set("Last-Modified", updated.Format(http.TimeFormat))
		}
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(body)
		}
	}
}

func alloyYAMLHandler(c *Catalog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		targets, _ := c.Snapshot()
		targets, err := applyShardQuery(r, targets)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if targets == nil {
			targets = []AlloyTarget{}
		}
		body, err := yaml.Marshal(targets)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/yaml")
		w.Header().Set("X-Snmp-Discovery-Count", strconv.Itoa(len(targets)))
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(body)
		}
	}
}

func healthzHandler(c *Catalog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targets, updated := c.Snapshot()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		ts := "never"
		if !updated.IsZero() {
			ts = updated.Format(time.RFC3339)
		}
		_, _ = w.Write([]byte("ok " + strconv.Itoa(len(targets)) + " targets " + ts + "\n"))
	}
}

func NewDiscoveryMux(c *Catalog) *http.ServeMux {
	return NewDiscoveryMuxTiers(c, nil)
}

// NewDiscoveryMuxTiers is the HTTP SD mux. /sd is one row per device
// (name/module/auth/address). /sd/prometheus expands EnabledTiers so
// Prometheus + snmp_exporter can scrape hot and cold as separate targets.
func NewDiscoveryMuxTiers(c *Catalog, tiers []string) *http.ServeMux {
	if len(tiers) == 0 {
		tiers = append([]string{}, AllTiers...)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/sd", httpSDHandler(c, false, nil))
	mux.HandleFunc("/sd/prometheus", httpSDHandler(c, true, tiers))
	mux.HandleFunc("/alloy", alloyYAMLHandler(c))
	mux.HandleFunc("/healthz", healthzHandler(c))
	return mux
}
