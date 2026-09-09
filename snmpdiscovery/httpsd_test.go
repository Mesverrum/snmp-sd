package snmpdiscovery

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func sampleTargets() []AlloyTarget {
	return []AlloyTarget{
		{
			Name:        "spine1",
			Address:     "172.20.20.2",
			Module:      "system_mib,if_mib,nokia_srlinux",
			Auth:        "public_v2",
			DeviceName:  "spine1",
			SysObjectID: "1.3.6.1.4.1.6527.1.20.26",
			SnmpGroup:   "srl-hq",
			Aliases:     []string{"10.0.0.10"},
		},
		{
			Name:       "leaf1",
			Address:    "172.20.20.3",
			Module:     "system_mib,if_mib,nokia_srlinux",
			Auth:       "public_v2",
			DeviceName: "leaf1",
			SnmpGroup:  "srl-hq",
		},
	}
}

func TestHTTPAlloySDLabels(t *testing.T) {
	c := NewCatalog()
	c.Replace(sampleTargets())
	mux := NewDiscoveryMux(c)

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/sd", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, "community") {
		t.Fatalf("community leaked: %s", body)
	}
	if strings.Contains(body, "__param_") {
		t.Fatalf("Alloy /sd must not emit __param_* (leaks onto series): %s", body)
	}
	var groups []FileSDGroup
	if err := json.Unmarshal(rr.Body.Bytes(), &groups); err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 {
		t.Fatalf("groups=%d", len(groups))
	}
	l := groups[0].Labels
	for _, k := range []string{"name", "module", "auth", "address", "device_name", "snmp_group"} {
		if l[k] == "" {
			t.Fatalf("missing %s in %v", k, l)
		}
	}
	if l["name"] != "spine1" || l["auth"] != "public_v2" || l["module"] != "system_mib,if_mib,nokia_srlinux" {
		t.Fatalf("labels=%v", l)
	}
	if l["snmp_aliases"] != "10.0.0.10" {
		t.Fatalf("aliases=%v", l)
	}
	if rr.Header().Get("X-Snmp-Discovery-Count") != "2" {
		t.Fatalf("count header=%s", rr.Header().Get("X-Snmp-Discovery-Count"))
	}
}

func TestHTTPPrometheusSDParams(t *testing.T) {
	c := NewCatalog()
	c.Replace(sampleTargets())
	mux := NewDiscoveryMux(c)

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/sd/prometheus", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var groups []FileSDGroup
	if err := json.Unmarshal(rr.Body.Bytes(), &groups); err != nil {
		t.Fatal(err)
	}
	l := groups[0].Labels
	if l["__param_module"] != "system_mib,if_mib,nokia_srlinux" || l["__param_auth"] != "public_v2" {
		t.Fatalf("labels=%v", l)
	}
	if l["snmp_tier"] != "hot" {
		t.Fatalf("prometheus SD should project tiers: %v", l)
	}
	if _, ok := l["module"]; ok {
		t.Fatal("classic /sd/prometheus should use __param_module only")
	}
	if _, ok := l["name"]; ok {
		t.Fatal("name is Alloy-only")
	}
}

func TestHTTPPrometheusSDExpandsCold(t *testing.T) {
	c := NewCatalog()
	c.Replace([]AlloyTarget{{
		Name:       "spine1",
		Address:    "172.20.20.2",
		Module:     "if_mib,nokia_srlinux",
		ModuleCold: "if_mib_meta,ip_addr,nokia_srlinux_sensors",
		Auth:       "public_v2",
		DeviceName: "spine1",
	}})
	mux := NewDiscoveryMuxTiers(c, []string{"hot", "cold"})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/sd/prometheus", nil))
	var groups []FileSDGroup
	if err := json.Unmarshal(rr.Body.Bytes(), &groups); err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 {
		t.Fatalf("groups=%d body=%s", len(groups), rr.Body.String())
	}
	mods := map[string]string{}
	for _, g := range groups {
		mods[g.Labels["snmp_tier"]] = g.Labels["__param_module"]
	}
	if mods["hot"] != "if_mib,nokia_srlinux" || !strings.Contains(mods["cold"], "if_mib_meta") {
		t.Fatalf("mods=%v", mods)
	}
}

func TestHTTPEmptyCatalogIsArray(t *testing.T) {
	mux := NewDiscoveryMux(NewCatalog())
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/sd", nil))
	if strings.TrimSpace(rr.Body.String()) != "[]" {
		t.Fatalf("empty catalog must be [] not null: %s", rr.Body.String())
	}
}

func TestHTTPShardQuery(t *testing.T) {
	c := NewCatalog()
	c.Replace(sampleTargets())
	mux := NewDiscoveryMux(c)

	var all []FileSDGroup
	seen := map[string]struct{}{}
	for shard := 0; shard < 2; shard++ {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/sd?shard="+itoa(shard)+"&shards=2", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("shard %d status=%d %s", shard, rr.Code, rr.Body.String())
		}
		var groups []FileSDGroup
		if err := json.Unmarshal(rr.Body.Bytes(), &groups); err != nil {
			t.Fatal(err)
		}
		for _, g := range groups {
			addr := g.Targets[0]
			if _, ok := seen[addr]; ok {
				t.Fatalf("overlap %s", addr)
			}
			seen[addr] = struct{}{}
			if shardOf(addr, 2) != shard {
				t.Fatalf("%s in shard %d want %d", addr, shard, shardOf(addr, 2))
			}
		}
		all = append(all, groups...)
	}
	if len(seen) != 2 {
		t.Fatalf("partitioned %d unique want 2 (%v)", len(seen), seen)
	}
	_ = all

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/sd?shard=0", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("incomplete query status=%d", rr.Code)
	}
}

func TestHealthz(t *testing.T) {
	c := NewCatalog()
	c.Replace(sampleTargets())
	mux := NewDiscoveryMux(c)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code)
	}
	body, _ := io.ReadAll(rr.Body)
	if !strings.Contains(string(body), "2 targets") {
		t.Fatalf("body=%s", body)
	}
}

func itoa(n int) string {
	return []string{"0", "1", "2", "3"}[n]
}
