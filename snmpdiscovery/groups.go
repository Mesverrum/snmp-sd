package snmpdiscovery

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// DiscoveryFile is the admin object: CIDR-scoped named auths (ktranslate group
// equivalent). Secrets stay in snmp.yml `auths:`; this file never holds a community.
type DiscoveryFile struct {
	Groups    []DiscoveryGroup `yaml:"groups"`
	Overrides []Override       `yaml:"overrides"`
}

type DiscoveryGroup struct {
	Name          string   `yaml:"name"`
	CIDRs         []string `yaml:"cidrs"`
	Exclude       []string `yaml:"exclude"`
	Seeds         []string `yaml:"seeds"`
	Auths         []string `yaml:"auths"`
	Fingerprinter string   `yaml:"fingerprinter"`
	Port          uint16   `yaml:"port"`
	AllowLarge    bool     `yaml:"allow_large"`
	// Mode is sweep (CIDR ping+SNMP), crawl (LLDP/CDP from seeds/catalog), or both.
	Mode string `yaml:"mode"`
	// Ping filters sweep candidates with ICMP first. nil = true. Does not apply to crawl.
	Ping *bool `yaml:"ping"`
}

const (
	modeSweep = "sweep"
	modeCrawl = "crawl"
	modeBoth  = "both"
)

func groupMode(g DiscoveryGroup) string {
	m := strings.ToLower(strings.TrimSpace(g.Mode))
	if m == "" {
		return modeBoth
	}
	return m
}

func groupUsesPing(g DiscoveryGroup, global bool) bool {
	if !global {
		return false
	}
	if g.Ping != nil {
		return *g.Ping
	}
	return true
}

// Override is operator intent on top of live probes. Address is the SNMP IP.
//
// Module alone (legacy): treated as a full chain and partitioned into
// hot / cold / topology. Prefer module_hot / module_cold / module_topology
// when pinning a single tier.
type Override struct {
	Address        string `yaml:"address"`
	Ignore         bool   `yaml:"ignore"`
	Name           string `yaml:"name"`
	Module         string `yaml:"module"` // legacy full chain OR hot when tier fields set
	ModuleHot      string `yaml:"module_hot"`
	ModuleCold     string `yaml:"module_cold"`
	ModuleTopology string `yaml:"module_topology"`
	Auth           string `yaml:"auth"`
}

func LoadDiscoveryFile(path string) (DiscoveryFile, error) {
	var f DiscoveryFile
	b, err := os.ReadFile(path)
	if err != nil {
		return f, err
	}
	if err := yaml.Unmarshal(b, &f); err != nil {
		return f, err
	}
	if err := f.Validate(); err != nil {
		return f, err
	}
	return f, nil
}

// Validate checks groups (name, cidrs, auths, mode).
func (f DiscoveryFile) Validate() error {
	return f.validate()
}

func (f DiscoveryFile) validate() error {
	if len(f.Groups) == 0 {
		return fmt.Errorf("discovery config: at least one group is required")
	}
	seen := map[string]struct{}{}
	for i, g := range f.Groups {
		name := strings.TrimSpace(g.Name)
		if name == "" {
			return fmt.Errorf("discovery config: groups[%d] missing name", i)
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("discovery config: duplicate group %q", name)
		}
		seen[name] = struct{}{}
		if len(g.CIDRs) == 0 {
			return fmt.Errorf("discovery config: group %q has no cidrs", name)
		}
		if len(g.Auths) == 0 {
			return fmt.Errorf("discovery config: group %q has no auths (name the snmp.yml auth; do not omit)", name)
		}
		switch groupMode(g) {
		case modeSweep, modeCrawl, modeBoth:
		default:
			return fmt.Errorf("discovery config: group %q mode %q (want sweep, crawl, or both)", name, g.Mode)
		}
	}
	return nil
}

func cliGroup(name string, cidrs, auths []string, port uint16, allowLarge bool, fp string) DiscoveryFile {
	if name == "" {
		name = "cli"
	}
	if fp == "" {
		fp = "network"
	}
	return DiscoveryFile{
		Groups: []DiscoveryGroup{{
			Name:          name,
			CIDRs:         cidrs,
			Auths:         auths,
			Fingerprinter: fp,
			Port:          port,
			AllowLarge:    allowLarge,
			Mode:          modeSweep,
		}},
	}
}

func ignoredAddresses(ov []Override) []string {
	var out []string
	for _, o := range ov {
		if !o.Ignore {
			continue
		}
		a := strings.TrimSpace(o.Address)
		if a == "" {
			continue
		}
		out = append(out, mustCanonIP(a))
	}
	return out
}

func splitCSVModules(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func applyModuleOverride(t *AlloyTarget, o Override) {
	hot := strings.TrimSpace(o.ModuleHot)
	cold := strings.TrimSpace(o.ModuleCold)
	topo := strings.TrimSpace(o.ModuleTopology)
	legacy := strings.TrimSpace(o.Module)
	if hot != "" || cold != "" || topo != "" {
		if hot != "" {
			t.Module = hot
		} else if legacy != "" {
			t.Module = legacy
		}
		if cold != "" {
			t.ModuleCold = cold
		}
		if topo != "" {
			t.ModuleTopology = topo
		}
		return
	}
	if legacy == "" {
		return
	}
	// Legacy pin: partition system_mib,if_mib,vendor → hot/cold/topology.
	tiers := partitionLegacyModules(splitCSVModules(legacy))
	t.Module = joinModules(tiers.Hot)
	t.ModuleCold = joinModules(tiers.Cold)
	t.ModuleTopology = joinModules(tiers.Topology)
}

func applyOverrides(targets []AlloyTarget, ov []Override) []AlloyTarget {
	byAddr := map[string]Override{}
	for _, o := range ov {
		a := strings.TrimSpace(o.Address)
		if a == "" {
			continue
		}
		byAddr[mustCanonIP(a)] = o
	}
	out := make([]AlloyTarget, 0, len(targets))
	for _, t := range targets {
		addr := mustCanonIP(t.Address)
		t.Address = addr
		o, ok := byAddr[addr]
		if !ok {
			out = append(out, t)
			continue
		}
		if o.Ignore {
			continue
		}
		if n := strings.TrimSpace(o.Name); n != "" {
			t.Name = n
			t.DeviceName = n
		}
		applyModuleOverride(&t, o)
		if a := strings.TrimSpace(o.Auth); a != "" {
			t.Auth = a
		}
		out = append(out, t)
	}
	return out
}
