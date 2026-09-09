package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Mesverrum/snmp-sd/snmpdiscovery"
)

type walkFlags struct {
	file, target, auth, snmpCfg, oid, modules, prefix string
	port                                              uint
	timeout                                           time.Duration
}

func addWalkSourceFlags(fs *flag.FlagSet, w *walkFlags) {
	fs.StringVar(&w.file, "file", "", "snmpwalk -On dump")
	fs.StringVar(&w.target, "target", "", "live device address")
	fs.StringVar(&w.auth, "auth", "public_v2", "named auth in --snmp-config (live walk)")
	fs.StringVar(&w.snmpCfg, "snmp-config", "snmp/snmp-network.yml", "auths + modules for a live walk")
	fs.StringVar(&w.oid, "oid", "1.3.6.1", "live walk start (default: whole internet tree)")
	fs.UintVar(&w.port, "port", 161, "SNMP UDP port")
	fs.DurationVar(&w.timeout, "timeout", 3*time.Second, "SNMP timeout")
	fs.StringVar(&w.modules, "modules", "snmp/modules", "shipped module dir (for “already covered”)")
	fs.StringVar(&w.prefix, "prefix", "", "only consider OIDs under this prefix")
}

func loadWalk(w walkFlags) ([]snmpdiscovery.WalkVar, snmpdiscovery.LibraryOIDs, error) {
	var vars []snmpdiscovery.WalkVar
	switch {
	case strings.TrimSpace(w.file) != "":
		f, err := os.Open(w.file)
		if err != nil {
			return nil, snmpdiscovery.LibraryOIDs{}, err
		}
		parsed, err := snmpdiscovery.ParseWalkText(f)
		_ = f.Close()
		if err != nil {
			return nil, snmpdiscovery.LibraryOIDs{}, err
		}
		vars = parsed
	case strings.TrimSpace(w.target) != "":
		live, err := snmpdiscovery.WalkTarget(w.target, uint16(w.port), w.auth, w.snmpCfg, w.oid, w.timeout, 1)
		if err != nil {
			return nil, snmpdiscovery.LibraryOIDs{}, err
		}
		vars = live
	default:
		return nil, snmpdiscovery.LibraryOIDs{}, fmt.Errorf("pass --file or --target")
	}
	vars = snmpdiscovery.FilterWalk(vars, w.prefix)
	if len(vars) == 0 {
		return nil, snmpdiscovery.LibraryOIDs{}, fmt.Errorf("no OIDs left after --prefix")
	}
	lib, err := snmpdiscovery.LoadLibraryOIDs(w.modules)
	if err != nil {
		fmt.Fprintf(os.Stderr, "note: not marking covered OIDs (%v)\n", err)
		lib = snmpdiscovery.LibraryOIDs{}
	}
	return vars, lib, nil
}

func runWalkCatalog(argv []string) error {
	fs := flag.NewFlagSet("snmp-discovery walk-catalog", flag.ContinueOnError)
	var w walkFlags
	addWalkSourceFlags(fs, &w)
	showCovered := fs.Bool("show-covered", false, "also list OIDs the library already scrapes")
	writePick := fs.String("write-pick", "", "also write a draft pick.yml from uncovered OIDs")
	force := fs.Bool("force", false, "overwrite --write-pick")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `Usage:
  snmp-discovery walk-catalog --file box.walk
  snmp-discovery walk-catalog --file box.walk --write-pick pick.yml
  snmp-discovery walk-catalog --target 192.0.2.10 --auth public_v2

Reads a numeric snmpwalk (-On) or walks the device, groups scalars vs tables,
and marks OIDs the shipped library already scrapes. Default live start is
1.3.6.1 (the whole useful tree). Pass --oid only if the agent chokes.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}
	vars, lib, err := loadWalk(w)
	if err != nil {
		return fmt.Errorf("walk-catalog: %w", err)
	}
	cat := snmpdiscovery.ClusterWalk(vars)
	snmpdiscovery.WriteWalkCatalog(os.Stdout, cat, lib, *showCovered)
	if path := strings.TrimSpace(*writePick); path != "" {
		p := snmpdiscovery.DraftPick(cat, lib, vars)
		if err := snmpdiscovery.WritePickFile(path, p, *force); err != nil {
			return err
		}
		fmt.Printf("wrote %s (%d scalars, %d tables) — edit names, then walk-emit\n", path, len(p.Scalars), len(p.Tables))
	}
	return nil
}

func runWalkPick(argv []string) error {
	fs := flag.NewFlagSet("snmp-discovery walk-pick", flag.ContinueOnError)
	var w walkFlags
	addWalkSourceFlags(fs, &w)
	out := fs.String("out", "pick.yml", "draft shopping list")
	force := fs.Bool("force", false, "overwrite --out")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `Usage:
  snmp-discovery walk-pick --file box.walk --out pick.yml

Writes a draft pick.yml from OIDs the library does not already scrape.
STRING columns become labels; numbers become metrics. Edit the file, then:

  snmp-discovery walk-emit --pick pick.yml --out mymodule.yml

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}
	vars, lib, err := loadWalk(w)
	if err != nil {
		return fmt.Errorf("walk-pick: %w", err)
	}
	p := snmpdiscovery.DraftPick(snmpdiscovery.ClusterWalk(vars), lib, vars)
	if err := snmpdiscovery.WritePickFile(*out, p, *force); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d scalars, %d tables)\n", *out, len(p.Scalars), len(p.Tables))
	fmt.Println("edit names, delete what you do not want, then: snmp-discovery walk-emit --pick " + *out + " --out mymodule.yml")
	return nil
}

func runWalkEmit(argv []string) error {
	fs := flag.NewFlagSet("snmp-discovery walk-emit", flag.ContinueOnError)
	pick := fs.String("pick", "pick.yml", "shopping list from walk-pick")
	out := fs.String("out", "mymodule.yml", "one-module snmp_exporter overlay")
	modules := fs.String("modules", "snmp/modules", "shipped library (warn if a pick is already scraped)")
	force := fs.Bool("force", false, "overwrite --out")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `Usage:
  snmp-discovery walk-emit --pick pick.yml --out mymodule.yml

Turns the edited pick.yml into a one-module overlay. Merge it with the shipped
library — do not replace snmp/modules. Column OIDs only; full index list.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}
	p, err := snmpdiscovery.LoadPickFile(*pick)
	if err != nil {
		return fmt.Errorf("walk-emit: %w", err)
	}
	if lib, err := snmpdiscovery.LoadLibraryOIDs(*modules); err == nil {
		if hits := snmpdiscovery.PickCoveredNames(p, lib); len(hits) > 0 {
			fmt.Fprintln(os.Stderr, "warning: these picks are already in the library (duplicate scrapes):")
			for _, h := range hits {
				fmt.Fprintln(os.Stderr, "  ", h)
			}
		}
	}
	body, err := snmpdiscovery.EmitPickModule(p)
	if err != nil {
		return fmt.Errorf("walk-emit: %w", err)
	}
	if err := snmpdiscovery.WriteEmitFile(*out, body, *force); err != nil {
		return err
	}
	fmt.Printf("wrote %s (module %s)\n", *out, p.Module)
	return nil
}
