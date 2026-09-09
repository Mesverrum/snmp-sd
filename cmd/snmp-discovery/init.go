package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/Mesverrum/snmp-sd/snmpdiscovery"
)

func runInit(argv []string) error {
	fs := flag.NewFlagSet("snmp-discovery init", flag.ContinueOnError)
	authsOut := fs.String("out-auths", "auths.yml", "auths overlay (mode 0600)")
	discOut := fs.String("out-discovery", "discovery.yml", "discovery groups")
	force := fs.Bool("force", false, "overwrite existing files")
	check := fs.Bool("check", false, "verify discovery auth names exist in auths / snmp-config")
	checkAuths := fs.String("auths", "", "auths.yml for --check (default --out-auths)")
	checkDisc := fs.String("discovery", "", "discovery.yml for --check (default --out-discovery)")
	snmpCfg := fs.String("snmp-config", "", "optional library snmp.yml for --check")
	var authV2, authV1, authV3, groups flagStrings
	fs.Var(&authV2, "auth-v2", "repeatable: name=community")
	fs.Var(&authV1, "auth-v1", "repeatable: name=community")
	fs.Var(&authV3, "auth-v3", "repeatable: name,user=…,auth=…,priv=…")
	fs.Var(&groups, "group", "repeatable: name,cidrs=10.0.0.0/24,auths=public_v2")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `Usage:
  snmp-discovery init
  snmp-discovery init --auth-v2 public_v2=public --group lab,cidrs=172.20.20.0/24,auths=public_v2
  snmp-discovery init --check --auths auths.yml --discovery discovery.yml

Writes matching auths.yml + discovery.yml so auth names cannot typo-drift.
With no --auth-* / --group flags, asks questions on stdin.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}

	if *check {
		ap := strings.TrimSpace(*checkAuths)
		if ap == "" {
			ap = *authsOut
		}
		dp := strings.TrimSpace(*checkDisc)
		if dp == "" {
			dp = *discOut
		}
		if err := snmpdiscovery.CheckAuthDiscovery(ap, dp, *snmpCfg); err != nil {
			return err
		}
		fmt.Printf("ok %s matches %s\n", dp, ap)
		return nil
	}

	var plan snmpdiscovery.InitPlan
	var err error
	if len(authV2)+len(authV1)+len(authV3)+len(groups) > 0 {
		plan, err = planFromFlags(authV1, authV2, authV3, groups)
	} else {
		plan, err = runInitWizard(os.Stdin, os.Stdout)
	}
	if err != nil {
		return err
	}
	if err := snmpdiscovery.WriteInitFiles(*authsOut, *discOut, plan, *force); err != nil {
		return err
	}
	fmt.Printf("wrote %s (0600) and %s\n", *authsOut, *discOut)
	fmt.Printf("merge %s into the exporter --config.file, then:\n", *authsOut)
	fmt.Printf("  snmp-discovery --config %s --snmp-config snmp/snmp-network.yml --listen :9780 --interval 24h\n", *discOut)
	return nil
}

func planFromFlags(v1, v2, v3, groups flagStrings) (snmpdiscovery.InitPlan, error) {
	var p snmpdiscovery.InitPlan
	for _, s := range v1 {
		a, err := snmpdiscovery.ParseAuthV2Flag(s, 1)
		if err != nil {
			return p, err
		}
		p.Auths = append(p.Auths, a)
	}
	for _, s := range v2 {
		a, err := snmpdiscovery.ParseAuthV2Flag(s, 2)
		if err != nil {
			return p, err
		}
		p.Auths = append(p.Auths, a)
	}
	for _, s := range v3 {
		a, err := snmpdiscovery.ParseAuthV3Flag(s)
		if err != nil {
			return p, err
		}
		p.Auths = append(p.Auths, a)
	}
	for _, s := range groups {
		g, err := snmpdiscovery.ParseGroupFlag(s)
		if err != nil {
			return p, err
		}
		p.Groups = append(p.Groups, g)
	}
	return p, snmpdiscovery.ValidateInitPlan(p)
}

type flagStrings []string

func (f *flagStrings) String() string { return strings.Join(*f, "; ") }
func (f *flagStrings) Set(s string) error {
	*f = append(*f, s)
	return nil
}

func runInitWizard(in io.Reader, out io.Writer) (snmpdiscovery.InitPlan, error) {
	sc := bufio.NewScanner(in)
	ask := func(prompt, def string) (string, error) {
		if def != "" {
			fmt.Fprintf(out, "%s [%s]: ", prompt, def)
		} else {
			fmt.Fprintf(out, "%s: ", prompt)
		}
		if !sc.Scan() {
			if err := sc.Err(); err != nil {
				return "", err
			}
			return "", fmt.Errorf("init: stdin closed")
		}
		s := strings.TrimSpace(sc.Text())
		if s == "" {
			return def, nil
		}
		return s, nil
	}
	yes := func(prompt string, defYes bool) (bool, error) {
		d := "n"
		if defYes {
			d = "Y"
		}
		s, err := ask(prompt+" [y/n]", d)
		if err != nil {
			return false, err
		}
		switch strings.ToLower(s) {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			return defYes, nil
		}
	}

	fmt.Fprint(out, `snmp-discovery init
Write auths.yml (secrets, names only on discovery) then discovery.yml.
Auth names are chosen once and reused — no copy-paste.

`)

	var p snmpdiscovery.InitPlan
	for {
		fmt.Fprintln(out, "— auth —")
		name, err := ask("Auth name", suggestNextAuth(p.Auths))
		if err != nil {
			return p, err
		}
		verS, err := ask("SNMP version (1, 2, 3)", "2")
		if err != nil {
			return p, err
		}
		ver, err := strconv.Atoi(verS)
		if err != nil {
			return p, fmt.Errorf("version: %w", err)
		}
		a := snmpdiscovery.InitAuth{Name: name, Version: ver}
		switch ver {
		case 1, 2:
			a.Community, err = ask("Community", "public")
			if err != nil {
				return p, err
			}
		case 3:
			a.SecurityLevel, err = ask("security_level (noAuthNoPriv, authNoPriv, authPriv)", "authPriv")
			if err != nil {
				return p, err
			}
			a.Username, err = ask("username", "")
			if err != nil {
				return p, err
			}
			if a.SecurityLevel != "noAuthNoPriv" {
				a.Password, err = ask("auth password (visible)", "")
				if err != nil {
					return p, err
				}
				a.AuthProtocol, err = ask("auth_protocol", "SHA256")
				if err != nil {
					return p, err
				}
			}
			if a.SecurityLevel == "authPriv" {
				a.PrivPassword, err = ask("priv password (visible)", "")
				if err != nil {
					return p, err
				}
				a.PrivProtocol, err = ask("priv_protocol", "AES")
				if err != nil {
					return p, err
				}
			}
			a.ContextName, err = ask("context_name (empty if none)", "")
			if err != nil {
				return p, err
			}
		default:
			return p, fmt.Errorf("version %d", ver)
		}
		p.Auths = append(p.Auths, a)
		more, err := yes("Add another auth?", false)
		if err != nil {
			return p, err
		}
		if !more {
			break
		}
	}

	names := make([]string, 0, len(p.Auths))
	for _, a := range p.Auths {
		names = append(names, a.Name)
	}
	fmt.Fprintf(out, "\nKnown auths: %s\n", strings.Join(names, ", "))

	for {
		fmt.Fprintln(out, "— group —")
		gname, err := ask("Group name", suggestNextGroup(p.Groups))
		if err != nil {
			return p, err
		}
		cidrsS, err := ask("CIDRs (comma-separated)", "172.20.20.0/24")
		if err != nil {
			return p, err
		}
		authPick, err := ask("Auth names for this group (comma-separated, or 'all')", names[0])
		if err != nil {
			return p, err
		}
		var gAuths []string
		if strings.EqualFold(authPick, "all") {
			gAuths = append([]string{}, names...)
		} else {
			for _, pth := range strings.Split(authPick, ",") {
				pth = strings.TrimSpace(pth)
				if pth != "" {
					gAuths = append(gAuths, pth)
				}
			}
		}
		mode, err := ask("mode (sweep, crawl, both)", "sweep")
		if err != nil {
			return p, err
		}
		portS, err := ask("UDP port", "161")
		if err != nil {
			return p, err
		}
		port64, err := strconv.ParseUint(portS, 10, 16)
		if err != nil {
			return p, fmt.Errorf("port: %w", err)
		}
		ping, err := yes("ICMP ping before SNMP?", true)
		if err != nil {
			return p, err
		}
		allow := false
		for _, c := range splitCSV(cidrsS) {
			if err := wideCIDR(c); err != nil && strings.Contains(err.Error(), "allow_large") {
				allow, err = yes(fmt.Sprintf("%s is wider than /22. Set allow_large?", c), false)
				if err != nil {
					return p, err
				}
				break
			}
		}
		p.Groups = append(p.Groups, snmpdiscovery.InitGroup{
			Name:          gname,
			CIDRs:         splitCSV(cidrsS),
			Auths:         gAuths,
			Fingerprinter: "network",
			Mode:          mode,
			Port:          uint16(port64),
			Ping:          ping,
			AllowLarge:    allow,
		})
		more, err := yes("Add another group?", false)
		if err != nil {
			return p, err
		}
		if !more {
			break
		}
	}
	return p, snmpdiscovery.ValidateInitPlan(p)
}

func suggestNextAuth(have []snmpdiscovery.InitAuth) string {
	if len(have) == 0 {
		return "public_v2"
	}
	return fmt.Sprintf("site%d_v2", len(have)+1)
}

func suggestNextGroup(have []snmpdiscovery.InitGroup) string {
	if len(have) == 0 {
		return "lab"
	}
	return fmt.Sprintf("site%d", len(have)+1)
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func wideCIDR(raw string) error {
	p := snmpdiscovery.InitPlan{
		Auths:  []snmpdiscovery.InitAuth{{Name: "x", Version: 2, Community: "public"}},
		Groups: []snmpdiscovery.InitGroup{{Name: "g", CIDRs: []string{raw}, Auths: []string{"x"}}},
	}
	return snmpdiscovery.ValidateInitPlan(p)
}
