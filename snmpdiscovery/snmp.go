package snmpdiscovery

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"gopkg.in/yaml.v3"
)

// snmpAuth is a named snmp_exporter auth (secrets stay here — never on SD labels).
type snmpAuth struct {
	Name         string
	Community    string
	Version      gosnmp.SnmpVersion
	Username     string
	Password     string
	PrivPassword string
	ContextName  string
	MsgFlags     gosnmp.SnmpV3MsgFlags
	AuthProtocol gosnmp.SnmpV3AuthProtocol
	PrivProtocol gosnmp.SnmpV3PrivProtocol
}

// snmpAuthYAML mirrors prometheus/snmp_exporter config.Auth fields we need.
type snmpAuthYAML struct {
	Community     string `yaml:"community"`
	Version       int    `yaml:"version"`
	Username      string `yaml:"username"`
	Password      string `yaml:"password"`
	PrivPassword  string `yaml:"priv_password"`
	ContextName   string `yaml:"context_name"`
	SecurityLevel string `yaml:"security_level"`
	AuthProtocol  string `yaml:"auth_protocol"`
	PrivProtocol  string `yaml:"priv_protocol"`
}

type snmpFile struct {
	Auths map[string]snmpAuthYAML `yaml:"auths"`
}

func loadAuths(path string, names []string) ([]snmpAuth, error) {
	return loadAuthsOverlay(path, nil, names)
}

// ResolveAuthsOverlay returns YAML bytes for an auths-only overlay.
// inline and file are mutually exclusive. Both empty is a no-op.
func ResolveAuthsOverlay(inline, file string) ([]byte, error) {
	inline = strings.TrimSpace(inline)
	file = strings.TrimSpace(file)
	if inline != "" && file != "" {
		return nil, fmt.Errorf("auths and auths_file are mutually exclusive")
	}
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("auths_file: %w", err)
		}
		if err := validateAuthsOverlay(b); err != nil {
			return nil, err
		}
		return b, nil
	}
	if inline != "" {
		b := []byte(inline)
		if err := validateAuthsOverlay(b); err != nil {
			return nil, err
		}
		return b, nil
	}
	return nil, nil
}

func validateAuthsOverlay(b []byte) error {
	var cfg snmpFile
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return fmt.Errorf("auths overlay: %w", err)
	}
	if len(cfg.Auths) == 0 {
		return fmt.Errorf("auths overlay: missing or empty auths: map")
	}
	return nil
}

func readAuthsMap(path string, overlay []byte) (map[string]snmpAuthYAML, string, error) {
	merged := map[string]snmpAuthYAML{}
	src := path
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			if len(bytes.TrimSpace(overlay)) == 0 {
				return nil, path, err
			}
		} else {
			var cfg snmpFile
			if err := yaml.Unmarshal(b, &cfg); err != nil {
				return nil, path, err
			}
			for k, v := range cfg.Auths {
				merged[k] = v
			}
		}
	}
	if len(bytes.TrimSpace(overlay)) > 0 {
		var cfg snmpFile
		if err := yaml.Unmarshal(overlay, &cfg); err != nil {
			return nil, "auths overlay", fmt.Errorf("auths overlay: %w", err)
		}
		if len(cfg.Auths) == 0 {
			return nil, "auths overlay", fmt.Errorf("auths overlay: missing or empty auths: map")
		}
		for k, v := range cfg.Auths {
			merged[k] = v
		}
		if strings.TrimSpace(src) == "" {
			src = "auths overlay"
		} else {
			src = path + " + auths overlay"
		}
	}
	return merged, src, nil
}

func loadAuthsOverlay(path string, overlay []byte, names []string) ([]snmpAuth, error) {
	cfg, src, err := readAuthsMap(path, overlay)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		for n := range cfg {
			names = append(names, n)
		}
		sort.Strings(names)
	}
	var out []snmpAuth
	for _, n := range names {
		a, ok := cfg[n]
		if !ok {
			return nil, fmt.Errorf("auth %q not in %s", n, src)
		}
		parsed, err := parseAuth(n, a)
		if err != nil {
			return nil, err
		}
		out = append(out, parsed)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no auths to try")
	}
	return out, nil
}

func loadModuleNames(path string) (map[string]struct{}, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		return nil, err
	}
	doc := root
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		doc = *root.Content[0]
	}
	if doc.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("snmp config %s: expected mapping", path)
	}
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value != "modules" {
			continue
		}
		return mappingKeys(doc.Content[i+1]), nil
	}
	return nil, nil
}

func mappingKeys(n *yaml.Node) map[string]struct{} {
	out := map[string]struct{}{}
	if n == nil || n.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := strings.TrimSpace(n.Content[i].Value)
		if k != "" {
			out[k] = struct{}{}
		}
	}
	return out
}

func parseAuth(name string, a snmpAuthYAML) (snmpAuth, error) {
	out := snmpAuth{Name: name, ContextName: a.ContextName}
	switch a.Version {
	case 1:
		out.Version = gosnmp.Version1
	case 3:
		out.Version = gosnmp.Version3
	case 0, 2:
		out.Version = gosnmp.Version2c
	default:
		return snmpAuth{}, fmt.Errorf("auth %q: unsupported version %d", name, a.Version)
	}

	if out.Version != gosnmp.Version3 {
		out.Community = a.Community
		if out.Community == "" {
			out.Community = "public"
		}
		return out, nil
	}

	out.Username = a.Username
	out.Password = a.Password
	out.PrivPassword = a.PrivPassword
	if out.Username == "" {
		return snmpAuth{}, fmt.Errorf("auth %q: version 3 requires username", name)
	}

	flags, err := parseSecurityLevel(a.SecurityLevel)
	if err != nil {
		return snmpAuth{}, fmt.Errorf("auth %q: %w", name, err)
	}
	out.MsgFlags = flags

	authProto, err := parseAuthProtocol(a.AuthProtocol)
	if err != nil {
		return snmpAuth{}, fmt.Errorf("auth %q: %w", name, err)
	}
	privProto, err := parsePrivProtocol(a.PrivProtocol)
	if err != nil {
		return snmpAuth{}, fmt.Errorf("auth %q: %w", name, err)
	}

	switch flags {
	case gosnmp.NoAuthNoPriv:
		out.AuthProtocol = gosnmp.NoAuth
		out.PrivProtocol = gosnmp.NoPriv
	case gosnmp.AuthNoPriv:
		if out.Password == "" {
			return snmpAuth{}, fmt.Errorf("auth %q: authNoPriv requires password", name)
		}
		out.AuthProtocol = authProto
		if out.AuthProtocol == gosnmp.NoAuth {
			out.AuthProtocol = gosnmp.SHA
		}
		out.PrivProtocol = gosnmp.NoPriv
	case gosnmp.AuthPriv:
		if out.Password == "" {
			return snmpAuth{}, fmt.Errorf("auth %q: authPriv requires password", name)
		}
		if out.PrivPassword == "" {
			return snmpAuth{}, fmt.Errorf("auth %q: authPriv requires priv_password", name)
		}
		out.AuthProtocol = authProto
		if out.AuthProtocol == gosnmp.NoAuth {
			out.AuthProtocol = gosnmp.SHA
		}
		out.PrivProtocol = privProto
		if out.PrivProtocol == gosnmp.NoPriv {
			out.PrivProtocol = gosnmp.AES
		}
	}
	return out, nil
}

func parseSecurityLevel(s string) (gosnmp.SnmpV3MsgFlags, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "noauthnopriv":
		return gosnmp.NoAuthNoPriv, nil
	case "authnopriv":
		return gosnmp.AuthNoPriv, nil
	case "authpriv":
		return gosnmp.AuthPriv, nil
	default:
		return 0, fmt.Errorf("unknown security_level %q (want noAuthNoPriv|authNoPriv|authPriv)", s)
	}
}

func parseAuthProtocol(s string) (gosnmp.SnmpV3AuthProtocol, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "", "MD5":
		return gosnmp.MD5, nil
	case "SHA", "SHA1":
		return gosnmp.SHA, nil
	case "SHA224":
		return gosnmp.SHA224, nil
	case "SHA256":
		return gosnmp.SHA256, nil
	case "SHA384":
		return gosnmp.SHA384, nil
	case "SHA512":
		return gosnmp.SHA512, nil
	case "NOAUTH":
		return gosnmp.NoAuth, nil
	default:
		return 0, fmt.Errorf("unknown auth_protocol %q", s)
	}
}

func parsePrivProtocol(s string) (gosnmp.SnmpV3PrivProtocol, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "", "DES":
		return gosnmp.DES, nil
	case "AES", "AES128":
		return gosnmp.AES, nil
	case "AES192":
		return gosnmp.AES192, nil
	case "AES256":
		return gosnmp.AES256, nil
	case "AES192C":
		return gosnmp.AES192C, nil
	case "AES256C":
		return gosnmp.AES256C, nil
	case "NOPRIV":
		return gosnmp.NoPriv, nil
	default:
		return 0, fmt.Errorf("unknown priv_protocol %q", s)
	}
}

func newGoSNMP(addr string, port uint16, timeout time.Duration, retries int, auth snmpAuth) *gosnmp.GoSNMP {
	g := &gosnmp.GoSNMP{
		Target:  addr,
		Port:    port,
		Timeout: timeout,
		Retries: retries,
		Version: auth.Version,
	}
	if auth.Version == gosnmp.Version3 {
		g.SecurityModel = gosnmp.UserSecurityModel
		g.MsgFlags = auth.MsgFlags
		g.ContextName = auth.ContextName
		g.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 auth.Username,
			AuthenticationProtocol:   auth.AuthProtocol,
			AuthenticationPassphrase: auth.Password,
			PrivacyProtocol:          auth.PrivProtocol,
			PrivacyPassphrase:        auth.PrivPassword,
		}
		return g
	}
	g.Community = auth.Community
	return g
}

type probeResult struct {
	Addr        string
	AuthName    string
	SysObjectID string
	SysName     string
	SysDescr    string
}

func probe(addr string, port uint16, timeout time.Duration, retries int, auths []snmpAuth, oids []string) (*probeResult, ProbeDetail) {
	start := time.Now()
	detail := ProbeDetail{Reason: ProbeReasonNoAuth}
	defer func() { detail.Duration = time.Since(start) }()

	if len(oids) == 0 {
		oids = []string{"1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.1.0"}
	}
	if len(auths) == 0 {
		return nil, detail
	}
	if retries < 0 {
		retries = 0
	}

	var last error
	for i, auth := range auths {
		// Drive retries ourselves so we can count them; gosnmp Retries is silent.
		g := newGoSNMP(addr, port, timeout, 0, auth)
		if err := g.Connect(); err != nil {
			last = err
			detail.AuthFails++
			detail.Reason = classifyProbeError(err)
			continue
		}
		var (
			pkt *gosnmp.SnmpPacket
			err error
		)
		for attempt := 0; attempt <= retries; attempt++ {
			if attempt > 0 {
				detail.Retries++
			}
			pkt, err = g.Get(oids)
			if err == nil {
				break
			}
			last = err
		}
		_ = g.Conn.Close()
		if err != nil {
			detail.AuthFails++
			detail.Reason = classifyProbeError(last)
			continue
		}
		if pkt == nil || len(pkt.Variables) == 0 {
			last = fmt.Errorf("empty SNMP response")
			detail.AuthFails++
			detail.Reason = ProbeReasonEmpty
			continue
		}
		res := &probeResult{Addr: addr, AuthName: auth.Name}
		for _, v := range pkt.Variables {
			oid := normalizeOID(v.Name)
			val := stringifyPDU(v)
			switch {
			case strings.HasSuffix(oid, "1.2.1.1.2.0"):
				res.SysObjectID = normalizeOID(val)
			case strings.HasSuffix(oid, "1.2.1.1.5.0"):
				res.SysName = val
			case strings.HasSuffix(oid, "1.2.1.1.1.0"):
				res.SysDescr = val
			}
		}
		if res.SysObjectID == "" && res.SysName == "" && res.SysDescr == "" {
			last = fmt.Errorf("no sys* fields")
			detail.AuthFails++
			detail.Reason = ProbeReasonNoSys
			continue
		}
		detail.Success = true
		detail.Reason = ProbeReasonOK
		detail.FirstAuth = i == 0
		detail.AuthFails = i
		return res, detail
	}
	if last == nil {
		last = fmt.Errorf("no auth succeeded")
	}
	if detail.Reason == ProbeReasonNoAuth || detail.Reason == "" {
		detail.Reason = classifyProbeError(last)
	}
	return nil, detail
}

func stringifyPDU(v gosnmp.SnmpPDU) string {
	switch val := v.Value.(type) {
	case string:
		return strings.TrimSpace(val)
	case []byte:
		return strings.TrimSpace(string(val))
	default:
		if v.Value == nil {
			return ""
		}
		return strings.TrimSpace(fmt.Sprint(v.Value))
	}
}
