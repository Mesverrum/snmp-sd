package snmpdiscovery

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gosnmp/gosnmp"
)

func writeAuthsYAML(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "snmp.yml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadModuleNames(t *testing.T) {
	path := writeAuthsYAML(t, `
auths:
  public_v2:
    community: public
    version: 2
modules:
  if_mib:
    walk: ["1.3.6.1.2.1.2"]
  nokia_srlinux:
    walk: ["1.3.6.1.4.1.6527"]
`)
	got, err := loadModuleNames(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["if_mib"]; !ok {
		t.Fatalf("missing if_mib: %v", got)
	}
	if _, ok := got["nokia_srlinux"]; !ok {
		t.Fatalf("missing nokia_srlinux: %v", got)
	}
	if _, ok := got["nokia_srlinux_hot"]; ok {
		t.Fatalf("invented sidecar: %v", got)
	}
}

func TestLoadAuthsV2Community(t *testing.T) {
	path := writeAuthsYAML(t, `
auths:
  public_v2:
    community: lab-public
    version: 2
`)
	auths, err := loadAuths(path, []string{"public_v2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(auths) != 1 {
		t.Fatalf("len=%d", len(auths))
	}
	a := auths[0]
	if a.Name != "public_v2" || a.Community != "lab-public" || a.Version != gosnmp.Version2c {
		t.Fatalf("unexpected: %+v", a)
	}
}

func TestLoadAuthsV3AuthPriv(t *testing.T) {
	path := writeAuthsYAML(t, `
auths:
  dc1_v3:
    version: 3
    security_level: authPriv
    username: netops
    password: auth-secret
    auth_protocol: SHA
    priv_protocol: AES
    priv_password: priv-secret
    context_name: mgmt
`)
	auths, err := loadAuths(path, []string{"dc1_v3"})
	if err != nil {
		t.Fatal(err)
	}
	a := auths[0]
	if a.Version != gosnmp.Version3 {
		t.Fatalf("version=%v", a.Version)
	}
	if a.Username != "netops" || a.Password != "auth-secret" || a.PrivPassword != "priv-secret" {
		t.Fatalf("secrets mismatch: %+v", a)
	}
	if a.MsgFlags != gosnmp.AuthPriv {
		t.Fatalf("MsgFlags=%v", a.MsgFlags)
	}
	if a.AuthProtocol != gosnmp.SHA || a.PrivProtocol != gosnmp.AES {
		t.Fatalf("protocols auth=%v priv=%v", a.AuthProtocol, a.PrivProtocol)
	}
	if a.ContextName != "mgmt" {
		t.Fatalf("context=%q", a.ContextName)
	}
	if a.Community != "" {
		t.Fatalf("v3 must not set community, got %q", a.Community)
	}
}

func TestLoadAuthsV3AuthNoPriv(t *testing.T) {
	path := writeAuthsYAML(t, `
auths:
  edge_v3:
    version: 3
    security_level: authNoPriv
    username: monitor
    password: only-auth
    auth_protocol: SHA256
`)
	auths, err := loadAuths(path, []string{"edge_v3"})
	if err != nil {
		t.Fatal(err)
	}
	a := auths[0]
	if a.MsgFlags != gosnmp.AuthNoPriv {
		t.Fatalf("MsgFlags=%v", a.MsgFlags)
	}
	if a.AuthProtocol != gosnmp.SHA256 || a.PrivProtocol != gosnmp.NoPriv {
		t.Fatalf("protocols auth=%v priv=%v", a.AuthProtocol, a.PrivProtocol)
	}
}

func TestLoadAuthsV3MissingUsername(t *testing.T) {
	path := writeAuthsYAML(t, `
auths:
  bad:
    version: 3
    security_level: noAuthNoPriv
`)
	if _, err := loadAuths(path, []string{"bad"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestResolveAuthsOverlay(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		b, err := ResolveAuthsOverlay("", "")
		if err != nil {
			t.Fatal(err)
		}
		if b != nil {
			t.Fatalf("got %q", b)
		}
	})
	t.Run("both set", func(t *testing.T) {
		if _, err := ResolveAuthsOverlay("auths:\n  a:\n    version: 2\n", "/tmp/x"); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("inline", func(t *testing.T) {
		b, err := ResolveAuthsOverlay("auths:\n  site_v2:\n    version: 2\n    community: secret\n", "")
		if err != nil {
			t.Fatal(err)
		}
		if len(b) == 0 {
			t.Fatal("empty")
		}
	})
	t.Run("empty map", func(t *testing.T) {
		if _, err := ResolveAuthsOverlay("auths: {}\n", ""); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("file", func(t *testing.T) {
		path := writeAuthsYAML(t, `
auths:
  file_v2:
    community: from-file
    version: 2
`)
		b, err := ResolveAuthsOverlay("", path)
		if err != nil {
			t.Fatal(err)
		}
		auths, err := loadAuthsOverlay("", b, []string{"file_v2"})
		if err != nil {
			t.Fatal(err)
		}
		if auths[0].Community != "from-file" {
			t.Fatalf("got %+v", auths[0])
		}
	})
}

func TestLoadAuthsOverlayWins(t *testing.T) {
	path := writeAuthsYAML(t, `
auths:
  public_v2:
    community: image-public
    version: 2
  leftover:
    community: unused
    version: 2
`)
	overlay := []byte(`
auths:
  public_v2:
    community: overlay-secret
    version: 2
`)
	auths, err := loadAuthsOverlay(path, overlay, []string{"public_v2"})
	if err != nil {
		t.Fatal(err)
	}
	if auths[0].Community != "overlay-secret" {
		t.Fatalf("overlay should win: %+v", auths[0])
	}
}

func TestLoadAuthsOverlayOnly(t *testing.T) {
	overlay := []byte(`
auths:
  dc1_v3:
    version: 3
    security_level: authPriv
    username: netops
    password: auth-secret
    priv_password: priv-secret
    auth_protocol: SHA
    priv_protocol: AES
`)
	auths, err := loadAuthsOverlay("/no/such/snmp-network.yml", overlay, []string{"dc1_v3"})
	if err != nil {
		t.Fatal(err)
	}
	if auths[0].Username != "netops" {
		t.Fatalf("got %+v", auths[0])
	}
}

func TestLoadAuthsV3AuthPrivRequiresPrivPassword(t *testing.T) {
	path := writeAuthsYAML(t, `
auths:
  bad:
    version: 3
    security_level: authPriv
    username: u
    password: p
    auth_protocol: SHA
    priv_protocol: AES
`)
	if _, err := loadAuths(path, []string{"bad"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestNewGoSNMPV3ConfiguresUSM(t *testing.T) {
	auth := snmpAuth{
		Name:         "dc1_v3",
		Version:      gosnmp.Version3,
		Username:     "netops",
		Password:     "auth-secret",
		PrivPassword: "priv-secret",
		ContextName:  "mgmt",
		MsgFlags:     gosnmp.AuthPriv,
		AuthProtocol: gosnmp.SHA,
		PrivProtocol: gosnmp.AES,
	}
	g := newGoSNMP("10.0.0.1", 161, 0, 0, auth)
	if g.Version != gosnmp.Version3 || g.SecurityModel != gosnmp.UserSecurityModel {
		t.Fatalf("version/model: %v %v", g.Version, g.SecurityModel)
	}
	if g.MsgFlags != gosnmp.AuthPriv || g.ContextName != "mgmt" {
		t.Fatalf("flags/context: %v %q", g.MsgFlags, g.ContextName)
	}
	usp, ok := g.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if !ok || usp == nil {
		t.Fatal("expected UsmSecurityParameters")
	}
	if usp.UserName != "netops" || usp.AuthenticationPassphrase != "auth-secret" || usp.PrivacyPassphrase != "priv-secret" {
		t.Fatalf("usp secrets: %+v", usp)
	}
	if usp.AuthenticationProtocol != gosnmp.SHA || usp.PrivacyProtocol != gosnmp.AES {
		t.Fatalf("usp protocols: %+v", usp)
	}
	if g.Community != "" {
		t.Fatalf("community should be empty for v3, got %q", g.Community)
	}
}

func TestNewGoSNMPV2UsesCommunity(t *testing.T) {
	auth := snmpAuth{Name: "public_v2", Community: "public", Version: gosnmp.Version2c}
	g := newGoSNMP("10.0.0.1", 161, 0, 0, auth)
	if g.Community != "public" || g.Version != gosnmp.Version2c {
		t.Fatalf("%+v", g)
	}
	if g.SecurityParameters != nil {
		t.Fatal("v2 must not set SecurityParameters")
	}
}
