package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureWG() string {
	k := base64.StdEncoding.EncodeToString(make([]byte, 32))
	return "[Interface]\nPrivateKey = " + k + "\nAddress = 10.77.0.2/32, fd00::2/128\nDNS = 10.77.0.1\n\n[Peer]\nPublicKey = " + k + "\nEndpoint = 203.0.113.1:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"
}
func TestWireguardImport(t *testing.T) {
	conf, endpoint, addr, e := parseWG(fixtureWG())
	if e != nil {
		t.Fatal(e)
	}
	if endpoint != "203.0.113.1" || addr != "10.77.0.2/32" || strings.Contains(conf, "DNS") || strings.Contains(conf, "::/0") {
		t.Fatal("configuration not normalized")
	}
}
func TestWireguardRejectsUnsafeProfiles(t *testing.T) {
	for _, s := range []string{fixtureWG() + "PostUp = curl attacker.test\n", fixtureWG() + "[Peer]\n", strings.ReplaceAll(fixtureWG(), "0.0.0.0/0, ::/0", "10.0.0.0/8"), strings.ReplaceAll(fixtureWG(), "51820", "0"), strings.ReplaceAll(fixtureWG(), "PrivateKey = ", "SaveConfig = "), fixtureWG() + "PersistentKeepalive = 2\nPersistentKeepalive = 3"} {
		if _, _, _, e := parseWG(s); e == nil {
			t.Fatalf("unsafe profile accepted")
		}
	}
}
func TestProjectDoesNotExposeHomeOrSecrets(t *testing.T) {
	h := t.TempDir()
	t.Setenv("HOME", h)
	t.Setenv("USERPROFILE", h)
	t.Setenv("LOCKLANE_HOME", filepath.Join(h, "settings"))
	_ = os.MkdirAll(homeDir(), 0700)
	project := filepath.Join(h, "project")
	_ = os.Mkdir(project, 0700)
	if _, e := validateProject(project); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{h, homeDir(), string(os.PathSeparator)} {
		if _, e := validateProject(p); e == nil {
			t.Fatalf("broad mount accepted: %s", p)
		}
	}
}
func TestComposeSecurityBoundaries(t *testing.T) {
	t.Setenv("LOCKLANE_HOME", t.TempDir())
	c := Config{Provider: "tailscale", ExpectedIP: "203.0.113.9", ExitNode: "100.1.2.3", Project: t.TempDir()}
	if e := materialize(c); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(filepath.Join(homeDir(), "compose.json"))
	var x map[string]any
	if e := json.Unmarshal(b, &x); e != nil {
		t.Fatal(e)
	}
	services := x["services"].(map[string]any)
	w := services["workspace"].(map[string]any)
	g := services["gateway"].(map[string]any)
	if w["user"] != "1000:1000" || w["network_mode"] != "service:gateway" || w["read_only"] != true {
		t.Fatal("workspace privilege boundary weakened")
	}
	if _, ok := w["ports"]; ok {
		t.Fatal("port exposed")
	}
	if _, ok := g["privileged"]; ok {
		t.Fatal("privileged gateway")
	}
	if os.PathSeparator == '/' {
		st, _ := os.Stat(filepath.Join(homeDir(), "resolv.conf"))
		if st.Mode().Perm() != 0644 {
			t.Fatal("unprivileged DNS resolver cannot read resolv.conf")
		}
	}
	if strings.Contains(string(b), "docker.sock") || strings.Contains(string(b), "host.docker.internal") {
		t.Fatal("host access leaked")
	}
}
func TestAPITokenAndOriginRequired(t *testing.T) {
	a := &App{token: "test-token", origin: "http://127.0.0.1:12345"}
	called := false
	handler := a.auth(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(204) })
	cases := []struct {
		token, host, origin string
		ok                  bool
	}{{"", "127.0.0.1:12345", "", false}, {"wrong", "127.0.0.1:12345", "", false}, {"test-token", "evil.test:12345", "", false}, {"test-token", "127.0.0.1:12345", "https://evil.test", false}, {"test-token", "127.0.0.1:12345", "http://127.0.0.1:12345", true}}
	for _, v := range cases {
		called = false
		r := httptest.NewRequest("POST", a.origin+"/api/start", nil)
		r.Host = v.host
		r.Header.Set("X-Locklane-Token", v.token)
		r.Header.Set("Origin", v.origin)
		w := httptest.NewRecorder()
		handler(w, r)
		if called != v.ok {
			t.Fatal("authorization boundary failed", v)
		}
	}
}
func TestSecretNotStoredInConfig(t *testing.T) {
	t.Setenv("LOCKLANE_HOME", t.TempDir())
	secret := "TEST-PRIVATE-KEY"
	c := Config{Provider: "wireguard", Wireguard: secret}
	if e := store(c, secret); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(filepath.Join(homeDir(), "config.json"))
	if strings.Contains(string(b), secret) {
		t.Fatal("key leaked into config")
	}
	if os.PathSeparator == '/' {
		st, _ := os.Stat(filepath.Join(homeDir(), "secrets", "wg.conf"))
		if st.Mode().Perm() != 0600 {
			t.Fatal("secret permissions")
		}
	}
}
func TestAtomicGateAndFailClosedOrder(t *testing.T) {
	b, _ := assets.ReadFile("runtime/gateway.sh")
	s := string(b)
	if strings.Index(s, "iptables -P OUTPUT DROP") > strings.Index(s, "exec /usr/local/bin/locklane-gate") {
		t.Fatal("VPN started before lock")
	}
	b, _ = assets.ReadFile("runtime/gate.go")
	s = string(b)
	if !strings.Contains(s, `"iptables-restore", "--noflush"`) || !strings.Contains(s, `"--reuid=1001"`) {
		t.Fatal("atomic gate or unprivileged probe missing")
	}
}
func TestPowerShellLiteralEscaping(t *testing.T) {
	if ps("a'b") != "'a''b'" {
		t.Fatal("PowerShell injection")
	}
	if shell("a'b") != "'a'\"'\"'b'" {
		t.Fatal("shell injection")
	}
}

func TestProductionDockerEndpointIsLocal(t *testing.T) {
	for _, s := range []string{"unix:///var/run/docker.sock", "npipe:////./pipe/dockerDesktopLinuxEngine"} {
		if !localEndpoint(s) {
			t.Fatal("local endpoint rejected")
		}
	}
	for _, s := range []string{"ssh://production", "tcp://remote:2376", "https://server"} {
		if localEndpoint(s) {
			t.Fatal("remote engine accepted")
		}
	}
}
