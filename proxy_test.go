package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testUUID = "11111111-2222-4333-8444-555555555555"

func TestProxyFormats(t *testing.T) {
	ss := base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:example-password"))
	vm, _ := json.Marshal(map[string]any{"v": "2", "ps": "demo", "add": "example.com", "port": "443", "id": testUUID, "aid": "0", "net": "ws", "path": "/path", "tls": "tls"})
	links := []string{"vless://" + testUUID + "@example.com:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd&type=tcp#Demo", "vless://" + testUUID + "@example.com:443?security=tls&type=xhttp&path=%2Ftest&mode=auto", "vmess://" + base64.StdEncoding.EncodeToString(vm), "trojan://password@example.com:443?security=tls&type=grpc&serviceName=demo", "ss://" + ss + "@example.com:443#demo", "hy2://password@example.com:443?sni=example.com&obfs=salamander&obfs-password=test", "tuic://" + testUUID + ":password@example.com:443", "socks://user:pass@example.com:1080"}
	for _, link := range links {
		n, e := parseProxyLink(link, false)
		if e != nil {
			t.Fatal(e)
		}
		if n.ServerIP != "example.com" || n.Outbound == nil {
			t.Fatal("profile incomplete")
		}
	}
}
func TestImportBase64Subscription(t *testing.T) {
	one := "trojan://test@example.com:443#Example"
	raw := base64.StdEncoding.EncodeToString([]byte(one + "\n" + one))
	n, _, e := importNodes(raw, false)
	if e != nil || len(n) != 2 {
		t.Fatal("subscription import failed", e)
	}
	b, _ := json.Marshal(n)
	if strings.Contains(string(b), "test@") || strings.Contains(string(b), "outbound") || strings.Contains(string(b), "password") {
		t.Fatal("credentials exposed in API result")
	}
}
func TestClosedCryptoExplained(t *testing.T) {
	_, _, e := importNodes("happ://crypto/example", false)
	if e == nil || !strings.Contains(e.Error(), "обычный HTTPS") {
		t.Fatal("missing actionable crypto error")
	}
}
func TestInsecureAndUnsupportedModesRejected(t *testing.T) {
	for _, link := range []string{"trojan://pass@example.com:443?allowInsecure=1", "vless://" + testUUID + "@example.com:443?type=xhttp&extra=untrusted", "ss://YWVzLTEyOC1nY206cGFzcw@example.com:443?plugin=plugin"} {
		if _, e := parseProxyLink(link, false); e == nil {
			t.Fatal("unsupported security mode accepted")
		}
	}
}
func TestPrivateSubscriptionTargetsRejected(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.169.254", "100.64.0.1", "::1"} {
		if publicIP(net.ParseIP(ip)) {
			t.Fatal("private target allowed")
		}
	}
}

func TestExportCoreFixtures(t *testing.T) {
	dir := os.Getenv("LOCKLANE_FIXTURES_DIR")
	if dir == "" {
		t.Skip("core fixture export requested only by integration")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	links := []string{
		"vless://" + testUUID + "@203.0.113.1:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd&type=tcp&sni=example.com",
		"vless://" + testUUID + "@203.0.113.1:443?security=tls&type=xhttp&path=%2Ftest&mode=auto&sni=example.com",
		"vless://" + testUUID + "@203.0.113.1:443?security=tls&type=ws&path=%2Ftest&sni=example.com",
		"vless://" + testUUID + "@203.0.113.1:443?security=tls&type=grpc&serviceName=demo&sni=example.com",
		"trojan://password@203.0.113.1:443?security=tls&type=grpc&serviceName=demo&sni=example.com",
		"hy2://password@203.0.113.1:443?sni=example.com&obfs=salamander&obfs-password=test",
		"tuic://" + testUUID + ":password@203.0.113.1:443?sni=example.com",
		"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@203.0.113.1:443",
	}
	for i, link := range links {
		n, e := parseProxyLink(link, false)
		if e != nil {
			t.Fatal(e)
		}
		b, _ := json.Marshal(ProxySecret{Core: n.Core, Outbound: n.Outbound, ServerIP: n.ServerIP})
		if e = os.WriteFile(filepath.Join(dir, fmt.Sprintf("%02d.json", i)), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
}
