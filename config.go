package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const version = "0.1.0-beta.1"

type Config struct {
	Profile     string `json:"-"`
	ProfileID   string `json:"profile_id,omitempty"`
	ProfileName string `json:"profile_name,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Provider    string `json:"provider"`
	ExpectedIP  string `json:"expected_ip"`
	ExitNode    string `json:"exit_node"`
	Project     string `json:"project"`
	Endpoint    string `json:"endpoint,omitempty"`
	Addresses   string `json:"addresses,omitempty"`
	Wireguard   string `json:"wireguard,omitempty"`
}

func homeDir() string {
	if s := os.Getenv("LOCKLANE_HOME"); s != "" {
		return s
	}
	s, e := os.UserConfigDir()
	if e != nil {
		panic(e)
	}
	return filepath.Join(s, "Locklane")
}
func readConfig() (Config, error) {
	b, e := os.ReadFile(filepath.Join(homeDir(), "config.json"))
	var c Config
	if e != nil {
		return c, e
	}
	e = json.Unmarshal(b, &c)
	return c, e
}
func writePrivate(path string, b []byte) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.OpenFile(path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if e != nil {
		return e
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(path+".tmp", path)
}
func within(parent, child string) bool {
	r, e := filepath.Rel(parent, child)
	return e == nil && r != ".." && !strings.HasPrefix(r, ".."+string(os.PathSeparator))
}
func validateProject(s string) (string, error) {
	p, e := filepath.Abs(s)
	if e != nil {
		return "", e
	}
	p, e = filepath.EvalSymlinks(p)
	if e != nil {
		return "", errors.New("Выбери существующую папку проекта")
	}
	st, e := os.Stat(p)
	if e != nil || !st.IsDir() {
		return "", errors.New("Нужна папка, не файл")
	}
	user, _ := os.UserHomeDir()
	vol := filepath.VolumeName(p) + string(os.PathSeparator)
	protected := homeDir()
	if real, err := filepath.EvalSymlinks(protected); err == nil {
		protected = real
	}
	if p == vol || p == user || within(p, protected) || within(protected, p) {
		return "", errors.New("Нельзя передавать корень диска, домашнюю папку или настройки LOCKLANE")
	}
	for _, name := range []string{".ssh", ".aws", ".codex", ".config", "Library", "AppData"} {
		if within(filepath.Join(user, name), p) {
			return "", errors.New("Выбери папку проекта, а не папку личных настроек")
		}
	}
	for _, q := range []string{"/System", "/Library", "/etc", "/private", "/usr", "/Applications"} {
		if p == q {
			return "", errors.New("Системная папка не подходит")
		}
	}
	if strings.ContainsAny(p, "\r\n\x00") {
		return "", errors.New("Недопустимый путь")
	}
	return p, nil
}
func parseWG(s string) (string, string, string, error) {
	bad := func() (string, string, string, error) {
		return "", "", "", errors.New("Нужен WireGuard .conf: один Peer, IPv4 Address, PrivateKey, PublicKey, Endpoint и AllowedIPs=0.0.0.0/0. Командные хуки запрещены")
	}
	if len(s) > 32768 {
		return bad()
	}
	section := ""
	m := map[string]string{}
	peers := 0
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		ln := strings.TrimSpace(strings.SplitN(sc.Text(), "#", 2)[0])
		if ln == "" {
			continue
		}
		if strings.HasPrefix(ln, "[") {
			if ln != "[Interface]" && ln != "[Peer]" {
				return bad()
			}
			section = ln
			if ln == "[Peer]" {
				peers++
			}
			continue
		}
		kv := strings.SplitN(ln, "=", 2)
		if len(kv) != 2 {
			return bad()
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		allowed := map[string]bool{"[Interface]PrivateKey": true, "[Interface]Address": true, "[Interface]DNS": true, "[Interface]MTU": true, "[Peer]PublicKey": true, "[Peer]PresharedKey": true, "[Peer]Endpoint": true, "[Peer]AllowedIPs": true, "[Peer]PersistentKeepalive": true}
		k := section + key
		if !allowed[k] || m[k] != "" {
			return bad()
		}
		m[k] = val
	}
	if sc.Err() != nil || peers != 1 {
		return bad()
	}
	for _, k := range []string{"[Interface]PrivateKey", "[Peer]PublicKey"} {
		b, e := base64.StdEncoding.DecodeString(m[k])
		if e != nil || len(b) != 32 {
			return bad()
		}
	}
	if v := m["[Peer]PresharedKey"]; v != "" {
		b, e := base64.StdEncoding.DecodeString(v)
		if e != nil || len(b) != 32 {
			return bad()
		}
	}
	full := false
	for _, v := range strings.Split(m["[Peer]AllowedIPs"], ",") {
		if strings.TrimSpace(v) == "0.0.0.0/0" {
			full = true
		}
	}
	if !full {
		return bad()
	}
	var addresses []string
	for _, v := range strings.Split(m["[Interface]Address"], ",") {
		v = strings.TrimSpace(v)
		ip, _, e := net.ParseCIDR(v)
		if e != nil {
			return bad()
		}
		if ip.To4() != nil {
			addresses = append(addresses, v)
		}
	}
	if len(addresses) == 0 {
		return bad()
	}
	host, port, e := net.SplitHostPort(m["[Peer]Endpoint"])
	if e != nil {
		return bad()
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return bad()
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ips, e := net.LookupIP(host)
		if e != nil {
			return "", "", "", errors.New("Не удалось разрешить Endpoint VPN")
		}
		for _, v := range ips {
			if v.To4() != nil {
				ip = v
				break
			}
		}
	}
	if ip == nil || ip.To4() == nil {
		return bad()
	}
	conf := "[Interface]\nPrivateKey = " + m["[Interface]PrivateKey"] + "\n\n[Peer]\nPublicKey = " + m["[Peer]PublicKey"] + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = " + net.JoinHostPort(ip.String(), port) + "\nPersistentKeepalive = 25\n"
	if v := m["[Peer]PresharedKey"]; v != "" {
		conf += "PresharedKey = " + v + "\n"
	}
	return conf, ip.String(), strings.Join(addresses, ","), nil
}
func validate(c Config) (Config, string, error) {
	var e error
	c.Project, e = validateProject(c.Project)
	if e != nil {
		return c, "", e
	}
	ip := net.ParseIP(strings.TrimSpace(c.ExpectedIP))
	if c.ExpectedIP != "" && !publicIP(ip) {
		return c, "", errors.New("Укажи постоянный публичный IPv4 своего VPN")
	}
	if ip != nil {
		c.ExpectedIP = ip.String()
	}
	if c.Provider == "tailscale" {
		ip := net.ParseIP(strings.TrimSpace(c.ExitNode))
		if ip == nil || ip.To4() == nil {
			return c, "", errors.New("Укажи Tailscale IPv4 своего exit node (обычно 100.x.x.x)")
		}
		c.ExitNode = ip.String()
		c.Wireguard = ""
		return c, "", nil
	}
	if c.Provider == "proxy" {
		if c.Profile == "" {
			return c, "", errors.New("Импортируй и выбери сервер из подписки")
		}
		return c, c.Profile, nil
	}
	if c.Provider != "wireguard" {
		return c, "", errors.New("Выбери Tailscale или WireGuard")
	}
	conf, endpoint, addresses, e := parseWG(c.Wireguard)
	if e != nil {
		return c, "", e
	}
	c.Endpoint = endpoint
	c.Addresses = addresses
	c.Wireguard = ""
	c.ExitNode = ""
	return c, conf, nil
}
func store(c Config, secret string) error {
	if c.Provider == "proxy" && secret != "" {
		if e := writePrivate(filepath.Join(homeDir(), "secrets", "proxy.json"), []byte(secret)); e != nil {
			return e
		}
	}
	if c.Provider == "wireguard" && secret != "" {
		if e := writePrivate(filepath.Join(homeDir(), "secrets", "wg.conf"), []byte(secret)); e != nil {
			return e
		}
	}
	c.Wireguard = ""
	b, _ := json.MarshalIndent(c, "", "  ")
	return writePrivate(filepath.Join(homeDir(), "config.json"), b)
}
func scalar(v any) string { b, _ := json.Marshal(v); return string(b) }
