package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type State struct {
	Ready    bool   `json:"ready"`
	Reason   string `json:"reason"`
	IP       string `json:"ip"`
	Checked  int64  `json:"checked_at"`
	LoginURL string `json:"login_url,omitempty"`
}

func run(name string, args ...string) (string, error) {
	b, e := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(b)), e
}
func write(s State) {
	s.Checked = time.Now().Unix()
	b, _ := json.Marshal(s)
	_ = os.WriteFile("/state/status.tmp", b, 0644)
	_ = os.Rename("/state/status.tmp", "/state/status.json")
}

// iptables-restore replaces only our chain atomically: no flush/append gap.
func gate(open bool) error {
	rule := "*filter\n:LL_APP - [0:0]\n-F LL_APP\n"
	if open {
		rule += "-A LL_APP -o " + iface() + " -j ACCEPT\n"
	}
	rule += "-A LL_APP -j DROP\nCOMMIT\n"
	c := exec.Command("iptables-restore", "--noflush")
	c.Stdin = strings.NewReader(rule)
	b, e := c.CombinedOutput()
	if e != nil {
		return fmt.Errorf("firewall update failed: %s", b)
	}
	return nil
}
func iface() string {
	if os.Getenv("LL_PROVIDER") == "proxy" {
		return "ll0"
	}
	if os.Getenv("LL_PROVIDER") == "tailscale" {
		return "tailscale0"
	}
	return "wg0"
}
func startVPN() error {
	if os.Getenv("LL_PROVIDER") == "proxy" {
		return startProxy()
	}
	if os.Getenv("LL_PROVIDER") == "tailscale" {
		c := exec.Command("tailscaled", "--state=/var/lib/tailscale/tailscaled.state", "--socket=/var/run/tailscale/tailscaled.sock", "--tun=tailscale0")
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		if err := c.Start(); err != nil {
			return err
		}
		go c.Wait()
		for i := 0; i < 40; i++ {
			if _, e := os.Stat("/var/run/tailscale/tailscaled.sock"); e == nil {
				return nil
			}
			time.Sleep(250 * time.Millisecond)
		}
		return errors.New("tailscaled did not start")
	}
	// A userspace implementation works across Docker Desktop kernels.
	c := exec.Command("wireguard-go", "-f", "wg0")
	c.Env = append(os.Environ(), "WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1")
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if e := c.Start(); e != nil {
		return e
	}
	go c.Wait()
	for i := 0; i < 40; i++ {
		if _, e := run("ip", "link", "show", "wg0"); e == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, e := run("wg", "setconf", "wg0", "/secrets/wg.conf"); e != nil {
		return errors.New("invalid WireGuard configuration")
	}
	for _, addr := range strings.Split(os.Getenv("LL_ADDRESSES"), ",") {
		if _, e := run("ip", "-4", "address", "add", addr, "dev", "wg0"); e != nil {
			return errors.New("cannot set tunnel address")
		}
	}
	if _, e := run("ip", "link", "set", "dev", "wg0", "mtu", "1280", "up"); e != nil {
		return e
	}
	def, e := run("ip", "-4", "route", "show", "default")
	if e != nil {
		return e
	}
	fields := strings.Fields(def)
	if len(fields) < 5 {
		return errors.New("missing gateway route")
	}
	endpoint := os.Getenv("LL_ENDPOINT")
	if net.ParseIP(endpoint) == nil {
		return errors.New("invalid endpoint")
	}
	if _, e = run("ip", "-4", "route", "replace", endpoint+"/32", "via", fields[2], "dev", fields[4]); e != nil {
		return e
	}
	_, e = run("ip", "-4", "route", "replace", "default", "dev", "wg0")
	return e
}
func tailscaleState() (string, error) {
	raw, e := run("tailscale", "status", "--json")
	if e != nil {
		return "", e
	}
	var s struct {
		BackendState   string
		AuthURL        string
		ExitNodeStatus *struct {
			Online bool
			ID     string
		}
	}
	if json.Unmarshal([]byte(raw), &s) != nil {
		return "", errors.New("cannot read Tailscale state")
	}
	if s.BackendState != "Running" {
		// Login URL is written to a local status file, never shipped in the package.
		c := exec.Command("tailscale", "up", "--accept-dns=false", "--accept-routes=false", "--netfilter-mode=off", "--hostname=locklane", "--timeout=3s")
		_ = c.Run()
		raw, _ = run("tailscale", "status", "--json")
		_ = json.Unmarshal([]byte(raw), &s)
		return s.AuthURL, errors.New("Sign in to Tailscale")
	}
	// Do not accept fallback to any other selected exit node.
	if _, e = run("tailscale", "set", "--exit-node="+os.Getenv("LL_EXIT_NODE"), "--exit-node-allow-lan-access=false", "--accept-dns=false", "--netfilter-mode=off"); e != nil {
		return "", errors.New("Exit node unavailable or not permitted")
	}
	raw, e = run("tailscale", "status", "--json")
	if e != nil {
		return "", e
	}
	_ = json.Unmarshal([]byte(raw), &s)
	if s.ExitNodeStatus == nil || !s.ExitNodeStatus.Online {
		return "", errors.New("Exit node is offline")
	}
	return "", nil
}
func probe() (string, error) {
	// Never probe as root: root is allowed bootstrap access outside the tunnel.
	out, e := run("setpriv", "--reuid=1001", "--regid=1001", "--clear-groups", "curl", "-4", "--noproxy", "*", "-fsS", "--connect-timeout", "2", "--max-time", "4", "https://api.ipify.org")
	if e != nil || net.ParseIP(out) == nil {
		return "", errors.New("Cannot verify tunnel exit IP")
	}
	return out, nil
}
func main() {
	if len(os.Args) > 1 && os.Args[1] == "check-profile" {
		if e := validateProxy(); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "check" {
		b, e := os.ReadFile("/state/status.json")
		var s State
		if e != nil || json.Unmarshal(b, &s) != nil || !s.Ready || time.Now().Unix()-s.Checked > 8 {
			os.Exit(1)
		}
		return
	}

	if e := gate(false); e != nil {
		panic(e)
	}
	write(State{Reason: "Starting isolated gateway"})
	if e := startVPN(); e != nil {
		write(State{Reason: e.Error()})
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case <-sig:
			_ = gate(false)
			write(State{Reason: "Gateway stopped"})
			return
		default:
		}
		s := State{}
		if os.Getenv("LL_PROVIDER") == "tailscale" {
			url, e := tailscaleState()
			if e != nil {
				s.Reason = e.Error()
				s.LoginURL = url
				_ = gate(false)
				write(s)
				time.Sleep(2 * time.Second)
				continue
			}
		}
		ip, e := probe()
		s.IP = ip
		if e != nil {
			s.Reason = e.Error()
		} else if os.Getenv("LL_EXPECTED_IP") == "" {
			s.Reason = "Pin this observed exit IP"
		} else if ip != os.Getenv("LL_EXPECTED_IP") {
			s.Reason = "Exit IP does not match the pinned address"
		} else {
			s.Ready = true
			s.Reason = "Tunnel and exit IP verified"
		}
		if e = gate(s.Ready); e != nil {
			s.Ready = false
			s.Reason = e.Error()
			_ = gate(false)
		}
		write(s)
		// In case of a process crash, the kernel's tunnel-only rules remain in place.
		time.Sleep(2 * time.Second)
	}
}

// Keep no HTTP control service, Docker socket or shell endpoint in the gateway.

func prepareProxy() (string, error) {
	b, e := os.ReadFile("/secrets/proxy.json")
	if e != nil {
		return "", errors.New("Proxy profile is missing")
	}
	var p struct {
		Core     string         `json:"core"`
		Outbound map[string]any `json:"outbound"`
		ServerIP string         `json:"server_ip"`
	}
	if json.Unmarshal(b, &p) != nil || net.ParseIP(p.ServerIP) == nil {
		return "", errors.New("Proxy profile is invalid")
	}
	outbound := p.Outbound
	if p.Core == "xray" {
		cfg := map[string]any{"log": map[string]string{"loglevel": "warning", "access": "none"}, "inbounds": []any{map[string]any{"listen": "127.0.0.2", "port": 1080, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": true}}}, "outbounds": []any{outbound}}
		raw, _ := json.Marshal(cfg)
		if e = os.WriteFile("/run/xray.json", raw, 0600); e != nil {
			return "", e
		}
		// This private loopback address is NOT allowed to the workspace by iptables.
		outbound = map[string]any{"type": "socks", "tag": "proxy", "server": "127.0.0.2", "server_port": 1080, "version": "5"}
	} else if p.Core != "singbox" {
		return "", errors.New("Unknown proxy engine")
	}
	cfg := map[string]any{
		"log":       map[string]string{"level": "warn"},
		"dns":       map[string]any{"servers": []any{map[string]any{"type": "https", "tag": "dns-vpn", "server": "1.1.1.1", "server_port": 443, "path": "/dns-query", "detour": "proxy"}}, "final": "dns-vpn", "strategy": "ipv4_only"},
		"inbounds":  []any{map[string]any{"type": "tun", "tag": "tun-in", "interface_name": "ll0", "address": []string{"172.30.0.1/30"}, "auto_route": true, "strict_route": true, "route_exclude_address": []string{p.ServerIP + "/32"}}},
		"outbounds": []any{outbound},
		"route":     map[string]any{"auto_detect_interface": true, "final": "proxy", "rules": []any{map[string]any{"port": 53, "action": "hijack-dns"}}},
	}
	raw, _ := json.Marshal(cfg)
	if e = os.WriteFile("/run/singbox.json", raw, 0600); e != nil {
		return "", e
	}
	return p.Core, nil
}

func startProxy() error {
	core, e := prepareProxy()
	if e != nil {
		return e
	}
	if core == "xray" {
		c := exec.Command("xray", "run", "-config", "/run/xray.json")
		c.Stderr = os.Stderr
		if e = c.Start(); e != nil {
			return e
		}
		go c.Wait()
	}
	c := exec.Command("sing-box", "run", "-c", "/run/singbox.json")
	c.Stderr = os.Stderr
	if e = c.Start(); e != nil {
		return e
	}
	go c.Wait()
	return nil
}
func validateProxy() error {
	core, e := prepareProxy()
	if e != nil {
		return e
	}
	if core == "xray" {
		if out, err := run("xray", "run", "-test", "-config", "/run/xray.json"); err != nil {
			return fmt.Errorf("Xray configuration invalid: %s", out)
		}
	}
	if out, err := run("sing-box", "check", "-c", "/run/singbox.json"); err != nil {
		return fmt.Errorf("sing-box configuration invalid: %s", out)
	}
	return nil
}
