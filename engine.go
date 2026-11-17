package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

//go:embed web/*.html web/*.css web/*.js web/*.svg runtime/*
var assets embed.FS

func dockerContext() string {
	if s := os.Getenv("LOCKLANE_DOCKER_CONTEXT"); s != "" {
		return s
	}
	return "desktop-linux"
}
func docker(ctx context.Context, args ...string) (string, error) {
	a := append([]string{"--context", dockerContext()}, args...)
	b, e := exec.CommandContext(ctx, "docker", a...).CombinedOutput()
	if e != nil {
		return string(b), fmt.Errorf("Docker: %w", e)
	}
	return string(b), nil
}
func compose(ctx context.Context, args ...string) (string, error) {
	a := []string{"compose", "--project-name", "locklane", "--file", filepath.Join(homeDir(), "compose.json")}
	a = append(a, args...)
	return docker(ctx, a...)
}
func doctor() error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, e := docker(ctx, "info", "--format", "{{json .}}")
	if e != nil {
		return errors.New("Запусти Docker Desktop в режиме Linux containers. Настройки текущего Docker-контекста LOCKLANE не переключает")
	}
	var v struct {
		OSType          string
		OperatingSystem string
	}
	if json.Unmarshal([]byte(out), &v) != nil || v.OSType != "linux" {
		return errors.New("Нужен Linux-движок Docker Desktop")
	}
	if os.Getenv("LOCKLANE_DOCKER_CONTEXT") == "" && !strings.Contains(strings.ToLower(v.OperatingSystem), "docker desktop") {
		return errors.New("Для этой сборки нужен локальный Docker Desktop")
	}
	_, e = docker(ctx, "compose", "version")
	return e
}
func materialize(c Config) error {
	root := filepath.Join(homeDir(), "runtime")
	names, e := fs.ReadDir(assets, "runtime")
	if e != nil {
		return e
	}
	for _, n := range names {
		if n.IsDir() {
			continue
		}
		b, e := assets.ReadFile("runtime/" + n.Name())
		if e != nil {
			return e
		}
		if e = writePrivate(filepath.Join(root, n.Name()), b); e != nil {
			return e
		}
	}
	if e = writePrivate(filepath.Join(homeDir(), "resolv.conf"), []byte("nameserver 1.1.1.1\noptions timeout:2 attempts:1\n")); e != nil {
		return e
	}
	if e = os.Chmod(filepath.Join(homeDir(), "resolv.conf"), 0644); e != nil {
		return e
	}
	mounts := []any{map[string]any{"type": "volume", "source": "status", "target": "/state"}, map[string]any{"type": "volume", "source": "tailscale", "target": "/var/lib/tailscale"}, map[string]any{"type": "bind", "source": filepath.Join(homeDir(), "resolv.conf"), "target": "/etc/resolv.conf", "read_only": true}}
	if c.Provider == "wireguard" {
		mounts = append(mounts, map[string]any{"type": "bind", "source": filepath.Join(homeDir(), "secrets", "wg.conf"), "target": "/secrets/wg.conf", "read_only": true})
	}
	if c.Provider == "proxy" {
		mounts = append(mounts, map[string]any{"type": "bind", "source": filepath.Join(homeDir(), "secrets", "proxy.json"), "target": "/secrets/proxy.json", "read_only": true})
	}
	gateway := map[string]any{"build": map[string]any{"context": root, "dockerfile": "Dockerfile.gateway"}, "image": "locklane-gateway:0.1.0", "cap_drop": []string{"ALL"}, "cap_add": []string{"NET_ADMIN", "NET_RAW", "SETUID", "SETGID", "DAC_OVERRIDE"}, "devices": []string{"/dev/net/tun:/dev/net/tun"}, "security_opt": []string{"no-new-privileges:true"}, "environment": map[string]string{"LL_PROVIDER": c.Provider, "LL_EXPECTED_IP": c.ExpectedIP, "LL_EXIT_NODE": c.ExitNode, "LL_ENDPOINT": c.Endpoint, "LL_ADDRESSES": c.Addresses}, "volumes": mounts, "restart": "unless-stopped", "pids_limit": 150, "stop_grace_period": "12s"}
	workspace := map[string]any{"build": map[string]any{"context": root, "dockerfile": "Dockerfile.workspace"}, "image": "locklane-workspace:0.1.0", "network_mode": "service:gateway", "depends_on": map[string]any{"gateway": map[string]string{"condition": "service_healthy"}}, "user": "1000:1000", "cap_drop": []string{"ALL"}, "security_opt": []string{"no-new-privileges:true"}, "read_only": true, "tmpfs": []string{"/tmp:rw,nosuid,size=256m"}, "volumes": []any{map[string]any{"type": "bind", "source": c.Project, "target": "/workspace"}, map[string]any{"type": "volume", "source": "claude-home", "target": "/home/node"}, map[string]any{"type": "volume", "source": "status", "target": "/state", "read_only": true}, map[string]any{"type": "bind", "source": filepath.Join(homeDir(), "resolv.conf"), "target": "/etc/resolv.conf", "read_only": true}}, "pids_limit": 300, "init": true, "restart": "no"}
	data := map[string]any{"services": map[string]any{"gateway": gateway, "workspace": workspace}, "volumes": map[string]any{"status": map[string]string{}, "tailscale": map[string]string{}, "claude-home": map[string]string{}}}
	b, _ := json.MarshalIndent(data, "", "  ")
	return writePrivate(filepath.Join(homeDir(), "compose.json"), b)
}

type TunnelState struct {
	Ready    bool   `json:"ready"`
	Reason   string `json:"reason"`
	IP       string `json:"ip"`
	Checked  int64  `json:"checked_at"`
	LoginURL string `json:"login_url,omitempty"`
}

func tunnel() TunnelState {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	raw, e := compose(ctx, "exec", "-T", "gateway", "cat", "/state/status.json")
	var s TunnelState
	if e != nil || json.Unmarshal([]byte(raw), &s) != nil {
		return TunnelState{Reason: "Среда не запущена"}
	}
	age := time.Now().Unix() - s.Checked
	if age < 0 || age > 8 {
		s.Ready = false
		s.Reason = "Нет свежего подтверждения туннеля"
	}
	return s
}
func stopStack() error {
	if _, e := os.Stat(filepath.Join(homeDir(), "compose.json")); os.IsNotExist(e) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, e := compose(ctx, "down", "--remove-orphans")
	return e
}
func startStack(ctx context.Context, log func(string)) error {
	if e := doctor(); e != nil {
		return e
	}
	c, e := readConfig()
	if e != nil {
		return errors.New("Сначала сохрани настройки")
	}
	if e = stopStack(); e != nil {
		return e
	}
	if e = materialize(c); e != nil {
		return e
	}
	log("Собираем изолированную среду. Первая сборка требует загрузки образов.")
	out, e := compose(ctx, "build")
	if e != nil {
		log(tail(out, 4000))
		return errors.New("Сборка не завершена. Проверь журнал и доступ к Docker Hub")
	}
	log("Образы готовы. Запускаем шлюз с закрытой сетью.")
	out, e = compose(ctx, "up", "-d", "gateway")
	if e != nil {
		log(tail(out, 2000))
		return e
	}
	log("Шлюз запущен. Ожидаем вход в VPN и проверку закреплённого IP.")
	return nil
}
func ensureWorkspace() error {
	s := tunnel()
	if !s.Ready {
		return errors.New("VPN не подтверждён: " + s.Reason)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, e := compose(ctx, "up", "-d", "--no-deps", "workspace")
	if e != nil {
		return fmt.Errorf("Не удалось запустить среду: %s", tail(out, 1000))
	}
	return nil
}
func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}
