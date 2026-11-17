package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

type App struct {
	nodes     []ProxyNode
	mu        sync.Mutex
	busy      bool
	logs      []string
	lastError string
	cancel    context.CancelFunc
	token     string
	origin    string
}

func (a *App) log(s string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.logs = append(a.logs, s)
	if len(a.logs) > 30 {
		a.logs = a.logs[len(a.logs)-30:]
	}
}
func (a *App) job(fn func(context.Context) error) error {
	a.mu.Lock()
	if a.busy {
		a.mu.Unlock()
		return errors.New("Дождись завершения текущей операции")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	a.cancel = cancel
	a.busy = true
	a.lastError = ""
	a.mu.Unlock()
	go func() {
		defer cancel()
		e := fn(ctx)
		a.mu.Lock()
		defer a.mu.Unlock()
		a.busy = false
		if e != nil {
			a.lastError = e.Error()
		}
	}()
	return nil
}
func jsonOut(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, e error) {
	w.WriteHeader(400)
	jsonOut(w, map[string]string{"error": e.Error()})
}
func (a *App) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Host != strings.TrimPrefix(a.origin, "http://") || r.Header.Get("X-Locklane-Token") != a.token || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != a.origin) {
			http.Error(w, "Forbidden", 403)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next(w, r)
	}
}
func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	web, _ := fs.Sub(assets, "web")
	files := http.FileServer(http.FS(web))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Host != strings.TrimPrefix(a.origin, "http://") {
			http.Error(w, "Forbidden", 403)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		files.ServeHTTP(w, r)
	})
	mux.HandleFunc("GET /api/ping", a.auth(func(w http.ResponseWriter, r *http.Request) { jsonOut(w, map[string]string{"version": version}) }))
	mux.HandleFunc("POST /api/quit", a.auth(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		if a.cancel != nil {
			a.cancel()
		}
		a.mu.Unlock()
		if e := stopStack(); e != nil {
			fail(w, e)
			return
		}
		jsonOut(w, map[string]bool{"ok": true})
		go func() { time.Sleep(time.Second); _ = os.Remove(filepath.Join(homeDir(), "session.json")); os.Exit(0) }()
	}))
	mux.HandleFunc("GET /api/state", a.auth(func(w http.ResponseWriter, r *http.Request) {
		c, _ := readConfig()
		c.Wireguard = ""
		a.mu.Lock()
		busy, logs, errS := a.busy, append([]string{}, a.logs...), a.lastError
		a.mu.Unlock()
		s := tunnel()
		url := s.LoginURL
		if !strings.HasPrefix(url, "https://login.tailscale.com/") {
			s.LoginURL = ""
		}
		jsonOut(w, map[string]any{"config": c, "tunnel": s, "busy": busy, "logs": logs, "error": errS, "version": version, "context": dockerContext()})
	}))
	mux.HandleFunc("POST /api/import", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Source string `json:"source"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 2*1024*1024)
		if json.NewDecoder(r.Body).Decode(&v) != nil {
			fail(w, errors.New("Не удалось прочитать подписку"))
			return
		}
		nodes, skipped, e := importNodes(v.Source, false)
		if e != nil {
			fail(w, e)
			return
		}
		a.mu.Lock()
		a.nodes = nodes
		a.mu.Unlock()
		jsonOut(w, map[string]any{"nodes": nodes, "skipped": skipped})
	}))
	mux.HandleFunc("POST /api/config", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var c Config
		r.Body = http.MaxBytesReader(w, r.Body, 65536)
		if e := json.NewDecoder(r.Body).Decode(&c); e != nil {
			fail(w, errors.New("Некорректные настройки"))
			return
		}
		old, _ := readConfig()
		if c.Provider == "proxy" {
			a.mu.Lock()
			nodes := append([]ProxyNode{}, a.nodes...)
			a.mu.Unlock()
			found := false
			for _, n := range nodes {
				if c.ProfileID == n.ID {
					resolved, err := resolveNode(n)
					if err != nil {
						fail(w, err)
						return
					}
					n = resolved
					b, _ := json.Marshal(ProxySecret{Core: n.Core, Outbound: n.Outbound, ServerIP: n.ServerIP})
					c.Profile = string(b)
					c.ProfileName = n.Name
					c.Protocol = n.Protocol
					found = true
					break
				}
			}
			if !found && old.Provider == "proxy" && c.ProfileID == "" {
				b, e := os.ReadFile(filepath.Join(homeDir(), "secrets", "proxy.json"))
				if e == nil {
					c.Profile = string(b)
					c.ProfileName = old.ProfileName
					c.Protocol = old.Protocol
					found = true
				}
			}
			if !found {
				fail(w, errors.New("Выбери сервер из импортированного списка"))
				return
			}
			c.ProfileID = ""
		}

		if c.Provider == "wireguard" && c.Wireguard == "" && old.Provider == "wireguard" {
			b, e := os.ReadFile(filepath.Join(homeDir(), "secrets", "wg.conf"))
			if e != nil {
				fail(w, errors.New("Загрузи WireGuard .conf заново"))
				return
			}
			c.Wireguard = "[Interface]\nAddress = " + old.Addresses + "\n" + strings.TrimPrefix(string(b), "[Interface]\n")
		}
		valid, secret, e := validate(c)
		if e != nil {
			fail(w, e)
			return
		}
		e = a.job(func(ctx context.Context) error {
			if e := stopStack(); e != nil {
				return errors.New("Не удалось остановить прежнюю среду; настройки не изменены")
			}
			if e := store(valid, secret); e != nil {
				return e
			}
			if e := materialize(valid); e != nil {
				return e
			}
			a.log("Настройки сохранены локально. Ключ VPN доступен только шлюзу.")
			return nil
		})
		if e != nil {
			fail(w, e)
			return
		}
		jsonOut(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/pin", a.auth(func(w http.ResponseWriter, r *http.Request) {
		c, e := readConfig()
		if e != nil || c.ExpectedIP != "" {
			fail(w, errors.New("Закрепление доступно только при первичной настройке"))
			return
		}
		s := tunnel()
		if s.Reason != "Pin this observed exit IP" || !publicIP(net.ParseIP(s.IP)) {
			fail(w, errors.New("Сначала дождись проверки адреса выбранного узла"))
			return
		}
		e = a.job(func(ctx context.Context) error {
			c.ExpectedIP = s.IP
			if e := store(c, ""); e != nil {
				return e
			}
			return startStack(ctx, a.log)
		})
		if e != nil {
			fail(w, e)
			return
		}
		jsonOut(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/start", a.auth(func(w http.ResponseWriter, r *http.Request) {
		if e := a.job(func(ctx context.Context) error { return startStack(ctx, a.log) }); e != nil {
			fail(w, e)
			return
		}
		jsonOut(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/stop", a.auth(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		if a.cancel != nil {
			a.cancel()
		}
		a.mu.Unlock()
		if e := stopStack(); e != nil {
			fail(w, e)
			return
		}
		a.log("Среда остановлена. Проект и данные входа сохранены.")
		jsonOut(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/launch", a.auth(func(w http.ResponseWriter, r *http.Request) {
		if e := ensureWorkspace(); e != nil {
			fail(w, e)
			return
		}
		if e := openTerminal(); e != nil {
			fail(w, e)
			return
		}
		jsonOut(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/folder", a.auth(func(w http.ResponseWriter, r *http.Request) {
		s, e := chooseFolder()
		if e != nil {
			fail(w, errors.New("Папка не выбрана. Можно вписать путь вручную"))
			return
		}
		jsonOut(w, map[string]string{"path": strings.TrimSpace(s)})
	}))
	mux.HandleFunc("POST /api/check", a.auth(func(w http.ResponseWriter, r *http.Request) {
		if e := ensureWorkspace(); e != nil {
			fail(w, e)
			return
		}
		e := a.job(func(ctx context.Context) error {
			out, e := compose(ctx, "exec", "-T", "workspace", "python3", "-c", selfTest)
			a.log(out)
			if e != nil {
				return errors.New("Самопроверка не пройдена; не запускай Claude до исправления")
			}
			return nil
		})
		if e != nil {
			fail(w, e)
			return
		}
		jsonOut(w, map[string]bool{"ok": true})
	}))
	return mux
}

const selfTest = `import os,socket,json,time,subprocess
s=json.load(open('/state/status.json'));assert s['ready'] and 0<=time.time()-s['checked_at']<8
assert os.getuid()==1000 and not os.path.exists('/var/run/docker.sock')
assert 'NoNewPrivs:\t1' in open('/proc/self/status').read()
assert 'CapEff:\t0000000000000000' in open('/proc/self/status').read()
for addr in [('169.254.169.254',80),('192.168.1.1',80),('127.0.0.11',53)]:
 try:
  c=socket.create_connection(addr,1);c.close();raise AssertionError('Private network reachable')
 except OSError: pass
p=subprocess.run(['curl','-6','--max-time','2','-fsS','https://api64.ipify.org'],capture_output=True);assert p.returncode!=0
p=subprocess.run(['curl','-4','--interface','eth0','--max-time','2','-fsS','https://api.ipify.org'],capture_output=True);assert p.returncode!=0
p=subprocess.run(['curl','-4','--max-time','5','-fsS','https://api.ipify.org'],capture_output=True,text=True);assert p.returncode==0 and p.stdout.strip()==s['ip']
print('PASS: tunnel IP, IPv6 denial, direct-interface denial, private network denial, unprivileged user, no Docker socket.')`

func ps(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
func powershell(s string) (string, error) {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		b[2*i] = byte(v)
		b[2*i+1] = byte(v >> 8)
	}
	out, e := exec.Command("powershell.exe", "-NoProfile", "-EncodedCommand", base64.StdEncoding.EncodeToString(b)).CombinedOutput()
	return string(out), e
}
func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		_, e := powershell("Start-Process " + ps(url))
		return e
	default:
		return exec.Command("xdg-open", url).Start()
	}
}
func shell(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func openTerminal() error {
	bin, e := os.Executable()
	if e != nil {
		return e
	}
	switch runtime.GOOS {
	case "darwin":
		p := filepath.Join(homeDir(), "Claude Code.command")
		body := "#!/bin/sh\nexport LOCKLANE_HOME=" + shell(homeDir()) + "\nexport LOCKLANE_DOCKER_CONTEXT=" + shell(os.Getenv("LOCKLANE_DOCKER_CONTEXT")) + "\nexec " + shell(bin) + " run\n"
		if e = writePrivate(p, []byte(body)); e != nil {
			return e
		}
		_ = os.Chmod(p, 0700)
		return exec.Command("open", "-a", "Terminal", p).Start()
	case "windows":
		_, e := powershell("$env:LOCKLANE_HOME=" + ps(homeDir()) + ";$env:LOCKLANE_DOCKER_CONTEXT=" + ps(os.Getenv("LOCKLANE_DOCKER_CONTEXT")) + ";Start-Process -FilePath " + ps(bin) + " -ArgumentList 'run'")
		return e
	default:
		return errors.New("Запусти locklane run в терминале")
	}
}
func chooseFolder() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		out, e := exec.Command("osascript", "-e", `POSIX path of (choose folder with prompt "Папка проекта для LOCKLANE")`).CombinedOutput()
		return string(out), e
	case "windows":
		return powershell("Add-Type -AssemblyName System.Windows.Forms; $d=New-Object System.Windows.Forms.FolderBrowserDialog; if($d.ShowDialog() -eq 'OK'){$d.SelectedPath}")
	default:
		return "", errors.New("Введите путь вручную")
	}
}
func runCLI() {
	if e := doctor(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	if e := ensureWorkspace(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	args := []string{"--context", dockerContext(), "compose", "--project-name", "locklane", "--file", filepath.Join(homeDir(), "compose.json"), "exec", "workspace", "locklane-run"}
	args = append(args, os.Args[2:]...)
	cmd := exec.Command(dockerBinary(), args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if e := cmd.Run(); e != nil {
		if x, ok := e.(*exec.ExitError); ok {
			os.Exit(x.ExitCode())
		}
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version":
			fmt.Println("LOCKLANE", version)
			return
		case "run":
			runCLI()
			return
		case "stop":
			if e := stopStack(); e != nil {
				fmt.Fprintln(os.Stderr, e)
				os.Exit(1)
			}
			return
		case "doctor":
			if e := doctor(); e != nil {
				fmt.Fprintln(os.Stderr, e)
				os.Exit(1)
			}
			fmt.Println("Docker Linux runtime ready:", dockerContext())
			return
		}
	}
	if e := os.MkdirAll(homeDir(), 0700); e != nil {
		panic(e)
	}
	if existing := existingSession(); existing != "" {
		fmt.Println("LOCKLANE is already running.")
		if os.Getenv("LOCKLANE_NO_BROWSER") == "" {
			_ = openBrowser(existing)
		}
		return
	}
	go doctor()
	token := make([]byte, 32)
	if _, e := rand.Read(token); e != nil {
		panic(e)
	}
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		panic(e)
	}
	addr := "http://" + ln.Addr().String()
	a := &App{token: hex.EncodeToString(token), origin: addr}
	url := addr + "/#" + a.token
	session, _ := json.Marshal(map[string]string{"url": url})
	_ = writePrivate(filepath.Join(homeDir(), "session.json"), session)
	fmt.Println("LOCKLANE", version, "— local control panel:", url)
	if os.Getenv("LOCKLANE_NO_BROWSER") == "" {
		_ = openBrowser(url)
	}
	server := &http.Server{Handler: a.routes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
	if e := server.Serve(ln); e != nil && e != http.ErrServerClosed {
		panic(e)
	}
}

func existingSession() string {
	b, e := os.ReadFile(filepath.Join(homeDir(), "session.json"))
	if e != nil {
		return ""
	}
	var s struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(b, &s) != nil {
		return ""
	}
	u, e := url.Parse(s.URL)
	if e != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || len(u.Fragment) != 64 {
		return ""
	}
	token := u.Fragment
	u.Fragment = ""
	u.Path = "/api/ping"
	req, e := http.NewRequest("GET", u.String(), nil)
	if e != nil {
		return ""
	}
	req.Header.Set("X-Locklane-Token", token)
	client := &http.Client{Timeout: time.Second}
	res, e := client.Do(req)
	if e != nil {
		return ""
	}
	defer res.Body.Close()
	if res.StatusCode == 200 {
		return s.URL
	}
	return ""
}
