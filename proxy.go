package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type ProxyNode struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Protocol string         `json:"protocol"`
	Core     string         `json:"-"`
	Outbound map[string]any `json:"-"`
	ServerIP string         `json:"-"`
}
type ProxySecret struct {
	Core     string         `json:"core"`
	Outbound map[string]any `json:"outbound"`
	ServerIP string         `json:"server_ip"`
}

func decode64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, e := enc.DecodeString(s); e == nil {
			return b, nil
		}
	}
	return nil, errors.New("invalid base64")
}
func publicIP(ip net.IP) bool {
	if ip == nil || ip.To4() == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	_, cgn, _ := net.ParseCIDR("100.64.0.0/10")
	return !cgn.Contains(ip)
}
func publicHost(ctx context.Context, host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !publicIP(ip) {
			return "", errors.New("Адрес сервера должен быть публичным IPv4")
		}
		return ip.String(), nil
	}
	ips, e := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if e != nil {
		return "", errors.New("Не удалось разрешить адрес сервера")
	}
	for _, ip := range ips {
		if publicIP(ip) {
			return ip.String(), nil
		}
	}
	return "", errors.New("У сервера нет доступного публичного IPv4")
}
func fetchSubscription(source string) (string, error) {
	u, e := url.Parse(source)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" {
		return "", errors.New("Нужна обычная HTTPS-подписка без логина в адресе")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tr := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		h, p, e := net.SplitHostPort(addr)
		if e != nil {
			return nil, e
		}
		ip, e := publicHost(ctx, h)
		if e != nil {
			return nil, e
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp4", net.JoinHostPort(ip, p))
	}}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 4 || req.URL.Scheme != "https" || req.URL.User != nil {
			return errors.New("redirect rejected")
		}
		return nil
	}}
	req, _ := http.NewRequestWithContext(ctx, "GET", source, nil)
	req.Header.Set("User-Agent", "LOCKLANE/"+version)
	req.Header.Set("Accept", "text/plain, application/octet-stream")
	res, e := cl.Do(req)
	if e != nil {
		return "", errors.New("Не удалось загрузить подписку напрямую у провайдера. Проверь ссылку или вставь отдельный ключ")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return "", fmt.Errorf("Провайдер вернул HTTP %d. Нужен стандартный экспорт или отдельный ключ", res.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, 2*1024*1024+1))
	if e != nil || len(b) > 2*1024*1024 {
		return "", errors.New("Подписка слишком большая")
	}
	return string(b), nil
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func parseProxyLink(raw string, resolve bool) (ProxyNode, error) {
	var node ProxyNode
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "vmess://") {
		b, e := decode64(strings.TrimPrefix(raw, "vmess://"))
		if e != nil {
			return node, errors.New("Некорректный VMess ключ")
		}
		var m map[string]any
		if json.Unmarshal(b, &m) != nil {
			return node, errors.New("Некорректный VMess JSON")
		}
		str := func(k string) string {
			if x, ok := m[k]; ok {
				return fmt.Sprint(x)
			}
			return ""
		}
		host := str("add")
		port := str("port")
		user := str("id")
		if !uuidPattern.MatchString(user) {
			return node, errors.New("Некорректный VMess UUID")
		}
		u := &url.URL{Scheme: "vmess", Host: net.JoinHostPort(host, port), User: url.User(user), Fragment: str("ps")}
		q := url.Values{}
		q.Set("type", str("net"))
		q.Set("host", str("host"))
		q.Set("path", str("path"))
		q.Set("sni", str("sni"))
		q.Set("serviceName", str("path"))
		if str("tls") == "tls" {
			q.Set("security", "tls")
		}
		q.Set("scy", str("scy"))
		q.Set("aid", str("aid"))
		if str("allowInsecure") == "true" || str("allowInsecure") == "1" {
			q.Set("allowInsecure", "1")
		}
		u.RawQuery = q.Encode()
		raw = u.String()
	}
	if strings.HasPrefix(raw, "ss://") {
		rest := strings.TrimPrefix(raw, "ss://")
		parts := strings.SplitN(rest, "#", 2)
		rest = parts[0]
		if !strings.Contains(rest, "@") {
			b, e := decode64(strings.TrimSuffix(rest, "/"))
			if e != nil {
				return node, errors.New("Некорректный Shadowsocks ключ")
			}
			rest = string(b)
		}
		at := strings.LastIndex(rest, "@")
		if at < 0 {
			return node, errors.New("В Shadowsocks нет сервера")
		}
		credentials := rest[:at]
		if !strings.Contains(credentials, ":") {
			b, e := decode64(credentials)
			if e != nil {
				return node, errors.New("Некорректный Shadowsocks пароль")
			}
			credentials = string(b)
		}
		pair := strings.SplitN(credentials, ":", 2)
		if len(pair) != 2 {
			return node, errors.New("Некорректные Shadowsocks параметры")
		}
		raw = "ss://" + url.UserPassword(pair[0], pair[1]).String() + "@" + rest[at+1:]
		if len(parts) == 2 {
			raw += "#" + parts[1]
		}
	}
	u, e := url.Parse(raw)
	if e != nil || u.Hostname() == "" || u.User == nil {
		return node, errors.New("Не удалось распознать ключ подключения")
	}
	scheme := strings.ToLower(u.Scheme)
	port, e := strconv.Atoi(u.Port())
	if e != nil || port < 1 || port > 65535 {
		return node, errors.New("Укажи порт сервера в ключе")
	}
	q := u.Query()
	for _, k := range []string{"allowInsecure", "insecure", "skip-cert-verify"} {
		if q.Get(k) == "1" || q.Get(k) == "true" {
			return node, errors.New("Профиль отключает проверку TLS. Для этой версии нужен профиль с проверкой сертификата")
		}
	}
	host := u.Hostname()
	ip := host
	if resolve {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		ip, e = publicHost(ctx, host)
		if e != nil {
			return node, e
		}
	}
	node.ServerIP = ip
	node.Name = u.Fragment
	if node.Name == "" {
		node.Name = host
	}
	if len(node.Name) > 120 {
		node.Name = node.Name[:120]
	}
	node.Protocol = scheme
	node.Core = "xray"
	user := u.User.Username()
	password, hasPass := u.User.Password()
	if hasPass && scheme != "ss" && scheme != "socks" && scheme != "socks5" {
		user += " : " + password
		user = strings.Replace(user, " : ", ":", 1)
	}
	transport := q.Get("type")
	if transport == "" || transport == "tcp" {
		transport = "raw"
	}
	stream := map[string]any{"network": transport, "sockopt": map[string]any{"interface": "eth0"}}
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}
	if sni == "" {
		sni = host
	}
	security := q.Get("security")
	if scheme == "trojan" && security == "" {
		security = "tls"
	}
	if security == "tls" {
		tls := map[string]any{"serverName": sni, "allowInsecure": false}
		if a := q.Get("alpn"); a != "" {
			tls["alpn"] = strings.Split(a, ",")
		}
		if fp := q.Get("fp"); fp != "" {
			tls["fingerprint"] = fp
		}
		stream["security"] = "tls"
		stream["tlsSettings"] = tls
	} else if security == "reality" {
		if q.Get("pbk") == "" {
			return node, errors.New("Reality public key отсутствует")
		}
		stream["security"] = "reality"
		stream["realitySettings"] = map[string]any{"serverName": sni, "fingerprint": value(q.Get("fp"), "chrome"), "publicKey": q.Get("pbk"), "shortId": q.Get("sid"), "spiderX": q.Get("spx")}
	} else if security != "" && security != "none" {
		return node, errors.New("Этот тип безопасности ещё не поддерживается")
	}
	switch transport {
	case "raw":
		if q.Get("headerType") != "" && q.Get("headerType") != "none" {
			return node, errors.New("TCP header camouflage пока не поддерживается")
		}
	case "ws":
		w := map[string]any{"path": value(q.Get("path"), "/")}
		if h := q.Get("host"); h != "" {
			w["headers"] = map[string]string{"Host": h}
		}
		stream["wsSettings"] = w
	case "grpc":
		stream["grpcSettings"] = map[string]any{"serviceName": q.Get("serviceName"), "authority": q.Get("authority"), "multiMode": q.Get("mode") == "multi"}
	case "xhttp":
		x := map[string]any{"path": value(q.Get("path"), "/"), "host": q.Get("host"), "mode": value(q.Get("mode"), "auto")}
		if q.Get("extra") != "" {
			return node, errors.New("XHTTP extra требует отдельной проверки; запроси обычный экспорт без extra")
		}
		stream["xhttpSettings"] = x
	case "httpupgrade":
		stream["httpupgradeSettings"] = map[string]any{"host": q.Get("host"), "path": value(q.Get("path"), "/")}
	default:
		return node, fmt.Errorf("Транспорт %s пока не поддерживается", transport)
	}
	out := map[string]any{"tag": "proxy", "streamSettings": stream}
	switch scheme {
	case "vless", "vmess":
		if !uuidPattern.MatchString(user) {
			return node, errors.New("Некорректный UUID")
		}
		who := map[string]any{"id": user}
		if scheme == "vless" {
			who["encryption"] = "none"
			if f := q.Get("flow"); f != "" {
				if f != "xtls-rprx-vision" {
					return node, errors.New("Flow пока не поддерживается")
				}
				who["flow"] = f
			}
			if enc := q.Get("encryption"); enc != "" && enc != "none" {
				return node, errors.New("VLESS Encryption пока не поддерживается; используй экспорт Reality/TLS")
			}
		} else {
			who["security"] = value(q.Get("scy"), "auto")
			aid, _ := strconv.Atoi(q.Get("aid"))
			who["alterId"] = aid
		}
		out["protocol"] = scheme
		out["settings"] = map[string]any{"vnext": []any{map[string]any{"address": ip, "port": port, "users": []any{who}}}}
	case "trojan":
		out["protocol"] = "trojan"
		out["settings"] = map[string]any{"servers": []any{map[string]any{"address": ip, "port": port, "password": user}}}
	case "ss":
		if q.Get("plugin") != "" {
			return node, errors.New("Shadowsocks plugins пока не поддерживаются")
		}
		method := u.User.Username()
		pass, _ := u.User.Password()
		out["protocol"] = "shadowsocks"
		out["settings"] = map[string]any{"servers": []any{map[string]any{"address": ip, "port": port, "method": method, "password": pass}}}
		node.Protocol = "Shadowsocks"
	case "socks", "socks5":
		out["protocol"] = "socks"
		server := map[string]any{"address": ip, "port": port}
		if user != "" {
			server["users"] = []any{map[string]string{"user": u.User.Username(), "pass": password}}
		}
		out["settings"] = map[string]any{"servers": []any{server}}
		node.Protocol = "SOCKS5"
	case "hy2", "hysteria2", "tuic":
		node.Core = "singbox"
		typ := "hysteria2"
		if scheme == "tuic" {
			typ = "tuic"
		}
		out = map[string]any{"type": typ, "tag": "proxy", "server": ip, "server_port": port, "bind_interface": "eth0", "tls": map[string]any{"enabled": true, "server_name": sni, "insecure": false}}
		if typ == "hysteria2" {
			out["password"] = user
			if q.Get("obfs") != "" {
				if q.Get("obfs") != "salamander" {
					return node, errors.New("Hysteria2 obfs не поддерживается")
				}
				out["obfs"] = map[string]string{"type": "salamander", "password": q.Get("obfs-password")}
			}
		} else {
			if !uuidPattern.MatchString(u.User.Username()) || !hasPass {
				return node, errors.New("TUIC требует UUID и пароль")
			}
			out["uuid"] = u.User.Username()
			out["password"] = password
			out["congestion_control"] = value(q.Get("congestion_control"), "cubic")
		}
		node.Protocol = strings.ToUpper(typ)
	default:
		return node, errors.New("Поддерживаются VLESS/Reality, VMess, Trojan, Shadowsocks, Hysteria2, TUIC и SOCKS5")
	}
	node.Outbound = out
	return node, nil
}
func value(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
func importNodes(source string, resolve bool) ([]ProxyNode, []string, error) {
	source = strings.TrimSpace(strings.TrimPrefix(source, "\ufeff"))
	if strings.HasPrefix(source, "happ://crypto") {
		return nil, nil, errors.New("Это закрытая Happ crypto-подписка. Нужен обычный HTTPS URL или экспорт отдельного vless:// ключа от провайдера; LOCKLANE не отправляет ссылку сторонним конвертерам")
	}
	if strings.HasPrefix(source, "happ://add/") {
		source = strings.TrimPrefix(source, "happ://add/")
	}
	if strings.HasPrefix(source, "happ://") {
		return nil, nil, errors.New("Нужен исходный ключ или обычная HTTPS-подписка, не закрытая ссылка приложения")
	}
	if strings.HasPrefix(source, "https://") {
		var e error
		source, e = fetchSubscription(source)
		if e != nil {
			return nil, nil, e
		}
	}
	if !strings.Contains(source, "://") {
		if b, e := decode64(source); e == nil {
			source = string(b)
		}
	}
	var nodes []ProxyNode
	var skipped []string
	for _, ln := range strings.Split(strings.ReplaceAll(source, "\r", ""), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if len(nodes) >= 300 {
			return nil, nil, errors.New("В подписке больше 300 серверов; выбери отдельный ключ")
		}
		n, e := parseProxyLink(ln, resolve)
		if e != nil {
			if len(skipped) < 8 {
				skipped = append(skipped, e.Error())
			}
			continue
		}
		n.ID = strconv.Itoa(len(nodes))
		nodes = append(nodes, n)
	}
	if len(nodes) == 0 {
		msg := "Не найдено поддерживаемых серверов. Нужны обычные ключи или base64-список, не страница сайта и не Clash/Xray JSON"
		if len(skipped) > 0 {
			msg += ". " + skipped[0]
		}
		return nil, skipped, errors.New(msg)
	}
	return nodes, skipped, nil
}

func resolveNode(n ProxyNode) (ProxyNode, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	ip, e := publicHost(ctx, n.ServerIP)
	if e != nil {
		return n, e
	}
	b, _ := json.Marshal(n.Outbound)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	n.Outbound = out
	n.ServerIP = ip
	if n.Core == "singbox" {
		out["server"] = ip
	} else {
		settings := out["settings"].(map[string]any)
		for _, k := range []string{"servers", "vnext"} {
			if list, ok := settings[k].([]any); ok && len(list) > 0 {
				list[0].(map[string]any)["address"] = ip
			}
		}
	}
	return n, nil
}
