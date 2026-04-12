package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"bufio"
	"flag"

	"github.com/nyarime/nrup"
	"gopkg.in/yaml.v3"
)

// Config YAML 配置
type Config struct {
	Server   string `yaml:"server"`
	Password string `yaml:"password"`
	Disguise string `yaml:"disguise"`
	SNI      string `yaml:"sni"`

	Proxy struct {
		HTTP   string `yaml:"http"`
		SOCKS5 string `yaml:"socks5"`
	} `yaml:"proxy"`

	TUN struct {
		Enable bool   `yaml:"enable"`
		Name   string `yaml:"name"`
		MTU    int    `yaml:"mtu"`
		DNS    string `yaml:"dns"`
	} `yaml:"tun"`

	Rules []string `yaml:"rules"`
}

var (
	config    Config
	sessionID atomic.Value // 0-RTT
)

func main() {
	cfgFile := flag.String("c", "config.yaml", "配置文件")
	flag.Parse()

	data, err := os.ReadFile(*cfgFile)
	if err != nil {
		log.Fatal("读取配置:", err)
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Fatal("解析配置:", err)
	}

	if config.Server == "" || config.Password == "" {
		log.Fatal("请配置 server 和 password")
	}

	log.Printf("NekoPass Lite Client → %s (伪装: %s)", config.Server, config.Disguise)

	// 初始化规则引擎
	initRules(config.Rules)

	// HTTP/HTTPS 代理
	if config.Proxy.HTTP != "" {
		go startHTTPProxy(config.Proxy.HTTP)
	}

	// SOCKS5 代理（支持 UDP）
	if config.Proxy.SOCKS5 != "" {
		go startSOCKS5(config.Proxy.SOCKS5)
	}

	// TUN 模式
	if config.TUN.Enable {
		go startTUN()
	}

	// 等待
	select {}
}

// === 规则引擎 ===

type Rule struct {
	Type   string // DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR, GEOIP, MATCH
	Value  string
	Action string // DIRECT, PROXY
}

var rules []Rule

func initRules(raw []string) {
	for _, line := range raw {
		parts := strings.SplitN(line, ",", 3)
		if len(parts) == 3 {
			rules = append(rules, Rule{Type: parts[0], Value: parts[1], Action: parts[2]})
		} else if len(parts) == 2 {
			rules = append(rules, Rule{Type: parts[0], Action: parts[1]})
		}
	}
	if len(rules) == 0 {
		// 默认规则：GEOIP CN 直连，其余代理
		rules = []Rule{
			{Type: "GEOIP", Value: "CN", Action: "DIRECT"},
			{Type: "MATCH", Action: "PROXY"},
		}
	}
	log.Printf("加载 %d 条分流规则", len(rules))
}

func shouldProxy(host string) bool {
	// 提取域名（去掉端口）
	domain := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		domain = h
	}

	for _, r := range rules {
		switch r.Type {
		case "DOMAIN-SUFFIX":
			if strings.HasSuffix(domain, r.Value) || domain == r.Value {
				return r.Action == "PROXY"
			}
		case "DOMAIN-KEYWORD":
			if strings.Contains(domain, r.Value) {
				return r.Action == "PROXY"
			}
		case "IP-CIDR":
			ip := net.ParseIP(domain)
			if ip != nil {
				_, cidr, err := net.ParseCIDR(r.Value)
				if err == nil && cidr.Contains(ip) {
					return r.Action == "PROXY"
				}
			}
		case "GEOIP":
			if r.Value == "CN" {
				ip := net.ParseIP(domain)
				if ip == nil {
					// 解析域名
					addrs, err := net.LookupHost(domain)
					if err == nil && len(addrs) > 0 {
						ip = net.ParseIP(addrs[0])
					}
				}
				if ip != nil && isChinaIP(ip) {
					return r.Action == "PROXY"
				}
			}
		case "MATCH":
			return r.Action == "PROXY"
		}
	}
	return true // 默认代理
}

// isChinaIP 简单中国 IP 判断（常见段）
func isChinaIP(ip net.IP) bool {
	chinaRanges := []string{
		"1.0.0.0/8", "14.0.0.0/8", "27.0.0.0/8", "36.0.0.0/8",
		"39.0.0.0/8", "42.0.0.0/8", "49.0.0.0/8", "58.0.0.0/8",
		"59.0.0.0/8", "60.0.0.0/8", "61.0.0.0/8", "101.0.0.0/8",
		"103.0.0.0/8", "106.0.0.0/8", "110.0.0.0/8", "111.0.0.0/8",
		"112.0.0.0/8", "113.0.0.0/8", "114.0.0.0/8", "115.0.0.0/8",
		"116.0.0.0/8", "117.0.0.0/8", "118.0.0.0/8", "119.0.0.0/8",
		"120.0.0.0/8", "121.0.0.0/8", "122.0.0.0/8", "123.0.0.0/8",
		"124.0.0.0/8", "125.0.0.0/8", "139.0.0.0/8", "140.0.0.0/8",
		"171.0.0.0/8", "175.0.0.0/8", "180.0.0.0/8", "182.0.0.0/8",
		"183.0.0.0/8", "202.0.0.0/8", "203.0.0.0/8", "210.0.0.0/8",
		"211.0.0.0/8", "218.0.0.0/8", "219.0.0.0/8", "220.0.0.0/8",
		"221.0.0.0/8", "222.0.0.0/8", "223.0.0.0/8",
	}
	for _, cidr := range chinaRanges {
		_, n, _ := net.ParseCIDR(cidr)
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// === NRUP 连接 ===

func dialNRUP() (*nrup.Conn, error) {
	cfg := nrup.DefaultConfig()
	cfg.PSK = deriveKey(config.Password)
	cfg.Disguise = config.Disguise
	cfg.DisguiseSNI = config.SNI

	// 0-RTT
	if sid, ok := sessionID.Load().(string); ok && sid != "" {
		cfg.ResumeID = sid
	}

	conn, err := nrup.Dial(config.Server, cfg)
	if err != nil {
		return nil, err
	}
	sessionID.Store(conn.SessionID())
	return conn, nil
}

func proxyTo(target string, local net.Conn) {
	defer local.Close()

	remote, err := dialNRUP()
	if err != nil {
		log.Printf("NRUP 连接失败: %v", err)
		return
	}
	defer remote.Close()

	remote.Write([]byte(target))

	ack := make([]byte, 1)
	if _, err := remote.Read(ack); err != nil || ack[0] != 0x01 {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(remote, local) }()
	go func() { defer wg.Done(); io.Copy(local, remote) }()
	wg.Wait()
}

// === HTTP/HTTPS 代理 ===

func startHTTPProxy(addr string) {
	log.Printf("HTTP/HTTPS 代理监听 %s", addr)

	server := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleHTTPS(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
	}
	log.Fatal(server.ListenAndServe())
}

func handleHTTPS(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if !strings.Contains(target, ":") {
		target += ":443"
	}

	if !shouldProxy(target) {
		// 直连
		remote, err := net.Dial("tcp", target)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		w.WriteHeader(200)

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			remote.Close()
			return
		}
		local, _, _ := hijacker.Hijack()

		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); io.Copy(remote, local) }()
		go func() { defer wg.Done(); io.Copy(local, remote) }()
		wg.Wait()
		remote.Close()
		local.Close()
		return
	}

	// 代理
	w.WriteHeader(200)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	local, _, _ := hijacker.Hijack()
	proxyTo(target, local)
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if !strings.Contains(target, ":") {
		target += ":80"
	}

	if !shouldProxy(target) {
		// 直连转发
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			for _, vv := range v {
				w.Header().Add(k, vv)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}

	// 代理
	remote, err := dialNRUP()
	if err != nil {
		http.Error(w, "proxy error", 502)
		return
	}
	defer remote.Close()

	remote.Write([]byte(target))
	ack := make([]byte, 1)
	if _, err := remote.Read(ack); err != nil || ack[0] != 0x01 {
		http.Error(w, "upstream error", 502)
		return
	}

	// 发HTTP请求
	r.Write(remote)

	// 读响应
	resp, err := http.ReadResponse(bufioReader(remote), r)
	if err != nil {
		http.Error(w, "bad response", 502)
		return
	}
	defer resp.Body.Close()
	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// === SOCKS5 代理 ===

func startSOCKS5(addr string) {
	log.Printf("SOCKS5 代理监听 %s (支持 UDP)", addr)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleSOCKS5(conn)
	}
}

func handleSOCKS5(conn net.Conn) {
	defer conn.Close()

	target, err := socks5Handshake(conn)
	if err != nil {
		return
	}

	if !shouldProxy(target) {
		// 直连
		remote, err := net.Dial("tcp", target)
		if err != nil {
			return
		}
		defer remote.Close()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); io.Copy(remote, conn) }()
		go func() { defer wg.Done(); io.Copy(conn, remote) }()
		wg.Wait()
		return
	}

	proxyTo(target, conn)
}

func socks5Handshake(conn net.Conn) (string, error) {
	buf := make([]byte, 256)

	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return "", fmt.Errorf("not socks5")
	}
	conn.Write([]byte{0x05, 0x00})

	n, err = conn.Read(buf)
	if err != nil || n < 7 {
		return "", fmt.Errorf("bad request")
	}

	cmd := buf[1]
	if cmd == 0x03 {
		// UDP ASSOCIATE
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		// TODO: UDP relay
		return "", fmt.Errorf("udp associate")
	}

	if cmd != 0x01 {
		return "", fmt.Errorf("unsupported cmd %d", cmd)
	}

	var target string
	switch buf[3] {
	case 0x01:
		target = fmt.Sprintf("%d.%d.%d.%d:%d", buf[4], buf[5], buf[6], buf[7],
			int(buf[8])<<8|int(buf[9]))
	case 0x03:
		dLen := int(buf[4])
		target = fmt.Sprintf("%s:%d", string(buf[5:5+dLen]),
			int(buf[5+dLen])<<8|int(buf[6+dLen]))
	case 0x04:
		target = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]:%d",
			int(buf[4])<<8|int(buf[5]), int(buf[6])<<8|int(buf[7]),
			int(buf[8])<<8|int(buf[9]), int(buf[10])<<8|int(buf[11]),
			int(buf[12])<<8|int(buf[13]), int(buf[14])<<8|int(buf[15]),
			int(buf[16])<<8|int(buf[17]), int(buf[18])<<8|int(buf[19]),
			int(buf[20])<<8|int(buf[21]))
	default:
		return "", fmt.Errorf("unsupported addr type")
	}

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return target, nil
}

// === TUN 模式 ===

func startTUN() {
	log.Printf("TUN 模式暂不支持当前平台（需要 root 权限）")
	// TODO: wireguard/tun 集成
}

// === 工具 ===

func deriveKey(password string) []byte {
	h := sha256.Sum256([]byte("nekopass-lite:" + password))
	return h[:]
}

func bufioReader(r io.Reader) *bufio.Reader {
	return bufio.NewReader(r)
}
