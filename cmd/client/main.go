package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"flag"

	"github.com/nyarime/nrup"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Server   string `yaml:"server"`
	Password string `yaml:"password"`
	Disguise string `yaml:"disguise"`
	SNI      string `yaml:"sni"`

	Proxy struct {
		Listen string `yaml:"listen"`
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
	sessionID atomic.Value
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
	if config.Proxy.Listen == "" {
		config.Proxy.Listen = "127.0.0.1:1080"
	}

	log.Printf("NekoPass Lite → %s (伪装: %s)", config.Server, config.Disguise)
	initRules(config.Rules)

	if config.TUN.Enable {
		go startTUN()
	}

	// 单端口监听：自动识别 SOCKS5 / HTTP
	ln, err := net.Listen("tcp", config.Proxy.Listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("代理监听 %s (HTTP/HTTPS/SOCKS5 自动识别)", config.Proxy.Listen)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleMixed(conn)
	}
}

// handleMixed 自动识别 SOCKS5 / HTTP 协议
func handleMixed(conn net.Conn) {
	defer conn.Close()

	// 偷看第一个字节
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	// SOCKS5: 首字节 0x05
	if buf[0] == 0x05 {
		handleSOCKS5(conn, buf[0])
		return
	}

	// HTTP: 首字节是字母 (GET/POST/CONNECT/...)
	handleHTTPConn(conn, buf[0])
}

// === SOCKS5 ===

func handleSOCKS5(conn net.Conn, firstByte byte) {
	buf := make([]byte, 256)

	// 已读第一个字节(0x05)，读剩余认证协商
	n, err := conn.Read(buf)
	if err != nil || n < 1 {
		return
	}
	conn.Write([]byte{0x05, 0x00}) // 无需认证

	// 读请求
	n, err = conn.Read(buf)
	if err != nil || n < 7 {
		return
	}

	cmd := buf[1]
	if cmd == 0x03 {
		// UDP ASSOCIATE
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	if cmd != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	target := parseSOCKS5Addr(buf[:n])
	if target == "" {
		return
	}

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	if !shouldProxy(target) {
		directRelay(conn, target)
	} else {
		proxyTo(target, conn)
	}
}

func parseSOCKS5Addr(buf []byte) string {
	if len(buf) < 7 {
		return ""
	}
	switch buf[3] {
	case 0x01: // IPv4
		if len(buf) < 10 { return "" }
		return fmt.Sprintf("%d.%d.%d.%d:%d", buf[4], buf[5], buf[6], buf[7],
			int(buf[8])<<8|int(buf[9]))
	case 0x03: // Domain
		dLen := int(buf[4])
		if len(buf) < 5+dLen+2 { return "" }
		return fmt.Sprintf("%s:%d", string(buf[5:5+dLen]),
			int(buf[5+dLen])<<8|int(buf[6+dLen]))
	case 0x04: // IPv6
		if len(buf) < 22 { return "" }
		return fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]:%d",
			int(buf[4])<<8|int(buf[5]), int(buf[6])<<8|int(buf[7]),
			int(buf[8])<<8|int(buf[9]), int(buf[10])<<8|int(buf[11]),
			int(buf[12])<<8|int(buf[13]), int(buf[14])<<8|int(buf[15]),
			int(buf[16])<<8|int(buf[17]), int(buf[18])<<8|int(buf[19]),
			int(buf[20])<<8|int(buf[21]))
	}
	return ""
}

// === HTTP/HTTPS ===

func handleHTTPConn(conn net.Conn, firstByte byte) {
	// 拼回完整的第一行
	br := bufio.NewReader(io.MultiReader(strings.NewReader(string(firstByte)), conn))
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}

	parts := strings.Fields(line)
	if len(parts) < 3 {
		return
	}

	method := parts[0]

	if method == "CONNECT" {
		// HTTPS: CONNECT host:port HTTP/1.1
		target := parts[1]
		if !strings.Contains(target, ":") {
			target += ":443"
		}

		// 读完header
		for {
			l, err := br.ReadString('\n')
			if err != nil || l == "\r\n" || l == "\n" {
				break
			}
		}

		if !shouldProxy(target) {
			conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
			directRelay(conn, target)
		} else {
			conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
			proxyTo(target, conn)
		}
		return
	}

	// HTTP: GET http://host/path HTTP/1.1
	// 简单处理：提取host，转发
	target := ""
	for {
		l, err := br.ReadString('\n')
		if err != nil || l == "\r\n" || l == "\n" {
			break
		}
		if strings.HasPrefix(strings.ToLower(l), "host:") {
			target = strings.TrimSpace(l[5:])
		}
	}
	if target == "" {
		return
	}
	if !strings.Contains(target, ":") {
		target += ":80"
	}

	if !shouldProxy(target) {
		remote, err := net.Dial("tcp", target)
		if err != nil {
			return
		}
		defer remote.Close()
		remote.Write([]byte(line))
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); io.Copy(remote, conn) }()
		go func() { defer wg.Done(); io.Copy(conn, remote) }()
		wg.Wait()
	} else {
		remote, err := dialNRUP()
		if err != nil {
			return
		}
		defer remote.Close()
		remote.Write([]byte(target))
		ack := make([]byte, 1)
		if _, err := remote.Read(ack); err != nil || ack[0] != 0x01 {
			return
		}
		remote.Write([]byte(line))
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); io.Copy(remote, conn) }()
		go func() { defer wg.Done(); io.Copy(conn, remote) }()
		wg.Wait()
	}
}

// === NRUP 连接 ===

func dialNRUP() (*nrup.Conn, error) {
	cfg := nrup.DefaultConfig()
	cfg.PSK = deriveKey(config.Password)
	cfg.Disguise = config.Disguise
	cfg.DisguiseSNI = config.SNI

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

func directRelay(local net.Conn, target string) {
	remote, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer remote.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(remote, local) }()
	go func() { defer wg.Done(); io.Copy(local, remote) }()
	wg.Wait()
}

// === 规则引擎 ===

type Rule struct {
	Type, Value, Action string
}

var rules []Rule

func initRules(raw []string) {
	for _, line := range raw {
		parts := strings.SplitN(line, ",", 3)
		if len(parts) == 3 {
			rules = append(rules, Rule{parts[0], parts[1], parts[2]})
		} else if len(parts) == 2 {
			rules = append(rules, Rule{Type: parts[0], Action: parts[1]})
		}
	}
	if len(rules) == 0 {
		rules = []Rule{
			{"GEOIP", "CN", "DIRECT"},
			{"MATCH", "", "PROXY"},
		}
	}
	log.Printf("加载 %d 条分流规则", len(rules))
}

func shouldProxy(host string) bool {
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
				if _, cidr, err := net.ParseCIDR(r.Value); err == nil && cidr.Contains(ip) {
					return r.Action == "PROXY"
				}
			}
		case "GEOIP":
			if r.Value == "CN" {
				ip := net.ParseIP(domain)
				if ip == nil {
					if addrs, err := net.LookupHost(domain); err == nil && len(addrs) > 0 {
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
	return true
}

func isChinaIP(ip net.IP) bool {
	for _, cidr := range []string{
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
	} {
		if _, n, _ := net.ParseCIDR(cidr); n != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// === TUN ===

func startTUN() {
	log.Printf("TUN 模式暂不支持当前平台")
}

// === 工具 ===

func deriveKey(password string) []byte {
	h := sha256.Sum256([]byte("nekopass-lite:" + password))
	return h[:]
}
