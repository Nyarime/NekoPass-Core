package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/nyarime/nrup"
)

func main() {
	listen := flag.String("listen", ":443", "监听地址")
	password := flag.String("password", "", "连接密码")
	disguise := flag.String("disguise", "anyconnect", "伪装模式 (anyconnect/quic)")
	sni := flag.String("sni", "", "QUIC 模式 SNI")
	portal := flag.String("portal", ":8443", "AnyConnect Portal HTTPS 监听 (留空禁用)")
	portalTitle := flag.String("portal-title", "HKU VPN Service", "Portal 页面标题")
	flag.Parse()

	if *password == "" {
		log.Fatal("请指定 -password")
	}

	// AnyConnect Portal 回落页面
	if *portal != "" {
		go startPortal(*portal, *portalTitle)
	}

	cfg := nrup.DefaultConfig()
	cfg.PSK = deriveKey(*password)
	cfg.Disguise = *disguise
	cfg.DisguiseSNI = *sni

	listener, err := nrup.Listen(*listen, cfg)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("NekoPass Lite Server 监听 %s (UDP: NRUP | TCP: TLS)", *listen)
	if *portal != "" {
		log.Printf("AnyConnect Portal 监听 %s", *portal)
	}

	// TCP TLS 监听（同端口）
	go startTCPListener(*listen, deriveKey(*password))

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return
	}

	target := string(buf[:n])
	remote, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("连接 %s 失败: %v", target, err)
		return
	}
	defer remote.Close()

	conn.Write([]byte{0x01})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(remote, conn) }()
	go func() { defer wg.Done(); io.Copy(conn, remote) }()
	wg.Wait()
}

// startPortal 启动 AnyConnect Portal 回落页面
// 当 DPI 或浏览器直接访问时，返回 Cisco ASA 风格的 SSL VPN 登录页
func startPortal(addr, title string) {
	mux := http.NewServeMux()

	// Cisco ASA AnyConnect Portal 页面
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Cisco ASA SSL VPN")
		w.Header().Set("X-Powered-By", "Cisco Systems, Inc.")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, portalHTML, title, title, title)
	})

	// AnyConnect 客户端探测端点
	mux.HandleFunc("/+CSCOE+/logon.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Cisco ASA SSL VPN")
		fmt.Fprintf(w, portalHTML, title, title, title)
	})

	// AnyConnect XML profile
	mux.HandleFunc("/+CSCOT+/tunnel-group-list.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Cisco ASA SSL VPN")
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprintf(w, tunnelGroupXML, title)
	})

	// CONNECT 端点（Cisco AnyConnect 风格）
	mux.HandleFunc("/CSCOSSLC/tunnel", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "SSL VPN session required", 403)
	})

	log.Fatal(http.ListenAndServe(addr, mux))
}

const portalHTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>%s - SSL VPN Portal</title>
<style>
body { font-family: -apple-system, "Segoe UI", Arial, sans-serif; margin: 0; background: #f5f5f5; }
.header { background: linear-gradient(135deg, #1a5276 0%%%%, #2980b9 100%%%%); padding: 15px 30px; color: white; display: flex; align-items: center; }
.header h1 { margin: 0; font-size: 18px; font-weight: normal; }
.container { max-width: 420px; margin: 60px auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,.1); overflow: hidden; }
.form-header { background: #2c3e50; color: white; padding: 20px; text-align: center; }
.form-header h2 { margin: 0 0 5px 0; font-size: 16px; }
.form-header .subtitle { font-size: 12px; color: #bbb; }
.welcome { padding: 15px 25px; background: #eaf2f8; border-bottom: 1px solid #d4e6f1; font-size: 15px; color: #1a5276; font-weight: 600; }
.mfa-note { padding: 12px 25px; font-size: 12px; color: #666; line-height: 1.5; border-bottom: 1px solid #eee; }
.form-body { padding: 20px 25px; }
.form-group { margin-bottom: 12px; }
.form-group label { display: block; margin-bottom: 4px; color: #555; font-size: 12px; font-weight: 600; text-transform: uppercase; }
.form-group input, .form-group select { width: 100%%%%; padding: 8px 10px; border: 1px solid #ccc; border-radius: 3px; font-size: 14px; box-sizing: border-box; }
.form-group input:focus { border-color: #2980b9; outline: none; box-shadow: 0 0 3px rgba(41,128,185,.3); }
.btn { width: 100%%%%; padding: 10px; background: #2980b9; color: white; border: none; border-radius: 3px; font-size: 14px; cursor: pointer; margin-top: 5px; }
.btn:hover { background: #1a6fa0; }
.footer { text-align: center; padding: 12px; color: #aaa; font-size: 10px; border-top: 1px solid #eee; }
</style>
</head>
<body>
<div class="header"><h1>%s</h1></div>
<div class="container">
<div class="form-header"><h2>MFA Login</h2><div class="subtitle">Multi-Factor Authentication</div></div>
<div class="welcome">Welcome to the %s</div>
<div class="mfa-note">Please enter your email address (either uid@hku.hk or uid@connect.hku.hk) in the Username field and your Portal PIN in the Password field.<br>Then, enter the Microsoft MFA one-time password (OTP) when prompted.</div>
<div class="form-body">
<form>
<div class="form-group">
<label>USERNAME:</label>
<input type="text" placeholder="uid@hku.hk">
</div>
<div class="form-group">
<label>PASSWORD:</label>
<input type="password" placeholder="Portal PIN">
</div>
<button type="button" class="btn" onclick="alert('Please use AnyConnect client to connect.')">Login</button>
</form>
</div>
<div class="footer">Powered by Cisco ASA SSL VPN</div>
</div>
</body>
</html>`

const tunnelGroupXML = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request">
  <version who="sg">9.16(4)48</version>
  <tunnel-group-list>
    <tunnel-group>
      <group-name>%s</group-name>
      <group-policy>DefaultWEBVPNGroup</group-policy>
    </tunnel-group>
  </tunnel-group-list>
</config-auth>`

func deriveKey(password string) []byte {
	h := sha256.Sum256([]byte("nekopass-lite:" + password))
	return h[:]
}

// startTCPListener TCP TLS 监听（UDP被封时的备用通道）
func startTCPListener(addr string, psk []byte) {
	// 自签名证书（生产环境建议用ACME）
	cert, err := tls.X509KeyPair(selfSignedCert())
	if err != nil {
		log.Printf("[TCP] 证书生成失败: %v", err)
		return
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		// 端口可能被UDP占了，换一个
		// TCP用+1端口
		host, port, _ := net.SplitHostPort(addr)
		p := 0
		fmt.Sscanf(port, "%d", &p)
		addr2 := fmt.Sprintf("%s:%d", host, p+1)
		ln, err = tls.Listen("tcp", addr2, tlsCfg)
		if err != nil {
			log.Printf("[TCP] 监听失败: %v", err)
			return
		}
		log.Printf("[TCP] TLS 监听 %s", addr2)
	} else {
		log.Printf("[TCP] TLS 监听 %s", addr)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleTCPConn(conn, psk)
	}
}

func handleTCPConn(conn net.Conn, psk []byte) {
	defer conn.Close()

	// 简单PSK验证：客户端发32字节PSK hash
	authBuf := make([]byte, 32)
	if _, err := io.ReadFull(conn, authBuf); err != nil {
		return
	}

	// 验证
	expected := sha256.Sum256(psk)
	match := true
	for i := range authBuf {
		if authBuf[i] != expected[i] {
			match = false
		}
	}
	if !match {
		return
	}
	conn.Write([]byte{0x01}) // 认证成功

	// 后续跟UDP模式相同：读目标地址 → 转发
	handleConn(conn)
}

// selfSignedCert 生成自签名证书（开发/临时用）
func selfSignedCert() ([]byte, []byte) {

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "vpn2fa.hku.hk"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{"vpn2fa.hku.hk"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	keyDER, _ := x509.MarshalECPrivateKey(key)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}
