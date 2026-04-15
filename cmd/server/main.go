package main

import (
	"crypto/sha256"
	"crypto/tls"
	"flag"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"crypto/rand"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"github.com/xtaci/smux"
	"time"

	"github.com/nyarime/nrup"
	"github.com/nyarime/nrtp"
)

func main() {
	listen := flag.String("listen", ":443", "监听地址")
	password := flag.String("password", "", "连接密码")
	sni := flag.String("sni", "vpn.sjsu.edu", "QUIC 模式 SNI")
	portal := flag.String("portal", ":39444", "AnyConnect Portal HTTPS 监听 (留空禁用)")
	portalTitle := flag.String("portal-title", "Employee-SSO", "Portal 页面标题")
	flag.Parse()

	// stop子命令: 杀所有nekopass-server进程
	if len(os.Args) > 1 && os.Args[1] == "stop" {
		out, _ := exec.Command("pkill", "-f", "nekopass-server").CombinedOutput()
		_ = out
		fmt.Println("NekoPass Server 已停止")
		os.Exit(0)
	}

	if *password == "" {
		// 自动生成强密码
		randBytes := make([]byte, 32)
		rand.Read(randBytes)
		generated := fmt.Sprintf("%x", randBytes)
		password = &generated
		log.Printf("⚠️ 未指定密码，已自动生成: %s", generated)
		log.Printf("客户端请使用此密码连接")
	}

	// 获取远端证书
	var remoteCertDER []byte
	if *sni != "" {
		log.Printf("正在从 %s 获取远端证书...", *sni)
		// 获取证书用于TLS指纹
		addr := *sni
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = *sni + ":443"
		}
		host, _, _ := net.SplitHostPort(addr)
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 10 * time.Second},
			"tcp", addr,
			&tls.Config{ServerName: host, InsecureSkipVerify: true},
		)
		if err == nil {
			state := conn.ConnectionState()
			if len(state.PeerCertificates) > 0 {
				remoteCertDER = state.PeerCertificates[0].Raw
				log.Printf("✅ 证书获取成功: CN=%s", state.PeerCertificates[0].Subject.CommonName)
			}
			conn.Close()
		}
	}
	_ = remoteCertDER

	// AnyConnect Portal 回落页面
	if *portal != "" {
		go startPortal(*portal, *portalTitle)
	}

	cfg := nrup.DefaultConfig()
	cfg.PSK = deriveKey(*password)
	cfg.CertDER = remoteCertDER // nDTLS握手也用远端证书

	listener, err := nrup.Listen(*listen, cfg)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("NekoPass Lite Server 监听 %s (UDP: NRUP | TCP: TLS)", *listen)
	go serverPool.Preheat()
	go startCertRefresh(*sni, 24*time.Hour) // P4: 每24小时刷新证书
	if *portal != "" {
		log.Printf("AnyConnect Portal 监听 %s", *portal)
	}

	// TCP TLS 监听（同端口）
	go startNRTP(*listen, *password, *sni, nil)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		log.Printf("[MAIN] NRUP Accept: %T", conn); go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	defer func() { recover() }() // 防panic

	// 先读4字节判断是否MUX
	head := make([]byte, 4)
	n, err := io.ReadFull(conn, head)
	if err != nil || n < 3 {
		return
	}

	// MUX多路复用
	if string(head[:3]) == "MUX" {
		// P2: 下发session token (0x01 + 32字节hex token)
		token := nrtp.GenerateSessionToken()
		ack := make([]byte, 33)
		ack[0] = 0x01
		copy(ack[1:], []byte(token))
		conn.Write(ack)
		log.Printf("[Mux] Session token: %s", token[:8]+"...")
		handleMux(conn)
		return
	}

	// v1.5.0: 二进制协议(AnyConnect NRUP路径)
	if head[0] == 0x01 { // Protocol Version
		// 拼回已读的4字节+stream
		prefixed := io.MultiReader(bytes.NewReader(head[:n]), conn)
		network, addr, err := nrtp.ParseTargetFrame(prefixed)
		if err != nil { return }
		if network == "udp" {
			handleUDPForward(conn, addr)
			return
		}
		remote, err := serverPool.Get("tcp", addr)
		if err != nil { return }
		defer remote.Close()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); io.Copy(remote, conn) }()
		go func() { defer wg.Done(); io.Copy(conn, remote) }()
		wg.Wait()
		return
	}

	// 旧协议兼容: target\n
	rest := make([]byte, 252)
	m, err := conn.Read(rest); if err != nil || m <= 0 { return }
	target := strings.TrimRight(string(head[:n]) + string(rest[:m]), "\n")

	// UDP转发
	if len(target) > 4 && target[:4] == "UDP:" {
		handleUDPForward(conn, target[4:])
		return
	}

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
	// 选择模板: sjsu(默认) 或 hku
	tpl := "default"
	if title == "hku" || title == "HKU" {
		tpl = "hku"
	}
	tplDir := "templates/" + tpl

	mux := http.NewServeMux()

	// 首页: JS跳转(真实ASA行为)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Cisco ASA SSL VPN")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<html><script>
document.cookie = "tg=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure";
document.cookie = "sdesktop=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure";
document.location.replace("/+CSCOE+/logon.html");
</script></html>`)
	})

	serveFile := func(path, contentType string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// 真实ASA响应头
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-XSS-Protection", "1")
			w.Header().Set("Cross-Origin-Opener-Policy", "same-origin-allow-popups")
			w.Header().Set("X-XSS-Protection", "1")
			w.Header().Set("X-XSS-Protection", "1")
			w.Header().Set("Cross-Origin-Opener-Policy", "same-origin-allow-popups")
			w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:; frame-ancestors 'self'; base-uri 'self'; block-all-mixed-content")
			w.Header().Set("Cross-Origin-Opener-Policy", "same-origin-allow-popups")
			// Cisco cookies (真实ASA清理+设置)
			expired := "Thu, 01 Jan 1970 22:00:00 GMT"
			for _, name := range []string{"webvpn", "webvpnc", "webvpn_portal", "acSamlv2Token", "webvpn_as", "webvpnSharePoint", "samlPreauthSessionHash", "acSamlv2Error"} {
				w.Header().Add("Set-Cookie", name+"=; expires="+expired+"; path=/; secure")
			}
			w.Header().Add("Set-Cookie", "webvpnlogin=1; path=/; secure")
			if contentType != "" { w.Header().Set("Content-Type", contentType) }
			data, err := templates.ReadFile(tplDir + path)
			if err != nil { http.NotFound(w, r); return }
			w.Write(data)
		}
	}

	mux.HandleFunc("/+CSCOE+/logon.html", serveFile("/+CSCOE+/logon.html", "text/html; charset=utf-8"))
	mux.HandleFunc("/+CSCOE+/logon_custom.css", serveFile("/+CSCOE+/logon_custom.css", "text/css"))
	mux.HandleFunc("/+CSCOE+/win.js", serveFile("/+CSCOE+/win.js", "application/javascript"))
	mux.HandleFunc("/+CSCOE+/blank.html", serveFile("/+CSCOE+/blank.html", "text/html"))
	mux.HandleFunc("/+CSCOU+/csco_logo.gif", serveFile("/+CSCOU+/csco_logo.gif", "image/gif"))
	mux.HandleFunc("/+CSCOU+/portal.css", serveFile("/+CSCOU+/portal.css", "text/css"))
	mux.HandleFunc("/+CSCOU+/login-header-icon.jpg", serveFile("/+CSCOU+/login-header-icon.jpg", "image/jpeg"))
	mux.HandleFunc("/+CSCOU+/login-header-end.jpg", serveFile("/+CSCOU+/login-header-end.jpg", "image/jpeg"))
	mux.HandleFunc("/+CSCOU+/login-header-middle.jpg", serveFile("/+CSCOU+/login-header-middle.jpg", "image/jpeg"))
	mux.HandleFunc("/+CSCOU+/gradient.gif", serveFile("/+CSCOU+/gradient.gif", "image/gif"))
	mux.HandleFunc("/+CSCOE+/saml/sp/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Cisco ASA SSL VPN")
		http.Redirect(w, r, "/+CSCOE+/logon.html", http.StatusFound)
	})
	mux.HandleFunc("/CSCOSSLC/tunnel", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "SSL VPN session required", 403)
	})

	log.Fatal(http.ListenAndServe(addr, mux))
}

const portalHTML = `<!DOCTYPE html>
<html style="height:100%;width:100%;">
<head>
<title>SSL VPN Service</title>
<meta name="HandheldFriendly" content="true" />
<meta name="viewport" content="width=500,user-scalable=no" />
<script>
if(self != top) top.location.href="/+CSCOE+/logon.html";
if (typeof navigator === 'object' && 'serviceWorker' in navigator && typeof navigator.serviceWorker === 'object' && 'register' in navigator.serviceWorker) {
 navigator.serviceWorker.getRegistration('/').then(function(registration) {
 if (registration) { registration.unregister().then(function() { location.reload(); }); }
 });
}
function scrollToLogonForm() { document.location.hash = "form_title_text"; }
</script>
<style>
body { margin: 0; font-family: Arial, Helvetica, sans-serif; background: #fff; height: 100%; }
#header { background: #336699; padding: 6px 10px; }
#header img { height: 28px; vertical-align: middle; }
#content { width: 340px; margin: 30px auto; }
#form_title_text { font-size: 14px; font-weight: bold; color: #333; padding: 8px 0; border-bottom: 1px solid #ccc; margin-bottom: 12px; }
.login-label { font-size: 12px; color: #333; font-weight: bold; margin-bottom: 3px; display: block; }
.auth-msg { font-size: 11px; color: #666; margin: 8px 0 12px 0; }
select { width: 100%; padding: 4px; font-size: 13px; border: 1px solid #999; margin-bottom: 10px; }
input[type=text], input[type=password] { width: 100%; padding: 4px; font-size: 13px; border: 1px solid #999; margin-bottom: 8px; box-sizing: border-box; }
.login-btn { background: #336699; color: #fff; border: 1px solid #224466; padding: 4px 18px; font-size: 13px; cursor: pointer; }
.login-btn:hover { background: #224466; }
#footer { text-align: center; color: #999; font-size: 10px; margin-top: 20px; }
</style>
</head>
<body onload="scrollToLogonForm()">
<div id="header"><img src="/+CSCOU+/csco_logo.gif" alt=""></div>
<div id="content">
<div id="form_title_text">SSL VPN Service</div>
<form method="post" action="/+CSCOE+/logon.html">
<span class="login-label">Login</span>
<div class="auth-msg">You will be redirected to SAML Identity Provider for authentication</div>
<span class="login-label">GROUP:</span>
<select id="group_list" name="group_list">
<option value="employee-sso" selected>Employee-SSO</option>
<option value="student-lab">Student-Lab-Test</option>
<option value="student-sso">Student-SSO</option>
</select>
<br>
<input type="submit" class="login-btn" value="Login">
</form>
</div>
<div id="footer">Cisco Systems, Inc.</div>
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
func handleUDPForward(conn net.Conn, target string) {
	rAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return
	}

	udpConn, err := net.DialUDP("udp", nil, rAddr)
	if err != nil {
		log.Printf("[UDP] 连接 %s 失败: %v", target, err)
		return
	}
	defer udpConn.Close()

	conn.Write([]byte{0x01}) // 连接成功

	// 双向转发
	done := make(chan struct{}, 2)

	// client → target
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := conn.Read(buf)
			if err != nil { break }
			udpConn.Write(buf[:n])
		}
		done <- struct{}{}
	}()

	// target → client
	go func() {
		buf := make([]byte, 65536)
		for {
			udpConn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := udpConn.Read(buf)
			if err != nil { break }
			conn.Write(buf[:n])
		}
		done <- struct{}{}
	}()

	<-done
}


func chunkedCopy(dst, src net.Conn) {
	buf := make([]byte, 1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil { return }
		}
		if err != nil { return }
	}
}

// startNRTP 用NRTP库启动TCP通道
func startNRTP(addr, password, sni string, portalHandler http.Handler) {
	nrtpCfg := &nrtp.Config{
		Password: password,
		Mode:     "tls",
		SNI:      sni,
	}
	if sni != "" {
		nrtpCfg.Mode = "fake-tls"
	}
	// v1.5.3: 非法连接→本地Portal (embed模板)
	portalMux := buildPortalMux("default")
	nrtpCfg.FallbackCfg = &nrtp.Fallback{
		Mode:        "handler",
		HTTPHandler: portalMux,
	}

	listener, err := nrtp.Listen(addr, nrtpCfg)
	if err != nil {
		// 端口可能被UDP占了，用+1
		host, port, _ := net.SplitHostPort(addr)
		p := 0
		fmt.Sscanf(port, "%d", &p)
		addr2 := fmt.Sprintf("%s:%d", host, p+1)
		listener, err = nrtp.Listen(addr2, nrtpCfg)
		if err != nil {
			log.Printf("[NRTP] 监听失败: %v", err)
			return
		}
		log.Printf("[NRTP] TCP 监听 %s", addr2)
	} else {
		log.Printf("[NRTP] TCP 监听 %s", addr)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		log.Printf("[MAIN] NRUP Accept: %T", conn); go handleConn(conn)
	}
}

// handleMux 多路复用处理
func handleMux(conn net.Conn) {
	cfg := smux.DefaultConfig()
	cfg.MaxReceiveBuffer = 16 * 1024 * 1024
	cfg.KeepAliveInterval = 10 * time.Second
	cfg.KeepAliveTimeout = 60 * time.Second
	session, err := smux.Server(conn, cfg)
	if err != nil {
		log.Printf("[Mux] 创建session失败: %v", err)
		return
	}
	defer session.Close()
	log.Printf("[Mux] 新的多路复用连接")

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			return // session关闭
		}
		go handleStream(stream)
	}
}

func handleStream(stream net.Conn) {
	defer stream.Close()

	// v1.5.0: 0-RTT二进制帧
	network, addr, err := nrtp.ParseTargetFrame(stream)
	if err != nil { return }

	if network == "udp" {
		handleUDPForward(stream, addr)
		return
	}

	remote, err := serverPool.Get("tcp", addr)
	if err != nil { return }
	defer remote.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(remote, stream) }()
	go func() { defer wg.Done(); io.Copy(stream, remote) }()
	wg.Wait()
}

// === P3: AnyConnect XML认证接口 ===

const xmlAuthRequest = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<opaque is-for="sg">
<tunnel-group>%s</tunnel-group>
<group-alias>%s</group-alias>
<config-hash>%d</config-hash>
</opaque>
<auth id="main">
<title>Login</title>
<message>Please enter your username and password.</message>
<banner></banner>
<form>
<input type="text" name="username" label="Username:"></input>
<input type="password" name="password" label="Password:"></input>
<select name="group_list" label="GROUP:">
<option selected="true">%s</option>
</select>
</form>
</auth>
</config-auth>`

const xmlAuthComplete = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
<session-id>%s</session-id>
<session-token>%s</session-token>
<auth id="success">
<title>SSL VPN Service</title>
<message id="0">Login Successful.</message>
<banner>&lt;p&gt;Welcome to SSL VPN Service.&lt;/p&gt;</banner>
</auth>
<config client="vpn" type="private">
<vpn-base-config>
<server-cert-hash>%s</server-cert-hash>
</vpn-base-config>
<opaque is-for="vpn-client"></opaque>
</config>
</config-auth>`

func handleAnyConnectXML(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Header().Set("X-Transcend-Version", "1")
	w.Header().Set("X-Aggregate-Auth", "1")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	
	groupName := "DefaultWEBVPNGroup"
	configHash := time.Now().Unix()
	
	// 返回认证请求(模拟真实ASA)
	fmt.Fprintf(w, xmlAuthRequest, groupName, groupName, configHash, groupName)
}

// === P4: 证书动态刷新 ===

func startCertRefresh(sni string, interval time.Duration) {
	if sni == "" { return }
	
	for {
		time.Sleep(interval)
		
		addr := sni
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = sni + ":443"
		}
		host, _, _ := net.SplitHostPort(addr)
		
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 10 * time.Second},
			"tcp", addr,
			&tls.Config{ServerName: host, InsecureSkipVerify: true},
		)
		if err != nil {
			log.Printf("[CertRefresh] 获取失败: %v", err)
			continue
		}
		
		state := conn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			newCert := state.PeerCertificates[0].Raw
			log.Printf("[CertRefresh] ✅ 证书刷新: CN=%s (%d bytes)", 
				state.PeerCertificates[0].Subject.CommonName, len(newCert))
		}
		conn.Close()
	}
}

// buildPortalMux 构建Portal HTTP handler (embed模板)
func buildPortalMux(tpl string) http.Handler {
	tplDir := "templates/" + tpl
	mux := http.NewServeMux()

	serveFile := func(path, contentType string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-XSS-Protection", "1")
			w.Header().Set("Cross-Origin-Opener-Policy", "same-origin-allow-popups")
			w.Header().Set("X-XSS-Protection", "1")
			w.Header().Set("Cross-Origin-Opener-Policy", "same-origin-allow-popups")
			w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:; frame-ancestors 'self'; base-uri 'self'; block-all-mixed-content")
			expired := "Thu, 01 Jan 1970 22:00:00 GMT"
			for _, name := range []string{"webvpn", "webvpnc", "webvpn_portal", "acSamlv2Token", "webvpn_as", "webvpnSharePoint", "samlPreauthSessionHash", "acSamlv2Error"} {
				w.Header().Add("Set-Cookie", name+"=; expires="+expired+"; path=/; secure")
			}
			w.Header().Add("Set-Cookie", "webvpnlogin=1; path=/; secure")
			if contentType != "" { w.Header().Set("Content-Type", contentType) }
			data, err := templates.ReadFile(tplDir + path)
			if err != nil { http.NotFound(w, r); return }
			w.Write(data)
		}
	}

	// 首页JS跳转
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<html><script>
document.cookie = "tg=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure";
document.cookie = "sdesktop=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure";
document.location.replace("/+CSCOE+/logon.html");
</script></html>`)
	})

	mux.HandleFunc("/+CSCOE+/logon.html", serveFile("/+CSCOE+/logon.html", "text/html; charset=utf-8"))
	mux.HandleFunc("/+CSCOE+/logon_custom.css", serveFile("/+CSCOE+/logon_custom.css", "text/css"))
	mux.HandleFunc("/+CSCOE+/win.js", serveFile("/+CSCOE+/win.js", "application/javascript"))
	mux.HandleFunc("/+CSCOE+/blank.html", serveFile("/+CSCOE+/blank.html", "text/html"))
	mux.HandleFunc("/+CSCOU+/csco_logo.gif", serveFile("/+CSCOU+/csco_logo.gif", "image/gif"))
	mux.HandleFunc("/+CSCOU+/portal.css", serveFile("/+CSCOU+/portal.css", "text/css"))
	mux.HandleFunc("/+CSCOU+/login-header-icon.jpg", serveFile("/+CSCOU+/login-header-icon.jpg", "image/jpeg"))
	mux.HandleFunc("/+CSCOU+/login-header-end.jpg", serveFile("/+CSCOU+/login-header-end.jpg", "image/jpeg"))
	mux.HandleFunc("/+CSCOU+/login-header-middle.jpg", serveFile("/+CSCOU+/login-header-middle.jpg", "image/jpeg"))
	mux.HandleFunc("/+CSCOU+/gradient.gif", serveFile("/+CSCOU+/gradient.gif", "image/gif"))
	mux.HandleFunc("/+CSCOE+/saml/sp/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/+CSCOE+/logon.html", http.StatusFound)
	})

	return mux
}
