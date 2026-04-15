package main

import (
	"crypto/sha256"
	"crypto/tls"
	"flag"
	"fmt"
	"crypto/rand"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/nyarime/nrup"
	"github.com/nyarime/nrtp"
)

func main() {
	listen := flag.String("listen", ":443", "监听地址")
	password := flag.String("password", "", "连接密码")
	sni := flag.String("sni", "vpn.sjsu.edu", "QUIC 模式 SNI")
	portal := flag.String("portal", ":8443", "AnyConnect Portal HTTPS 监听 (留空禁用)")
	portalTitle := flag.String("portal-title", "Employee-SSO", "Portal 页面标题")
	flag.Parse()

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
	if *portal != "" {
		log.Printf("AnyConnect Portal 监听 %s", *portal)
	}

	// TCP TLS 监听（同端口）
	go startNRTP(*listen, *password, *sni)

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
	mux := http.NewServeMux()

	// Cisco ASA AnyConnect Portal 页面
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Cisco ASA SSL VPN")
		w.Header().Set("X-Powered-By", "Cisco Systems, Inc.")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, portalHTML)
	})

	// AnyConnect 客户端探测端点
	mux.HandleFunc("/+CSCOE+/logon.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Cisco ASA SSL VPN")
		fmt.Fprint(w, portalHTML)
	})

	// AnyConnect XML profile
	// Cisco logo
	mux.HandleFunc("/+CSCOU+/csco_logo.gif", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Cisco ASA SSL VPN")
		w.Header().Set("Content-Type", "image/gif")
		// 1x1 transparent GIF
		w.Write([]byte{0x47,0x49,0x46,0x38,0x39,0x61,0x01,0x00,0x01,0x00,0x80,0x00,0x00,0xff,0xff,0xff,0x00,0x00,0x00,0x21,0xf9,0x04,0x00,0x00,0x00,0x00,0x00,0x2c,0x00,0x00,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x02,0x02,0x44,0x01,0x00,0x3b})
	})

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
func startNRTP(addr, password, sni string) {
	nrtpCfg := &nrtp.Config{
		Password: password,
		Mode:     "tls",
		SNI:      sni,
	}
	if sni != "" {
		nrtpCfg.Mode = "fake-tls"
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
		go handleConn(conn)
	}
}
