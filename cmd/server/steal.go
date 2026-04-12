package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

// stealCert 连接目标AnyConnect服务器，偷取其TLS证书
func stealCert(target string) (*tls.Certificate, error) {
	addr := target
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = target + ":443"
	}
	host, _, _ := net.SplitHostPort(addr)

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp", addr,
		&tls.Config{ServerName: host, InsecureSkipVerify: true},
	)
	if err != nil {
		return nil, fmt.Errorf("连接 %s 失败: %w", addr, err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("无证书: %s", addr)
	}

	cert := state.PeerCertificates[0]
	log.Printf("[Steal] 证书: CN=%s Issuer=%s", cert.Subject.CommonName, cert.Issuer.CommonName)

	// 用偷来的证书创建TLS证书（私钥用自己的，证书用对方的）
	// 注意：客户端需要跳过验证，因为私钥不匹配
	// 但对DPI来说，证书指纹和真实服务器一致
	return nil, nil // 返回DER用于指纹伪装
}

// stealPortal 从目标服务器抓取AnyConnect登录页面
func stealPortal(sni string) string {
	if sni == "" {
		return ""
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, path := range []string{"/+CSCOE+/logon.html", "/"} {
		url := fmt.Sprintf("https://%s%s", sni, path)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 200 && len(body) > 100 {
			log.Printf("[Steal] Portal页面: %s (%d bytes)", url, len(body))
			return string(body)
		}
	}

	log.Printf("[Steal] Portal抓取失败: %s，使用内置页面", sni)
	return ""
}
