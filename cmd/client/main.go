package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"github.com/nyarime/nrup"
)

func main() {
	server := flag.String("server", "", "服务端地址 (ip:port)")
	password := flag.String("password", "", "连接密码")
	listen := flag.String("listen", "127.0.0.1:1080", "本地 SOCKS5 监听")
	disguise := flag.String("disguise", "anyconnect", "伪装模式 (anyconnect/quic)")
	flag.Parse()

	if *server == "" || *password == "" {
		log.Fatal("请指定 -server 和 -password")
	}

	cfg := nrup.DefaultConfig()
	cfg.PSK = deriveKey(*password)
	cfg.Disguise = *disguise

	// 本地 SOCKS5 监听
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("NekoPass Lite Client 监听 %s → %s", *listen, *server)

	var sessionID string // 0-RTT 复用

	for {
		local, err := ln.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer local.Close()

			// SOCKS5 握手
			target, err := socks5Handshake(local)
			if err != nil {
				return
			}

			// 连接服务端（尝试 0-RTT）
			dialCfg := nrup.DefaultConfig()
			dialCfg.PSK = cfg.PSK
			dialCfg.Disguise = cfg.Disguise
			if sessionID != "" {
				dialCfg.ResumeID = sessionID
			}

			remote, err := nrup.Dial(*server, dialCfg)
			if err != nil {
				log.Printf("连接服务端失败: %v", err)
				return
			}
			defer remote.Close()

			// 保存 sessionID 用于后续 0-RTT
			sessionID = remote.SessionID()

			// 发送目标地址
			remote.Write([]byte(target))

			// 等确认
			ack := make([]byte, 1)
			if _, err := remote.Read(ack); err != nil || ack[0] != 0x01 {
				return
			}

			// 双向转发
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); io.Copy(remote, local) }()
			go func() { defer wg.Done(); io.Copy(local, remote) }()
			wg.Wait()
		}()
	}
}

// socks5Handshake 处理 SOCKS5 协议握手
func socks5Handshake(conn net.Conn) (string, error) {
	buf := make([]byte, 256)

	// 认证协商
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return "", fmt.Errorf("not socks5")
	}
	conn.Write([]byte{0x05, 0x00}) // 无需认证

	// 请求
	n, err = conn.Read(buf)
	if err != nil || n < 7 || buf[1] != 0x01 {
		return "", fmt.Errorf("unsupported command")
	}

	var target string
	switch buf[3] {
	case 0x01: // IPv4
		target = fmt.Sprintf("%d.%d.%d.%d:%d", buf[4], buf[5], buf[6], buf[7],
			int(buf[8])<<8|int(buf[9]))
	case 0x03: // 域名
		domainLen := int(buf[4])
		target = fmt.Sprintf("%s:%d", string(buf[5:5+domainLen]),
			int(buf[5+domainLen])<<8|int(buf[6+domainLen]))
	case 0x04: // IPv6
		target = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]:%d",
			int(buf[4])<<8|int(buf[5]), int(buf[6])<<8|int(buf[7]),
			int(buf[8])<<8|int(buf[9]), int(buf[10])<<8|int(buf[11]),
			int(buf[12])<<8|int(buf[13]), int(buf[14])<<8|int(buf[15]),
			int(buf[16])<<8|int(buf[17]), int(buf[18])<<8|int(buf[19]),
			int(buf[20])<<8|int(buf[21]))
	default:
		return "", fmt.Errorf("unsupported address type")
	}

	// 成功响应
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return target, nil
}

func deriveKey(password string) []byte {
	h := sha256.Sum256([]byte("nekopass-lite:" + password))
	return h[:]
}
