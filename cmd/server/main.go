package main

import (
	"crypto/sha256"
	"flag"
	"io"
	"log"
	"net"
	"sync"

	"github.com/nyarime/nrup"
)

func main() {
	listen := flag.String("listen", ":443", "监听地址")
	password := flag.String("password", "", "连接密码")
	disguise := flag.String("disguise", "anyconnect", "伪装模式 (anyconnect/quic)")
	sni := flag.String("sni", "", "QUIC 模式 SNI")
	flag.Parse()

	if *password == "" {
		log.Fatal("请指定 -password")
	}

	cfg := nrup.DefaultConfig()
	cfg.PSK = deriveKey(*password)
	cfg.Disguise = *disguise
	cfg.DisguiseSNI = *sni

	listener, err := nrup.Listen(*listen, cfg)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("NekoPass Lite Server 监听 %s (伪装: %s)", *listen, *disguise)

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

	// 读取目标地址
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

	conn.Write([]byte{0x01}) // 连接成功

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(remote, conn) }()
	go func() { defer wg.Done(); io.Copy(conn, remote) }()
	wg.Wait()
}

func deriveKey(password string) []byte {
	h := sha256.Sum256([]byte("nekopass-lite:" + password))
	return h[:]
}
