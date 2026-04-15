package main

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/nyarime/nrtp"
	"github.com/xtaci/smux"
)

// MuxPool 多路复用连接池
// 1个NRTP连接 → smux → 多个代理流
type MuxPool struct {
	mu      sync.Mutex
	session *smux.Session
	conn    net.Conn
}

var muxPool = &MuxPool{}

func (p *MuxPool) GetStream() (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 检查现有session
	if p.session != nil && !p.session.IsClosed() {
		stream, err := p.session.OpenStream()
		if err == nil {
			return stream, nil
		}
		// session坏了，重建
		p.session.Close()
		p.session = nil
	}

	// 建立新NRTP连接 + smux
	conn, err := dialNRTP()
	if err != nil {
		return nil, err
	}

	session, err := smux.Client(conn, smux.DefaultConfig())
	if err != nil {
		conn.Close()
		return nil, err
	}

	p.session = session
	p.conn = conn
	log.Printf("[Mux] 建立多路复用连接")

	return session.OpenStream()
}

func dialNRTP() (net.Conn, error) {
	cfg := &nrtp.Config{
		Password: config.Password,
		Mode:     "fake-tls",
		SNI:      config.SNI,
		UseUTLS:  true,
	}
	if config.SNI == "" {
		cfg.Mode = "tls"
	}
	start := time.Now()
	conn, err := nrtp.Dial(config.Server, cfg)
	if err != nil {
		return nil, err
	}
	// 发送mux标记让服务端知道这是mux连接
	conn.Write([]byte("MUX"))
	ack := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	conn.Read(ack)
	conn.SetReadDeadline(time.Time{})
	log.Printf("[Mux] NRTP连接建立 %v", time.Since(start).Round(time.Millisecond))
	return conn, nil
}
