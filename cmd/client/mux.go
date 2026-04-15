package main

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/nyarime/nrtp"
	"github.com/xtaci/smux"
)

type MuxPool struct {
	mu      sync.Mutex
	session *smux.Session
}

var muxPool = &MuxPool{}

func (p *MuxPool) GetStream() (net.Conn, error) {
	p.mu.Lock()
	s := p.session
	p.mu.Unlock()

	if s != nil && !s.IsClosed() {
		stream, err := s.OpenStream()
		if err == nil {
			return stream, nil
		}
		// session异常,清空让下次重建
		p.mu.Lock()
		if p.session == s {
			p.session = nil
		}
		p.mu.Unlock()
	}

	// 需要新session
	p.mu.Lock()
	defer p.mu.Unlock()

	// double check
	if p.session != nil && !p.session.IsClosed() {
		return p.session.OpenStream()
	}

	conn, err := dialNRTPConn()
	if err != nil {
		return nil, err
	}

	cfg := smux.DefaultConfig()
	cfg.MaxReceiveBuffer = 16 * 1024 * 1024 // 16MB
	cfg.KeepAliveInterval = 10 * time.Second
	cfg.KeepAliveTimeout = 60 * time.Second

	session, err := smux.Client(conn, cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}

	p.session = session
	log.Printf("[Mux] 多路复用就绪")
	return session.OpenStream()
}

func dialNRTPConn() (net.Conn, error) {
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
	// MUX标记
	conn.Write([]byte("MUX\n"))
	ack := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	conn.Read(ack)
	conn.SetReadDeadline(time.Time{})
	log.Printf("[Mux] NRTP %v", time.Since(start).Round(time.Millisecond))
	return conn, nil
}
