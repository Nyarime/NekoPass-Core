package main

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nyarime/nrtp"
	"github.com/xtaci/smux"
)

const maxSessions = 4

type MuxPool struct {
	mu       sync.Mutex
	sessions []*smux.Session
	conns    []net.Conn
	robin    atomic.Uint64
}

var muxPool = &MuxPool{}

func (p *MuxPool) GetStream() (net.Conn, error) {
	// round-robin选session
	for attempts := 0; attempts < maxSessions*2; attempts++ {
		idx := int(p.robin.Add(1)) % p.getSessionCount()
		
		p.mu.Lock()
		if idx < len(p.sessions) {
			s := p.sessions[idx]
			p.mu.Unlock()
			
			if s != nil && !s.IsClosed() {
				stream, err := s.OpenStream()
				if err == nil {
					return stream, nil
				}
			}
			// 这个session死了，替换
			p.replaceSession(idx)
			continue
		}
		p.mu.Unlock()
	}

	// 没有可用session，新建
	return p.addSession()
}

func (p *MuxPool) getSessionCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := len(p.sessions)
	if n == 0 { return 1 }
	return n
}

func (p *MuxPool) replaceSession(idx int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	if idx < len(p.sessions) && (p.sessions[idx] == nil || p.sessions[idx].IsClosed()) {
		conn, session, err := dialMuxSession()
		if err != nil {
			return
		}
		if idx < len(p.conns) && p.conns[idx] != nil {
			p.conns[idx].Close()
		}
		p.sessions[idx] = session
		if idx < len(p.conns) {
			p.conns[idx] = conn
		}
	}
}

func (p *MuxPool) addSession() (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	conn, session, err := dialMuxSession()
	if err != nil {
		return nil, err
	}

	p.sessions = append(p.sessions, session)
	p.conns = append(p.conns, conn)
	
	return session.OpenStream()
}

// Warm 预热多个session
func (p *MuxPool) Warm(n int) {
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, session, err := dialMuxSession()
			if err != nil {
				log.Printf("[Mux] 预热失败: %v", err)
				return
			}
			p.mu.Lock()
			p.sessions = append(p.sessions, session)
			p.conns = append(p.conns, conn)
			p.mu.Unlock()
		}()
	}
	wg.Wait()
	log.Printf("[Mux] 预热完成: %d个session", len(p.sessions))
}

func dialMuxSession() (net.Conn, *smux.Session, error) {
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
		return nil, nil, err
	}

	conn.Write([]byte("MUX\n"))
	ack := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	conn.Read(ack)
	conn.SetReadDeadline(time.Time{})

	smuxCfg := smux.DefaultConfig()
	smuxCfg.MaxReceiveBuffer = 16 * 1024 * 1024
	smuxCfg.KeepAliveInterval = 10 * time.Second
	smuxCfg.KeepAliveTimeout = 60 * time.Second

	session, err := smux.Client(conn, smuxCfg)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	log.Printf("[Mux] session建立 %v (共%d个)", time.Since(start).Round(time.Millisecond), muxPool.getSessionCount()+1)
	return conn, session, nil
}
