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

var maxSessions = 8

// adjustSessions 根据session存活率动态调整数量
func (p *MuxPool) adjustSessions() {
	p.mu.Lock()
	alive := 0
	for _, s := range p.sessions {
		if s != nil && !s.IsClosed() { alive++ }
	}
	p.mu.Unlock()

	ratio := float64(alive) / float64(maxSessions)
	if ratio < 0.5 && maxSessions < 12 {
		maxSessions += 2 // 存活率低→加更多session
	} else if ratio > 0.9 && maxSessions > 6 {
		maxSessions -= 1 // 存活率高→可以减少
	}
}

type MuxPool struct {
	mu       sync.Mutex
	sessions []*smux.Session
	conns    []net.Conn
	robin    atomic.Uint64
}

var muxPool = &MuxPool{}

func (p *MuxPool) GetStream() (net.Conn, error) {
	p.mu.Lock()
	n := len(p.sessions)
	p.mu.Unlock()

	// 没有session，直接创建
	if n == 0 {
		return p.addSession()
	}

	// round-robin选session
	idx := int(p.robin.Add(1)) % n
	
	p.mu.Lock()
	s := p.sessions[idx]
	p.mu.Unlock()
	
	if s != nil && !s.IsClosed() {
		stream, err := s.OpenStream()
		if err == nil {
			return stream, nil
		}
	}

	// session死了或OpenStream失败，替换
	p.replaceSession(idx)
	
	// 重试一次
	p.mu.Lock()
	if idx < len(p.sessions) && p.sessions[idx] != nil && !p.sessions[idx].IsClosed() {
		s2 := p.sessions[idx]
		p.mu.Unlock()
		return s2.OpenStream()
	}
	p.mu.Unlock()
	
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

	log.Printf("[Mux] session建立 %s (共%d个)", fmtDuration(time.Since(start)), muxPool.getSessionCount()+1)
	return conn, session, nil
}

func init() {
	go func() {
		for {
			time.Sleep(30 * time.Second)
			muxPool.adjustSessions()
		}
	}()
}
