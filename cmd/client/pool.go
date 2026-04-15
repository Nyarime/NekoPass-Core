package main

import (
	"net"
	"sync"
	"time"
	"log"

	"github.com/nyarime/nrtp"
)

// ConnPool NRTP连接池
type ConnPool struct {
	mu    sync.Mutex
	conns []net.Conn
	max   int
}

var nrtpPool = &ConnPool{max: 8}

func (p *ConnPool) Get() (net.Conn, error) {
	p.mu.Lock()
	if len(p.conns) > 0 {
		conn := p.conns[len(p.conns)-1]
		p.conns = p.conns[:len(p.conns)-1]
		p.mu.Unlock()
		// 检查连接是否还活着
		conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
		buf := make([]byte, 1)
		_, err := conn.Read(buf)
		conn.SetReadDeadline(time.Time{})
		if err != nil && !isTimeout(err) {
			conn.Close()
			return p.dial() // 死连接,新建
		}
		return conn, nil
	}
	p.mu.Unlock()
	return p.dial()
}

func (p *ConnPool) Put(conn net.Conn) {
	// 用过的连接不能放回(已发送target,是专用连接)
	conn.Close()
}

func (p *ConnPool) dial() (net.Conn, error) {
	cfg := &nrtp.Config{
		Password: config.Password,
		Mode:     "fake-tls",
		SNI:      config.SNI,
		UseUTLS:  true,
	}
	if config.SNI == "" {
		cfg.Mode = "tls"
	}
	return nrtp.Dial(config.Server, cfg)
}

// 预热连接池
func (p *ConnPool) Warm(n int) {
	for i := 0; i < n; i++ {
		conn, err := p.dial()
		if err != nil {
			log.Printf("[Pool] 预热失败: %v", err)
			return
		}
		p.mu.Lock()
		p.conns = append(p.conns, conn)
		p.mu.Unlock()
	}
	log.Printf("[Pool] 预热 %d 个连接", n)
}

func isTimeout(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}
