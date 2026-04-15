package main

import (
	"log"
	"net"
	"sync"
	"time"
)

// ConnPool 服务端连接池
// 缓存最近使用的目标连接，避免每个stream都重新Dial
type ConnPool struct {
	mu    sync.Mutex
	conns map[string][]net.Conn // target → 可复用连接
	max   int
}

var serverPool = &ConnPool{
	conns: make(map[string][]net.Conn),
	max:   5, // 每个target最多缓存5个连接
}

// Get 获取到target的连接(优先复用)
func (p *ConnPool) Get(network, target string) (net.Conn, error) {
	p.mu.Lock()
	if conns, ok := p.conns[target]; ok && len(conns) > 0 {
		conn := conns[len(conns)-1]
		p.conns[target] = conns[:len(conns)-1]
		p.mu.Unlock()
		// 检查连接是否还活着
		conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
		buf := make([]byte, 1)
		_, err := conn.Read(buf)
		conn.SetReadDeadline(time.Time{})
		if err != nil && !isTimeoutErr(err) {
			conn.Close()
			return net.DialTimeout(network, target, 10*time.Second)
		}
		return conn, nil
	}
	p.mu.Unlock()
	return net.DialTimeout(network, target, 10*time.Second)
}

// Put 归还连接到池(仅HTTP/1.1 keep-alive时有用)
func (p *ConnPool) Put(target string, conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if conns, ok := p.conns[target]; ok && len(conns) >= p.max {
		conn.Close()
		return
	}
	p.conns[target] = append(p.conns[target], conn)
}

// 定期清理过期连接
func (p *ConnPool) cleanup() {
	for {
		time.Sleep(60 * time.Second)
		p.mu.Lock()
		for target, conns := range p.conns {
			var alive []net.Conn
			for _, c := range conns {
				c.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
				buf := make([]byte, 1)
				_, err := c.Read(buf)
				c.SetReadDeadline(time.Time{})
				if err != nil && !isTimeoutErr(err) {
					c.Close()
				} else {
					alive = append(alive, c)
				}
			}
			if len(alive) == 0 {
				delete(p.conns, target)
			} else {
				p.conns[target] = alive
			}
		}
		p.mu.Unlock()
	}
}

func isTimeoutErr(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}

func init() {
	go serverPool.cleanup()
}

// Preheat 预热热门目标
func (p *ConnPool) Preheat() {
	targets := []string{
		"www.google.com:443",
		"github.com:443",
		"www.youtube.com:443",
	}
	for _, t := range targets {
		go func(addr string) {
			conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
			if err == nil {
				p.Put(addr, conn)
				log.Printf("[Pool] 预热: %s", addr)
			}
		}(t)
	}
}
