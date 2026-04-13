package main

import (
	"log"
	"net"
	"sync"
	"time"
)

func handleTUNTCPCommon(target string) {
	if !shouldProxy(target) {
		return
	}
	remote, err := smartDialForTCP()
	if err != nil {
		log.Printf("[TUN] TCP %s 连接失败: %v", target, err)
		return
	}
	defer remote.Close()
	remote.Write([]byte(target))
	ack := make([]byte, 1)
	if _, err := remote.Read(ack); err != nil || ack[0] != 0x01 {
		return
	}
	remote.SetReadDeadline(time.Now().Add(5 * time.Minute))
	buf := make([]byte, 4096)
	for {
		_, err := remote.Read(buf)
		if err != nil { return }
		remote.SetReadDeadline(time.Now().Add(5 * time.Minute))
	}
}

func handleTUNUDPCommon(target string, payload []byte) {
	if !shouldProxy(target) {
		addr, _ := net.ResolveUDPAddr("udp", target)
		if addr != nil {
			conn, _ := net.DialUDP("udp", nil, addr)
			if conn != nil {
				conn.Write(payload)
				conn.Close()
			}
		}
		return
	}
	remote, err := smartDialForUDP()
	if err != nil { return }
	defer remote.Close()
	remote.Write([]byte("UDP:" + target))
	ack := make([]byte, 1)
	if _, err := remote.Read(ack); err != nil || ack[0] != 0x01 { return }
	remote.Write(payload)
}

// connTrack全局连接跟踪（跨平台共享）
type tunConnTrack struct {
	mu    sync.RWMutex
	conns map[string]net.Conn
}

var connTrack = &tunConnTrack{conns: make(map[string]net.Conn)}

func (t *tunConnTrack) Get(key string) (net.Conn, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	c, ok := t.conns[key]
	return c, ok
}

func (t *tunConnTrack) Set(key string, conn net.Conn) {
	t.mu.Lock()
	t.conns[key] = conn
	t.mu.Unlock()
}

func (t *tunConnTrack) Delete(key string) {
	t.mu.Lock()
	delete(t.conns, key)
	t.mu.Unlock()
}

func (t *tunConnTrack) cleanup() {
	for {
		time.Sleep(60 * time.Second)
		t.mu.Lock()
		if len(t.conns) > 1000 {
			count := 0
			for k, c := range t.conns {
				c.Close()
				delete(t.conns, k)
				count++
				if count >= 500 { break }
			}
		}
		t.mu.Unlock()
	}
}
