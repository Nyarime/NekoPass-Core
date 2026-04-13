package main

import (
	"log"
	"sync"
	"sync/atomic"
	"time"
	"net"
)

// transportManager 智能传输管理（UDP↔TCP自动切换）
type transportManager struct {
	udpAvailable atomic.Bool
	failures     atomic.Int64
	lastProbe    time.Time
	mu           sync.Mutex
}

var transport = &transportManager{}

func init() {
	transport.udpAvailable.Store(true)
	go transport.probeLoop()
}

// probeLoop 定期探测UDP是否恢复
func (t *transportManager) probeLoop() {
	for {
		time.Sleep(5 * time.Minute)
		if !t.udpAvailable.Load() {
			// UDP之前失败过，尝试恢复
			log.Printf("[Transport] 探测UDP恢复...")
			conn, err := dialNRUP()
			if err == nil {
				conn.Close()
				t.udpAvailable.Store(true)
				t.failures.Store(0)
				log.Printf("[Transport] ✅ UDP已恢复，切回NRUP")
			} else {
				log.Printf("[Transport] UDP仍不可用，继续TCP")
			}
		}
	}
}

// recordUDPFailure 记录UDP失败
func (t *transportManager) recordUDPFailure() {
	count := t.failures.Add(1)
	if count >= 3 && t.udpAvailable.Load() {
		t.udpAvailable.Store(false)
		log.Printf("[Transport] ⚠️ UDP连续%d次失败，降级到TCP", count)
	}
}

// recordUDPSuccess 记录UDP成功
func (t *transportManager) recordUDPSuccess() {
	t.failures.Store(0)
	if !t.udpAvailable.Load() {
		t.udpAvailable.Store(true)
		log.Printf("[Transport] ✅ UDP恢复")
	}
}

// smartDialForTCP TCP代理：优先TCP，失败走NRUP
func smartDialForTCP() (net.Conn, error) {
	conn, err := dialTCP()
	if err != nil {
		return dialNRUPStream()
	}
	return conn, nil
}

// smartDialForUDP UDP代理：优先NRUP(FEC)，不可用时走TCP
func smartDialForUDP() (net.Conn, error) {
	if !transport.udpAvailable.Load() {
		// UDP不可用，直接走TCP
		return dialTCP()
	}

	conn, err := dialNRUP()
	if err != nil {
		transport.recordUDPFailure()
		return dialTCP()
	}
	transport.recordUDPSuccess()
	return conn, nil
}
