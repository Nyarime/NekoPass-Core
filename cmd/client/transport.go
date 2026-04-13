package main

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type transportManager struct {
	udpAvailable atomic.Bool
	failures     atomic.Int64
	probeCount   int
	mu           sync.Mutex
}

var transport = &transportManager{}

func init() {
	transport.udpAvailable.Store(true)
	go transport.probeLoop()
}

func (t *transportManager) recoverInterval() time.Duration {
	if config.Smart.RecoverInterval != "" {
		if d, err := time.ParseDuration(config.Smart.RecoverInterval); err == nil {
			return d
		}
	}
	return 5 * time.Minute
}

// probeLoop 指数退避探测UDP恢复
func (t *transportManager) probeLoop() {
	baseInterval := t.recoverInterval()
	backoff := baseInterval

	for {
		time.Sleep(backoff)

		if !t.udpAvailable.Load() {
			log.Printf("[Transport] 探测UDP恢复 (间隔%v)...", backoff)
			conn, err := dialNRUP()
			if err == nil {
				conn.Close()
				t.udpAvailable.Store(true)
				t.failures.Store(0)
				t.probeCount = 0
				backoff = baseInterval
				log.Printf("[Transport] ✅ UDP已恢复，切回NRUP")
			if bridge != nil { bridge.NotifyUDPChange(true) }
			} else {
				t.probeCount++
				// 指数退避: 5m → 10m → 20m，最大20m
				backoff = baseInterval * time.Duration(1<<uint(min(t.probeCount, 2)))
				log.Printf("[Transport] UDP仍不可用，下次%v后重试", backoff)
			}
		}
	}
}

func (t *transportManager) recordUDPFailure() {
	count := t.failures.Add(1)
	if count >= 3 && t.udpAvailable.Load() {
		t.udpAvailable.Store(false)
		log.Printf("[Transport] ⚠️ UDP连续%d次失败，降级TCP", count)
		if bridge != nil { bridge.NotifyUDPChange(false) }
	}
}

func (t *transportManager) recordUDPSuccess() {
	t.failures.Store(0)
	if !t.udpAvailable.Load() {
		t.udpAvailable.Store(true)
		log.Printf("[Transport] ✅ UDP恢复")
		if bridge != nil { bridge.NotifyUDPChange(true) }
	}
}

func smartDialForTCP() (net.Conn, error) {
	conn, err := dialTCP()
	if err != nil {
		return dialNRUPStream()
	}
	return conn, nil
}

func smartDialForUDP() (net.Conn, error) {
	if !transport.udpAvailable.Load() {
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

func min(a, b int) int {
	if a < b { return a }
	return b
}
