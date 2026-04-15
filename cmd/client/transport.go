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
	lastFECEff   float64 // 最近FEC有效性
}

var proxyConns atomic.Int64
var transport = &transportManager{}

func init() {
	// transport配置决定初始状态
	switch config.Transport {
	case "tcp":
		transport.udpAvailable.Store(false) // 强制TCP
	case "udp":
		transport.udpAvailable.Store(true)
	default: // auto
		transport.udpAvailable.Store(true) // 先假设可用，SmartTransport自动降级
	}
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
		// FEC效果差时延长探测间隔
		sleep := backoff
		if t.lastFECEff > 0 && t.lastFECEff < 0.5 {
			mult := config.Smart.ProbeMultiplier
			if mult <= 0 { mult = 1.5 }
			sleep = time.Duration(float64(backoff) * mult)
		}
		time.Sleep(sleep)

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
	// FEC效果差+丢包多→提前降级
	threshold := int64(3)
	if t.lastFECEff > 0 && t.lastFECEff < 0.4 {
		threshold = int64(config.Smart.FECThreshold)
		if threshold <= 0 { threshold = 2 }
	}
	if count >= threshold && t.udpAvailable.Load() {
		if threshold < 3 { log.Printf("[Smart] FEC效果差(%.0f%%) → 提前降级TCP", t.lastFECEff*100) }
		t.udpAvailable.Store(false)
		log.Printf("[Transport] ⚠️ UDP连续%d次失败，降级TCP (FEC效率%.0f%%)", count, t.lastFECEff*100)
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

// updateFECEffectiveness 从 NRUP Conn 更新FEC有效性
func (t *transportManager) updateFECEffectiveness(eff float64) {
	t.lastFECEff = eff
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

// TUI日志收集
var tuiLogs []string
var tuiLogsMu sync.Mutex

func addTUILog(msg string) {
	tuiLogsMu.Lock()
	tuiLogs = append(tuiLogs, msg)
	if len(tuiLogs) > 100 { tuiLogs = tuiLogs[len(tuiLogs)-100:] }
	tuiLogsMu.Unlock()
}

func getTUILogs() []string {
	tuiLogsMu.Lock()
	defer tuiLogsMu.Unlock()
	cp := make([]string, len(tuiLogs))
	copy(cp, tuiLogs)
	return cp
}
