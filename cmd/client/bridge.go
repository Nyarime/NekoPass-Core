package main

import (
	"context"
	"log"
	"time"
	"github.com/nyarime/nrup"
	"sync"
	"sync/atomic"

	"github.com/nyarime/nrtp"
)

// Bridge NRUP↔NRTP 事件驱动状态桥
type Bridge struct {
	nrupConn *nrup.Conn // TUI Metrics用
	mu           sync.RWMutex
	CertDER      []byte
	PSK          []byte
	SNI          string
	udpAvailable atomic.Bool
	notifyCh     chan bool
	ctx          context.Context
	cancel       context.CancelFunc
	closed       atomic.Bool
}

var bridge *Bridge

func initBridge() {
	ctx, cancel := context.WithCancel(context.Background())
	bridge = &Bridge{
		PSK:      deriveKey(config.Password),
		SNI:      config.SNI,
		notifyCh: make(chan bool, 1),
		ctx:      ctx,
		cancel:   cancel,
	}
	bridge.udpAvailable.Store(true)

	// 证书共享(异步，不阻塞启动)
	if config.SNI != "" {
		go func() {
			certDER, err := nrtp.FetchCert(config.SNI)
			if err == nil && len(certDER) > 0 {
				bridge.mu.Lock()
				bridge.CertDER = certDER
				bridge.mu.Unlock()
				log.Printf("[Bridge] 证书共享: %s (%d bytes)", config.SNI, len(certDER))
			}
		}()
	}

	go bridge.monitorLoop()
	log.Printf("[Bridge] NRUP↔NRTP 桥接就绪 (事件驱动)")
}

// NotifyUDPChange 状态变化时立即通知（<1ms）
func (b *Bridge) NotifyUDPChange(available bool) {
	if b.closed.Load() {
		return
	}
	b.udpAvailable.Store(available)
	select {
	case b.notifyCh <- available:
	default:
	}
}

func (b *Bridge) monitorLoop() {
	for {
		select {
		case <-b.ctx.Done():
			return
		case state := <-b.notifyCh:
			log.Printf("[Bridge] UDP状态更新: %v", state)
		}
	}
}

func (b *Bridge) Close() {
	if b.closed.Swap(true) {
		return
	}
	b.cancel()
}

func (b *Bridge) GetCertDER() []byte {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.CertDER
}

func (b *Bridge) IsUDPOk() bool {
	return b.udpAvailable.Load()
}

// FECStats 返回FEC/SACK统计(TUI用)
type FECStats struct {
	Parity      int
	Effectiveness float64
	Recovered   int64
	Decodes     int64
	LossRate    float64
	RTT         string
	Jitter      string
	RetransmitQ int
	MTU         int
}

func (b *Bridge) GetFECStats() *FECStats {
	if b == nil || b.nrupConn == nil { return nil }
	s := b.nrupConn.Stats()
	return &FECStats{
		Parity:       s.CurrentParity,
		Effectiveness: s.FECEffectiveness,
		Recovered:    s.FECRecovered,
		Decodes:      s.FECDecodes,
		LossRate:     s.LossRate,
		RTT:          s.RTT.Round(time.Millisecond).String(),
		Jitter:       s.Jitter.Round(time.Millisecond).String(),
		RetransmitQ:  s.RetransmitQ,
		MTU:          s.MTU,
	}
}
