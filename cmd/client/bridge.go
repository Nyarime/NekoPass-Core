package main

import (
	"context"
	"log"
	"sync"
	"sync/atomic"

	"github.com/nyarime/nrtp"
)

// Bridge NRUP↔NRTP 事件驱动状态桥
type Bridge struct {
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

	// 证书共享
	if config.SNI != "" {
		certDER, err := nrtp.FetchCert(config.SNI)
		if err == nil && len(certDER) > 0 {
			bridge.mu.Lock()
			bridge.CertDER = certDER
			bridge.mu.Unlock()
			log.Printf("[Bridge] 证书共享: %s (%d bytes)", config.SNI, len(certDER))
		} else {
			log.Printf("[Bridge] 证书获取失败: %v", err)
		}
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
