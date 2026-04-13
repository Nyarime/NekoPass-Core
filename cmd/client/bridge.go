package main

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/nyarime/nrtp"
)

// Bridge NRUP↔NRTP 内部状态桥
// 同进程共享，零网络开销
type Bridge struct {
	mu      sync.RWMutex
	PSK     []byte
	CertDER []byte
	UDPOk   bool
	SNI     string
	cancel  context.CancelFunc
}

var bridge = &Bridge{UDPOk: true}

func initBridge() {
	bridge.PSK = deriveKey(config.Password)
	bridge.SNI = config.SNI
	bridge.UDPOk = true

	// NRTP获取证书 → 共享给NRUP nDTLS
	if config.SNI != "" {
		certDER, err := nrtp.FetchCert(config.SNI)
		if err == nil && len(certDER) > 0 {
			bridge.mu.Lock()
			bridge.CertDER = certDER
			bridge.mu.Unlock()
			log.Printf("[Bridge] 证书共享: %s (%d bytes)", config.SNI, len(certDER))
		} else {
			log.Printf("[Bridge] 证书获取失败: %v (nDTLS将不带证书)", err)
		}
	}

	// 后台同步状态（3秒间隔，可停止）
	ctx, cancel := context.WithCancel(context.Background())
	bridge.cancel = cancel
	go bridge.syncLoop(ctx)
	log.Printf("[Bridge] NRUP↔NRTP 桥接就绪")
}

func (b *Bridge) syncLoop(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.mu.Lock()
			b.UDPOk = transport.udpAvailable.Load()
			b.mu.Unlock()
		}
	}
}

func (b *Bridge) Close() {
	if b.cancel != nil {
		b.cancel()
	}
}

func (b *Bridge) GetCertDER() []byte {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.CertDER
}

func (b *Bridge) IsUDPOk() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.UDPOk
}
