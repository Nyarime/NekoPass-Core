package main

import (
	"log"
	"sync"
	"time"

	"github.com/nyarime/nrtp"
)

// Bridge NRUP↔NRTP 内部通信桥
// 同进程共享状态，零开销
type Bridge struct {
	mu       sync.RWMutex
	PSK      []byte  // 共用密钥
	CertDER  []byte  // 证书 (NRTP获取→NRUP使用)
	LossRate float64 // 丢包率 (NRUP更新→NRTP读取)
	UDPOk    bool    // UDP可用性
	SNI      string  // 共用SNI
}

var bridge = &Bridge{UDPOk: true}

// initBridge 初始化桥接（启动时调用）
func initBridge() {
	bridge.PSK = deriveKey(config.Password)
	bridge.SNI = config.SNI
	bridge.UDPOk = true

	// NRTP获取证书 → 共享给NRUP
	if config.SNI != "" {
		certDER, err := nrtp.FetchCert(config.SNI)
		if err == nil && len(certDER) > 0 {
			bridge.mu.Lock()
			bridge.CertDER = certDER
			bridge.mu.Unlock()
			log.Printf("[Bridge] 证书共享: %s (%d bytes)", config.SNI, len(certDER))
		}
	}

	// 后台同步NRUP指标
	go bridge.syncLoop()
}

// syncLoop 定期同步NRUP连接指标到Bridge
func (b *Bridge) syncLoop() {
	// SmartTransport的recordSuccess/Failure已经在更新transport.udpAvailable
	// Bridge只需要映射这个状态
	for {
		select {
		case <-make(chan struct{}): // placeholder
			return
		default:
		}

		b.mu.Lock()
		b.UDPOk = transport.udpAvailable.Load()
		b.mu.Unlock()

		// 每秒同步一次（轻量）
		<-after(1)
	}
}


func after(seconds int) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		<-time.After(time.Duration(seconds) * time.Second)
		close(ch)
	}()
	return ch
}

// GetCertDER Bridge获取共享证书
func (b *Bridge) GetCertDER() []byte {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.CertDER
}

// IsUDPOk Bridge获取UDP状态
func (b *Bridge) IsUDPOk() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.UDPOk
}
