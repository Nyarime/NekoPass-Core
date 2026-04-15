package main

import (
	"context"
	"net"

	"github.com/nyarime/nrup"
	"github.com/nyarime/nrtp"
)

// liteSmartDialer 实现nrup.SmartDialer接口
// 注入NRTP作为TCP路径
type liteSmartDialer struct{}

func (d *liteSmartDialer) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	cfg := nrup.DefaultConfig()
	cfg.PSK = deriveKey(config.Password)
	if config.FECType != "" { cfg.FECType = nrup.FECType(config.FECType) }
	cfg.Disguise = config.Disguise
	cfg.DisguiseSNI = config.SNI
	cfg.HandshakeTimeout = 5 * 1e9 // 5秒
	return nrup.Dial(addr, cfg)
}

func (d *liteSmartDialer) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	cfg := &nrtp.Config{
		Password: config.Password,
		Mode:     "fake-tls",
		SNI:      config.SNI,
		UseUTLS:  true,
	}
	if config.SNI == "" {
		cfg.Mode = "tls"
	}
	return nrtp.Dial(addr, cfg)
}

func (d *liteSmartDialer) Stats() nrup.TransportStats {
	return nrup.TransportStats{
		Mode:         "NRTP+NRUP",
		UDPAvailable: transport.udpAvailable.Load(),
		Sessions:     muxPool.getSessionCount(),
	}
}

func (d *liteSmartDialer) SetUDPAvailable(available bool) {
	transport.udpAvailable.Store(available)
}

func (d *liteSmartDialer) Close() error {
	return nil
}

// muxPool helper
