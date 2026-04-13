// +build linux darwin

package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
	"sync"

	"github.com/songgao/water"
)

// startTUN 创建TUN设备并路由流量到代理
func startTUN() {
	tunCfg := water.Config{DeviceType: water.TUN}

	if config.TUN.Name != "" {
		tunCfg.Name = config.TUN.Name
	}

	iface, err := water.New(tunCfg)
	if err != nil {
		log.Printf("[TUN] 创建失败: %v (需要root权限)", err)
		return
	}
	defer iface.Close()

	tunName := iface.Name()
	mtu := config.TUN.MTU
	if mtu == 0 {
		mtu = 1400
	}

	// 配置TUN设备
	switch runtime.GOOS {
	case "linux":
		exec.Command("ip", "link", "set", tunName, "up").Run()
		exec.Command("ip", "addr", "add", "10.0.85.1/24", "dev", tunName).Run()
		exec.Command("ip", "link", "set", tunName, "mtu", fmt.Sprintf("%d", mtu)).Run()
		// 设置路由（非CN流量走TUN）
		exec.Command("ip", "route", "add", "0.0.0.0/1", "dev", tunName).Run()
		exec.Command("ip", "route", "add", "128.0.0.0/1", "dev", tunName).Run()
	case "darwin":
		exec.Command("ifconfig", tunName, "10.0.85.1", "10.0.85.2", "up").Run()
		exec.Command("ifconfig", tunName, "mtu", fmt.Sprintf("%d", mtu)).Run()
		exec.Command("route", "add", "0.0.0.0/1", "10.0.85.2").Run()
		exec.Command("route", "add", "128.0.0.0/1", "10.0.85.2").Run()
	}

	log.Printf("[TUN] %s 已启动 (MTU=%d)", tunName, mtu)

	// 读取IP包并路由
	buf := make([]byte, 65536)
	for {
		n, err := iface.Read(buf)
		if err != nil {
			return
		}
		if n < 20 {
			continue
		}

		// 解析IP头
		version := buf[0] >> 4
		if version != 4 {
			continue // 只处理IPv4
		}

		protocol := buf[9]
		dstIP := net.IP(buf[16:20])
		ihl := int(buf[0]&0x0F) * 4

		// 跳过发往服务器的包（避免循环）
		serverIP := resolveServerIP()
		if dstIP.Equal(serverIP) {
			// 直接发出去（不走TUN）
			continue
		}

		switch protocol {
		case 6: // TCP
			if n < ihl+4 {
				continue
			}
			dstPort := binary.BigEndian.Uint16(buf[ihl+2 : ihl+4])
			target := fmt.Sprintf("%s:%d", dstIP.String(), dstPort)

			go func(target string) {
				// 通过NRTP代理TCP
				if shouldProxy(target) {
					remote, err := dialForTCP()
					if err != nil {
						return
					}
					defer remote.Close()
					remote.Write([]byte(target))
					ack := make([]byte, 1)
					remote.Read(ack)
				}
			}(target)

		case 17: // UDP
			if n < ihl+8 {
				continue
			}
			dstPort := binary.BigEndian.Uint16(buf[ihl+2 : ihl+4])
			payload := buf[ihl+8 : n]
			target := fmt.Sprintf("%s:%d", dstIP.String(), dstPort)

			go func(target string, data []byte) {
				if shouldProxy(target) {
					remote, err := dialForUDP()
					if err != nil {
						return
					}
					defer remote.Close()
					remote.Write([]byte("UDP:" + target))
					ack := make([]byte, 1)
					remote.Read(ack)
					remote.Write(data)
				} else {
					// 直连
					addr, _ := net.ResolveUDPAddr("udp", target)
					if addr != nil {
						conn, _ := net.DialUDP("udp", nil, addr)
						if conn != nil {
							conn.Write(data)
							conn.Close()
						}
					}
				}
			}(target, append([]byte{}, payload...))
		}
	}
}

var (
	serverIPOnce sync.Once
	serverIPAddr net.IP
)

func resolveServerIP() net.IP {
	serverIPOnce.Do(func() {
		host := config.Server
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		addrs, err := net.LookupHost(host)
		if err == nil && len(addrs) > 0 {
			serverIPAddr = net.ParseIP(addrs[0])
		}
	})
	return serverIPAddr
}
