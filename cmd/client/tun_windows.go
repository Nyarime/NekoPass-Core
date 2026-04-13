//go:build windows

package main

import (
	"embed"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

//go:embed embed/wintun
var wintunFS embed.FS

// ensureWintunDLL 自动解压wintun.dll到exe同目录
func ensureWintunDLL() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	dllPath := filepath.Join(filepath.Dir(exePath), "wintun.dll")

	if _, err := os.Stat(dllPath); err == nil {
		return nil // 已存在
	}

	arch := "amd64"
	if runtime.GOARCH == "arm64" {
		arch = "arm64"
	}

	data, err := wintunFS.ReadFile("embed/wintun/" + arch + "/wintun.dll")
	if err != nil {
		return fmt.Errorf("读取嵌入wintun.dll失败: %w", err)
	}

	return os.WriteFile(dllPath, data, 0644)
}

func startTUN() {
	if err := ensureWintunDLL(); err != nil {
		log.Printf("[TUN] wintun.dll准备失败: %v", err)
		return
	}

	name := config.TUN.Name
	if name == "" {
		name = "NekoTUN"
	}
	mtu := config.TUN.MTU
	if mtu == 0 {
		mtu = 1400
	}

	iface, err := wgtun.CreateTUN(name, mtu)
	if err != nil {
		log.Printf("[TUN] 创建失败: %v (需要管理员权限)", err)
		return
	}
	defer iface.Close()

	realName, _ := iface.Name()
	log.Printf("[TUN] %s 已启动 (MTU=%d)", realName, mtu)

	// 配置IP和路由
	exec.Command("netsh", "interface", "ipv4", "set", "address", realName, "static", "10.0.85.1", "255.255.255.0").Run()

	serverIP := resolveServerIP()
	if serverIP != nil {
		exec.Command("route", "add", serverIP.String(), "MASK", "255.255.255.255", "0.0.0.0", "METRIC", "1").Run()
	}
	exec.Command("route", "add", "0.0.0.0", "MASK", "128.0.0.0", "10.0.85.1", "METRIC", "5").Run()
	exec.Command("route", "add", "128.0.0.0", "MASK", "128.0.0.0", "10.0.85.1", "METRIC", "5").Run()

	// 读取IP包
	buf := make([]byte, 65536)
	for {
		bufs := [][]byte{buf}
		sizes := []int{0}
		_, err := iface.Read(bufs, sizes, 0)
		n := sizes[0]
		if err != nil {
			log.Printf("[TUN] Read: %v", err)
			return
		}
		if n < 20 {
			continue
		}

		pkt := buf[:n]
		version := pkt[0] >> 4
		if version != 4 {
			continue
		}

		protocol := pkt[9]
		dstIP := net.IP(make([]byte, 4))
		copy(dstIP, pkt[16:20])
		ihl := int(pkt[0]&0x0F) * 4

		if serverIP != nil && dstIP.Equal(serverIP) {
			continue
		}

		switch protocol {
		case 6: // TCP
			if n < ihl+14 {
				continue
			}
			dstPort := binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
			flags := pkt[ihl+13]
			target := fmt.Sprintf("%s:%d", dstIP, dstPort)

			if flags&0x02 != 0 { // SYN
				go handleTUNTCPCommon(target)
			}

		case 17: // UDP
			if n < ihl+8 {
				continue
			}
			dstPort := binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
			payload := make([]byte, n-ihl-8)
			copy(payload, pkt[ihl+8:n])
			target := fmt.Sprintf("%s:%d", dstIP, dstPort)
			go handleTUNUDPCommon(target, payload)
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
		if ip := net.ParseIP(host); ip != nil {
			serverIPAddr = ip
			return
		}
		addrs, _ := net.LookupHost(host)
		if len(addrs) > 0 {
			serverIPAddr = net.ParseIP(addrs[0])
		}
	})
	return serverIPAddr
}

// Windows不需要的函数（在tun.go里定义）
func getDefaultGateway() string { return "" }

var _ = time.Second // 避免unused
