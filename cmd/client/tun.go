//go:build linux || darwin

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"runtime"
	"sync"

	"github.com/songgao/water"
)






// 定期清理过期连接

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

	// 解析服务器IP（路由豁免）
	serverIP := resolveServerIP()

	// 配置TUN设备
	switch runtime.GOOS {
	case "linux":
		run("ip", "link", "set", tunName, "up")
		run("ip", "addr", "add", "10.0.85.1/24", "dev", tunName)
		run("ip", "link", "set", tunName, "mtu", fmt.Sprintf("%d", mtu))
		// 服务器IP豁免（必须在添加默认路由前）
		if serverIP != nil {
			gateway := getDefaultGateway()
			if gateway != "" {
				run("ip", "route", "add", serverIP.String()+"/32", "via", gateway)
			}
		}
		run("ip", "route", "add", "0.0.0.0/1", "dev", tunName)
		run("ip", "route", "add", "128.0.0.0/1", "dev", tunName)
	case "darwin":
		run("ifconfig", tunName, "10.0.85.1", "10.0.85.2", "up")
		run("ifconfig", tunName, "mtu", fmt.Sprintf("%d", mtu))
		if serverIP != nil {
			gateway := getDefaultGateway()
			if gateway != "" {
				run("route", "add", "-host", serverIP.String(), gateway)
			}
		}
		run("route", "add", "-net", "0.0.0.0/1", "10.0.85.2")
		run("route", "add", "-net", "128.0.0.0/1", "10.0.85.2")
	}

	log.Printf("[TUN] %s 已启动 (MTU=%d)", tunName, mtu)

	// 启动连接清理
	go connTrack.cleanup()

	var tcpCount, udpCount, skipCount int64

	buf := make([]byte, 65536)
	for {
		n, err := iface.Read(buf)
		if err != nil {
			return
		}
		if n < 20 {
			continue
		}

		version := buf[0] >> 4
		if version != 4 {
			continue
		}

		protocol := buf[9]
		srcIP := net.IP(make([]byte, 4))
		dstIP := net.IP(make([]byte, 4))
		copy(srcIP, buf[12:16])
		copy(dstIP, buf[16:20])
		ihl := int(buf[0]&0x0F) * 4

		// 跳过发往服务器的包
		if serverIP != nil && dstIP.Equal(serverIP) {
			skipCount++
			continue
		}

		switch protocol {
		case 6: // TCP
			if n < ihl+4 {
				continue
			}
			srcPort := binary.BigEndian.Uint16(buf[ihl : ihl+2])
			dstPort := binary.BigEndian.Uint16(buf[ihl+2 : ihl+4])
			target := fmt.Sprintf("%s:%d", dstIP, dstPort)
			connKey := fmt.Sprintf("%s:%d-%s", srcIP, srcPort, target)

			// TCP flags
			flags := buf[ihl+13]
			syn := flags&0x02 != 0
			fin := flags&0x01 != 0
			rst := flags&0x04 != 0

			if fin || rst {
				if conn, ok := connTrack.Get(connKey); ok {
					conn.Close()
					connTrack.Delete(connKey)
				}
				continue
			}

			if syn {
				// 新TCP连接
				tcpCount++
				go handleTUNTCPCommon(target)
			}

		case 17: // UDP
			if n < ihl+8 {
				continue
			}
			dstPort := binary.BigEndian.Uint16(buf[ihl+2 : ihl+4])
			payload := make([]byte, n-ihl-8)
			copy(payload, buf[ihl+8:n])
			target := fmt.Sprintf("%s:%d", dstIP, dstPort)
			udpCount++

			go handleTUNUDPCommon(target, payload)
		}
	}
}



func run(name string, args ...string) {
	if err := exec.Command(name, args...).Run(); err != nil {
		log.Printf("[TUN] %s %v: %v", name, args, err)
	}
}

func getDefaultGateway() string {
	switch runtime.GOOS {
	case "linux":
		out, err := exec.Command("ip", "route", "show", "default").Output()
		if err != nil {
			return ""
		}
		// "default via 1.2.3.4 dev eth0"
		fields := splitFields(string(out))
		for i, f := range fields {
			if f == "via" && i+1 < len(fields) {
				return fields[i+1]
			}
		}
	case "darwin":
		out, err := exec.Command("route", "-n", "get", "default").Output()
		if err != nil {
			return ""
		}
		fields := splitFields(string(out))
		for i, f := range fields {
			if f == "gateway:" && i+1 < len(fields) {
				return fields[i+1]
			}
		}
	}
	return ""
}

func splitFields(s string) []string {
	var fields []string
	field := ""
	for _, c := range s {
		if c == ' ' || c == '\n' || c == '\t' {
			if field != "" {
				fields = append(fields, field)
				field = ""
			}
		} else {
			field += string(c)
		}
	}
	if field != "" {
		fields = append(fields, field)
	}
	return fields
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
		addrs, err := net.LookupHost(host)
		if err == nil && len(addrs) > 0 {
			serverIPAddr = net.ParseIP(addrs[0])
		}
	})
	return serverIPAddr
}

// io包用于编译
var _ = io.EOF
