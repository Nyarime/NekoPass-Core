package main

import (
	"log"
	"net"
	"time"
)

func handleTUNTCPCommon(target string) {
	if !shouldProxy(target) {
		return
	}
	remote, err := dialForTCP()
	if err != nil {
		log.Printf("[TUN] TCP %s 连接失败: %v", target, err)
		return
	}
	defer remote.Close()
	remote.Write([]byte(target))
	ack := make([]byte, 1)
	if _, err := remote.Read(ack); err != nil || ack[0] != 0x01 {
		return
	}
	remote.SetReadDeadline(time.Now().Add(5 * time.Minute))
	buf := make([]byte, 4096)
	for {
		_, err := remote.Read(buf)
		if err != nil { return }
		remote.SetReadDeadline(time.Now().Add(5 * time.Minute))
	}
}

func handleTUNUDPCommon(target string, payload []byte) {
	if !shouldProxy(target) {
		addr, _ := net.ResolveUDPAddr("udp", target)
		if addr != nil {
			conn, _ := net.DialUDP("udp", nil, addr)
			if conn != nil {
				conn.Write(payload)
				conn.Close()
			}
		}
		return
	}
	remote, err := dialForUDP()
	if err != nil { return }
	defer remote.Close()
	remote.Write([]byte("UDP:" + target))
	ack := make([]byte, 1)
	if _, err := remote.Read(ack); err != nil || ack[0] != 0x01 { return }
	remote.Write(payload)
}
