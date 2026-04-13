package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"
)

// handleUDPAssociate SOCKS5 UDP ASSOCIATE (RFC 1928)
func handleUDPAssociate(tcpConn net.Conn) {
	// 开本地UDP口
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		tcpConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	localAddr := udpConn.LocalAddr().(*net.UDPAddr)

	// 回复客户端UDP地址
	resp := make([]byte, 10)
	resp[0] = 0x05
	resp[1] = 0x00
	resp[3] = 0x01
	copy(resp[4:8], net.ParseIP("127.0.0.1").To4())
	binary.BigEndian.PutUint16(resp[8:10], uint16(localAddr.Port))
	tcpConn.Write(resp)

	log.Printf("[UDP] ASSOCIATE :%d", localAddr.Port)

	go udpRelay(udpConn, tcpConn)
}

// udpRelay 通过NRUP转发UDP
func udpRelay(udpConn *net.UDPConn, tcpConn net.Conn) {
	defer udpConn.Close()

	var clientAddr *net.UDPAddr
	buf := make([]byte, 65536)

	// TCP连接关闭时停止relay
	go func() {
		b := make([]byte, 1)
		tcpConn.Read(b) // 阻塞到TCP断开
		udpConn.Close()
	}()

	for {
		udpConn.SetReadDeadline(time.Now().Add(120 * time.Second))
		n, addr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if clientAddr == nil {
			clientAddr = addr
		}
		if n < 4 {
			continue
		}

		// 解析SOCKS5 UDP头
		// [2B RSV][1B FRAG][1B ATYP][ADDR][2B PORT][DATA]
		frag := buf[2]
		if frag != 0 {
			continue // 不支持分片
		}

		atyp := buf[3]
		var target string
		var dataOffset int

		switch atyp {
		case 0x01: // IPv4
			if n < 10 { continue }
			target = fmt.Sprintf("%d.%d.%d.%d:%d",
				buf[4], buf[5], buf[6], buf[7],
				binary.BigEndian.Uint16(buf[8:10]))
			dataOffset = 10
		case 0x03: // Domain
			dLen := int(buf[4])
			if n < 5+dLen+2 { continue }
			target = fmt.Sprintf("%s:%d",
				string(buf[5:5+dLen]),
				binary.BigEndian.Uint16(buf[5+dLen:7+dLen]))
			dataOffset = 7 + dLen
		case 0x04: // IPv6
			if n < 22 { continue }
			target = fmt.Sprintf("[%s]:%d",
				net.IP(buf[4:20]).String(),
				binary.BigEndian.Uint16(buf[20:22]))
			dataOffset = 22
		default:
			continue
		}

		payload := buf[dataOffset:n]
		header := make([]byte, dataOffset)
		copy(header, buf[:dataOffset])

		if shouldProxy(target) {
			go udpProxyPacket(udpConn, clientAddr, target, header, payload)
		} else {
			go udpDirectPacket(udpConn, clientAddr, target, header, payload)
		}
	}
}

// udpProxyPacket 通过NRUP转发单个UDP包
func udpProxyPacket(udpConn *net.UDPConn, clientAddr *net.UDPAddr, target string, header, payload []byte) {
	remote, err := smartDialForUDP()
	if err != nil {
		return
	}
	defer remote.Close()

	// 告诉服务端目标（加UDP标记）
	remote.Write([]byte("UDP:" + target))

	ack := make([]byte, 1)
	if _, err := remote.Read(ack); err != nil || ack[0] != 0x01 {
		return
	}

	// 发数据
	remote.Write(payload)

	// 读回复
	resp := make([]byte, 65536)
	remote.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := remote.Read(resp)
	if err != nil || n == 0 {
		return
	}

	// 封装SOCKS5 UDP响应
	reply := append(header, resp[:n]...)
	udpConn.WriteToUDP(reply, clientAddr)
}

// udpDirectPacket 直连UDP
func udpDirectPacket(udpConn *net.UDPConn, clientAddr *net.UDPAddr, target string, header, payload []byte) {
	rAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return
	}

	conn, err := net.DialUDP("udp", nil, rAddr)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.Write(payload)

	resp := make([]byte, 65536)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(resp)
	if err != nil || n == 0 {
		return
	}

	reply := append(header, resp[:n]...)
	udpConn.WriteToUDP(reply, clientAddr)
}
