package main

import (
	"encoding/binary"
	"math/rand"
	"net"
)

const (
	minSrcPort = 40000
	maxSrcPort = 65000
)

func getSrcPort() uint16 {
	return uint16(rand.Intn(maxSrcPort-minSrcPort+1) + minSrcPort)
}

// Вычисление 16-битной контрольной суммы (RFC 1071)
func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// Сборка IPv4 + TCP пакета с флагом SYN
func craftSYNPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq uint32) []byte {
	packet := make([]byte, 40) // 20 байт IP + 20 байт TCP

	// --- IPv4 Header (20 байт) ---
	packet[0] = 0x45                                                  // Version: 4, IHL: 5
	packet[1] = 0x00                                                  // DSCP / ECN
	binary.BigEndian.PutUint16(packet[2:4], 40)                       // Total Length
	binary.BigEndian.PutUint16(packet[4:6], uint16(rand.Intn(65535))) // ID
	binary.BigEndian.PutUint16(packet[6:8], 0x4000)                   // Flags: DF
	packet[8] = 64                                                    // TTL
	packet[9] = 6                                                     // Protocol: TCP (6)
	copy(packet[12:16], srcIP.To4())
	copy(packet[16:20], dstIP.To4())

	ipChecksum := checksum(packet[0:20])
	binary.BigEndian.PutUint16(packet[10:12], ipChecksum)

	// --- TCP Header (20 байт) ---
	tcp := packet[20:40]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], 0)      // Ack number
	tcp[12] = 0x50                                // Data offset: 5 (20 байт)
	tcp[13] = 0x02                                // Flags: SYN
	binary.BigEndian.PutUint16(tcp[14:16], 64240) // Window Size

	// --- Checksum TCP (Псевдозаголовок IP + TCP) ---
	pseudo := make([]byte, 12+20)
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[9] = 6 // TCP
	binary.BigEndian.PutUint16(pseudo[10:12], 20)
	copy(pseudo[12:], tcp)

	tcpChecksum := checksum(pseudo)
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum)

	return packet
}
