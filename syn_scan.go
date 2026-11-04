package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/imgk/divert-go"
)

// Отправка crafted raw SYN-пакетов
func sendSYNPackets(ctx context.Context, handle *divert.Handle, srcIP, dstIP net.IP, ports []int, rateDelay time.Duration) {
	var sendAddr divert.Address
	sendAddr.SetLayer(divert.LayerNetwork)
	sendAddr.Flags = 0x02 // Outbound
	if dstIP.IsLoopback() {
		sendAddr.Flags |= 0x04 // Loopback
	}

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return
		default:
		}

		seq := uint32(port) ^ secretKey
		srcPort := getSrcPort()
		pkt := craftSYNPacket(srcIP, dstIP, srcPort, uint16(port), seq)
		_, err := handle.Send(pkt, &sendAddr)
		if err != nil {
			fmt.Printf("Порт %d ошибка: %v\n", port, err)
			continue
		}

		if rateDelay > 0 {
			time.Sleep(rateDelay)
		}
	}
}

func runSYNScan(ctx context.Context, target string, dstIP net.IP, ports []int, rateDelay time.Duration, waitTimeout time.Duration, probeBanners bool) ([]Result, error) {
	srcIP, err := getOutboundIP(dstIP)
	if err != nil {
		return nil, err
	}

	filter := fmt.Sprintf(
		"(inbound and ip.SrcAddr == %s and tcp.DstPort >= %d and tcp.DstPort <= %d and tcp.Syn and tcp.Ack) or "+
			"(outbound and ip.DstAddr == %s and tcp.SrcPort >= %d and tcp.SrcPort <= %d and tcp.Rst)",
		dstIP, minSrcPort, maxSrcPort,
		dstIP, minSrcPort, maxSrcPort,
	)

	handle, err := divert.Open(filter, divert.LayerNetwork, 0, divert.FlagDefault)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	var (
		openPorts []int
		mu        sync.Mutex
	)

	// фоновый sniffer
	snifferDone := make(chan struct{})
	go func() {
		defer close(snifferDone)
		seen := make(map[int]bool)
		buf := make([]byte, 1500)
		addr := new(divert.Address)

		for {
			n, err := handle.Recv(buf, addr)
			if err != nil || addr.Flags&0x02 != 0 || n < 40 {
				if err != nil {
					return // handle закрыт — выходим
				}
				continue
			}

			ipHeaderLen := uint(buf[0]&0x0F) * 4
			if n < ipHeaderLen+20 {
				continue
			}
			tcp := buf[ipHeaderLen:]
			ackNum := binary.BigEndian.Uint32(tcp[8:12])

			if tcp[13]&0x12 == 0x12 { // SYN-ACK
				port := int(binary.BigEndian.Uint16(tcp[0:2]))
				if ackNum-1 == (uint32(port) ^ secretKey) {
					mu.Lock()
					if !seen[port] {
						seen[port] = true
						openPorts = append(openPorts, port)
						fmt.Printf("[+] [SYN-ACK] Порт %-5d ОТКРЫТ\n", port)
					}
					mu.Unlock()
				}
			}
		}
	}()

	fmt.Printf("[*] Этап 1: Отправка %d SYN-пакетов...\n", len(ports))
	sendSYNPackets(ctx, handle, srcIP, dstIP, ports, rateDelay)

	// ждем ответы до таймаута или до ctrl+c
	fmt.Printf("[*] Этап 2: Все пакеты отправлены. Ожидание ответов (%v)...\n", waitTimeout)
	select {
	case <-ctx.Done():
	case <-time.After(waitTimeout):
	}

	// Закрываем сокет и дожидаемся завершения сниффера
	handle.Close()
	<-snifferDone

	sort.Ints(openPorts)

	// сборка результатов
	var results []Result
	if probeBanners && len(openPorts) > 0 {
		fmt.Printf("\n[*] Этап 3: Определение служб и баннеров (%d портов)...\n", len(openPorts))
		for _, port := range openPorts {
			service := "open"
			if conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", dstIP, port), 800*time.Millisecond); err == nil {
				service = probeService(conn, port)
				conn.Close()
			}
			fmt.Printf("    -> %-5d/tcp : %s\n", port, service)
			results = append(results, Result{Port: port, Service: service})
		}
	} else {
		for _, port := range openPorts {
			results = append(results, Result{Port: port, Service: "open"})
		}
	}

	return results, nil
}
