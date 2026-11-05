package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type UDPService struct {
	Name    string
	Payload []byte
}

var udpServices = map[int]UDPService{
	53:   {Name: "DNS", Payload: buildDNSQuery("google.com")},
	69:   {Name: "TFTP", Payload: []byte{0x00, 0x01, 't', 'e', 's', 't', 0x00, 'o', 'c', 't', 'e', 't', 0x00}},
	123:  {Name: "NTP", Payload: buildNTPQuery()},
	137:  {Name: "NetBIOS", Payload: buildNetBIOSQuery()},
	161:  {Name: "SNMP", Payload: buildSNMPQuery()},
	1434: {Name: "MSSQL Browser", Payload: []byte{0x02}},
	1900: {Name: "SSDP / UPnP", Payload: []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")},
	5353: {Name: "mDNS", Payload: buildDNSQuery("local")},
}

func buildNetBIOSQuery() []byte {
	return []byte{
		0x80, 0xf0, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
		0x00, 0x01,
	}
}

func buildSNMPQuery() []byte {
	return []byte{
		0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',
		0xa0, 0x19, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02,
		0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02,
		0x01, 0x01, 0x01, 0x00,
	}
}

func buildNTPQuery() []byte {
	pkt := make([]byte, 48)
	pkt[0] = 0x1b // LI=0, VN=3, Mode=3 (client)
	return pkt
}

func buildDNSQuery(domain string) []byte {
	var buf []byte

	// 12 байт стандартного DNS заголовка
	buf = append(buf, 0x12, 0x34) // Transaction ID (любые 2 байта)
	buf = append(buf, 0x01, 0x00) // Flags: Standard query + Recursion Desired
	buf = append(buf, 0x00, 0x01) // QDCOUNT = 1 вопрос
	buf = append(buf, 0x00, 0x00) // ANCOUNT = 0 ответов
	buf = append(buf, 0x00, 0x00) // NSCOUNT = 0
	buf = append(buf, 0x00, 0x00) // ARCOUNT = 0

	// Доменное имя: "google.com" -> [6]google[3]com[0]
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0x00) // Нулевой байт - конец домена

	buf = append(buf, 0x00, 0x01) // QTYPE: A-запись (IPv4)
	buf = append(buf, 0x00, 0x01) // QCLASS: IN (Internet)

	return buf
}

func runUDPScan(ctx context.Context, target string, threads int, portsList []int, waitTimeout time.Duration) []Result {
	ports := make(chan int, threads)
	resultsChan := make(chan Result)
	var wg sync.WaitGroup

	for range threads {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for {
				select {
				case <-ctx.Done():
					return
				case port, ok := <-ports:
					if !ok {
						return
					}

					probe, known := udpServices[port]
					payload := probe.Payload
					if !known || len(payload) == 0 {
						payload = []byte{0x00}
					}

					conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", target, port), waitTimeout)
					if err != nil {
						continue
					}
					_ = conn.SetDeadline(time.Now().Add(waitTimeout))
					_, _ = conn.Write(payload)
					buf := make([]byte, 1024)
					n, err := conn.Read(buf)
					conn.Close()
					if err == nil && n > 0 {
						service := "open"
						if known && probe.Name != "" {
							service = probe.Name
						}
						select {
						case <-ctx.Done():
							return
						case resultsChan <- Result{Port: port, Service: service}:
						}
					}
				}
			}
		}()
	}

	go func() {
		defer close(ports)
		for _, p := range portsList {
			select {
			case <-ctx.Done():
				return
			case ports <- p:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var found []Result
	for {
		select {
		case <-ctx.Done():
			return found
		case r, ok := <-resultsChan:
			if !ok {
				return found
			}
			fmt.Printf("[+] Найден открытый UDP порт: %-5d | %s\n", r.Port, r.Service)
			found = append(found, r)
		}
	}

}
