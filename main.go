package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/imgk/divert-go"
)

type Result struct {
	Port    int
	Service string
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

// Определение исходящего IP-адреса для маршрута до dstIP
func getOutboundIP(dstIP net.IP) (net.IP, error) {
	if dstIP.IsLoopback() {
		return net.IPv4(127, 0, 0, 1), nil
	}
	conn, err := net.Dial("udp", fmt.Sprintf("%s:80", dstIP.String()))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP, nil
}

// Разрешение хоста/IP в IPv4-адрес
func resolveTarget(target string) (net.IP, error) {
	if ip := net.ParseIP(target); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4, nil
		}
		return nil, fmt.Errorf("поддерживаются только IPv4-адреса: %s", target)
	}

	ips, err := net.LookupIP(target)
	if err != nil {
		return nil, fmt.Errorf("не удалось разрешить имя хоста %s: %w", target, err)
	}
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4, nil
		}
	}
	return nil, fmt.Errorf("IPv4-адрес для хоста %s не найден", target)
}

// Сниффер входящих пакетов через WinDivert
func sniffPackets(ctx context.Context, handle *divert.Handle, srcPort uint16, synAckChan chan<- int) {
	buf := make([]byte, 1500)
	addr := new(divert.Address)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := handle.Recv(buf, addr)
		if err != nil {
			// Handle закрыт или сканирование завершено/прервано
			return
		}

		// 0x02 = FlagOutbound: глушим исходящие системные RST от Windows, не отправляя их повторно
		if addr.Flags&0x02 != 0 {
			continue
		}

		if n >= 40 {
			ipHeaderLen := int(buf[0]&0x0F) * 4
			if ipHeaderLen < 20 || int(n) < ipHeaderLen+20 {
				continue
			}

			tcp := buf[ipHeaderLen:]
			srcP := binary.BigEndian.Uint16(tcp[0:2])
			dstP := binary.BigEndian.Uint16(tcp[2:4])
			tcpFlags := tcp[13]

			// Проверяем, что ответ адресован на наш локальный порт
			if dstP != srcPort {
				continue
			}

			// 0x12 = SYN (0x02) | ACK (0x10)
			if tcpFlags&0x12 == 0x12 {
				select {
				case <-ctx.Done():
					return
				case synAckChan <- int(srcP):
				}
			}
		}
	}
}

// Отправка crafted raw SYN-пакетов
func sendSYNPackets(ctx context.Context, handle *divert.Handle, srcIP, dstIP net.IP, srcPort uint16, ports []int, rateDelay time.Duration) {
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

		seq := rand.Uint32()
		pkt := craftSYNPacket(srcIP, dstIP, srcPort, uint16(port), seq)
		_, _ = handle.Send(pkt, &sendAddr)

		if rateDelay > 0 {
			time.Sleep(rateDelay)
		}
	}
}

// Определение сервиса / баннера
func probeService(conn net.Conn, port int) string {
	_ = conn.SetDeadline(time.Now().Add(800 * time.Millisecond))

	switch port {
	case 6379:
		_, _ = conn.Write([]byte("PING\r\n"))
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		if strings.Contains(string(buf[:n]), "+PONG") {
			return "Redis (без пароля!)"
		}
		return "Redis (защищен)"

	case 80, 8080, 8000:
		_, _ = conn.Write([]byte("HEAD / HTTP/1.0\r\nHost: target\r\n\r\n"))
		buf := make([]byte, 512)
		n, _ := conn.Read(buf)
		resp := string(buf[:n])
		for _, line := range strings.Split(resp, "\r\n") {
			if strings.HasPrefix(strings.ToLower(line), "server:") {
				return strings.TrimSpace(line[7:])
			}
		}
		return "HTTP Service"

	default:
		buf := make([]byte, 128)
		n, err := conn.Read(buf)
		if err == nil && n > 0 {
			clean := strings.Map(func(r rune) rune {
				if r >= 32 && r < 127 {
					return r
				}
				return -1
			}, string(buf[:n]))
			return strings.TrimSpace(clean)
		}
		return "unknown"
	}
}

func runSYNScan(ctx context.Context, target string, dstIP net.IP, ports []int, rateDelay time.Duration, waitTimeout time.Duration, probeBanners bool) ([]Result, error) {
	srcIP, err := getOutboundIP(dstIP)
	if err != nil {
		return nil, err
	}
	srcPort := uint16(rand.Intn(20000) + 40000)

	filter := fmt.Sprintf("(inbound and ip.SrcAddr == %s and tcp.DstPort == %d and tcp) or (outbound and ip.DstAddr == %s and tcp.SrcPort == %d and tcp.Rst)",
		dstIP, srcPort, dstIP, srcPort)

	handle, err := divert.Open(filter, divert.LayerNetwork, 0, divert.FlagDefault)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	foundChan := make(chan int, 100)

	// 1. Сниффер: слушает сеть, фильтрует дубли через локальный map и шлет уникальные порты в канал
	go func() {
		defer close(foundChan)
		seen := make(map[int]bool)
		buf := make([]byte, 1500)
		addr := new(divert.Address)

		for {
			n, err := handle.Recv(buf, addr)
			if err != nil || addr.Flags&0x02 != 0 || n < 40 {
				if err != nil {
					return
				} // ручка закрыта — выходим
				continue
			}
			tcp := buf[int(buf[0]&0x0F)*4:]
			if tcp[13]&0x12 == 0x12 { // SYN-ACK
				port := int(binary.BigEndian.Uint16(tcp[0:2]))
				if !seen[port] {
					seen[port] = true
					foundChan <- port
				}
			}
		}
	}()

	// 2. Отправитель (в фоне): выстрелил пакеты, подождал таймаут и закрыл сокет
	go func() {
		sendSYNPackets(ctx, handle, srcIP, dstIP, srcPort, ports, rateDelay)
		select {
		case <-ctx.Done():
		case <-time.After(waitTimeout):
		}
		handle.Close() // это остановит сниффер, и тот закроет foundChan
	}()

	// 3. Ждем таймаут ответов и закрываем handle (это корректно остановит сниффер)
	select {
	case <-ctx.Done():
	case <-time.After(waitTimeout):
	}
	handle.Close()

	// 4. Забираем результаты из канала и (при необходимости) снимаем баннеры
	var results []Result
	for port := range foundChan {
		fmt.Printf("[+] Порт %-5d ОТКРЫТ (получен SYN-ACK)\n", port)
		service := "open"
		if probeBanners {
			if conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", dstIP, port), 800*time.Millisecond); err == nil {
				service = probeService(conn, port)
				conn.Close()
			}
		}
		results = append(results, Result{Port: port, Service: service})
	}

	return results, nil
}

// Воркер для режима TCP Connect сканирования
func worker(ctx context.Context, target string, timeout time.Duration, ports <-chan int, results chan<- Result, wg *sync.WaitGroup, probeBanners bool) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case port, ok := <-ports:
			if !ok {
				return
			}

			d := net.Dialer{Timeout: timeout}
			conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", target, port))
			if err != nil {
				continue
			}

			service := "open"
			if probeBanners {
				service = probeService(conn, port)
			}
			_ = conn.Close()

			select {
			case <-ctx.Done():
				return
			case results <- Result{Port: port, Service: service}:
			}
		}
	}
}

// Выполнение стандартного TCP Connect сканирования
func runConnectScan(ctx context.Context, target string, timeout time.Duration, threads int, portsList []int, probeBanners bool) []Result {
	ports := make(chan int, threads)
	resultsChan := make(chan Result)
	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go worker(ctx, target, timeout, ports, resultsChan, &wg, probeBanners)
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
	for r := range resultsChan {
		fmt.Printf("[+] Найден открытый порт: %-5d | %s\n", r.Port, r.Service)
		found = append(found, r)
	}

	return found
}

func parsePorts(portArg string) ([]int, error) {
	portMap := make(map[int]bool)
	parts := strings.Split(portArg, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("неверный формат диапазона: %s", part)
			}
			start, err1 := strconv.Atoi(rangeParts[0])
			end, err2 := strconv.Atoi(rangeParts[1])

			if err1 != nil || err2 != nil || start < 1 || start > end || end > 65535 {
				return nil, fmt.Errorf("некорректный диапазон: %s", part)
			}
			for p := start; p <= end; p++ {
				portMap[p] = true
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("некорректный порт: %s", part)
			}
			portMap[p] = true
		}
	}

	var ports []int
	for p := range portMap {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

func main() {
	portArg := flag.String("p", "1-1000", "Порты: например -p 22,80,443 или -p 1-1024")
	threads := flag.Int("t", 50, "Количество параллельных потоков (для connect-режима)")
	timeoutMs := flag.Int("timeout", 500, "Таймаут подключения / ожидания ответов (мс)")
	scanMode := flag.String("scan", "syn", "Режим сканирования: 'syn' (WinDivert raw-пакеты) или 'connect' (TCP-соединение)")
	rateMs := flag.Int("rate", 1, "Задержка между отправкой SYN-пакетов в мс (для syn-режима)")
	noBanner := flag.Bool("no-banner", false, "Отключить определение служб и баннеров")
	flag.Parse()

	args := flag.Args()
	target := ""
	if len(args) > 0 {
		target = args[0]
	}

	portsList, err := parsePorts(*portArg)
	if err != nil {
		fmt.Printf("[-] Ошибка парсинга портов: %v\n", err)
		return
	}

	dstIP, err := resolveTarget(target)
	if err != nil {
		fmt.Printf("[-] Ошибка разрешения цели: %v\n", err)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	timeout := time.Duration(*timeoutMs) * time.Millisecond
	fmt.Printf("[*] Старт сканирования хоста %s (%s) [%d портов]...\n", target, dstIP, len(portsList))
	startTime := time.Now()

	var results []Result

	switch strings.ToLower(*scanMode) {
	case "syn":
		results, err = runSYNScan(ctx, target, dstIP, portsList, time.Duration(*rateMs)*time.Millisecond, timeout, !*noBanner)
		if err != nil {
			fmt.Printf("[-] Ошибка инициализации WinDivert: %v\n", err)
			fmt.Println("[!] Для работы с WinDivert (SYN-сканирование) требуются права Администратора.")
			fmt.Println("[*] Выполняется переключение на режим Connect-сканирования...\n")
			results = runConnectScan(ctx, target, timeout, *threads, portsList, !*noBanner)
		}
	case "connect":
		fmt.Printf("[*] Режим: TCP Connect сканирование (%d потоков)\n\n", *threads)
		results = runConnectScan(ctx, target, timeout, *threads, portsList, !*noBanner)
	default:
		fmt.Printf("[-] Неизвестный режим сканирования '%s'. Доступны: 'syn', 'connect'\n", *scanMode)
		return
	}

	if ctx.Err() != nil {
		fmt.Println("\n[!] Сканирование прервано пользователем (Ctrl+C).")
	}

	// Итоговый структурированный отчет
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	fmt.Printf("\n=== Итоговый отчет по хосту %s (%s) ===\n", target, dstIP)
	fmt.Printf("%-9s %-8s %s\n", "PORT", "STATE", "SERVICE / BANNER")
	fmt.Println("-------------------------------------------")
	for _, r := range results {
		fmt.Printf("%-9s %-8s %s\n", fmt.Sprintf("%d/tcp", r.Port), "open", r.Service)
	}
	fmt.Printf("\nВыполнено за %.2f сек. Открыто портов: %d\n", time.Since(startTime).Seconds(), len(results))
}
