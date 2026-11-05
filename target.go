package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func parseCIDR(cidr string) ([]net.IP, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var result []net.IP

	num := binary.BigEndian.Uint32(ipNet.IP.To4())
	nextIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(nextIP, num)

	for {
		if ipNet.Contains(nextIP) {
			result = append(result, nextIP)
			num++
			nextIP = make(net.IP, 4)
			binary.BigEndian.PutUint32(nextIP, num)
		} else {
			return result, nil
		}
	}

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

func discoverAliveHosts(ctx context.Context, targets []net.IP, timeout time.Duration) []net.IP {
	var (
		alive []net.IP
		mu    sync.Mutex
		wg    sync.WaitGroup
	)

	for _, ip := range targets {
		wg.Add(1)
		go func(targetIP net.IP) {
			defer wg.Done()
			if isAlive(ctx, targetIP, timeout) {
				mu.Lock()
				alive = append(alive, targetIP)
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	fmt.Printf("[+] Обнаружено %d живых хостов\n", len(alive))
	sort.Slice(alive, func(i, j int) bool {
		return binary.BigEndian.Uint32(alive[i].To4()) < binary.BigEndian.Uint32(alive[j].To4())
	})

	return alive
}

func isAlive(ctx context.Context, ip net.IP, timeout time.Duration) bool {
	ports := []int{80, 443, 445, 22, 135}
	d := net.Dialer{Timeout: timeout}

	for _, p := range ports {
		conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ip, p))

		if err == nil {
			conn.Close()
			return true
		}

		if strings.Contains(strings.ToLower(err.Error()), "refused") {
			return true
		}
	}

	return false
}
