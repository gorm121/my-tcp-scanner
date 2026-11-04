package main

import (
	"net"
	"strings"
	"time"
)

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
