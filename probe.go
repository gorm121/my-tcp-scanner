package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
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
		_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"))
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		resp := string(buf[:n])

		re := regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
		match := re.FindStringSubmatch(resp)
		if len(match) > 1 {
			title := strings.TrimSpace(match[1])
			return title
		}

		for _, line := range strings.Split(resp, "\r\n") {
			if strings.HasPrefix(strings.ToLower(line), "server:") {
				return strings.TrimSpace(line[7:])
			}
		}
		return "HTTP Service"

	case 443, 8443:
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}

		tlsConn := tls.Client(conn, tlsConfig)

		if err := tlsConn.Handshake(); err != nil {
			return "HTTPS (TLS handshake failed)"
		}

		certs := tlsConn.ConnectionState().PeerCertificates
		if len(certs) == 0 {
			return "HTTPS (no certs)"
		}

		leafCert := certs[0]
		var res strings.Builder
		_, _ = res.WriteString("HTTPS [CN:" + leafCert.Subject.CommonName + "] (SAN: ")
		sans := leafCert.DNSNames
		if len(sans) > 10 {
			sans = append(sans[:10], fmt.Sprintf("...+%d more", len(sans)-10))
		}
		sanStr := strings.Join(sans, ", ")
		return fmt.Sprintf("HTTPS [CN: %s] (SAN: %s)", leafCert.Subject.CommonName, sanStr)

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
