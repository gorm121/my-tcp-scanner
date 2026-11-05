package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"
)

var secretKey uint32

func init() {
	secretKey = rand.Uint32()
}

type Result struct {
	Port    int
	Service string
}

func main() {
	var (
		target    string
		portArg   string
		threads   int
		timeoutMs int
		scanMode  string
		rateMs    int
		noBanner  bool
		discover  bool
	)

	flag.StringVar(&target, "target", "127.0.0.1", "target address")
	flag.StringVar(&portArg, "p", "1-1000", "Порты: например -p 22,80,443 или -p 1-1024")
	flag.IntVar(&threads, "t", 50, "Количество параллельных потоков (для connect-режима)")
	flag.IntVar(&timeoutMs, "timeout", 500, "Таймаут подключения / ожидания ответов (мс)")
	flag.StringVar(&scanMode, "scan", "syn", "Режим сканирования: 'syn' или 'connect'")
	flag.IntVar(&rateMs, "rate", 1, "Задержка между отправкой SYN-пакетов в мс")
	flag.BoolVar(&noBanner, "no-banner", false, "Отключить определение служб и баннеров")
	flag.BoolVar(&discover, "discover", false, "Предварительный поиск активных хостов перед сканированием")

	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	portsList, err := parsePorts(portArg)
	if err != nil {
		fmt.Printf("[-] Ошибка парсинга портов: %v\n", err)
		return
	}

	rand.Shuffle(len(portsList), func(i, j int) {
		portsList[i], portsList[j] = portsList[j], portsList[i]
	})

	var targets []net.IP
	var isCIDR bool = strings.Contains(target, "/")
	if isCIDR {
		fmt.Println("[*] Сбор адресов подсети...")
		var err error
		targets, err = parseCIDR(target)
		if err != nil {
			fmt.Printf("[-] Ошибка парсинга CIDR: %v\n", err)
			return
		}
		fmt.Printf("[*] Найдено хостов в подсети: %d\n\n", len(targets))
	} else {
		dstIP, err := resolveTarget(target)
		if err != nil {
			fmt.Printf("[-] Ошибка разрешения цели: %v\n", err)
			return
		}
		targets = append(targets, dstIP)
	}

	if discover && isCIDR {
		fmt.Println("[*] Предварительный поиск активных хостов (ping)...")
		targets = discoverAliveHosts(ctx, targets, time.Millisecond*300)
		if len(targets) == 0 {
			fmt.Println("[*] Живых хостов не обнаружено.")
			return
		}
		fmt.Printf("[+] Готово к сканированию: %d хостов\n\n", len(targets))
	}

	for i, ip := range targets {
		ipStr := ip.String()

		timeout := time.Duration(timeoutMs) * time.Millisecond
		fmt.Printf("[*] Старт сканирования хоста %s [%d портов]...\n", ipStr, len(portsList))
		startTime := time.Now()

		fmt.Printf("[%d] Начинаем сканирование для %s\n", i, ipStr)
		var results []Result

		switch strings.ToLower(scanMode) {
		case "syn":
			results, err = runSYNScan(ctx, ipStr, ip, portsList, time.Duration(rateMs)*time.Millisecond, timeout, !noBanner)
			if err != nil {
				fmt.Printf("[-] Ошибка инициализации WinDivert: %v\n", err)
				fmt.Println("[!] Для работы с WinDivert (SYN-сканирование) требуются права Администратора.")
				fmt.Println("[*] Выполняется переключение на режим Connect-сканирования...\n")
				results = runConnectScan(ctx, ipStr, timeout, threads, portsList, !noBanner)
			}
		case "connect":
			fmt.Printf("[*] Режим: TCP Connect сканирование (%d потоков)\n\n", threads)
			results = runConnectScan(ctx, ipStr, timeout, threads, portsList, !noBanner)
		case "udp":
			fmt.Printf("[*] Режим: UDP сканирование (%d потоков)\n\n", threads)
			results = runUDPScan(ctx, ipStr, threads, portsList, timeout)
		default:
			fmt.Printf("[-] Неизвестный режим сканирования '%s'. Доступны: 'syn', 'connect'\n", scanMode)
			return
		}

		if ctx.Err() != nil {
			fmt.Println("\n[!] Сканирование прервано пользователем (Ctrl+C).")
			break
		}

		sort.Slice(results, func(i, j int) bool {
			return results[i].Port < results[j].Port
		})

		fmt.Printf("\n=== Итоговый отчет по хосту %s ===\n", ipStr)
		fmt.Printf("%-9s %-8s %s\n", "PORT", "STATE", "SERVICE / BANNER")
		fmt.Println("-------------------------------------------")
		proto := "tcp"
		if strings.ToLower(scanMode) == "udp" {
			proto = "udp"
		}
		for _, r := range results {
			fmt.Printf("%-9s %-8s %s\n", fmt.Sprintf("%d/%s", r.Port, proto), "open", r.Service)
		}
		fmt.Printf("\nВыполнено за %.2f сек. Открыто портов: %d\n\n\n", time.Since(startTime).Seconds(), len(results))
	}
}
