package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
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
	)

	flag.StringVar(&target, "target", "127.0.0.1", "target address")
	flag.StringVar(&portArg, "p", "1-1000", "Порты: например -p 22,80,443 или -p 1-1024")
	flag.IntVar(&threads, "t", 50, "Количество параллельных потоков (для connect-режима)")
	flag.IntVar(&timeoutMs, "timeout", 500, "Таймаут подключения / ожидания ответов (мс)")
	flag.StringVar(&scanMode, "scan", "syn", "Режим сканирования: 'syn' или 'connect'")
	flag.IntVar(&rateMs, "rate", 1, "Задержка между отправкой SYN-пакетов в мс")
	flag.BoolVar(&noBanner, "no-banner", false, "Отключить определение служб и баннеров")

	flag.Parse()

	portsList, err := parsePorts(portArg)
	if err != nil {
		fmt.Printf("[-] Ошибка парсинга портов: %v\n", err)
		return
	}

	var targets []string
	var dstIPS []net.IP
	var isCIDR bool = strings.Contains(target, "/")
	if isCIDR {
		fmt.Println("Собираем подсети...")
		ret, _ := parseCIDR(target)
		for _, value := range ret {
			dstIP, err := resolveTarget(value.String())
			if err != nil {
				fmt.Printf("[-] Ошибка разрешения цели: %v\n", err)
				continue
			}
			targets = append(targets, value.String())
			dstIPS = append(dstIPS, dstIP)

			fmt.Printf("Добавили %s (%s)\n", value.String(), dstIP)

		}
		fmt.Printf("Длина targets=%d, dstIPS=%d\n\n\n", len(targets), len(dstIPS))
	} else {
		dstIP, err := resolveTarget(target)
		if err != nil {
			fmt.Printf("[-] Ошибка разрешения цели: %v\n", err)
			return
		}

		targets = append(targets, target)
		dstIPS = append(dstIPS, dstIP)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	for i := 0; i < len(targets); i++ {
		tempDstIp := dstIPS[i]
		tempTarget := targets[i]

		timeout := time.Duration(timeoutMs) * time.Millisecond
		fmt.Printf("[*] Старт сканирования хоста %s (%s) [%d портов]...\n", tempTarget, tempDstIp, len(portsList))
		startTime := time.Now()

		fmt.Printf("[%d] Начинаем сканирование для %s \n", i, tempTarget)
		var results []Result

		switch strings.ToLower(scanMode) {
		case "syn":
			results, err = runSYNScan(ctx, tempTarget, tempDstIp, portsList, time.Duration(rateMs)*time.Millisecond, timeout, !noBanner)
			if err != nil {
				fmt.Printf("[-] Ошибка инициализации WinDivert: %v\n", err)
				fmt.Println("[!] Для работы с WinDivert (SYN-сканирование) требуются права Администратора.")
				fmt.Println("[*] Выполняется переключение на режим Connect-сканирования...\n")
				results = runConnectScan(ctx, tempTarget, timeout, threads, portsList, !noBanner)
			}
		case "connect":
			fmt.Printf("[*] Режим: TCP Connect сканирование (%d потоков)\n\n", threads)
			results = runConnectScan(ctx, tempTarget, timeout, threads, portsList, !noBanner)
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

		fmt.Printf("\n=== Итоговый отчет по хосту %s (%s) ===\n", tempTarget, tempDstIp)
		fmt.Printf("%-9s %-8s %s\n", "PORT", "STATE", "SERVICE / BANNER")
		fmt.Println("-------------------------------------------")
		for _, r := range results {
			fmt.Printf("%-9s %-8s %s\n", fmt.Sprintf("%d/tcp", r.Port), "open", r.Service)
		}
		fmt.Printf("\nВыполнено за %.2f сек. Открыто портов: %d\n\n\n", time.Since(startTime).Seconds(), len(results))
	}
}
