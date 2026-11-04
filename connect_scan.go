package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

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
