package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ScanResult struct {
	Target  string `json:"target"`
	Port    int    `json:"port"`
	Success bool   `json:"success"`
	Banner  string `json:"banner,omitempty"`
}

func worker(wg *sync.WaitGroup, tasks chan string, dialer net.Dialer, results chan ScanResult, timeout time.Duration) {
	defer wg.Done()
	maxRetries := 2
	for addr := range tasks {
		var success bool
		var banner string
		for i := 0; i < maxRetries; i++ {
			conn, err := dialer.Dial("tcp", addr)
			if err == nil {
				conn.SetDeadline(time.Now().Add(timeout))
				buf := make([]byte, 1024) // Buffer to read data from the connection
				n, err := conn.Read(buf)
				if err == nil && n > 0 {
					banner = string(buf[:n]) // Store the banner (initial server response)
				}
				conn.Close()

				portStr := strings.Split(addr, ":")[1]
				port, err := strconv.Atoi(portStr)
				if err != nil {
					fmt.Printf("Failed to parse port %s\n", portStr)
					continue
				}

				success = true
				if banner != "" {
					results <- ScanResult{
						Target:  strings.Split(addr, ":")[0],
						Port:    port,
						Success: true,
						Banner:  banner,
					}
				} else {
					// If no banner is received, report "No response"
					results <- ScanResult{
						Target:  strings.Split(addr, ":")[0],
						Port:    port,
						Success: true,
						Banner:  "No response",
					}
				}
				break
			}
			backoff := time.Duration(1<<i) * time.Second
			time.Sleep(backoff)
		}
		if !success {
			portStr := strings.Split(addr, ":")[1]
			port, err := strconv.Atoi(portStr)
			if err != nil {
				fmt.Printf("Failed to parse port %s\n", portStr)
				continue
			}

			results <- ScanResult{
				Target:  strings.Split(addr, ":")[0],
				Port:    port,
				Success: false,
			}
		}
	}
}

func main() {
	targets := flag.String("target", "scanme.nmap.org", "Comma-separated list of target hosts or IP addresses")
	startPort := flag.Int("start-port", 0, "Start port for the scan")
	endPort := flag.Int("end-port", 100, "End port for the scan")
	workers := flag.Int("workers", 100, "Number of concurrent workers")
	timeout := flag.Int("timeout", 1, "Timeout for each connection in seconds")
	jsonOutput := flag.Bool("json", false, "Output results in JSON format")
	flag.Parse()

	targetList := strings.Split(*targets, ",")
	var wg sync.WaitGroup
	tasks := make(chan string, *workers)
	results := make(chan ScanResult)

	dialer := net.Dialer{
		Timeout: time.Duration(*timeout) * time.Second,
	}

	for i := 1; i <= *workers; i++ {
		wg.Add(1)
		go worker(&wg, tasks, dialer, results, time.Duration(*timeout)*time.Second)
	}

	startTime := time.Now()
	totalPortsToScan := (*endPort - *startPort + 1) * len(targetList)
	for _, target := range targetList {
		for p := *startPort; p <= *endPort; p++ {
			port := strconv.Itoa(p)
			address := net.JoinHostPort(target, port)
			tasks <- address

			fmt.Printf("Scanning port %d/%d for target %s\n", p-*startPort+1, totalPortsToScan, target)

			time.Sleep(100 * time.Millisecond)
		}
	}

	close(tasks)

	go func() {
		wg.Wait()
		close(results)
	}()

	var openPorts []ScanResult
	var totalPorts int
	for result := range results {
		totalPorts++
		if result.Success {
			openPorts = append(openPorts, result)
		}
	}

	elapsedTime := time.Since(startTime)

	if *jsonOutput {
		output, err := json.MarshalIndent(openPorts, "", "  ")
		if err != nil {
			fmt.Println("Error marshalling JSON:", err)
			os.Exit(1)
		}
		fmt.Println(string(output))
	} else {
		fmt.Printf("\nScan Summary:\n")
		fmt.Printf("Targets: %s\n", *targets)
		fmt.Printf("Total ports scanned: %d\n", totalPorts)
		fmt.Printf("Open ports: %d\n", len(openPorts))
		fmt.Printf("Scan completed in: %v\n", elapsedTime)

		for _, result := range openPorts {
			fmt.Printf("Target %s: Port %d open\n", result.Target, result.Port)
			if result.Banner != "" && result.Banner != "No response" {
				fmt.Printf("Banner: %s\n", result.Banner)
			} else if result.Banner == "No response" {
				fmt.Printf("Target %s: Port %d open, but no response received.\n", result.Target, result.Port)
			}
		}
	}
}
