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

// ScanResult struct holds the scan results for each target and port
type ScanResult struct {
	Target  string `json:"target"`
	Port    int    `json:"port"`
	Success bool   `json:"success"`
	Banner  string `json:"banner,omitempty"`
}

// worker function handles scanning tasks concurrently
func worker(wg *sync.WaitGroup, tasks chan string, dialer net.Dialer, results chan ScanResult, timeout time.Duration) {
	defer wg.Done()
	maxRetries := 2 // Maximum retries for connection attempts

	// Process each address from the tasks channel
	for addr := range tasks {
		var success bool
		var banner string

		// Retry logic for connecting to the target
		for i := 0; i < maxRetries; i++ {
			conn, err := dialer.Dial("tcp", addr)
			if err == nil {
				conn.SetDeadline(time.Now().Add(timeout))
				buf := make([]byte, 1024) // Buffer to read server response
				n, err := conn.Read(buf)
				if err == nil && n > 0 {
					banner = string(buf[:n]) // Store received banner
				}
				conn.Close()

				// Extract the port number from the address
				portStr := strings.Split(addr, ":")[1]
				port, err := strconv.Atoi(portStr)
				if err != nil {
					fmt.Printf("Failed to parse port %s\n", portStr)
					continue
				}

				success = true
				// Send scan result to results channel
				if banner != "" {
					results <- ScanResult{Target: strings.Split(addr, ":")[0], Port: port, Success: true, Banner: banner}
				} else {
					results <- ScanResult{Target: strings.Split(addr, ":")[0], Port: port, Success: true, Banner: "No response"}
				}
				break
			}

			// Exponential backoff for retry
			backoff := time.Duration(1<<i) * time.Second
			time.Sleep(backoff)
		}

		// If all retries fail, mark the port as closed
		if !success {
			portStr := strings.Split(addr, ":")[1]
			port, err := strconv.Atoi(portStr)
			if err != nil {
				fmt.Printf("Failed to parse port %s\n", portStr)
				continue
			}
			results <- ScanResult{Target: strings.Split(addr, ":")[0], Port: port, Success: false}
		}
	}
}

func main() {
	// Parse command-line arguments to configure the scanner
	targets := flag.String("target", "scanme.nmap.org", "Comma-separated list of target hosts or IP addresses")
	// Defines the range of ports to scan
	startPort := flag.Int("start-port", 0, "Start port for the scan")
	endPort := flag.Int("end-port", 100, "End port for the scan")
	// Determines the number of concurrent worker goroutines
	workers := flag.Int("workers", 100, "Number of concurrent workers")
	// Specifies the timeout duration for each connection attempt
	timeout := flag.Int("timeout", 1, "Timeout for each connection in seconds")
	// Outputs scan results in JSON format if enabled
	jsonOutput := flag.Bool("json", false, "Output results in JSON format")
	flag.Parse()

	// Convert target string into a list of targets
	targetList := strings.Split(*targets, ",")
	var wg sync.WaitGroup
	tasks := make(chan string, *workers)
	results := make(chan ScanResult)

	// Configure the network dialer
	dialer := net.Dialer{
		Timeout: time.Duration(*timeout) * time.Second,
	}

	// Start worker goroutines to process scan tasks
	for i := 1; i <= *workers; i++ {
		wg.Add(1)
		go worker(&wg, tasks, dialer, results, time.Duration(*timeout)*time.Second)
	}

	// Track scan start time for performance metrics
	startTime := time.Now()
	totalPortsToScan := (*endPort - *startPort + 1) * len(targetList)

	// Generate tasks for each target and port
	for _, target := range targetList {
		for p := *startPort; p <= *endPort; p++ {
			port := strconv.Itoa(p)
			address := net.JoinHostPort(target, port)
			tasks <- address

			// Provide real-time feedback on scan progress
			fmt.Printf("Scanning port %d/%d for target %s\n", p-*startPort+1, totalPortsToScan, target)

			// Delay to avoid overwhelming the system
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Close task channel to signal workers that no more tasks will be added
	close(tasks)

	// Wait for all workers to finish, then close results channel
	go func() {
		wg.Wait()
		close(results)
	}()

	// Process scan results
	var openPorts []ScanResult
	var totalPorts int
	for result := range results {
		totalPorts++
		if result.Success {
			openPorts = append(openPorts, result)
		}
	}

	// Calculate scan duration
	elapsedTime := time.Since(startTime)

	// Output results in JSON format if requested
	if *jsonOutput {
		output, err := json.MarshalIndent(openPorts, "", "  ")
		if err != nil {
			fmt.Println("Error marshalling JSON:", err)
			os.Exit(1)
		}
		fmt.Println(string(output))
	} else {
		// Print a readable summary
		fmt.Printf("\nScan Summary:\n")
		fmt.Printf("Targets: %s\n", *targets)
		fmt.Printf("Total ports scanned: %d\n", totalPorts)
		fmt.Printf("Open ports: %d\n", len(openPorts))
		fmt.Printf("Scan completed in: %v\n", elapsedTime)
	}
}
