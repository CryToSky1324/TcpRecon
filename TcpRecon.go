package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"encoding/json"
	"golang.org/x/time/rate"
)

type ScanResult struct {
	Port        int      `json:"port"`
	State       string   `json:"state"`
	Banner      string   `json:"banner,omitempty"`
	CertSubject string   `json:"tls_subject,omitempty"`
	CertIssuer  string   `json:"tls_issuer,omitempty"`
	SANs        []string `json:"tls_sans,omitempty"`
}

type ScanReport struct {
	Target      string       `json:"target"`
	TargetIP    string       `json:"target_ip"`
	DurationSec float64      `json:"duration_seconds"`
	TotalOpen   int          `json:"total_open"`
	Ports       []ScanResult `json:"ports"`
}

func resolveTarget(target string) string {
	ips, err := net.LookupIP(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] FATAL ERROR: Unable to resolve target '%s': %v\n", target, err)
		os.Exit(1)
	}

	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String()
		}
	}

	fmt.Fprintf(os.Stderr, "[!] FATAL ERROR: No IPv4 address found for target '%s'\n", target)
	os.Exit(1)
	return ""
}

func parsePorts(portStr string) []int {
	var ports []int
	seen := make(map[int]bool)

	parts := strings.Split(portStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			if len(bounds) != 2 {
				fmt.Fprintf(os.Stderr, "[!] FATAL ERROR: Invalid port range format: %s\n", part)
				os.Exit(1)
			}

			start, err1 := strconv.Atoi(bounds[0])
			end, err2 := strconv.Atoi(bounds[1])

			if err1 != nil || err2 != nil || start > end || start < 1 || end > 65535 {
				fmt.Fprintf(os.Stderr, "[!] FATAL ERROR: Invalid port boundaries: %s\n", part)
				os.Exit(1)
			}

			for p := start; p <= end; p++ {
				if !seen[p] {
					ports = append(ports, p)
					seen[p] = true
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				fmt.Fprintf(os.Stderr, "[!] FATAL ERROR: Invalid port: %s\n", part)
				os.Exit(1)
			}
			if !seen[p] {
				ports = append(ports, p)
				seen[p] = true
			}
		}
	}

	if len(ports) == 0 {
		fmt.Fprintln(os.Stderr, "[!] FATAL ERROR: No valid ports specified.")
		os.Exit(1)
	}

	return ports
}

func worker(ctx context.Context, targetIP string, targetName string, jobs <-chan int, results chan<- ScanResult, timeout time.Duration, debug bool, limiter *rate.Limiter) {
	for {
		var port int
		var ok bool
		select {
		case <-ctx.Done():
			return
		case port, ok = <-jobs:
			if !ok {
				return
			}
		}

		// Token Bucket Throttle
		if err := limiter.Wait(ctx); err != nil {
			return
		}

		address := fmt.Sprintf("%s:%d", targetIP, port)

		// Layer 4: Context-Aware TCP Handshake
		var d net.Dialer
		dialCtx, cancelDial := context.WithTimeout(ctx, timeout)
		conn, err := d.DialContext(dialCtx, "tcp", address)
		cancelDial()

		if err != nil {
			if debug && err != context.Canceled {
				log.Printf("[DEBUG] Port %d Layer 4 Drop: %v", port, err)
			}
			results <- ScanResult{Port: port, State: "CLOSED"}
			continue
		}

		banner := ""
		activeConn := conn

		// Layer 6: TLS Wrapping
		// Declare variables to hold the extracted X.509 telemetry
		var certSubject, certIssuer string
		var sans []string

		if port == 443 || port == 8443 {
			tlsConfig := &tls.Config{
				InsecureSkipVerify: true,
				ServerName: 	targetName,
			}
			tlsConn := tls.Client(conn, tlsConfig)

			tlsConn.SetDeadline(time.Now().Add(timeout))
			err = tlsConn.Handshake()
			if err != nil {
				conn.Close()
				results <- ScanResult{
					Port: port, State: "OPEN", Banner: fmt.Sprintf("TLS Handshake Failed: %v", err),
				}
				continue
			}
			activeConn = tlsConn

			// NEW: X.509 Cryptographic Extraction
			// The Handshake populated the ConnectionState. We extract the leaf certificate [0].
			state := tlsConn.ConnectionState()
			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				certSubject = cert.Subject.CommonName
				certIssuer = cert.Issuer.CommonName
				sans = cert.DNSNames // Subject Alternative Names
			}
		}
	

		// Layer 7: Dynamic Payload Injection
		var payload []byte
		if port == 80 || port == 8080 || port == 443 || port == 8443 {
			payload = []byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n", targetIP))
		}

		if payload != nil {
			activeConn.SetWriteDeadline(time.Now().Add(timeout))
			activeConn.Write(payload)
		}

		// Banner Grabbing & Strict Error Handling
		activeConn.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, 1024)
		n, err := activeConn.Read(buf)

		if n > 0 {
			banner = string(buf[:n])
			banner = strings.ReplaceAll(banner, "\r", "")
			banner = strings.ReplaceAll(banner, "\n", " ")
			if len(banner) > 150 {
				banner = banner[:150] + " [...]"
			}
		} else if err != nil && err != context.Canceled {
			banner = fmt.Sprintf("Read Error: %v", err)
		}

		activeConn.Close()
		results <- ScanResult{
			Port:        port,
			State:       "OPEN",
			Banner:      strings.TrimSpace(banner),
			CertSubject: certSubject,
			CertIssuer:  certIssuer,
			SANs:        sans,
		}
	}
}

func main() {
	// 1. CLI Parsing
	workersPtr := flag.Int("w", 500, "Maximum number of concurrent Goroutine workers")
	timeoutPtr := flag.Int("t", 1000, "Timeout per port in milliseconds")
	portsPtr := flag.String("p", "1-1000", "Ports to scan (e.g., 80,443,1-1024)")
	debugPtr := flag.Bool("d", false, "Enable debug mode to log Layer 4 socket errors to stderr")
	ratePtr := flag.Int("r", 100, "Global rate limit in packets per second (PPS)")
	jsonPtr := flag.Bool("j", false, "Output results strictly in JSON format (mutes stdout text)")

	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <target>\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	rawTarget := args[0]
	targetIP := resolveTarget(rawTarget)
	numWorkers := *workersPtr
	timeout := time.Duration(*timeoutPtr) * time.Millisecond
	portsToScan := parsePorts(*portsPtr)
	debugMode := *debugPtr

	// 2. Lifecycle Management
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// 3. Global Rate Limiter
	globalLimiter := rate.NewLimiter(rate.Limit(*ratePtr), 1)

	// 4. Dispatcher Initialization
	// Extract JSON flag
	jsonMode := *jsonPtr

	// 4. Dispatcher Initialization
	jobs := make(chan int, numWorkers)
	results := make(chan ScanResult)
	var wg sync.WaitGroup

	// STRICT STREAM DISCIPLINE: 
	// If in JSON mode, we MUST send human updates to os.Stderr to prevent JSON corruption.
	if !jsonMode {
		fmt.Printf("[*] Target '%s' resolved to IPv4: %s\n", rawTarget, targetIP)
		fmt.Printf("[*] Initiating scan against %d ports with %d Goroutines...\n", len(portsToScan), numWorkers)
		fmt.Printf("[*] Engine Throttled at %d PPS (Timeout: %s)\n", *ratePtr, timeout)
	} else {
		fmt.Fprintf(os.Stderr, "[*] Scanning %s (%s) at %d PPS...\n", rawTarget, targetIP, *ratePtr)
	}
	
	startTime := time.Now()

	// 5. Spawn Worker Pool
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(ctx, targetIP, rawTarget, jobs, results, timeout, debugMode, globalLimiter)
		}()
	}

	// 6. Job Producer
	go func() {
		defer close(jobs)
		for _, port := range portsToScan {
			select {
			case <-ctx.Done():
				return
			case jobs <- port:
			}
		}
	}()

	// 7. Lifecycle Monitor
	go func() {
		wg.Wait()
		close(results)
	}()

	// 8. Result Consumer
	var discoveredPorts []ScanResult
	openPorts := 0

	for result := range results {
		if result.State == "OPEN" {
			discoveredPorts = append(discoveredPorts, result)
			openPorts++

			// Only print to terminal if we are NOT in JSON mode
			if !jsonMode {
				bannerDisplay := "No Banner"
				if result.Banner != "" {
					bannerDisplay = result.Banner
				}
				fmt.Printf("[+] Port %d/TCP is OPEN\t- %s\n", result.Port, bannerDisplay)
				
				if result.CertSubject != "" {
					fmt.Printf("    |_ TLS Subject: %s\n", result.CertSubject)
					fmt.Printf("    |_ TLS Issuer:  %s\n", result.CertIssuer)
					if len(result.SANs) > 0 {
						fmt.Printf("    |_ TLS SANs:    %s\n", strings.Join(result.SANs, ", "))
					}
				}
			}
		}
	}

	duration := time.Since(startTime)

	// 9. Final Output Generation
	if jsonMode {
		report := ScanReport{
			Target:      rawTarget,
			TargetIP:    targetIP,
			DurationSec: duration.Seconds(),
			TotalOpen:   openPorts,
			Ports:       discoveredPorts,
		}

		// Marshal into beautifully formatted JSON
		jsonData, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] JSON Encoding Error: %v\n", err)
			os.Exit(1)
		}
		// Write exactly one clean JSON object to standard output
		fmt.Println(string(jsonData))
	} else {
		fmt.Printf("[*] Scan completed in %.2f seconds. Discovered %d open ports.\n", duration.Seconds(), openPorts)
	}
}
