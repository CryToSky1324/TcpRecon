package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/time/rate"
)

// ScanResult structures our output for the main thread and JSON encoding
type ScanResult struct {
	Port        int      `json:"port"`
	State       string   `json:"state"`
	Banner      string   `json:"banner,omitempty"`
	OSHint      string   `json:"os_hint,omitempty"`
	CertSubject string   `json:"tls_subject,omitempty"`
	CertIssuer  string   `json:"tls_issuer,omitempty"`
	SANs        []string `json:"tls_sans,omitempty"`
}

// ScanReport encapsulates the entire execution telemetry for SIEM ingestion
type ScanReport struct {
	Target      string       `json:"target"`
	TargetIP    string       `json:"target_ip"`
	DurationSec float64      `json:"duration_seconds"`
	TotalOpen   int          `json:"total_open"`
	Ports       []ScanResult `json:"ports"`
}

// ScanJob defines a single atomic scanning task across the dispatcher
type ScanJob struct {
	TargetIP   string
	TargetName string
	Port       int
}

// TargetMap links the raw input name/CIDR to its resolved IPv4 slices
type TargetMap map[string][]string

// expandCIDR mathematically generates usable IPv4 addresses from a CIDR block
func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}

	// Filter out network and broadcast addresses for standard IPv4 subnets
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

// incIP increments an IP address byte slice sequentially
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ingestTargets processes a target text file line-by-line
func ingestTargets(filePath string) TargetMap {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] FATAL ERROR: Cannot open target file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	targets := make(TargetMap)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "/") {
			ips, err := expandCIDR(line)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] Skipping invalid CIDR %s: %v\n", line, err)
				continue
			}
			targets[line] = ips
			continue
		}

		ips, err := net.LookupIP(line)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Skipping unresolvable target %s: %v\n", line, err)
			continue
		}

		var validIPs []string
		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				validIPs = append(validIPs, ipv4.String())
			}
		}
		if len(validIPs) > 0 {
			targets[line] = validIPs
		}
	}

	return targets
}

// parsePortRange parses comma-separated ports and ranges (e.g., "80,443,1000-1024")
func parsePortRange(portStr string) ([]int, error) {
	var ports []int
	parts := strings.Split(portStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			var start, end int
			_, err := fmt.Sscanf(part, "%d-%d", &start, &end)
			if err != nil {
				return nil, fmt.Errorf("invalid port range syntax: %s", part)
			}
			for p := start; p <= end; p++ {
				if p < 1 || p > 65535 {
					return nil, fmt.Errorf("port out of range (1-65535): %d", p)
				}
				ports = append(ports, p)
			}
		} else {
			var p int
			_, err := fmt.Sscanf(part, "%d", &p)
			if err != nil {
				return nil, fmt.Errorf("invalid port syntax: %s", part)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("port out of range (1-65535): %d", p)
			}
			ports = append(ports, p)
		}
	}
	return ports, nil
}

// fingerprintOS analyzes application layer banners to deduce the underlying operating system
func fingerprintOS(banner string) string {
	if banner == "" {
		return ""
	}

	normalized := strings.ToLower(banner)

	if strings.Contains(normalized, "ubuntu") {
		return "Ubuntu Linux"
	}
	if strings.Contains(normalized, "debian") {
		return "Debian Linux"
	}
	if strings.Contains(normalized, "centos") {
		return "CentOS Linux"
	}
	if strings.Contains(normalized, "freebsd") {
		return "FreeBSD"
	}
	if strings.Contains(normalized, "windows") || strings.Contains(normalized, "iis") || strings.Contains(normalized, "win32") {
		return "Microsoft Windows"
	}

	return "Unknown/Obfuscated"
}

// worker executes the TCP connection, TLS wrapping, payload injection, and X.509 extraction
func worker(ctx context.Context, jobs <-chan ScanJob, results chan<- ScanResult, timeout time.Duration, debug bool, limiter *rate.Limiter) {
	dialer := net.Dialer{Timeout: timeout}

	for {
		var job ScanJob
		var ok bool
		select {
		case <-ctx.Done():
			return
		case job, ok = <-jobs:
			if !ok {
				return
			}
		}

		if err := limiter.Wait(ctx); err != nil {
			return
		}

		address := fmt.Sprintf("%s:%d", job.TargetIP, job.Port)
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] Dial failed for %s: %v\n", address, err)
			}
			continue
		}

		var activeConn net.Conn = conn
		var certSubject, certIssuer string
		var sans []string

		// Layer 6: TLS Wrapping for HTTPS / secure endpoints with SNI Injection
		if job.Port == 443 || job.Port == 8443 {
			tlsConfig := &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         job.TargetName,
			}
			tlsConn := tls.Client(conn, tlsConfig)
			
			// Set explicit handshake deadline to prevent hanging workers
			tlsConn.SetDeadline(time.Now().Add(timeout))
			if err := tlsConn.Handshake(); err == nil {
				activeConn = tlsConn
				state := tlsConn.ConnectionState()
				if len(state.PeerCertificates) > 0 {
					cert := state.PeerCertificates[0]
					certSubject = cert.Subject.CommonName
					if len(cert.Issuer.Organization) > 0 {
						certIssuer = cert.Issuer.Organization[0]
					}
					sans = cert.DNSNames
				}
			} else {
				if debug {
					fmt.Fprintf(os.Stderr, "[DEBUG] TLS handshake failed for %s: %v\n", address, err)
				}
				conn.Close()
				continue
			}
		}

		// Layer 7: Application-Layer Payload Injection
		activeConn.SetWriteDeadline(time.Now().Add(timeout))
		if job.Port == 80 || job.Port == 8080 {
			httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", job.TargetIP)
			activeConn.Write([]byte(httpReq))
		}

		// Banner Grabbing / Read Buffer
		activeConn.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, 1024)
		n, _ := activeConn.Read(buf)
		banner := string(buf[:n])

		osHint := fingerprintOS(banner)

		activeConn.Close()
		results <- ScanResult{
			Port:        job.Port,
			State:       "OPEN",
			Banner:      strings.TrimSpace(banner),
			OSHint:      osHint,
			CertSubject: certSubject,
			CertIssuer:  certIssuer,
			SANs:        sans,
		}
	}
}

func main() {
	// CLI Flag Definitions
	workersPtr := flag.Int("w", 500, "Maximum number of concurrent Goroutine workers")
	timeoutPtr := flag.Int("t", 1000, "Timeout per port in milliseconds")
	portsPtr := flag.String("p", "1-1000", "Ports to scan (e.g., 80,443,1-1024)")
	ratePtr := flag.Int("r", 100, "Global rate limit in packets per second (PPS)")
	inputListPtr := flag.String("iL", "", "Input file containing list of targets/CIDRs")
	debugPtr := flag.Bool("d", false, "Enable debug mode to log Layer 4 socket errors to stderr")
	jsonPtr := flag.Bool("j", false, "Output results strictly in JSON format (mutes stdout text)")

	flag.Parse()

	numWorkers := *workersPtr
	timeout := time.Duration(*timeoutPtr) * time.Millisecond
	debugMode := *debugPtr
	jsonMode := *jsonPtr

	// Parse Port Range Specification
	portsToScan, err := parsePortRange(*portsPtr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] FATAL: %v\n", err)
		os.Exit(1)
	}

	// Target Resolution & Ingestion
	targetList := make(TargetMap)

	if *inputListPtr != "" {
		targetList = ingestTargets(*inputListPtr)
	} else {
		rawTarget := flag.Arg(0)
		if rawTarget == "" {
			fmt.Fprintf(os.Stderr, "[!] FATAL: You must specify a target or an input file (-iL)\n")
			os.Exit(1)
		}

		ips, err := net.LookupIP(rawTarget)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] FATAL: Cannot resolve target %s: %v\n", rawTarget, err)
			os.Exit(1)
		}

		var validIPs []string
		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				validIPs = append(validIPs, ipv4.String())
			}
		}

		if len(validIPs) == 0 {
			fmt.Fprintf(os.Stderr, "[!] FATAL: No IPv4 addresses found for %s\n", rawTarget)
			os.Exit(1)
		}
		targetList[rawTarget] = validIPs
	}

	if len(targetList) == 0 {
		fmt.Fprintf(os.Stderr, "[!] FATAL: No valid targets loaded for scanning.\n")
		os.Exit(1)
	}

	// Context Cancellation & Signal Interception (SIGINT)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Fprintln(os.Stderr, "\n[!] Aborting scan gracefully... Shutting down workers.")
		cancel()
	}()

	// Token Bucket Rate Limiter
	globalLimiter := rate.NewLimiter(rate.Limit(*ratePtr), *ratePtr)

	// Dispatcher Initialization
	jobs := make(chan ScanJob, numWorkers)
	results := make(chan ScanResult)
	var wg sync.WaitGroup

	totalIPs := 0
	for _, ips := range targetList {
		totalIPs += len(ips)
	}

	if !jsonMode {
		fmt.Printf("[*] Loaded targets resolving to %d unique IPv4 addresses\n", totalIPs)
		fmt.Printf("[*] Initiating scan against %d ports with %d Goroutines...\n", len(portsToScan), numWorkers)
		fmt.Printf("[*] Engine Throttled at %d PPS (Timeout: %s)\n", *ratePtr, timeout)
	} else {
		fmt.Fprintf(os.Stderr, "[*] Scanning %d IPs at %d PPS...\n", totalIPs, *ratePtr)
	}

	startTime := time.Now()

	// Spawn Worker Pool
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(ctx, jobs, results, timeout, debugMode, globalLimiter)
		}()
	}

	// Job Producer
	go func() {
		defer close(jobs)
		for rawName, resolvedIPs := range targetList {
			for _, ip := range resolvedIPs {
				for _, port := range portsToScan {
					select {
					case <-ctx.Done():
						return
					case jobs <- ScanJob{TargetIP: ip, TargetName: rawName, Port: port}:
					}
				}
			}
		}
	}()

	// Lifecycle Monitor
	go func() {
		wg.Wait()
		close(results)
	}()

	// Result Consumer
	var discoveredPorts []ScanResult
	openPorts := 0

	for result := range results {
		if result.State == "OPEN" {
			discoveredPorts = append(discoveredPorts, result)
			openPorts++

			if !jsonMode {
				bannerDisplay := "No Banner"
				if result.Banner != "" {
					bannerDisplay = result.Banner
				}
				fmt.Printf("[+] Port %d/TCP is OPEN\t- %s\n", result.Port, bannerDisplay)

				if result.OSHint != "" && result.OSHint != "Unknown/Obfuscated" {
					fmt.Printf("    |_ OS Fingerprint: %s\n", result.OSHint)
				}

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

	// Final Output Generation
	if jsonMode {
		report := ScanReport{
			Target:      "multi-target-sweep",
			TargetIP:    "multiple",
			DurationSec: duration.Seconds(),
			TotalOpen:   openPorts,
			Ports:       discoveredPorts,
		}

		jsonData, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] JSON Encoding Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(jsonData))
	} else {
		fmt.Printf("[*] Scan completed in %.2f seconds. Discovered %d open ports.\n", duration.Seconds(), openPorts)
	}
}
