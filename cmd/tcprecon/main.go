package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	// IMPORTANT: Adjust these paths to match your actual go.mod module name
	"github.com/CryToSky1324/TcpRecon/internal/models"
	"github.com/CryToSky1324/TcpRecon/internal/scanner"
	"github.com/CryToSky1324/TcpRecon/internal/utils"

	"go.etcd.io/bbolt"
)

func main() {
	// 1. CLI Configuration
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

	// 12-Factor stream segregation: Lock structured logs to stdout
	if jsonMode {
		jsonHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})
		slog.SetDefault(slog.New(jsonHandler))
	}

	// 2. Stateless Parsing
	portsToScan, err := utils.ParsePortRange(*portsPtr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] FATAL: %v\n", err)
		os.Exit(1)
	}

	// 3. Target Ingestion Pipeline
	targetList := make(models.TargetMap)

	if *inputListPtr != "" {
		targetList = utils.IngestTargets(*inputListPtr)
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

	totalIPs := 0
	for _, ips := range targetList {
		totalIPs += len(ips)
	}

	if !jsonMode {
		fmt.Fprintf(os.Stderr, "[*] Loaded targets resolving to %d unique IPv4 addresses\n", totalIPs)
		fmt.Fprintf(os.Stderr, "[*] Initiating scan against %d ports with %d Goroutines...\n", len(portsToScan), numWorkers)
		fmt.Fprintf(os.Stderr, "[*] Engine Throttled at %d PPS (Timeout: %s)\n", *ratePtr, timeout)
	} else {
		fmt.Fprintf(os.Stderr, "[*] Scanning %d IPs at %d PPS...\n", totalIPs, *ratePtr)
	}

	// 4. Context Management (SIGINT Trap)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Fprintln(os.Stderr, "\n[!] Aborting scan gracefully... Shutting down workers.")
		cancel()
	}()

	// 4.5 Initialize State Store (Mapped to K8s PVC)
	dbPath := "./asm_state.db" // Must be mounted via Docker/K8s, ./asm_state.db for local testing
	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] FATAL: Failed to acquire DB lock. Is another instance running? %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	err = db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("PortStates"))
		return err
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] FATAL: Failed to initialize bucket: %v\n", err)
		os.Exit(1)
	}

	// 5. Engine Invocation
	resultsChan, startTime := scanner.Run(ctx, targetList, portsToScan, numWorkers, timeout, *ratePtr, debugMode, jsonMode)

	// 6. State Manager Execution
	openPorts := scanner.StateManager(db, resultsChan, jsonMode)
	duration := time.Since(startTime)

	if !jsonMode {
		fmt.Fprintf(os.Stderr, "[*] Scan completed in %.2f seconds. Discovered %d open ports.\n", duration.Seconds(), openPorts)
	}
}
