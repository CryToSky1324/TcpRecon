package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/CryToSky1324/TcpRecon/internal/scanner"
	"github.com/CryToSky1324/TcpRecon/internal/utils"

	"go.etcd.io/bbolt"
)

func main() {
	workersPtr := flag.Int("w", 500, "Maximum number of concurrent Goroutine workers")
	timeoutPtr := flag.Int("t", 1000, "Timeout per port in milliseconds")
	portsPtr := flag.String("p", "1-1000", "Ports to scan")
	ratePtr := flag.Int("r", 100, "Global rate limit in packets per second (PPS)")
	inputListPtr := flag.String("iL", "", "Input file containing list of targets/CIDRs")
	debugPtr := flag.Bool("d", false, "Enable debug mode")
	jsonPtr := flag.Bool("j", false, "Output results strictly in JSON format")

	flag.Parse()

	if *jsonPtr {
		jsonHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
		slog.SetDefault(slog.New(jsonHandler))
	}

	portsToScan, err := utils.ParsePortRange(*portsPtr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] FATAL: %v\n", err)
		os.Exit(1)
	}

	// 1. Context Management (Moved up for HTTP Fetcher)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Fprintln(os.Stderr, "\n[!] Aborting scan gracefully...")
		cancel()
	}()

	// 2. Dynamic Stream Routing (K8s Env vs Local CLI)
	var targetStream io.ReadCloser
	targetURL := os.Getenv("TARGET_URL")

	if targetURL != "" {
		targetStream, err = utils.FetchTargets(ctx, targetURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] FATAL: Failed to stream targets from URL: %v\n", err)
			os.Exit(1)
		}
	} else if *inputListPtr != "" {
		targetStream, err = os.Open(*inputListPtr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] FATAL: Cannot open input file: %v\n", err)
			os.Exit(1)
		}
	} else {
		rawTarget := flag.Arg(0)
		if rawTarget == "" {
			fmt.Fprintf(os.Stderr, "[!] FATAL: Specify a target, -iL, or TARGET_URL env var\n")
			os.Exit(1)
		}
		targetStream = io.NopCloser(strings.NewReader(rawTarget))
	}
	defer targetStream.Close()

	if !*jsonPtr {
		fmt.Fprintf(os.Stderr, "[*] Initiating stream scan against %d ports with %d Goroutines...\n", len(portsToScan), *workersPtr)
	}

	// 3. State Store Initialization
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "./asm_state.db" // Fallback for local CLI testing
	}

	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 5 * time.Second})

	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] FATAL: DB lock failed (K8s Concurrency Violation): %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	err = db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("PortStates"))
		return err
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] FATAL: Bucket init failed: %v\n", err)
		os.Exit(1)
	}

	// 4. Engine Invocation (Passing the io.Reader)
	resultsChan, startTime := scanner.Run(ctx, targetStream, portsToScan, *workersPtr, time.Duration(*timeoutPtr)*time.Millisecond, *ratePtr, *debugPtr, *jsonPtr)

	// 5. State Manager Execution
	openPorts := scanner.StateManager(db, resultsChan, *jsonPtr)
	duration := time.Since(startTime)

	if !*jsonPtr {
		fmt.Fprintf(os.Stderr, "[*] Scan completed in %.2f seconds. Discovered %d open ports.\n", duration.Seconds(), openPorts)
	}
}
