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
	portsPtr := flag.String("p", "1-1000", "TCP Ports to scan")
	udpPortsPtr := flag.String("uP", "", "UDP Ports to scan (e.g., 53,123,161)")
	ratePtr := flag.Int("r", 100, "Global rate limit in packets per second (PPS)")
	inputListPtr := flag.String("iL", "", "Input file containing list of targets/CIDRs")
	debugPtr := flag.Bool("d", false, "Enable debug mode")
	jsonPtr := flag.Bool("j", false, "Output results strictly in JSON format")

	flag.Parse()

	handlerOptions := &slog.HandlerOptions{Level: slog.LevelInfo}
	if *jsonPtr {
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, handlerOptions)))
	} else {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, handlerOptions)))
	}

	if err := validateCLI(*workersPtr, *timeoutPtr, *ratePtr, flag.Args(), *inputListPtr); err != nil {
		fmt.Fprintf(os.Stderr, "[!] FATAL: %v\n", err)
		os.Exit(1)
	}

	// 1. Context Management & Signal Interception
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Fprintln(os.Stderr, "\n[!] Aborting scan gracefully...")
		cancel()
	}()

	// 2. Dynamic Stream Routing (Supports Stdin, -iL flag, positional arg, and TARGET_URL env fallback)

	stat, statErr := os.Stdin.Stat()
	stdinPiped := statErr == nil && (stat.Mode()&os.ModeCharDevice) == 0
	targetsReader, err := selectTargetReader(ctx, flag.Args(), *inputListPtr, os.Getenv("TARGET_URL"), os.Stdin, stdinPiped)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] FATAL: %v\n", err)
		os.Exit(1)
	}
	defer targetsReader.Close()

	// 2. Parse Port Vectors
	tcpPortsToScan, err := utils.ParsePortRange(*portsPtr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] FATAL: Invalid TCP port specification: %v\n", err)
		os.Exit(1)
	}

	var udpPortsToScan []int
	if *udpPortsPtr != "" {
		udpPortsToScan, err = utils.ParsePortRange(*udpPortsPtr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] FATAL: Invalid UDP port specification: %v\n", err)
			os.Exit(1)
		}
	}

	if !*jsonPtr {
		totalPorts := len(tcpPortsToScan) + len(udpPortsToScan)
		fmt.Fprintf(os.Stderr, "[*] Initiating stream scan against %d ports (%d TCP, %d UDP) with %d Goroutines...\n", totalPorts, len(tcpPortsToScan), len(udpPortsToScan), *workersPtr)
	}

	// 4. State Store Initialization (bbolt)
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "./asm_state.db"
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

	// 5. Engine Invocation (Passing targetsReader correctly)
	resultsChan, startTime := scanner.Run(ctx, targetsReader, tcpPortsToScan, udpPortsToScan, *workersPtr, time.Duration(*timeoutPtr)*time.Millisecond, *ratePtr, *debugPtr, *jsonPtr)

	// 6. State Manager Execution
	openPorts := scanner.StateManager(db, resultsChan, *jsonPtr)
	duration := time.Since(startTime)

	if !*jsonPtr {
		fmt.Fprintf(os.Stderr, "[*] Scan completed in %.2f seconds. Discovered %d open ports.\n", duration.Seconds(), openPorts)
	}
}

func validateCLI(workers, timeout, rateLimit int, args []string, inputList string) error {
	if workers <= 0 {
		return fmt.Errorf("workers must be greater than zero")
	}
	if timeout <= 0 {
		return fmt.Errorf("timeout must be greater than zero")
	}
	if rateLimit <= 0 {
		return fmt.Errorf("rate must be greater than zero")
	}
	if len(args) > 1 {
		return fmt.Errorf("expected at most one positional target")
	}
	if len(args) == 1 && inputList != "" {
		return fmt.Errorf("positional target and -iL cannot be used together")
	}
	return nil
}

func selectTargetReader(ctx context.Context, args []string, inputList, targetURL string, stdin io.Reader, stdinPiped bool) (io.ReadCloser, error) {
	if len(args) == 1 {
		target := args[0]
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			return utils.FetchTargets(ctx, target)
		}
		return io.NopCloser(strings.NewReader(target + "\n")), nil
	}
	if inputList != "" {
		file, err := os.Open(inputList)
		if err != nil {
			return nil, fmt.Errorf("cannot open input list file %s: %w", inputList, err)
		}
		return file, nil
	}
	if stdinPiped {
		return io.NopCloser(stdin), nil
	}
	if targetURL != "" {
		return utils.FetchTargets(ctx, targetURL)
	}
	return nil, fmt.Errorf("specify a target, -iL, use stdin pipe, or TARGET_URL env var")
}
