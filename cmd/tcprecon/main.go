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

	if *jsonPtr {
		jsonHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
		slog.SetDefault(slog.New(jsonHandler))
	}

	tcpPortsToScan, err := utils.ParsePortRange(*portsPtr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] FATAL: %v\n", err)
		os.Exit(1)
	}

	var udpPortsToScan []int
    if *udpPortsPtr != "" {
        udpPortsToScan, err = utils.ParsePortRange(*udpPortsPtr)
        if err != nil {
            fmt.Fprintf(os.Stderr, "[!] FATAL UDP Port syntax: %v\n", err)
            os.Exit(1)
        }
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
	// 1. Target & Input Resolution (Supporting positional args, -iL flag, stdin, and TARGET_URL env fallback)
	var targetsReader io.Reader
	targetArg := flag.Arg(0)

	if targetArg == "" {
		targetArg = os.Getenv("TARGET_URL")
	}

	if targetArg != "" {
		if strings.HasPrefix(targetArg, "http://") || strings.HasPrefix(targetArg, "https://") {
			body, err := utils.FetchTargets(ctx, targetArg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] FATAL: Failed to fetch remote target URL: %v\n", err)
				os.Exit(1)
			}
			defer body.Close()
			targetsReader = body
		} else {
			file, err := os.Open(targetArg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] FATAL: Cannot open target file %s: %v\n", targetArg, err)
				os.Exit(1)
			}
			defer file.Close()
			targetsReader = file
		}
	} else if *inputListPtr != "" {
		file, err := os.Open(*inputListPtr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] FATAL: Cannot open input list file %s: %v\n", *inputListPtr, err)
			os.Exit(1)
		}
		defer file.Close()
		targetsReader = file
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			targetsReader = os.Stdin
		}
	}

	if targetsReader == nil {
		fmt.Fprintf(os.Stderr, "[!] FATAL: Specify a target, -iL, use stdin pipe, or TARGET_URL env var\n")
		os.Exit(1)
	}

	// 2. Parse Port Vectors
	tcpPortsToScan, err := utils.ParsePortString(*portsPtr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] FATAL: Invalid TCP port specification: %v\n", err)
		os.Exit(1)
	}

	var udpPortsToScan []int
	if *udpPortsPtr != "" {
		udpPortsToScan, err = utils.ParsePortString(*udpPortsPtr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] FATAL: Invalid UDP port specification: %v\n", err)
			os.Exit(1)
		}
	}

	if !*jsonPtr {
		totalPorts := len(tcpPortsToScan) + len(udpPortsToScan)
		fmt.Fprintf(os.Stderr, "[*] Initiating stream scan against %d ports (%d TCP, %d UDP) with %d Goroutines...\n", totalPorts, len(tcpPortsToScan), len(udpPortsToScan), *workersPtr)
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
	resultsChan, startTime := scanner.Run(ctx, targetStream, tcpPortsToScan, udpPortsToScan, *workersPtr, time.Duration(*timeoutPtr)*time.Millisecond, *ratePtr, *debugPtr, *jsonPtr)

	// 5. State Manager Execution
	openPorts := scanner.StateManager(db, resultsChan, *jsonPtr)
	duration := time.Since(startTime)

	if !*jsonPtr {
		fmt.Fprintf(os.Stderr, "[*] Scan completed in %.2f seconds. Discovered %d open ports.\n", duration.Seconds(), openPorts)
	}
}
