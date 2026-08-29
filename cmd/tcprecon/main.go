package main

import (
	"context"
	"crypto/rand"
	"errors"
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

	// 2. Parse Port Vectors before performing target-source I/O.
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

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "./asm_state.db"
	}

	stat, statErr := os.Stdin.Stat()
	stdinPiped := statErr == nil && (stat.Mode()&os.ModeCharDevice) == 0
	outcome := runLifecycleRuntime(ctx, lifecycleRuntimeConfig{
		DBPath: dbPath, TCPPorts: tcpPortsToScan, UDPPorts: udpPortsToScan,
		Workers: *workersPtr, Timeout: time.Duration(*timeoutPtr) * time.Millisecond,
		RateLimit: *ratePtr, DebugMode: *debugPtr, JSONMode: *jsonPtr,
		Stdout: os.Stdout, Stderr: os.Stderr,
	}, lifecycleRuntimeDependencies{
		PrepareTargets: func(ctx context.Context) (*preparedTargetSource, error) {
			source, err := selectTargetReader(ctx, flag.Args(), *inputListPtr, os.Getenv("TARGET_URL"), os.Stdin, stdinPiped)
			if err != nil {
				return nil, err
			}
			return prepareTargetSource(ctx, source)
		},
		OpenState: func(path string) (*bbolt.DB, error) {
			return bbolt.Open(path, 0600, &bbolt.Options{Timeout: 5 * time.Second})
		},
		GenerateScanID: func() (string, error) { return generateRuntimeScanID(rand.Reader) },
		StartScanner:   scanner.Run,
	})
	if outcome.Err != nil {
		os.Exit(1)
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

func finalizeScanCompletion(
	scannerCompletion scanner.ScanCompletion,
	stateErr error,
) scanner.ScanCompletion {
	if stateErr == nil {
		return scannerCompletion
	}

	if scannerCompletion.Successful() {
		return scanner.ScanCompletion{
			Status: scanner.ScanStatusStateFailed,
			Err:    stateErr,
		}
	}

	return scanner.ScanCompletion{
		Status: scannerCompletion.Status,
		Err: errors.Join(
			scannerCompletion.Err,
			stateErr,
		),
	}
}
