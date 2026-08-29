package main

import (
	"fmt"
	"io"
	"time"

	"github.com/CryToSky1324/TcpRecon/internal/models"
	"github.com/CryToSky1324/TcpRecon/internal/scanner"
)

type runtimeOutput struct {
	stdout   io.Writer
	stderr   io.Writer
	jsonMode bool
}

func newRuntimeOutput(stdout, stderr io.Writer, jsonMode bool) *runtimeOutput {
	return &runtimeOutput{
		stdout:   stdout,
		stderr:   stderr,
		jsonMode: jsonMode,
	}
}

// Observation intentionally emits nothing until B7 defines the replacement
// for the retired legacy port_state_delta output.
func (o *runtimeOutput) Observation(models.ScanResult) {}

// LifecycleChanges intentionally keeps B6 reconciliation results internal.
// B7 owns lifecycle-event serialization.
func (o *runtimeOutput) LifecycleChanges([]scanner.ServiceChange) {}

func (o *runtimeOutput) RuntimeFailure(err error) {
	if err != nil {
		_, _ = fmt.Fprintf(o.stderr, "[!] FATAL: %v\n", err)
	}
}

func (o *runtimeOutput) ScanStarted(tcpPorts, udpPorts, workers int) {
	if o.jsonMode {
		return
	}
	totalPorts := tcpPorts + udpPorts
	_, _ = fmt.Fprintf(
		o.stderr,
		"[*] Initiating stream scan against %d ports (%d TCP, %d UDP) with %d Goroutines...\n",
		totalPorts,
		tcpPorts,
		udpPorts,
		workers,
	)
}

func (o *runtimeOutput) ScanFinished(
	duration time.Duration,
	openPorts int,
	completion scanner.ScanCompletion,
) {
	if completion.Successful() {
		if !o.jsonMode {
			_, _ = fmt.Fprintf(
				o.stderr,
				"[*] Scan completed in %.2f seconds. Discovered %d open ports.\n",
				duration.Seconds(),
				openPorts,
			)
		}
		return
	}

	if completion.Err != nil {
		_, _ = fmt.Fprintf(
			o.stderr,
			"[!] Scan incomplete: status=%s error=%v\n",
			completion.Status,
			completion.Err,
		)
		return
	}
	_, _ = fmt.Fprintf(
		o.stderr,
		"[!] Scan incomplete: status=%s\n",
		completion.Status,
	)
}
