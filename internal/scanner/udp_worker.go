// internal/scanner/udp_worker.go
package scanner

import (
	"context"
	"fmt"
	"github.com/CryToSky1324/TcpRecon/internal/models"
	"golang.org/x/time/rate"
	"net"
	"time"
)

func UDPWorker(ctx context.Context, jobs <-chan models.ScanJob, results chan<- models.ScanResult, timeout time.Duration, debug bool, limiter *rate.Limiter) error {
	var workerErr error

	for {
		var job models.ScanJob
		var ok bool

		select {
		case <-ctx.Done():
			return ctx.Err()
		case job, ok = <-jobs:
			if !ok {
				return workerErr
			}
		}

		if err := limiter.Wait(ctx); err != nil {
			return err
		}

		payload, exists := UDPPayloads[job.Port]
		if !exists {
			if workerErr == nil {
				workerErr = fmt.Errorf("unsupported UDP payload for port %d", job.Port)
			}
			continue
		}

		address := joinHostPort(job.TargetIP, job.Port)
		conn, err := net.Dial("udp", address)
		if err != nil {
			continue
		}

		// 1. Force the application to respond
		if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			conn.Close()
			continue
		}

		if _, err := conn.Write(payload); err != nil {
			conn.Close()
			continue
		}

		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			conn.Close()
			continue
		}

		// Allocate memory and pull the payload from the socket buffer
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)

		state := "FILTERED"
		banner := ""

		// If we successfully read bytes before the deadline, the port is OPEN
		if err == nil && n > 0 {
			state = "OPEN"
			// Sanitize raw bytes to hex to prevent JSON marshaller panics
			banner = fmt.Sprintf("%x", buf[:n])
		}

		conn.Close()

		if state == "OPEN" {
			results <- models.ScanResult{
				TargetName: job.TargetName,
				TargetIP:   job.TargetIP,
				Port:       job.Port,
				Protocol:   "udp",
				State:      state,
				Banner:     banner,
			}
		}
	}
}
