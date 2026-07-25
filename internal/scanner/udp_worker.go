// internal/scanner/udp_worker.go
package scanner

import (
	"context"
	"fmt"
	"net"
	"time"
	"golang.org/x/time/rate"
	"github.com/CryToSky1324/TcpRecon/internal/models"
)

func UDPWorker(ctx context.Context, jobs <-chan models.ScanJob, results chan<- models.ScanResult, timeout time.Duration, debug bool, limiter *rate.Limiter) {
	for {
		var job models.ScanJob
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

		payload, exists := UDPPayloads[job.Port]
		if !exists {
			// Fail fast. If we can't inject a payload, we can't prove it's open.
			continue
		}

		address := fmt.Sprintf("%s:%d", job.TargetIP, job.Port)
		conn, err := net.Dial("udp", address)
		if err != nil {
			continue
		}

		// 1. Force the application to respond
		conn.SetWriteDeadline(time.Now().Add(timeout))
		if _, err := conn.Write(payload); err != nil {
			conn.Close()
			continue
		}

		// 2. Strict Read Deadline (The Anti-OOMKill pattern)
		conn.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		
		state := "FILTERED"
		banner := ""

		if err == nil && n > 0 {
			state = "OPEN"
			// Sanitize raw bytes to prevent JSON marshaller panics
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
