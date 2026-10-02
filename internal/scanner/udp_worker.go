// internal/scanner/udp_worker.go
package scanner

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/CryToSky1324/TcpRecon/internal/models"
	"golang.org/x/time/rate"
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

		// 1. Validate port support and construct dynamic or static payload
		var reqPayload []byte
		var txID uint16

		switch job.Port {
		case 53:
			txID = uint16(time.Now().UnixNano() & 0xFFFF)
			reqPayload = BuildDNSQuery(txID)
		case 123:
			reqPayload = BuildNTPRequest()
		default:
			payload, exists := UDPPayloads[job.Port]
			if !exists {
				if workerErr == nil {
					workerErr = fmt.Errorf("unsupported UDP payload for port %d", job.Port)
				}
				continue
			}
			reqPayload = payload
		}

		// 2. Initialize Layer 4 UDP Socket
		address := joinHostPort(job.TargetIP, job.Port)
		conn, err := net.Dial("udp", address)
		if err != nil {
			continue
		}

		// 3. Egress payload transmission with deadline
		if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			_ = conn.Close()
			continue
		}

		if _, err := conn.Write(reqPayload); err != nil {
			_ = conn.Close()
			continue
		}

		// 4. Ingress response read with fixed 2048-byte allocation
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			_ = conn.Close()
			continue
		}

		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		_ = conn.Close()

		if err != nil || n == 0 {
			// Dropped or timed out: UDP is connectionless; non-fatal
			continue
		}

		respBytes := buf[:n]

		// 5. Binary Protocol Validation
		var isOpen bool
		switch job.Port {
		case 53:
			isOpen = ValidateDNSResponse(reqPayload, respBytes)
		case 123:
			isOpen = ValidateNTPResponse(respBytes)
		default:
			isOpen = len(respBytes) > 0
		}

		// 6. Push verified open result
		if isOpen {
			results <- models.ScanResult{
				TargetName: job.TargetName,
				TargetIP:   job.TargetIP,
				Port:       job.Port,
				Protocol:   "udp",
				State:      "open",
				Banner:     fmt.Sprintf("%x", respBytes),
			}
		}
	}
}
