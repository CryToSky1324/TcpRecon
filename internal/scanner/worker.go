package scanner

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/CryToSky1324/TcpRecon/internal/models"
	"github.com/CryToSky1324/TcpRecon/internal/utils"
)

// Worker executes the TCP connection, TLS wrapping, payload injection, and X.509 extraction (Exported)
func Worker(ctx context.Context, jobs <-chan models.ScanJob, results chan<- models.ScanResult, timeout time.Duration, debug bool, limiter *rate.Limiter) {
	dialer := net.Dialer{Timeout: timeout}

	for {
		var job models.ScanJob
		var ok bool

		// 1. Context-Aware Job Consumption
		select {
		case <-ctx.Done():
			return
		case job, ok = <-jobs:
			if !ok {
				return
			}
		}

		// 2. Token Bucket Traffic Shaping
		if err := limiter.Wait(ctx); err != nil {
			return
		}

		// 3. Layer 4: Socket Initialization
		address := joinHostPort(job.TargetIP, job.Port)
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] Dial failed for %s: %v\n", address, err)
			}
			// L4 failed. Port is closed/filtered. Move to next job.
			continue
		}

		// L4 Succeeded. We MUST push a result for this port regardless of L7 success.
		var banner string
		var parseErr error

		// Step A: Attempt Opportunistic TLS Inspection
		meta := probeTLS(conn, job.TargetName, timeout)

		// Step B: Layer 7 Banner Dispatch
		if meta.Version != "" {
			// TLS Handshake succeeded on this port!
			// If it's a known HTTPS port, or default TLS, we record the TLS presence.
			// (Note: Since probeTLS completed the handshake on 'conn', conn is now in TLS state.)
		} else {
			// Plaintext Stream Dispatch
			switch job.Port {
			case 22, 2222:
				banner, parseErr = ParseSSH(conn, timeout)
			case 80, 8000, 8080:
				banner, parseErr = ParseHTTP(conn, timeout)
			default:
				// Safe fallback for server-first banners (FTP, SMTP, Redis, etc.)
				_ = conn.SetReadDeadline(time.Now().Add(timeout))
				lr := io.LimitReader(conn, 1024)
				buf := make([]byte, 1024)
				if n, readErr := lr.Read(buf); readErr == nil && n > 0 {
					banner = string(buf[:n])
				}
			}
		}

		if parseErr != nil && debug {
			fmt.Fprintf(os.Stderr, "[DEBUG] L7 parse failed for %s:%d: %v\n", job.TargetIP, job.Port, parseErr)
		}

		// 7. Stateless OS Fingerprinting Execution
		osHint := utils.FingerprintOS(banner)

		// 8. Graceful Teardown and Channel Push
		conn.Close()
		results <- models.ScanResult{
			TargetName:    job.TargetName,
			TargetIP:      job.TargetIP,
			Port:          job.Port,
			Protocol:      "tcp",
			State:         "open",
			Banner:        strings.TrimSpace(banner),
			OSHint:        osHint,
			CertSubject:   meta.CertSubject,
			CertIssuer:    meta.CertIssuer,
			SANs:          meta.SANs,
			TLSVersion:    meta.Version,
			CipherSuite:   meta.CipherSuite,
			CertVerified:  meta.CertVerified,
			CertNotBefore: meta.NotBefore,
			CertNotAfter:  meta.NotAfter,
		}
	}
}
