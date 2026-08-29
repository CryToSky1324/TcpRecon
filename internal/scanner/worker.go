package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
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
		var activeConn net.Conn = conn
		var certSubject, certIssuer, banner string
		var sans []string

		// 4. Layer 6: TLS Wrapping with SNI Injection
		if job.Port == 443 || job.Port == 8443 {
			tlsConfig := &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         job.TargetName,
			}
			tlsConn := tls.Client(conn, tlsConfig)

			// Trap deadline failure
			if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err == nil {
				if err := tlsConn.Handshake(); err == nil {
					activeConn = tlsConn
					state := tlsConn.ConnectionState()
					if len(state.PeerCertificates) > 0 {
						cert := state.PeerCertificates[0]
						certSubject = cert.Subject.CommonName
						if len(cert.Issuer.Organization) > 0 {
							certIssuer = cert.Issuer.Organization[0]
						}
						sans = cert.DNSNames
					}
				} else if debug {
					fmt.Fprintf(os.Stderr, "[DEBUG] TLS handshake failed for %s: %v\n", address, err)
				}
			}
		}

		// 5. Layer 7: Application-Layer Payload Injection
		// Trap WriteDeadline failure
		if err := activeConn.SetWriteDeadline(time.Now().Add(timeout)); err == nil {
			if job.Port == 80 || job.Port == 8080 {
				httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", job.TargetIP)
				// Trap payload transmission failure
				if _, err := activeConn.Write([]byte(httpReq)); err != nil && debug {
					fmt.Fprintf(os.Stderr, "[DEBUG] HTTP Write failed for %s: %v\n", address, err)
				}
			}
		}

		// 6. Buffer Allocation and Banner Extraction
		// Trap ReadDeadline failure
		if err := activeConn.SetReadDeadline(time.Now().Add(timeout)); err == nil {
			buf := make([]byte, 1024)
			// Trap Read failure (EOF or timeouts are common, don't panic)
			if n, err := activeConn.Read(buf); err == nil && n > 0 {
				banner = string(buf[:n])
			}
		}

		// 7. Stateless OS Fingerprinting Execution
		osHint := utils.FingerprintOS(banner)

		// 8. Graceful Teardown and Channel Push
		activeConn.Close()
		results <- models.ScanResult{
			TargetName:  job.TargetName,
			TargetIP:    job.TargetIP,
			Port:        job.Port,
			Protocol:    "tcp",
			State:       "OPEN",
			Banner:      strings.TrimSpace(banner),
			OSHint:      osHint,
			CertSubject: certSubject,
			CertIssuer:  certIssuer,
			SANs:        sans,
		}
	}
}
