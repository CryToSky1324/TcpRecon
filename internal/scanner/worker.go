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

	"github.com/CryToSky1324/TcpRecon/internal/models" // Adjust to your canonical go.mod module path
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
		address := fmt.Sprintf("%s:%d", job.TargetIP, job.Port)
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] Dial failed for %s: %v\n", address, err)
			}
			continue
		}

		var activeConn net.Conn = conn
		var certSubject, certIssuer string
		var sans []string

		// 4. Layer 6: TLS Wrapping with SNI Injection
		if job.Port == 443 || job.Port == 8443 {
			tlsConfig := &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         job.TargetName,
			}
			tlsConn := tls.Client(conn, tlsConfig)
			
			tlsConn.SetDeadline(time.Now().Add(timeout))
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
			} else {
				if debug {
					fmt.Fprintf(os.Stderr, "[DEBUG] TLS handshake failed for %s: %v\n", address, err)
				}
				conn.Close()
				continue
			}
		}

		// 5. Layer 7: Application-Layer Payload Injection
		activeConn.SetWriteDeadline(time.Now().Add(timeout))
		if job.Port == 80 || job.Port == 8080 {
			httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", job.TargetIP)
			activeConn.Write([]byte(httpReq))
		}

		// 6. Buffer Allocation and Banner Extraction
		activeConn.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, 1024)
		n, _ := activeConn.Read(buf)
		banner := string(buf[:n])

		// 7. Stateless OS Fingerprinting Execution
		osHint := utils.FingerprintOS(banner)

		// 8. Graceful Teardown and Channel Push
		activeConn.Close()
		results <- models.ScanResult{
			Port:        job.Port,
			State:       "OPEN",
			Banner:      strings.TrimSpace(banner),
			OSHint:      osHint,
			CertSubject: certSubject,
			CertIssuer:  certIssuer,
			SANs:        sans,
		}
	}
}
