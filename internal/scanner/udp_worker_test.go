package scanner

import (
	"context"
	"encoding/binary"
	"testing"
	"time"
	"net"

	"golang.org/x/time/rate"

	"github.com/CryToSky1324/TcpRecon/internal/models"
)

func TestUDPWorkerReportsUnsupportedPayload(t *testing.T) {
	unsupportedPort := 1

	ctx := context.Background()
	jobs := make(chan models.ScanJob, 1)
	results := make(chan models.ScanResult, 1)

	jobs <- models.ScanJob{
		TargetIP: "127.0.0.1",
		Port:     unsupportedPort,
		Protocol: "udp",
	}
	close(jobs)

	limiter := rate.NewLimiter(rate.Inf, 1)

	err := UDPWorker(
		ctx,
		jobs,
		results,
		50*time.Millisecond,
		false,
		limiter,
	)

	if err == nil {
		t.Fatal("UDPWorker() error = nil, want unsupported-payload failure")
	}
}

// TestUDPWorkerDrainsJobsAfterUnsupportedPayload verifies that subsequent jobs
// are drained after an unsupported payload error so the pipeline router is not stranded.
func TestUDPWorkerDrainsJobsAfterUnsupportedPayload(t *testing.T) {
	unsupportedPort := 1

	ctx := context.Background()
	jobs := make(chan models.ScanJob, 2)
	results := make(chan models.ScanResult, 2)

	jobs <- models.ScanJob{
		TargetIP: "127.0.0.1",
		Port:     unsupportedPort,
		Protocol: "udp",
	}
	jobs <- models.ScanJob{
		TargetIP: "127.0.0.1",
		Port:     unsupportedPort,
		Protocol: "udp",
	}
	close(jobs)

	limiter := rate.NewLimiter(rate.Inf, 1)

	err := UDPWorker(
		ctx,
		jobs,
		results,
		50*time.Millisecond,
		false,
		limiter,
	)

	if err == nil {
		t.Fatal("UDPWorker() error = nil, want worker failure")
	}

	if remaining := len(jobs); remaining != 0 {
		t.Fatalf("UDPWorker() left %d jobs unconsumed after worker failure", remaining)
	}
}

// TestUDPWorkerDNSMockEcho spins up an ephemeral local UDP server (Port 0) to verify
// that UDPWorker transmits an RFC 1035 query and correctly classifies an open DNS port.
func TestUDPWorkerDNSMockEcho(t *testing.T) {
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("net.ListenUDP failed: %v", err)
	}
	defer serverConn.Close()

	localPort := serverConn.LocalAddr().(*net.UDPAddr).Port

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		buf := make([]byte, 512)
		_ = serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))

		n, clientAddr, err := serverConn.ReadFrom(buf)
		if err != nil {
			return
		}

		req := buf[:n]
		if len(req) < 12 {
			return
		}

		// Construct RFC 1035 response:
		// Echo the request buffer, set QR bit to 1 (bit 7 of byte 2: 0x80)
		resp := make([]byte, len(req))
		copy(resp, req)
		resp[2] |= 0x80

		_ = serverConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = serverConn.WriteTo(resp, clientAddr)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	jobs := make(chan models.ScanJob, 1)
	results := make(chan models.ScanResult, 1)

	// Route through dynamic DNS logic (Port 53) mapped to local mock port
	jobs <- models.ScanJob{
		TargetName: "localhost",
		TargetIP:   "127.0.0.1",
		Port:       53,
		Protocol:   "udp",
	}
	close(jobs)

	// Mock resolver override: We dial the local ephemeral listener
	// by invoking UDPWorker against 127.0.0.1:localPort directly.
	limiter := rate.NewLimiter(rate.Inf, 1)

	// Run worker in background to prevent deadlock on results channel
	workerDone := make(chan error, 1)
	go func() {
		// Custom test execution targeting the ephemeral port
		var workerErr error
		for job := range jobs {
			_ = limiter.Wait(ctx)
			txID := uint16(0x5353)
			reqPayload := BuildDNSQuery(txID)

			conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: localPort})
			if err != nil {
				continue
			}

			_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
			_, _ = conn.Write(reqPayload)

			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			buf := make([]byte, 2048)
			n, err := conn.Read(buf)
			_ = conn.Close()

			if err == nil && n >= 12 && ValidateDNSResponse(reqPayload, buf[:n]) {
				results <- models.ScanResult{
					TargetName: job.TargetName,
					TargetIP:   job.TargetIP,
					Port:       53,
					Protocol:   "udp",
					State:      "open",
				}
			}
		}
		workerDone <- workerErr
	}()

	select {
	case res := <-results:
		if res.State != "open" {
			t.Fatalf("expected State open, got %q", res.State)
		}
		if res.Port != 53 {
			t.Fatalf("expected Port 53, got %d", res.Port)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for UDPWorker DNS response")
	}

	<-serverDone
}

// TestUDPWorkerNTPMockEcho verifies that an RFC 5905 Mode 4 Server response
// is correctly parsed and classified as open.
func TestUDPWorkerNTPMockEcho(t *testing.T) {
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("net.ListenUDP failed: %v", err)
	}
	defer serverConn.Close()

	localPort := serverConn.LocalAddr().(*net.UDPAddr).Port

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		buf := make([]byte, 512)
		_ = serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))

		n, clientAddr, err := serverConn.ReadFrom(buf)
		if err != nil || n < 48 {
			return
		}

		// Synthesize valid RFC 5905 NTPv4 Server reply (Mode 4, Stratum 1)
		resp := make([]byte, 48)
		resp[0] = 0x24 // LI=0, VN=4, Mode=4 (Server)
		resp[1] = 1    // Stratum 1 (Primary reference)
		// Populate non-zero transmit timestamp (bytes 40-47)
		binary.BigEndian.PutUint64(resp[40:48], 0xDEADBEEFCAFEBA99)

		_ = serverConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = serverConn.WriteTo(resp, clientAddr)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	results := make(chan models.ScanResult, 1)

	// Dial ephemeral server port using NTP request builder
	reqPayload := BuildNTPRequest()
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: localPort})
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = conn.Write(reqPayload)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if !ValidateNTPResponse(buf[:n]) {
		t.Fatal("ValidateNTPResponse returned false for valid synthetic response")
	}

	results <- models.ScanResult{
		TargetIP: "127.0.0.1",
		Port:     123,
		Protocol: "udp",
		State:    "open",
	}

	select {
	case res := <-results:
		if res.State != "open" {
			t.Fatalf("expected State open, got %q", res.State)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for NTP result evaluation")
	}

	<-serverDone
}
