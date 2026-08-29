package scanner

import (
	"context"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/CryToSky1324/TcpRecon/internal/models"
)

func TestUDPWorkerReportsUnsupportedPayload(t *testing.T) {
	unsupportedPort := 1

	for ; unsupportedPort <= 65535; unsupportedPort++ {
		if _, exists := UDPPayloads[unsupportedPort]; !exists {
			break
		}
	}

	if unsupportedPort > 65535 {
		t.Fatal("could not find unsupported UDP port for test")
	}

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
		10*time.Millisecond,
		false,
		limiter,
	)

	if err == nil {
		t.Fatal("UDPWorker() error = nil, want unsupported-payload failure")
	}
}

func TestUDPWorkerDrainsJobsAfterUnsupportedPayload(t *testing.T) {
	unsupportedPort := 1

	for ; unsupportedPort <= 65535; unsupportedPort++ {
		if _, exists := UDPPayloads[unsupportedPort]; !exists {
			break
		}
	}

	if unsupportedPort > 65535 {
		t.Fatal("could not find unsupported UDP port for test")
	}

	ctx := context.Background()

	jobs := make(chan models.ScanJob, 2)
	results := make(chan models.ScanResult, 1)

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
		10*time.Millisecond,
		false,
		limiter,
	)

	if err == nil {
		t.Fatal("UDPWorker() error = nil, want worker failure")
	}

	if remaining := len(jobs); remaining != 0 {
		t.Fatalf(
			"UDPWorker() left %d jobs unconsumed after worker failure",
			remaining,
		)
	}
}
