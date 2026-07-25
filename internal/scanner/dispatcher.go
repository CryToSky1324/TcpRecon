package scanner

import (
	"context"
	"sync"
	"time"
	"io"

	"golang.org/x/time/rate"

	"github.com/CryToSky1324/TcpRecon/internal/models"
	"github.com/CryToSky1324/TcpRecon/internal/utils"
)

// Run orchestrates the Thread Pool, Channel Pipelines, and WaitGroups
func Run(ctx context.Context, targetStream io.Reader, tcpPorts []int , udpPorts []int , numWorkers int, timeout time.Duration, rateLimit int, debugMode bool, jsonMode bool) (<-chan models.ScanResult, time.Time) {
	// Token Bucket Rate Limiter
	globalLimiter := rate.NewLimiter(rate.Limit(rateLimit), rateLimit)

	// Replace the single 'jobs' channel in Run() with:
	tcpJobs := make(chan models.ScanJob, numWorkers*2)
  udpJobs := make(chan models.ScanJob, numWorkers*2)
  rawJobs := make(chan models.ScanJob, numWorkers*2)
	results := make(chan models.ScanResult)
	var wg sync.WaitGroup

	startTime := time.Now()

	// 1. Spawn Worker Pool
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			Worker(ctx, tcpJobs, results, timeout, debugMode, globalLimiter)
		}()
	}
	// 2. Spawn UDP Worker Pool (Allocate 25% of workers to UDP dials)
	udpWorkers := numWorkers / 4
	if udpWorkers < 1 {
    udpWorkers = 1
	}

	for i := 0; i < udpWorkers; i++ {
    wg.Add(1)
    go func() {
        defer wg.Done()
        UDPWorker(ctx, udpJobs, results, timeout, debugMode, globalLimiter)
    }()
}

	
	// 3. The Router Goroutine
	go func() {
    defer close(tcpJobs)
    defer close(udpJobs)
    for job := range rawJobs {
        if job.Protocol == "udp" {
            udpJobs <- job
        } else {
            tcpJobs <- job
        }
    }
	}()

	// 4. Stream Producer
	go func() {
		defer close(rawJobs)
		utils.StreamTargets(ctx, targetStream, tcpPorts, udpPorts, rawJobs)
	}()

	// 5. Lifecycle Monitor (Monitor Pattern)
	go func() {
		wg.Wait()
		close(results)
	}()

	// Delegate consumption to the State Manager (Requires db pointer passed into Run, or handled in main)
	// We will return the channel to main.go so main can own the DB lifecycle.
	return results, startTime
}
