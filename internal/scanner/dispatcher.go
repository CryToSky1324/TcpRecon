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
func Run(ctx context.Context, targetStream io.Reader, portsToScan []int, numWorkers int, timeout time.Duration, rateLimit int, debugMode bool, jsonMode bool) (<-chan models.ScanResult, time.Time) {
	// Token Bucket Rate Limiter
	globalLimiter := rate.NewLimiter(rate.Limit(rateLimit), rateLimit)

	// Buffered channel dictates memory footprint. Buffer full = parser blocks.
	jobs := make(chan models.ScanJob, numWorkers*2)
	results := make(chan models.ScanResult)
	var wg sync.WaitGroup

	startTime := time.Now()

	// 1. Spawn Worker Pool
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			Worker(ctx, jobs, results, timeout, debugMode, globalLimiter)
		}()
	}

	// 2. Stream Producer
	go func() {
		defer close(jobs)
		utils.StreamTargets(ctx, targetStream, portsToScan, jobs)
	}()

	// 1. Lifecycle Monitor (Monitor Pattern)
	go func() {
		wg.Wait()
		close(results)
	}()

	// Delegate consumption to the State Manager (Requires db pointer passed into Run, or handled in main)
	// We will return the channel to main.go so main can own the DB lifecycle.
	return results, startTime
}
