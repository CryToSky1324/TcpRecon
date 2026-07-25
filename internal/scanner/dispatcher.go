package scanner

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/CryToSky1324/TcpRecon/internal/models"
)

// Run orchestrates the Thread Pool, Channel Pipelines, and WaitGroups
func Run(ctx context.Context, targetList models.TargetMap, portsToScan []int, numWorkers int, timeout time.Duration, rateLimit int, debugMode bool, jsonMode bool) (<-chan models.ScanResult, time.Time) {
	// Token Bucket Rate Limiter
	globalLimiter := rate.NewLimiter(rate.Limit(rateLimit), rateLimit)

	jobs := make(chan models.ScanJob, numWorkers)
	results := make(chan models.ScanResult)
	var wg sync.WaitGroup

	startTime := time.Now()

	// Spawn Worker Pool
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			Worker(ctx, jobs, results, timeout, debugMode, globalLimiter)
		}()
	}

	// Job Producer
	go func() {
		defer close(jobs)
		for rawName, resolvedIPs := range targetList {
			for _, ip := range resolvedIPs {
				for _, port := range portsToScan {
					select {
					case <-ctx.Done():
						return
					case jobs <- models.ScanJob{TargetIP: ip, TargetName: rawName, Port: port}:
					}
				}
			}
		}
	}()

	// Lifecycle Monitor (Monitor Pattern)
	go func() {
		wg.Wait()
		close(results)
	}()

	// Delegate consumption to the State Manager (Requires db pointer passed into Run, or handled in main)
	// We will return the channel to main.go so main can own the DB lifecycle.
	return results, startTime
}
