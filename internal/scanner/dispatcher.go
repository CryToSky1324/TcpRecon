package scanner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/CryToSky1324/TcpRecon/internal/models"
)

// Run orchestrates the Thread Pool, Channel Pipelines, and WaitGroups
func Run(ctx context.Context, targetList models.TargetMap, portsToScan []int, numWorkers int, timeout time.Duration, rateLimit int, debugMode bool, jsonMode bool) ([]models.ScanResult, int, time.Duration) {
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

	// Result Consumer
	var discoveredPorts []models.ScanResult
	openPorts := 0

	for result := range results {
		if result.State == "OPEN" {
			discoveredPorts = append(discoveredPorts, result)
			openPorts++

			if !jsonMode {
				bannerDisplay := "No Banner"
				if result.Banner != "" {
					bannerDisplay = result.Banner
				}
				fmt.Printf("[+] Port %d/TCP is OPEN\t- %s\n", result.Port, bannerDisplay)

				if result.OSHint != "" && result.OSHint != "Unknown/Obfuscated" {
					fmt.Printf("    |_ OS Fingerprint: %s\n", result.OSHint)
				}

				if result.CertSubject != "" {
					fmt.Printf("    |_ TLS Subject: %s\n", result.CertSubject)
					fmt.Printf("    |_ TLS Issuer:  %s\n", result.CertIssuer)
					if len(result.SANs) > 0 {
						fmt.Printf("    |_ TLS SANs:    %s\n", strings.Join(result.SANs, ", "))
					}
				}
			}
		}
	}

	duration := time.Since(startTime)
	return discoveredPorts, openPorts, duration
}
