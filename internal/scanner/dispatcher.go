package scanner

import (
	"context"
	"io"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/CryToSky1324/TcpRecon/internal/models"
	"github.com/CryToSky1324/TcpRecon/internal/utils"
)

// Run orchestrates the Thread Pool, Channel Pipelines, and WaitGroups
func Run(
	ctx context.Context,
	targetStream io.Reader,
	tcpPorts []int,
	udpPorts []int,
	numWorkers int,
	timeout time.Duration,
	rateLimit int,
	debugMode bool,
	jsonMode bool,
) (<-chan models.ScanResult, <-chan ScanCompletion, time.Time) {
	// Token Bucket Rate Limiter
	globalLimiter := rate.NewLimiter(
		rate.Limit(rateLimit),
		rateLimit,
	)

	tcpJobs := make(chan models.ScanJob, numWorkers*2)
	udpJobs := make(chan models.ScanJob, numWorkers*2)
	rawJobs := make(chan models.ScanJob, numWorkers*2)
	results := make(chan models.ScanResult)

	var wg sync.WaitGroup

	startTime := time.Now()

	// 1. Spawn TCP Worker Pool
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			Worker(
				ctx,
				tcpJobs,
				results,
				timeout,
				debugMode,
				globalLimiter,
			)
		}()
	}

	// 2. Spawn UDP Worker Pool
	udpWorkers := numWorkers / 4
	if udpWorkers < 1 {
		udpWorkers = 1
	}

	// Preserve the first worker-level error.
	workerErr := make(chan error, 1)

	for i := 0; i < udpWorkers; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			if err := UDPWorker(
				ctx,
				udpJobs,
				results,
				timeout,
				debugMode,
				globalLimiter,
			); err != nil {
				select {
				case workerErr <- err:
				default:
				}
			}
		}()
	}

	// 3. Start Job Router
	routerErr := startJobRouter(
		ctx,
		rawJobs,
		tcpJobs,
		udpJobs,
	)

	// 4. Start Target Producer
	producerErr := startTargetProducer(
		ctx,
		targetStream,
		tcpPorts,
		udpPorts,
		rawJobs,
	)

	// 5. Lifecycle Monitor
	workersDone := make(chan struct{})

	go func() {
		wg.Wait()

		close(results)
		close(workerErr)
		close(workersDone)
	}()

	// 6. Scanner Completion
	completionCh := startScannerCompletion(
		ctx,
		producerErr,
		routerErr,
		workerErr,
		workersDone,
	)

	return results, completionCh, startTime
}

func routeJobs(ctx context.Context, rawJobs <-chan models.ScanJob, tcpJobs chan<- models.ScanJob, udpJobs chan<- models.ScanJob) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case job, ok := <-rawJobs:
			if !ok {
				return nil
			}

			if job.Protocol == "udp" {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case udpJobs <- job:
				}
				continue
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case tcpJobs <- job:
			}
		}
	}
}

func produceTargets(ctx context.Context, targetStream io.Reader, tcpPorts []int, udpPorts []int, rawJobs chan<- models.ScanJob) error {
	return utils.StreamTargets(ctx, targetStream, tcpPorts, udpPorts, rawJobs)
}

func startTargetProducer(ctx context.Context, targetStream io.Reader, tcpPorts []int, udpPorts []int, rawJobs chan<- models.ScanJob) <-chan error {
	producerErr := make(chan error, 1)

	go func() {
		defer close(rawJobs)
		defer close(producerErr)

		producerErr <- produceTargets(ctx, targetStream, tcpPorts, udpPorts, rawJobs)
	}()
	return producerErr
}

func startJobRouter(ctx context.Context, rawJobs <-chan models.ScanJob, tcpJobs chan<- models.ScanJob, udpJobs chan<- models.ScanJob) <-chan error {
	routerErr := make(chan error, 1)

	go func() {
		err := routeJobs(ctx, rawJobs, tcpJobs, udpJobs)

		close(tcpJobs)
		close(udpJobs)

		routerErr <- err
		close(routerErr)
	}()

	return routerErr
}

func awaitScannerCompletion(
	ctx context.Context,
	producerErr <-chan error,
	routerErr <-chan error,
	workerErr <-chan error,
	workersDone <-chan struct{},
) ScanCompletion {
	producerResult, producerOK := <-producerErr
	routerResult, routerOK := <-routerErr
	// Do not decide final completion until every worker has exited.
	<-workersDone

	workerResult, workerOK := <-workerErr

	// Missing producer/router outcomes fail closed.
	if !producerOK || !routerOK {
		return ScanCompletion{}
	}

	// Cancellation is authoritative over worker errors caused by
	// the same cancelled context.
	if err := ctx.Err(); err != nil {
		return ScanCompletion{
			Status: ScanStatusCancelled,
			Err:    err,
		}
	}

	// Producer failures already have their own classification.
	if producerResult != nil {
		return scanCompletionFromProducerError(producerResult)
	}

	// Router failures are currently fail-closed but do not yet
	// have a dedicated ScanStatus.
	if routerResult != nil {
		return ScanCompletion{
			Err: routerResult,
		}
	}

	// A worker failure means intended scan work could not be completed.
	if workerOK && workerResult != nil {
		return ScanCompletion{
			Status: ScanStatusWorkerFailed,
			Err:    workerResult,
		}
	}

	return ScanCompletion{
		Status: ScanStatusCompleted,
	}
}

func startScannerCompletion(
	ctx context.Context,
	producerErr <-chan error,
	routerErr <-chan error,
	workerErr <-chan error,
	workersDone <-chan struct{},
) <-chan ScanCompletion {
	completionCh := make(chan ScanCompletion, 1)

	go func() {
		defer close(completionCh)

		completionCh <- awaitScannerCompletion(
			ctx,
			producerErr,
			routerErr,
			workerErr,
			workersDone,
		)
	}()

	return completionCh
}
