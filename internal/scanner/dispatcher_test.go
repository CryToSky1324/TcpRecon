package scanner

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/CryToSky1324/TcpRecon/internal/models"
	"github.com/CryToSky1324/TcpRecon/internal/utils"
)

func TestRouteJobsReturnsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rawJobs := make(chan models.ScanJob, 1)
	tcpJobs := make(chan models.ScanJob)
	udpJobs := make(chan models.ScanJob)

	rawJobs <- models.ScanJob{
		TargetIP: "127.0.0.1",
		Port:     80,
		Protocol: "tcp",
	}

	err := routeJobs(ctx, rawJobs, tcpJobs, udpJobs)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("routeJobs() error = %v, want context.Canceled", err)
	}
}
func TestRouteJobsRoutesByProtocol(t *testing.T) {

	rawJobs := make(chan models.ScanJob, 2)
	tcpJobs := make(chan models.ScanJob, 1)
	udpJobs := make(chan models.ScanJob, 1)

	tcpJob := models.ScanJob{
		TargetIP: "127.0.0.1",
		Port:     80,
		Protocol: "tcp",
	}

	udpJob := models.ScanJob{
		TargetIP: "127.0.0.1",
		Port:     53,
		Protocol: "udp",
	}

	rawJobs <- tcpJob
	rawJobs <- udpJob
	close(rawJobs)

	err := routeJobs(context.Background(), rawJobs, tcpJobs, udpJobs)

	if err != nil {
		t.Fatalf("routeJobs() error = %v", err)
	}
	gotTCP := <-tcpJobs
	gotUDP := <-udpJobs

	if gotTCP != tcpJob {
		t.Errorf("TCP job = %+v, want %+v", gotTCP, tcpJob)
	}
	if gotUDP != udpJob {
		t.Errorf("UDP job = %+v, want %+v", gotUDP, udpJob)
	}
}

func TestProduceTargetsReturnsCompletionError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	jobs := make(chan models.ScanJob, 1)

	err := produceTargets(
		ctx,
		strings.NewReader("127.0.0.1\n"),
		[]int{80},
		nil,
		jobs,
	)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("produceTargets() error = %v, want context.Canceled", err)
	}
}

func TestStartTargetProducerReportsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rawJobs := make(chan models.ScanJob, 1)

	producerErr := startTargetProducer(
		ctx,
		strings.NewReader("127.0.0.1\n"),
		[]int{80},
		nil,
		rawJobs,
	)

	err := <-producerErr
	if !errors.Is(err, context.Canceled) {
		t.Fatalf(
			"startTargetProducer() error = %v, want context.Canceled",
			err,
		)
	}

	_, ok := <-rawJobs
	if ok {
		t.Fatal("rawJobs remained open after producer finished")
	}
}

func TestStartJobRouterReportsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rawJobs := make(chan models.ScanJob, 1)
	tcpJobs := make(chan models.ScanJob)
	udpJobs := make(chan models.ScanJob)

	rawJobs <- models.ScanJob{
		TargetIP: "127.0.0.1",
		Port:     80,
		Protocol: "tcp",
	}

	routerErr := startJobRouter(
		ctx,
		rawJobs,
		tcpJobs,
		udpJobs,
	)

	err := <-routerErr
	if !errors.Is(err, context.Canceled) {
		t.Fatalf(
			"startJobRouter() error = %v, want context.Canceled",
			err,
		)
	}

	_, tcpOpen := <-tcpJobs
	if tcpOpen {
		t.Fatal("tcpJobs remained open after router finished")
	}

	_, udpOpen := <-udpJobs
	if udpOpen {
		t.Fatal("udpJobs remained open after router finished")
	}
}

func TestAwaitScannerCompletionReportsSuccess(t *testing.T) {
	ctx := context.Background()

	producerErr := make(chan error, 1)
	producerErr <- nil
	close(producerErr)

	routerErr := make(chan error, 1)
	routerErr <- nil
	close(routerErr)

	workerErr := make(chan error)
	close(workerErr)

	workersDone := make(chan struct{})
	close(workersDone)

	got := awaitScannerCompletion(
		ctx,
		producerErr,
		routerErr,
		workerErr,
		workersDone,
	)

	if !got.Successful() {
		t.Fatalf(
			"awaitScannerCompletion() = %+v, want successful completion",
			got,
		)
	}

	if got.Status != ScanStatusCompleted {
		t.Fatalf(
			"awaitScannerCompletion() status = %q, want %q",
			got.Status,
			ScanStatusCompleted,
		)
	}
}

func TestAwaitScannerCompletionReportsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	producerErr := make(chan error, 1)
	producerErr <- context.Canceled
	close(producerErr)

	routerErr := make(chan error, 1)
	routerErr <- context.Canceled
	close(routerErr)

	workersDone := make(chan struct{})
	close(workersDone)

	workerErr := make(chan error)
	close(workerErr)

	got := awaitScannerCompletion(
		ctx,
		producerErr,
		routerErr,
		workerErr,
		workersDone,
	)

	if got.Status != ScanStatusCancelled {
		t.Fatalf(
			"awaitScannerCompletion() status = %q, want %q",
			got.Status,
			ScanStatusCancelled,
		)
	}

	if !errors.Is(got.Err, context.Canceled) {
		t.Fatalf(
			"awaitScannerCompletion() error = %v, want context.Canceled",
			got.Err,
		)
	}

	if got.Successful() {
		t.Fatal("cancelled scan reported successful")
	}
}

func TestAwaitScannerCompletionReportsProducerParseFailure(t *testing.T) {
	ctx := context.Background()

	parseErr := fmt.Errorf(
		"%w: invalid target",
		utils.ErrTargetParse,
	)

	producerErr := make(chan error, 1)
	producerErr <- parseErr
	close(producerErr)

	routerErr := make(chan error, 1)
	routerErr <- nil
	close(routerErr)

	workersDone := make(chan struct{})
	close(workersDone)

	workerErr := make(chan error)
	close(workerErr)

	got := awaitScannerCompletion(
		ctx,
		producerErr,
		routerErr,
		workerErr,
		workersDone,
	)

	if got.Status != ScanStatusParseFailed {
		t.Fatalf(
			"awaitScannerCompletion() status = %q, want %q",
			got.Status,
			ScanStatusParseFailed,
		)
	}

	if !errors.Is(got.Err, utils.ErrTargetParse) {
		t.Fatalf(
			"awaitScannerCompletion() error = %v, want ErrTargetParse",
			got.Err,
		)
	}

	if got.Successful() {
		t.Fatal("parse-failed scan reported successful")
	}
}

func TestAwaitScannerCompletionReportsProducerResolutionFailure(t *testing.T) {
	ctx := context.Background()

	resolutionErr := fmt.Errorf(
		"%w: unresolved target",
		utils.ErrTargetResolution,
	)

	producerErr := make(chan error, 1)
	producerErr <- resolutionErr
	close(producerErr)

	routerErr := make(chan error, 1)
	routerErr <- nil
	close(routerErr)

	workersDone := make(chan struct{})
	close(workersDone)

	workerErr := make(chan error)
	close(workerErr)

	got := awaitScannerCompletion(
		ctx,
		producerErr,
		routerErr,
		workerErr,
		workersDone,
	)

	if got.Status != ScanStatusResolutionFailed {
		t.Fatalf(
			"awaitScannerCompletion() status = %q, want %q",
			got.Status,
			ScanStatusResolutionFailed,
		)
	}

	if !errors.Is(got.Err, utils.ErrTargetResolution) {
		t.Fatalf(
			"awaitScannerCompletion() error = %v, want ErrTargetResolution",
			got.Err,
		)
	}

	if got.Successful() {
		t.Fatal("resolution-failed scan reported successful")
	}
}

func TestStartScannerCompletionReportsSuccess(t *testing.T) {
	ctx := context.Background()

	producerErr := make(chan error, 1)
	producerErr <- nil
	close(producerErr)

	routerErr := make(chan error, 1)
	routerErr <- nil
	close(routerErr)

	workerErr := make(chan error)
	close(workerErr)

	workersDone := make(chan struct{})
	close(workersDone)

	completionCh := startScannerCompletion(
		ctx,
		producerErr,
		routerErr,
		workerErr,
		workersDone,
	)

	got, ok := <-completionCh
	if !ok {
		t.Fatal("completion channel closed without a result")
	}

	if !got.Successful() {
		t.Fatalf(
			"startScannerCompletion() = %+v, want successful completion",
			got,
		)
	}

	if got.Status != ScanStatusCompleted {
		t.Fatalf(
			"startScannerCompletion() status = %q, want %q",
			got.Status,
			ScanStatusCompleted,
		)
	}
}


func TestStartScannerCompletionWaitsForPipeline(t *testing.T) {
	ctx := context.Background()

	producerErr := make(chan error, 1)
	routerErr := make(chan error, 1)
	workersDone := make(chan struct{})
	workerErr := make(chan error)
	close(workerErr)

	completionCh := startScannerCompletion(
		ctx,
		producerErr,
		routerErr,
		workerErr,
		workersDone,
	)

	select {
	case got := <-completionCh:
		t.Fatalf(
			"completion reported before pipeline finished: %+v",
			got,
		)
	default:
	}

	producerErr <- nil
	close(producerErr)

	routerErr <- nil
	close(routerErr)

	close(workersDone)

	got, ok := <-completionCh
	if !ok {
		t.Fatal("completion channel closed without a result")
	}

	if !got.Successful() {
		t.Fatalf(
			"completion = %+v, want successful completion",
			got,
		)
	}
}

func TestRunExposesCompletion(t *testing.T) {
	ctx := context.Background()

	results, completionCh, _ := Run(
		ctx,
		strings.NewReader("127.0.0.1\n"),
		nil,
		nil,
		1,
		10*time.Millisecond,
		100,
		false,
		false,
	)

	for range results {
	}

	completion, ok := <-completionCh
	if !ok {
		t.Fatal("completion channel closed without a result")
	}

	if !completion.Successful() {
		t.Fatalf(
			"Run() completion = %+v, want successful completion",
			completion,
		)
	}

	if completion.Status != ScanStatusCompleted {
		t.Fatalf(
			"Run() completion status = %q, want %q",
			completion.Status,
			ScanStatusCompleted,
		)
	}
}

func TestRunCancellationDoesNotReportSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, completionCh, _ := Run(
		ctx,
		strings.NewReader("127.0.0.1\n"),
		nil,
		nil,
		1,
		10*time.Millisecond,
		100,
		false,
		false,
	)

	for range results {
	}

	completion, ok := <-completionCh
	if !ok {
		t.Fatal("completion channel closed without a result")
	}

	if completion.Status != ScanStatusCancelled {
		t.Fatalf(
			"Run() status = %q, want %q",
			completion.Status,
			ScanStatusCancelled,
		)
	}

	if completion.Successful() {
		t.Fatal("cancelled Run reported successful after results closed")
	}
}

func TestRunReportsWorkerFailureForUnsupportedUDPPort(t *testing.T) {
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

	results, completionCh, _ := Run(
		ctx,
		strings.NewReader("127.0.0.1\n"),
		nil,
		[]int{unsupportedPort},
		1,
		10*time.Millisecond,
		100,
		false,
		false,
	)

	for range results {
	}

	completion, ok := <-completionCh
	if !ok {
		t.Fatal("completion channel closed without a result")
	}

	if completion.Status != ScanStatusWorkerFailed {
		t.Fatalf(
			"Run() completion status = %q, want %q",
			completion.Status,
			ScanStatusWorkerFailed,
		)
	}

	if completion.Err == nil {
		t.Fatal("Run() completion error = nil, want worker failure diagnostic")
	}

	if completion.Successful() {
		t.Fatal("worker-failed Run reported successful")
	}
}
