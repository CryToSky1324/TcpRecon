package main

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/CryToSky1324/TcpRecon/internal/models"
	"github.com/CryToSky1324/TcpRecon/internal/scanner"
)

func testOwnedRuntimeExecution(t *testing.T) (*ownedRuntimeScan, *fakeTargetSpool, *bool) {
	t.Helper()
	prepared, spool, removed := testPreparedReservationSource()
	return &ownedRuntimeScan{
		scopeID:  "scope-a",
		scanID:   strings.Repeat("a", 32),
		prepared: prepared,
	}, spool, removed
}

func awaitRuntimeExecution(t *testing.T, run func() runtimeScanExecution) runtimeScanExecution {
	t.Helper()
	done := make(chan runtimeScanExecution, 1)
	go func() {
		done <- run()
	}()
	select {
	case outcome := <-done:
		return outcome
	case <-time.After(2 * time.Second):
		t.Fatal("runtime execution deadlocked")
		return runtimeScanExecution{}
	}
}

func TestExecuteOwnedRuntimeScanSupportsCompletionAndResultOrdering(t *testing.T) {
	tests := []struct {
		name     string
		channels func() (<-chan models.ScanResult, <-chan scanner.ScanCompletion, <-chan struct{})
	}{
		{
			name: "completion before results drain",
			channels: func() (<-chan models.ScanResult, <-chan scanner.ScanCompletion, <-chan struct{}) {
				producerDone := make(chan struct{})
				completions := make(chan scanner.ScanCompletion, 1)
				completions <- scanner.ScanCompletion{Status: scanner.ScanStatusCompleted}
				close(completions)
				results := make(chan models.ScanResult)
				go func() {
					results <- models.ScanResult{TargetIP: "192.0.2.1", Port: 80, Protocol: "tcp", State: "OPEN"}
					results <- models.ScanResult{TargetIP: "192.0.2.2", Port: 443, Protocol: "tcp", State: "OPEN"}
					close(producerDone)
					close(results)
				}()
				return results, completions, producerDone
			},
		},
		{
			name: "results drain before completion",
			channels: func() (<-chan models.ScanResult, <-chan scanner.ScanCompletion, <-chan struct{}) {
				producerDone := make(chan struct{})
				results := make(chan models.ScanResult)
				completions := make(chan scanner.ScanCompletion, 1)
				go func() {
					results <- models.ScanResult{TargetIP: "192.0.2.1", Port: 80, Protocol: "tcp", State: "OPEN"}
					results <- models.ScanResult{TargetIP: "192.0.2.2", Port: 443, Protocol: "tcp", State: "OPEN"}
					close(producerDone)
					close(results)
					completions <- scanner.ScanCompletion{Status: scanner.ScanStatusCompleted}
					close(completions)
				}()
				return results, completions, producerDone
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owned, spool, removed := testOwnedRuntimeExecution(t)
			results, completions, producerDone := tt.channels()
			persisted := 0
			finalized := 0
			outcome := awaitRuntimeExecution(t, func() runtimeScanExecution {
				return executeOwnedRuntimeScan(
					owned,
					results,
					completions,
					func(models.ScanResult) error {
						persisted++
						return nil
					},
					func(scopeID, scanID string, completion scanner.ScanCompletion) ([]scanner.ServiceChange, error) {
						finalized++
						select {
						case <-producerDone:
						default:
							t.Error("finalization ran before result producer quiesced")
						}
						if scopeID != owned.ScopeID() || scanID != owned.ScanID() {
							t.Errorf("finalization identity = (%q, %q), want (%q, %q)", scopeID, scanID, owned.ScopeID(), owned.ScanID())
						}
						if !completion.Successful() {
							t.Errorf("finalization completion = %+v, want successful", completion)
						}
						return nil, nil
					},
				)
			})

			if persisted != 2 || outcome.OpenPorts != 2 {
				t.Fatalf("drain counts = (persisted=%d, open=%d), want (2, 2)", persisted, outcome.OpenPorts)
			}
			if finalized != 1 {
				t.Fatalf("finalization calls = %d, want exactly 1", finalized)
			}
			if !outcome.Completion.Successful() || outcome.Err != nil {
				t.Fatalf("runtime outcome = %+v, want successful", outcome)
			}
			if !spool.closed || !*removed {
				t.Fatalf("owned source cleanup = (closed=%t, removed=%t), want both true", spool.closed, *removed)
			}
		})
	}
}

func TestExecuteOwnedRuntimeScanDrainsAfterStickyPersistenceFailure(t *testing.T) {
	owned, spool, removed := testOwnedRuntimeExecution(t)
	results := make(chan models.ScanResult)
	completions := make(chan scanner.ScanCompletion, 1)
	producerDone := make(chan struct{})
	go func() {
		for port := 80; port < 83; port++ {
			results <- models.ScanResult{TargetIP: "192.0.2.1", Port: port, Protocol: "tcp", State: "OPEN"}
		}
		close(producerDone)
		close(results)
	}()
	completions <- scanner.ScanCompletion{Status: scanner.ScanStatusCompleted}
	close(completions)

	errFirstPersist := errors.New("first persist failure")
	errLaterPersist := errors.New("later persist failure")
	persistAttempts := 0
	finalized := 0
	var finalizedCompletion scanner.ScanCompletion
	outcome := awaitRuntimeExecution(t, func() runtimeScanExecution {
		return executeOwnedRuntimeScan(
			owned,
			results,
			completions,
			func(models.ScanResult) error {
				persistAttempts++
				switch persistAttempts {
				case 1:
					return errFirstPersist
				case 2:
					return errLaterPersist
				}
				return nil
			},
			func(_, _ string, completion scanner.ScanCompletion) ([]scanner.ServiceChange, error) {
				finalized++
				finalizedCompletion = completion
				select {
				case <-producerDone:
				default:
					t.Error("finalization ran before all results drained")
				}
				return nil, nil
			},
		)
	})

	if outcome.OpenPorts != 3 {
		t.Fatalf("open ports = %d, want all 3 results drained", outcome.OpenPorts)
	}
	if persistAttempts != 3 {
		t.Fatalf("persistence attempts = %d, want every drained result offered", persistAttempts)
	}
	if finalized != 1 {
		t.Fatalf("finalization calls = %d, want exactly 1", finalized)
	}
	if finalizedCompletion.Status != scanner.ScanStatusStateFailed || !errors.Is(finalizedCompletion.Err, errFirstPersist) {
		t.Fatalf("finalization completion = %+v, want state_failed retaining persistence error", finalizedCompletion)
	}
	if errors.Is(finalizedCompletion.Err, errLaterPersist) {
		t.Fatal("later persistence failure replaced or altered the sticky first failure")
	}
	if outcome.Completion.Status != scanner.ScanStatusStateFailed || !errors.Is(outcome.Completion.Err, errFirstPersist) {
		t.Fatalf("runtime outcome completion = %+v, want state_failed retaining persistence error", outcome.Completion)
	}
	if !spool.closed || !*removed {
		t.Fatalf("owned source cleanup = (closed=%t, removed=%t), want both true", spool.closed, *removed)
	}
}

func TestExecuteOwnedRuntimeScanReportsCleanupFailureWithoutRefinalizing(t *testing.T) {
	errCleanup := errors.New("remove prepared spool failed")
	spool := &fakeTargetSpool{path: "cleanup-failure-spool"}
	prepared := &preparedTargetSource{
		spool: spool,
		path:  spool.path,
		remove: func(string) error {
			return errCleanup
		},
	}
	owned := &ownedRuntimeScan{
		scopeID:  "scope-a",
		scanID:   strings.Repeat("a", 32),
		prepared: prepared,
	}
	results := make(chan models.ScanResult)
	close(results)
	completions := make(chan scanner.ScanCompletion, 1)
	completions <- scanner.ScanCompletion{Status: scanner.ScanStatusCompleted}
	close(completions)
	finalized := 0

	outcome := executeOwnedRuntimeScan(
		owned,
		results,
		completions,
		func(models.ScanResult) error { return nil },
		func(_, _ string, completion scanner.ScanCompletion) ([]scanner.ServiceChange, error) {
			finalized++
			if !completion.Successful() {
				t.Errorf("completion supplied to finalization = %+v, want successful", completion)
			}
			return nil, nil
		},
	)

	if finalized != 1 {
		t.Fatalf("finalization calls = %d, want exactly 1", finalized)
	}
	if !outcome.Completion.Successful() {
		t.Fatalf("runtime completion = %+v, want successful finalization completion", outcome.Completion)
	}
	if errors.Is(outcome.Completion.Err, errCleanup) {
		t.Fatal("post-finalization cleanup error altered authoritative completion")
	}
	if !errors.Is(outcome.Err, errCleanup) {
		t.Fatalf("runtime error = %v, want cleanup error", outcome.Err)
	}
}

func TestExecuteOwnedRuntimeScanMissingCompletionFailsClosed(t *testing.T) {
	owned, _, _ := testOwnedRuntimeExecution(t)
	results := make(chan models.ScanResult)
	close(results)
	completions := make(chan scanner.ScanCompletion)
	close(completions)
	finalized := 0
	var supplied scanner.ScanCompletion

	outcome := executeOwnedRuntimeScan(
		owned,
		results,
		completions,
		func(models.ScanResult) error { return nil },
		func(_, _ string, completion scanner.ScanCompletion) ([]scanner.ServiceChange, error) {
			finalized++
			supplied = completion
			return nil, nil
		},
	)

	if finalized != 1 {
		t.Fatalf("finalization calls = %d, want exactly 1", finalized)
	}
	if supplied.Status != scanner.ScanStatusWorkerFailed || !errors.Is(supplied.Err, ErrScanCompletionMissing) {
		t.Fatalf("completion supplied to finalization = %+v, want worker_failed/ErrScanCompletionMissing", supplied)
	}
	if outcome.Completion.Status != scanner.ScanStatusWorkerFailed || !errors.Is(outcome.Completion.Err, ErrScanCompletionMissing) {
		t.Fatalf("runtime completion = %+v, want worker_failed/ErrScanCompletionMissing", outcome.Completion)
	}
	if !errors.Is(outcome.Err, ErrScanCompletionMissing) {
		t.Fatalf("runtime error = %v, want ErrScanCompletionMissing", outcome.Err)
	}
}

func TestExecuteOwnedRuntimeScanCompletionPrecedence(t *testing.T) {
	errScanner := errors.New("scanner failed")
	errPersistence := errors.New("persistence failed")
	errFinalization := errors.New("finalization failed")
	tests := []struct {
		name                string
		scannerCompletion   scanner.ScanCompletion
		persistenceErr      error
		finalizationErr     error
		wantSuppliedStatus  scanner.ScanStatus
		wantSuppliedErrors  []error
		wantSuppliedSuccess bool
		wantOutcomeStatus   scanner.ScanStatus
		wantOutcomeErrors   []error
		wantOutcomeSuccess  bool
	}{
		{
			name:                "scanner and state success",
			scannerCompletion:   scanner.ScanCompletion{Status: scanner.ScanStatusCompleted},
			wantSuppliedStatus:  scanner.ScanStatusCompleted,
			wantSuppliedSuccess: true,
			wantOutcomeStatus:   scanner.ScanStatusCompleted,
			wantOutcomeSuccess:  true,
		},
		{
			name:               "scanner success and state failure",
			scannerCompletion:  scanner.ScanCompletion{Status: scanner.ScanStatusCompleted},
			persistenceErr:     errPersistence,
			wantSuppliedStatus: scanner.ScanStatusStateFailed,
			wantSuppliedErrors: []error{errPersistence},
			wantOutcomeStatus:  scanner.ScanStatusStateFailed,
			wantOutcomeErrors:  []error{errPersistence},
		},
		{
			name: "scanner failure and state success",
			scannerCompletion: scanner.ScanCompletion{
				Status: scanner.ScanStatusCancelled,
				Err:    errScanner,
			},
			wantSuppliedStatus: scanner.ScanStatusCancelled,
			wantSuppliedErrors: []error{errScanner},
			wantOutcomeStatus:  scanner.ScanStatusCancelled,
			wantOutcomeErrors:  []error{errScanner},
		},
		{
			name: "scanner and state failure",
			scannerCompletion: scanner.ScanCompletion{
				Status: scanner.ScanStatusCancelled,
				Err:    errScanner,
			},
			persistenceErr:     errPersistence,
			wantSuppliedStatus: scanner.ScanStatusCancelled,
			wantSuppliedErrors: []error{errScanner, errPersistence},
			wantOutcomeStatus:  scanner.ScanStatusCancelled,
			wantOutcomeErrors:  []error{errScanner, errPersistence},
		},
		{
			name:                "successful authorization and promotion failure",
			scannerCompletion:   scanner.ScanCompletion{Status: scanner.ScanStatusCompleted},
			finalizationErr:     errFinalization,
			wantSuppliedStatus:  scanner.ScanStatusCompleted,
			wantSuppliedSuccess: true,
			wantOutcomeStatus:   scanner.ScanStatusStateFailed,
			wantOutcomeErrors:   []error{errFinalization},
		},
		{
			name: "scanner state and discard failure",
			scannerCompletion: scanner.ScanCompletion{
				Status: scanner.ScanStatusCancelled,
				Err:    errScanner,
			},
			persistenceErr:     errPersistence,
			finalizationErr:    errFinalization,
			wantSuppliedStatus: scanner.ScanStatusCancelled,
			wantSuppliedErrors: []error{errScanner, errPersistence},
			wantOutcomeStatus:  scanner.ScanStatusCancelled,
			wantOutcomeErrors:  []error{errScanner, errPersistence, errFinalization},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owned, _, _ := testOwnedRuntimeExecution(t)
			results := make(chan models.ScanResult, 1)
			results <- models.ScanResult{TargetIP: "192.0.2.1", Port: 443, Protocol: "tcp", State: "OPEN"}
			close(results)
			completions := make(chan scanner.ScanCompletion, 1)
			completions <- tt.scannerCompletion
			close(completions)
			var supplied scanner.ScanCompletion
			finalized := 0

			outcome := executeOwnedRuntimeScan(
				owned,
				results,
				completions,
				func(models.ScanResult) error { return tt.persistenceErr },
				func(_, _ string, completion scanner.ScanCompletion) ([]scanner.ServiceChange, error) {
					finalized++
					supplied = completion
					return nil, tt.finalizationErr
				},
			)

			if finalized != 1 {
				t.Fatalf("finalization calls = %d, want exactly 1", finalized)
			}
			if supplied.Status != tt.wantSuppliedStatus {
				t.Fatalf("supplied status = %q, want %q", supplied.Status, tt.wantSuppliedStatus)
			}
			if supplied.Successful() != tt.wantSuppliedSuccess {
				t.Errorf("supplied Successful() = %t, want %t; completion=%+v", supplied.Successful(), tt.wantSuppliedSuccess, supplied)
			}
			if outcome.Completion.Successful() != tt.wantOutcomeSuccess {
				t.Errorf("outcome Successful() = %t, want %t; completion=%+v", outcome.Completion.Successful(), tt.wantOutcomeSuccess, outcome.Completion)
			}
			if outcome.Completion.Status != tt.wantOutcomeStatus {
				t.Fatalf("outcome status = %q, want %q", outcome.Completion.Status, tt.wantOutcomeStatus)
			}

			knownErrors := []error{errScanner, errPersistence, errFinalization}
			for _, knownErr := range knownErrors {
				wantSupplied := slices.Contains(tt.wantSuppliedErrors, knownErr)
				if got := errors.Is(supplied.Err, knownErr); got != wantSupplied {
					t.Errorf("errors.Is(supplied.Err, %v) = %t, want %t; error=%v", knownErr, got, wantSupplied, supplied.Err)
				}
				wantOutcome := slices.Contains(tt.wantOutcomeErrors, knownErr)
				if got := errors.Is(outcome.Completion.Err, knownErr); got != wantOutcome {
					t.Errorf("errors.Is(outcome.Completion.Err, %v) = %t, want %t; error=%v", knownErr, got, wantOutcome, outcome.Completion.Err)
				}
				if got := errors.Is(outcome.Err, knownErr); got != wantOutcome {
					t.Errorf("errors.Is(outcome.Err, %v) = %t, want %t; error=%v", knownErr, got, wantOutcome, outcome.Err)
				}
			}
			if tt.wantOutcomeSuccess && outcome.Err != nil {
				t.Errorf("successful runtime error = %v, want nil", outcome.Err)
			}
		})
	}
}
