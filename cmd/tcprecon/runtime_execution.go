package main

import (
	"errors"

	"github.com/CryToSky1324/TcpRecon/internal/models"
	"github.com/CryToSky1324/TcpRecon/internal/scanner"
)

var ErrScanCompletionMissing = errors.New("scan completion missing")

type runtimeObservationPersister func(models.ScanResult) error

type runtimeScanFinalizer func(
	scopeID string,
	scanID string,
	completion scanner.ScanCompletion,
) ([]scanner.ServiceChange, error)

type runtimeScanExecution struct {
	OpenPorts  int
	Completion scanner.ScanCompletion
	Changes    []scanner.ServiceChange
	Err        error
}

func executeOwnedRuntimeScan(
	owned *ownedRuntimeScan,
	results <-chan models.ScanResult,
	completions <-chan scanner.ScanCompletion,
	persist runtimeObservationPersister,
	finalize runtimeScanFinalizer,
) runtimeScanExecution {
	var scannerCompletion scanner.ScanCompletion
	var firstPersistenceErr error
	openPorts := 0
	resultsQuiesced := false
	completionReceived := false

	for !resultsQuiesced || !completionReceived {
		select {
		case result, ok := <-results:
			if !ok {
				resultsQuiesced = true
				results = nil
				continue
			}
			if result.State == "OPEN" {
				openPorts++
			}
			if err := persist(result); err != nil && firstPersistenceErr == nil {
				firstPersistenceErr = err
			}

		case completion, ok := <-completions:
			if ok {
				scannerCompletion = completion
			} else {
				scannerCompletion = scanner.ScanCompletion{
					Status: scanner.ScanStatusWorkerFailed,
					Err:    ErrScanCompletionMissing,
				}
			}
			completionReceived = true
			completions = nil
		}
	}

	finalCompletion := finalizeScanCompletion(scannerCompletion, firstPersistenceErr)
	changes, finalizationErr := finalize(
		owned.ScopeID(),
		owned.ScanID(),
		finalCompletion,
	)
	cleanupErr := owned.Close()
	authoritativeCompletion := finalCompletion
	if finalizationErr != nil {
		authoritativeCompletion = finalizeScanCompletion(finalCompletion, finalizationErr)
	}

	return runtimeScanExecution{
		OpenPorts:  openPorts,
		Completion: authoritativeCompletion,
		Changes:    changes,
		Err:        errors.Join(authoritativeCompletion.Err, cleanupErr),
	}
}
