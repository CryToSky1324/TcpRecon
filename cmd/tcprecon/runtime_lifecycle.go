package main

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/CryToSky1324/TcpRecon/internal/models"
	"github.com/CryToSky1324/TcpRecon/internal/scanner"
	"go.etcd.io/bbolt"
)

type lifecycleRuntimeConfig struct {
	DBPath    string
	TCPPorts  []int
	UDPPorts  []int
	Workers   int
	Timeout   time.Duration
	RateLimit int
	DebugMode bool
	JSONMode  bool
	Stdout    io.Writer
	Stderr    io.Writer
}

type runtimeStateOpener func(string) (*bbolt.DB, error)

type runtimeScannerStart func(
	context.Context,
	io.Reader,
	[]int,
	[]int,
	int,
	time.Duration,
	int,
	bool,
	bool,
) (<-chan models.ScanResult, <-chan scanner.ScanCompletion, time.Time)

type lifecycleRuntimeDependencies struct {
	PrepareTargets func(context.Context) (*preparedTargetSource, error)
	OpenState      runtimeStateOpener
	GenerateScanID runtimeScanIDGenerator
	StartScanner   runtimeScannerStart
}

type lifecycleRuntimeOutcome struct {
	ScopeID   string
	ScanID    string
	Execution runtimeScanExecution
	Err       error
}

func runLifecycleRuntime(
	ctx context.Context,
	config lifecycleRuntimeConfig,
	dependencies lifecycleRuntimeDependencies,
) lifecycleRuntimeOutcome {
	output := newRuntimeOutput(config.Stdout, config.Stderr, config.JSONMode)
	fail := func(outcome lifecycleRuntimeOutcome, err error) lifecycleRuntimeOutcome {
		outcome.Err = err
		output.RuntimeFailure(err)
		return outcome
	}
	prepared, err := dependencies.PrepareTargets(ctx)
	if err != nil {
		return fail(lifecycleRuntimeOutcome{}, err)
	}

	scopeID := scanner.ScanScope{
		Targets:  prepared.Targets(),
		TCPPorts: config.TCPPorts,
		UDPPorts: config.UDPPorts,
	}.ID()
	outcome := lifecycleRuntimeOutcome{ScopeID: scopeID}

	db, err := dependencies.OpenState(config.DBPath)
	if err != nil {
		return fail(outcome, errors.Join(err, prepared.Close()))
	}
	if err := scanner.InitializeStateSchema(db); err != nil {
		return fail(outcome, errors.Join(err, prepared.Close(), db.Close()))
	}

	owned, err := reservePreparedRuntimeScanWith(
		ctx,
		db,
		scopeID,
		prepared,
		dependencies.GenerateScanID,
		scanner.CreateCurrentScanExclusive,
		func(*ownedRuntimeScan) {},
	)
	if err != nil {
		return fail(outcome, errors.Join(err, db.Close()))
	}
	outcome.ScanID = owned.ScanID()

	output.ScanStarted(len(config.TCPPorts), len(config.UDPPorts), config.Workers)
	results, completions, startedAt := dependencies.StartScanner(
		ctx,
		owned.Reader(),
		config.TCPPorts,
		config.UDPPorts,
		config.Workers,
		config.Timeout,
		config.RateLimit,
		config.DebugMode,
		config.JSONMode,
	)
	persistObservation := newRuntimeObservationPersister(db, owned)
	execution := executeOwnedRuntimeScan(
		owned,
		results,
		completions,
		func(result models.ScanResult) error {
			output.Observation(result)
			return persistObservation(result)
		},
		func(scopeID, scanID string, completion scanner.ScanCompletion) ([]scanner.ServiceChange, error) {
			return scanner.FinalizeCurrentScan(db, scopeID, scanID, completion)
		},
	)
	outcome.Execution = execution
	output.LifecycleChanges(execution.Changes)
	output.ScanFinished(time.Since(startedAt), execution.OpenPorts, execution.Completion)
	closeErr := db.Close()
	outcome.Err = errors.Join(execution.Err, closeErr)
	if closeErr != nil {
		output.RuntimeFailure(closeErr)
	}
	return outcome
}
