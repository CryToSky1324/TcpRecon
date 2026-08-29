package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/CryToSky1324/TcpRecon/internal/scanner"
	"go.etcd.io/bbolt"
)

func TestGenerateRuntimeScanIDKnownVectorAndEntropyFailure(t *testing.T) {
	entropy := bytes.NewReader([]byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	})
	got, err := generateRuntimeScanID(entropy)
	if err != nil {
		t.Fatalf("generateRuntimeScanID() error = %v", err)
	}
	if want := "00112233445566778899aabbccddeeff"; got != want {
		t.Fatalf("generateRuntimeScanID() = %q, want %q", got, want)
	}

	errEntropy := errors.New("entropy failed")
	if _, err := generateRuntimeScanID(failingReader{err: errEntropy}); !errors.Is(err, errEntropy) {
		t.Fatalf("generateRuntimeScanID() error = %v, want entropy failure", err)
	}
}

func TestReserveRuntimeScanRetriesCollisionAndCreatesEmptyScan(t *testing.T) {
	db := openRuntimeStartupTestDB(t)
	if err := scanner.InitializeStateSchema(db); err != nil {
		t.Fatal(err)
	}
	collision := strings.Repeat("a", 32)
	fresh := strings.Repeat("b", 32)
	if err := scanner.EnsureCurrentScan(db, "scope-a", collision); err != nil {
		t.Fatal(err)
	}
	values := []string{collision, fresh}
	calls := 0
	got, err := reserveRuntimeScan(context.Background(), db, "scope-a", func() (string, error) {
		value := values[calls]
		calls++
		return value, nil
	})
	if err != nil {
		t.Fatalf("reserveRuntimeScan() error = %v", err)
	}
	if got != fresh || calls != 2 {
		t.Fatalf("reservation = (%q, calls=%d), want (%q, 2)", got, calls, fresh)
	}
	records, exists, err := scanner.LoadCurrentScan(db, "scope-a", fresh)
	if err != nil || !exists || len(records) != 0 {
		t.Fatalf("reserved scan = (len=%d, exists=%t, err=%v), want existing empty", len(records), exists, err)
	}
}

func TestReserveRuntimeScanStopsAfterCollisionRetryLimit(t *testing.T) {
	db := openRuntimeStartupTestDB(t)
	if err := scanner.InitializeStateSchema(db); err != nil {
		t.Fatal(err)
	}
	const wantAttempts = 4
	calls := 0
	_, err := reserveRuntimeScanWith(
		context.Background(), db, "scope-a",
		func() (string, error) {
			calls++
			return strings.Repeat("f", 32), nil
		},
		func(*bbolt.DB, string, string) error {
			return scanner.ErrStateScanAlreadyExists
		},
	)
	if !errors.Is(err, ErrRuntimeScanIDCollisions) {
		t.Fatalf("reserveRuntimeScanWith() error = %v, want ErrRuntimeScanIDCollisions", err)
	}
	if !errors.Is(err, scanner.ErrStateScanAlreadyExists) {
		t.Fatalf("reserveRuntimeScanWith() error = %v, want retained ErrStateScanAlreadyExists", err)
	}
	if calls != wantAttempts {
		t.Fatalf("generator calls = %d, want fixed retry limit %d", calls, wantAttempts)
	}
}

func TestReserveRuntimeScanCancellationAfterCollisionStopsRetry(t *testing.T) {
	db := openRuntimeStartupTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	generated := 0
	created := 0
	_, err := reserveRuntimeScanWith(
		ctx, db, "scope-a",
		func() (string, error) {
			generated++
			return strings.Repeat("a", 32), nil
		},
		func(*bbolt.DB, string, string) error {
			created++
			cancel()
			return scanner.ErrStateScanAlreadyExists
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("reserveRuntimeScanWith() error = %v, want context.Canceled", err)
	}
	if generated != 1 || created != 1 {
		t.Fatalf("calls after collision cancellation = (generated=%d, created=%d), want (1, 1)", generated, created)
	}
}

func TestReserveRuntimeScanFailsImmediatelyWithoutRetry(t *testing.T) {
	errGenerator := errors.New("generator failed")
	errCreate := errors.New("create failed")
	tests := []struct {
		name       string
		value      string
		genErr     error
		createErr  error
		wantErr    error
		wantCreate bool
	}{
		{name: "generator failure", genErr: errGenerator, wantErr: errGenerator},
		{name: "short ID", value: "scan-a", wantErr: ErrInvalidRuntimeScanID},
		{name: "uppercase ID", value: strings.Repeat("A", 32), wantErr: ErrInvalidRuntimeScanID},
		{name: "non-hex ID", value: strings.Repeat("z", 32), wantErr: ErrInvalidRuntimeScanID},
		{name: "non-collision create failure", value: strings.Repeat("c", 32), createErr: errCreate, wantErr: errCreate, wantCreate: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := openRuntimeStartupTestDB(t)
			if err := scanner.InitializeStateSchema(db); err != nil {
				t.Fatal(err)
			}
			generatorCalls := 0
			createCalls := 0
			_, err := reserveRuntimeScanWith(
				context.Background(), db, "scope-a",
				func() (string, error) {
					generatorCalls++
					return tt.value, tt.genErr
				},
				func(*bbolt.DB, string, string) error {
					createCalls++
					return tt.createErr
				},
			)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("reserveRuntimeScanWith() error = %v, want %v", err, tt.wantErr)
			}
			if generatorCalls != 1 || (createCalls == 1) != tt.wantCreate {
				t.Fatalf("calls = (generator=%d, create=%d), want generator=1 create=%t", generatorCalls, createCalls, tt.wantCreate)
			}
		})
	}
}

func testPreparedReservationSource() (*preparedTargetSource, *fakeTargetSpool, *bool) {
	spool := &fakeTargetSpool{path: "reservation-spool"}
	removed := false
	return &preparedTargetSource{
		spool: spool,
		path:  spool.path,
		remove: func(string) error {
			removed = true
			return nil
		},
	}, spool, &removed
}

func TestReservePreparedRuntimeScanFailureCleansUpWithoutReadyToStart(t *testing.T) {
	db := openRuntimeStartupTestDB(t)
	prepared, spool, removed := testPreparedReservationSource()
	errReservation := errors.New("reservation failed")
	ready := false
	owned, err := reservePreparedRuntimeScanWith(
		context.Background(), db, "scope-a", prepared,
		func() (string, error) { return strings.Repeat("d", 32), nil },
		func(*bbolt.DB, string, string) error { return errReservation },
		func(*ownedRuntimeScan) { ready = true },
	)
	if owned != nil || !errors.Is(err, errReservation) {
		t.Fatalf("failed reservation = (owned=%v, err=%v), want nil/reservation error", owned, err)
	}
	if ready || !spool.closed || !*removed {
		t.Fatalf("failure state = (ready=%t, closed=%t, removed=%t), want false/true/true", ready, spool.closed, *removed)
	}
}

func TestReservePreparedRuntimeScanSuccessHandsOffOwnedEmptyScan(t *testing.T) {
	db := openRuntimeStartupTestDB(t)
	if err := scanner.InitializeStateSchema(db); err != nil {
		t.Fatal(err)
	}
	prepared, spool, removed := testPreparedReservationSource()
	const scopeID = "scope-a"
	const scanID = "00112233445566778899aabbccddeeff"
	readyCalls := 0
	var readyOwned *ownedRuntimeScan

	owned, err := reservePreparedRuntimeScanWith(
		context.Background(), db, scopeID, prepared,
		func() (string, error) { return scanID, nil },
		scanner.CreateCurrentScanExclusive,
		func(value *ownedRuntimeScan) {
			readyCalls++
			readyOwned = value
			records, exists, err := scanner.LoadCurrentScan(db, scopeID, scanID)
			if err != nil || !exists || len(records) != 0 {
				t.Errorf("owned bucket at readiness = (len=%d, exists=%t, err=%v), want existing empty", len(records), exists, err)
			}
		},
	)
	if err != nil {
		t.Fatalf("reservePreparedRuntimeScanWith() error = %v", err)
	}
	if owned == nil || readyOwned != owned || readyCalls != 1 {
		t.Fatalf("ownership handoff = (owned=%p, ready_owned=%p, calls=%d), want same owner once", owned, readyOwned, readyCalls)
	}
	if owned.ScopeID() != scopeID || owned.ScanID() != scanID || owned.Reader() != prepared.Reader() {
		t.Fatalf("owned identity/source = (%q, %q, %p), want (%q, %q, %p)", owned.ScopeID(), owned.ScanID(), owned.Reader(), scopeID, scanID, prepared.Reader())
	}
	if spool.closed || *removed {
		t.Fatalf("successful ownership prematurely cleaned source = (closed=%t, removed=%t)", spool.closed, *removed)
	}
	if err := owned.Close(); err != nil {
		t.Fatalf("owned.Close() error = %v", err)
	}
	if !spool.closed || !*removed {
		t.Fatalf("owned cleanup = (closed=%t, removed=%t), want both true", spool.closed, *removed)
	}
}

func TestReservePreparedRuntimeScanCancellationPreventsOwnership(t *testing.T) {
	db := openRuntimeStartupTestDB(t)
	prepared, spool, removed := testPreparedReservationSource()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	generated, created, ready := false, false, false
	owned, err := reservePreparedRuntimeScanWith(
		ctx, db, "scope-a", prepared,
		func() (string, error) { generated = true; return strings.Repeat("e", 32), nil },
		func(*bbolt.DB, string, string) error { created = true; return nil },
		func(*ownedRuntimeScan) { ready = true },
	)
	if owned != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled reservation = (owned=%v, err=%v), want nil/context.Canceled", owned, err)
	}
	if generated || created || ready || !spool.closed || !*removed {
		t.Fatalf("cancelled state = (generated=%t, created=%t, ready=%t, closed=%t, removed=%t)", generated, created, ready, spool.closed, *removed)
	}
}
