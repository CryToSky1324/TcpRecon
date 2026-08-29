package scanner

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"go.etcd.io/bbolt"
)

func committedBaselineSnapshot(t *testing.T, db *bbolt.DB, scopeID string) map[string][]byte {
	t.Helper()
	snapshot := make(map[string][]byte)
	if err := db.View(func(tx *bbolt.Tx) error {
		scopes := tx.Bucket([]byte(stateScopeBucket))
		if scopes == nil {
			t.Fatal("scope root bucket does not exist")
		}
		scope := scopes.Bucket([]byte(scopeID))
		if scope == nil {
			t.Fatalf("scope bucket %q does not exist", scopeID)
		}
		baseline := scope.Bucket([]byte(stateBaselineBucket))
		if baseline == nil {
			t.Fatal("baseline bucket does not exist")
		}
		return baseline.ForEach(func(key, value []byte) error {
			if value == nil {
				t.Fatalf("unexpected nested bucket %q in baseline", key)
			}
			snapshot[string(key)] = append([]byte(nil), value...)
			return nil
		})
	}); err != nil {
		t.Fatalf("snapshot committed baseline: %v", err)
	}
	return snapshot
}

func TestFinalizeCurrentScanDiscardsEveryIncompleteScanWithoutBaselineMutation(t *testing.T) {
	tests := []struct {
		name       string
		completion ScanCompletion
	}{
		{name: "cancelled", completion: ScanCompletion{Status: ScanStatusCancelled, Err: errors.New("cancelled")}},
		{name: "resolution failed", completion: ScanCompletion{Status: ScanStatusResolutionFailed, Err: errors.New("resolution")}},
		{name: "parse failed", completion: ScanCompletion{Status: ScanStatusParseFailed, Err: errors.New("parse")}},
		{name: "worker failed", completion: ScanCompletion{Status: ScanStatusWorkerFailed, Err: errors.New("worker")}},
		{name: "state failed", completion: ScanCompletion{Status: ScanStatusStateFailed, Err: errors.New("state")}},
		{name: "completed with error", completion: ScanCompletion{Status: ScanStatusCompleted, Err: errors.New("inconsistent completion")}},
		{name: "unknown zero value", completion: ScanCompletion{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := openStateSchemaTestDB(t)
			if err := InitializeStateSchema(db); err != nil {
				t.Fatalf("InitializeStateSchema() error = %v", err)
			}
			identity := reconciliationIdentity("scope-a", "192.0.2.10", 443)
			seedCommittedRecordForTest(
				t,
				db,
				identity,
				recordForIdentity(t, identity, ServiceStatusOpen, "baseline"),
			)
			secondIdentity := reconciliationIdentity("scope-a", "192.0.2.11", 8443)
			seedCommittedRecordForTest(
				t,
				db,
				secondIdentity,
				recordForIdentity(t, secondIdentity, ServiceStatusClosed, "second-baseline"),
			)
			if err := SaveCurrentService(db, "scope-a", "scan-a", identity, ServiceObservation{Banner: "partial"}); err != nil {
				t.Fatalf("SaveCurrentService(scan-a) error = %v", err)
			}
			if err := EnsureCurrentScan(db, "scope-a", "other-scan"); err != nil {
				t.Fatalf("EnsureCurrentScan(other-scan) error = %v", err)
			}
			otherScopeIdentity := reconciliationIdentity("scope-b", "192.0.2.20", 443)
			if err := SaveCurrentService(db, "scope-b", "scan-a", otherScopeIdentity, ServiceObservation{Banner: "other-scope"}); err != nil {
				t.Fatalf("SaveCurrentService(scope-b/scan-a) error = %v", err)
			}
			before := committedBaselineSnapshot(t, db, "scope-a")

			changes, err := FinalizeCurrentScan(db, "scope-a", "scan-a", tt.completion)
			if !errors.Is(err, ErrScanIncomplete) {
				t.Fatalf("FinalizeCurrentScan() error = %v, want ErrScanIncomplete", err)
			}
			if tt.completion.Err != nil && !errors.Is(err, tt.completion.Err) {
				t.Fatalf("FinalizeCurrentScan() error = %v, want original diagnostic %v", err, tt.completion.Err)
			}
			if changes != nil {
				t.Fatalf("incomplete scan changes = %#v, want nil", changes)
			}
			after := committedBaselineSnapshot(t, db, "scope-a")
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("baseline changed from %#v to %#v", before, after)
			}
			current, exists, loadErr := LoadCurrentScan(db, "scope-a", "scan-a")
			if loadErr != nil || exists || len(current) != 0 {
				t.Fatalf("incomplete scan not discarded: records=%#v exists=%t error=%v", current, exists, loadErr)
			}
			_, otherExists, loadErr := LoadCurrentScan(db, "scope-a", "other-scan")
			if loadErr != nil || !otherExists {
				t.Fatalf("unrelated scan changed: exists=%t error=%v", otherExists, loadErr)
			}
			otherScope, otherScopeExists, loadErr := LoadCurrentScan(db, "scope-b", "scan-a")
			if loadErr != nil || !otherScopeExists || len(otherScope) != 1 {
				t.Fatalf("same scan_id in other scope changed: records=%#v exists=%t error=%v", otherScope, otherScopeExists, loadErr)
			}
		})
	}
}

func TestFinalizeCurrentScanPromotesSuccessfulScan(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := InitializeStateSchema(db); err != nil {
		t.Fatalf("InitializeStateSchema() error = %v", err)
	}
	identity := reconciliationIdentity("scope-a", "192.0.2.10", 443)
	if err := SaveCurrentService(db, "scope-a", "scan-a", identity, ServiceObservation{Banner: "first"}); err != nil {
		t.Fatalf("SaveCurrentService() error = %v", err)
	}

	changes, err := FinalizeCurrentScan(db, "scope-a", "scan-a", successfulReconciliationCompletion())
	if err != nil {
		t.Fatalf("FinalizeCurrentScan() error = %v", err)
	}
	if len(changes) != 1 || changes[0].Kind != ChangeOpened {
		t.Fatalf("successful changes = %#v, want one opened transition", changes)
	}
	_, baselineExists, err := LoadCommittedBaseline(db, "scope-a")
	if err != nil || !baselineExists {
		t.Fatalf("successful baseline missing: exists=%t error=%v", baselineExists, err)
	}
}

func TestFinalizeCurrentScanReportsDiscardFailureAndPreservesTemporaryState(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	db, err := bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := InitializeStateSchema(db); err != nil {
		t.Fatalf("InitializeStateSchema() error = %v", err)
	}
	identity := reconciliationIdentity("scope-a", "192.0.2.10", 443)
	seedCommittedRecordForTest(t, db, identity, recordForIdentity(t, identity, ServiceStatusOpen, "baseline"))
	if err := SaveCurrentService(db, "scope-a", "scan-a", identity, ServiceObservation{Banner: "partial"}); err != nil {
		t.Fatalf("SaveCurrentService() error = %v", err)
	}
	before := committedBaselineSnapshot(t, db, "scope-a")
	if err := db.Close(); err != nil {
		t.Fatalf("close test db: %v", err)
	}
	original := errors.New("state diagnostic")

	changes, err := FinalizeCurrentScan(db, "scope-a", "scan-a", ScanCompletion{
		Status: ScanStatusStateFailed,
		Err:    original,
	})
	if changes != nil {
		t.Fatalf("failed discard changes = %#v, want nil", changes)
	}
	if !errors.Is(err, ErrScanIncomplete) || !errors.Is(err, original) {
		t.Fatalf("FinalizeCurrentScan() error = %v, want incomplete and original diagnostic", err)
	}
	if !errors.Is(err, bbolt.ErrDatabaseNotOpen) {
		t.Fatalf("FinalizeCurrentScan() error = %v, want bbolt.ErrDatabaseNotOpen", err)
	}

	reopened, err := bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		t.Fatalf("reopen test db: %v", err)
	}
	defer reopened.Close()
	after := committedBaselineSnapshot(t, reopened, "scope-a")
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("baseline changed from %#v to %#v", before, after)
	}
	_, exists, err := LoadCurrentScan(reopened, "scope-a", "scan-a")
	if err != nil || !exists {
		t.Fatalf("temporary state changed despite discard failure: exists=%t error=%v", exists, err)
	}
}
