package scanner

import (
	"bytes"
	"errors"
	"testing"
)

func TestPromoteCurrentScanCreatesFirstBaselineAtomically(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := InitializeStateSchema(db); err != nil {
		t.Fatalf("InitializeStateSchema() error = %v", err)
	}
	identity := reconciliationIdentity("scope-a", "192.0.2.10", 443)
	serviceKey, err := identity.Key()
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	if err := SaveCurrentService(db, "scope-a", "scan-a", identity, ServiceObservation{Banner: "first"}); err != nil {
		t.Fatalf("SaveCurrentService() error = %v", err)
	}
	if err := EnsureCurrentScan(db, "scope-a", "other-scan"); err != nil {
		t.Fatalf("EnsureCurrentScan(other-scan) error = %v", err)
	}

	changes, err := PromoteCurrentScan(db, "scope-a", "scan-a", successfulReconciliationCompletion())
	if err != nil {
		t.Fatalf("PromoteCurrentScan() error = %v", err)
	}
	if len(changes) != 1 || changes[0].Kind != ChangeOpened || changes[0].ServiceKey != serviceKey {
		t.Fatalf("changes = %#v, want one opened service %q", changes, serviceKey)
	}
	baseline, exists, err := LoadCommittedBaseline(db, "scope-a")
	if err != nil {
		t.Fatalf("LoadCommittedBaseline() error = %v", err)
	}
	if !exists || len(baseline) != 1 || baseline[serviceKey].Status != ServiceStatusOpen {
		t.Fatalf("promoted baseline = (%#v, %t), want one open service", baseline, exists)
	}
	current, exists, err := LoadCurrentScan(db, "scope-a", "scan-a")
	if err != nil {
		t.Fatalf("LoadCurrentScan() error = %v", err)
	}
	if exists || len(current) != 0 {
		t.Fatalf("promoted current scan = (%#v, %t), want removed", current, exists)
	}
	_, exists, err = LoadCurrentScan(db, "scope-a", "other-scan")
	if err != nil || !exists {
		t.Fatalf("unrelated current scan was removed: exists=%t error=%v", exists, err)
	}
}

func TestPromoteCurrentScanReplacesBaselineAndRetainsClosedTombstones(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := InitializeStateSchema(db); err != nil {
		t.Fatalf("InitializeStateSchema() error = %v", err)
	}
	const scopeID = "scope-a"
	changed := reconciliationIdentity(scopeID, "192.0.2.10", 80)
	closed := reconciliationIdentity(scopeID, "192.0.2.10", 81)
	stillClosed := reconciliationIdentity(scopeID, "192.0.2.10", 82)
	opened := reconciliationIdentity(scopeID, "192.0.2.10", 83)
	reopened := reconciliationIdentity(scopeID, "192.0.2.10", 84)
	changedKey := seedCommittedRecordForTest(t, db, changed, recordForIdentity(t, changed, ServiceStatusOpen, "old"))
	closedKey := seedCommittedRecordForTest(t, db, closed, recordForIdentity(t, closed, ServiceStatusOpen, "close-me"))
	stillClosedKey := seedCommittedRecordForTest(t, db, stillClosed, recordForIdentity(t, stillClosed, ServiceStatusClosed, "closed-before"))
	reopenedKey := seedCommittedRecordForTest(t, db, reopened, recordForIdentity(t, reopened, ServiceStatusClosed, "before-reopen"))
	if err := SaveCurrentService(db, scopeID, "scan-a", changed, ServiceObservation{Banner: "new"}); err != nil {
		t.Fatalf("save changed service: %v", err)
	}
	if err := SaveCurrentService(db, scopeID, "scan-a", opened, ServiceObservation{Banner: "opened"}); err != nil {
		t.Fatalf("save opened service: %v", err)
	}
	if err := SaveCurrentService(db, scopeID, "scan-a", reopened, ServiceObservation{Banner: "after-reopen"}); err != nil {
		t.Fatalf("save reopened service: %v", err)
	}
	openedKey, err := opened.Key()
	if err != nil {
		t.Fatalf("opened Key() error = %v", err)
	}

	changes, err := PromoteCurrentScan(db, scopeID, "scan-a", successfulReconciliationCompletion())
	if err != nil {
		t.Fatalf("PromoteCurrentScan() error = %v", err)
	}
	if len(changes) != 4 {
		t.Fatalf("changes = %#v, want changed, closed, opened, and reopened", changes)
	}
	byKey := make(map[string]ServiceChange, len(changes))
	for _, change := range changes {
		byKey[change.ServiceKey] = change
	}
	assertServiceChange(t, byKey[changedKey], ChangeChanged, true, true)
	assertServiceChange(t, byKey[closedKey], ChangeClosed, true, false)
	assertServiceChange(t, byKey[openedKey], ChangeOpened, false, true)
	assertServiceChange(t, byKey[reopenedKey], ChangeReopened, true, true)

	baseline, exists, err := LoadCommittedBaseline(db, scopeID)
	if err != nil {
		t.Fatalf("LoadCommittedBaseline() error = %v", err)
	}
	if !exists || len(baseline) != 5 {
		t.Fatalf("baseline = (%#v, %t), want five records", baseline, exists)
	}
	if baseline[changedKey].Status != ServiceStatusOpen || baseline[changedKey].Banner != "new" {
		t.Fatalf("changed record not promoted: %#v", baseline[changedKey])
	}
	if baseline[closedKey].Status != ServiceStatusClosed {
		t.Fatalf("closed record status = %q, want closed", baseline[closedKey].Status)
	}
	if baseline[stillClosedKey].Status != ServiceStatusClosed {
		t.Fatalf("closed tombstone was not retained: %#v", baseline[stillClosedKey])
	}
	if baseline[openedKey].Status != ServiceStatusOpen {
		t.Fatalf("opened record not promoted: %#v", baseline[openedKey])
	}
	if baseline[reopenedKey].Status != ServiceStatusOpen || baseline[reopenedKey].Banner != "after-reopen" {
		t.Fatalf("reopened record not promoted as open: %#v", baseline[reopenedKey])
	}
}

func TestPromoteCurrentScanRejectsIncompleteScanWithoutMutation(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := InitializeStateSchema(db); err != nil {
		t.Fatalf("InitializeStateSchema() error = %v", err)
	}
	identity := reconciliationIdentity("scope-a", "192.0.2.10", 443)
	serviceKey := seedCommittedRecordForTest(t, db, identity, recordForIdentity(t, identity, ServiceStatusOpen, "baseline"))
	if err := EnsureCurrentScan(db, "scope-a", "scan-a"); err != nil {
		t.Fatalf("EnsureCurrentScan() error = %v", err)
	}
	before := committedRecordBytes(t, db, "scope-a", serviceKey)

	changes, err := PromoteCurrentScan(db, "scope-a", "scan-a", ScanCompletion{
		Status: ScanStatusCancelled,
		Err:    errors.New("cancelled test scan"),
	})
	if !errors.Is(err, ErrPromotionRequiresSuccessfulScan) {
		t.Fatalf("PromoteCurrentScan() error = %v, want ErrPromotionRequiresSuccessfulScan", err)
	}
	if changes != nil {
		t.Fatalf("incomplete promotion changes = %#v, want nil", changes)
	}
	after := committedRecordBytes(t, db, "scope-a", serviceKey)
	if !bytes.Equal(after, before) {
		t.Fatalf("baseline changed from %q to %q", before, after)
	}
	_, exists, loadErr := LoadCurrentScan(db, "scope-a", "scan-a")
	if loadErr != nil || !exists {
		t.Fatalf("incomplete scan was removed: exists=%t error=%v", exists, loadErr)
	}
}

func TestPromoteCurrentScanRollsBackOnInvalidCurrentRecord(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := InitializeStateSchema(db); err != nil {
		t.Fatalf("InitializeStateSchema() error = %v", err)
	}
	identity := reconciliationIdentity("scope-a", "192.0.2.10", 443)
	serviceKey := seedCommittedRecordForTest(t, db, identity, recordForIdentity(t, identity, ServiceStatusOpen, "baseline"))
	seedCurrentRecord(t, db, "scope-a", "scan-a", serviceKey, "not-json")
	before := committedRecordBytes(t, db, "scope-a", serviceKey)

	changes, err := PromoteCurrentScan(db, "scope-a", "scan-a", successfulReconciliationCompletion())
	if !errors.Is(err, ErrInvalidPersistentServiceRecord) {
		t.Fatalf("PromoteCurrentScan() error = %v, want ErrInvalidPersistentServiceRecord", err)
	}
	if changes != nil {
		t.Fatalf("failed promotion changes = %#v, want nil", changes)
	}
	after := committedRecordBytes(t, db, "scope-a", serviceKey)
	if !bytes.Equal(after, before) {
		t.Fatalf("baseline changed from %q to %q", before, after)
	}
	_, exists, loadErr := LoadCurrentScan(db, "scope-a", "scan-a")
	if !exists || !errors.Is(loadErr, ErrInvalidPersistentServiceRecord) {
		t.Fatalf("invalid current scan changed after rollback: exists=%t error=%v", exists, loadErr)
	}
}
