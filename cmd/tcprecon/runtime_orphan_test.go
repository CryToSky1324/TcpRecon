package main

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/CryToSky1324/TcpRecon/internal/models"
	"github.com/CryToSky1324/TcpRecon/internal/scanner"
	"go.etcd.io/bbolt"
)

func TestRuntimeOrphanScanRemainsIsolatedAcrossRestart(t *testing.T) {
	dbPath := t.TempDir() + "/state.db"
	db, err := bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := scanner.InitializeStateSchema(db); err != nil {
		t.Fatal(err)
	}

	const scopeID = "scope-a"
	const otherScopeID = "scope-b"
	const baselineScanID = "baseline-seed"
	orphanScanID := strings.Repeat("a", 32)
	freshScanID := strings.Repeat("b", 32)
	serviceIdentity := scanner.ServiceIdentity{ScopeID: scopeID, IP: "192.0.2.10", Port: 443, Protocol: "tcp"}
	orphanIdentity := scanner.ServiceIdentity{ScopeID: scopeID, IP: "192.0.2.20", Port: 8443, Protocol: "tcp"}
	otherOrphanIdentity := scanner.ServiceIdentity{ScopeID: otherScopeID, IP: "192.0.2.30", Port: 53, Protocol: "udp"}

	if err := scanner.EnsureCurrentScan(db, scopeID, baselineScanID); err != nil {
		t.Fatal(err)
	}
	if err := scanner.SaveCurrentService(db, scopeID, baselineScanID, serviceIdentity, scanner.ServiceObservation{Banner: "old"}); err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.FinalizeCurrentScan(
		db,
		scopeID,
		baselineScanID,
		scanner.ScanCompletion{Status: scanner.ScanStatusCompleted},
	); err != nil {
		t.Fatal(err)
	}

	if err := scanner.CreateCurrentScanExclusive(db, scopeID, orphanScanID); err != nil {
		t.Fatal(err)
	}
	if err := scanner.SaveCurrentService(db, scopeID, orphanScanID, orphanIdentity, scanner.ServiceObservation{Banner: "orphan-a"}); err != nil {
		t.Fatal(err)
	}
	if err := scanner.CreateCurrentScanExclusive(db, otherScopeID, orphanScanID); err != nil {
		t.Fatal(err)
	}
	if err := scanner.SaveCurrentService(db, otherScopeID, orphanScanID, otherOrphanIdentity, scanner.ServiceObservation{Banner: "orphan-b"}); err != nil {
		t.Fatal(err)
	}
	orphanBefore, orphanExists, err := scanner.LoadCurrentScan(db, scopeID, orphanScanID)
	if err != nil || !orphanExists {
		t.Fatalf("scope-a orphan before restart = (exists=%t, err=%v)", orphanExists, err)
	}
	otherOrphanBefore, otherOrphanExists, err := scanner.LoadCurrentScan(db, otherScopeID, orphanScanID)
	if err != nil || !otherOrphanExists {
		t.Fatalf("scope-b orphan before restart = (exists=%t, err=%v)", otherOrphanExists, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Errorf("close reopened DB: %v", err)
		}
	}()

	generated := []string{orphanScanID, freshScanID}
	generatorCalls := 0
	reservedID, err := reserveRuntimeScan(context.Background(), db, scopeID, func() (string, error) {
		value := generated[generatorCalls]
		generatorCalls++
		return value, nil
	})
	if err != nil {
		t.Fatalf("reserveRuntimeScan() error = %v", err)
	}
	if reservedID != freshScanID || generatorCalls != 2 {
		t.Fatalf("reservation = (%q, calls=%d), want fresh ID after orphan collision", reservedID, generatorCalls)
	}

	prepared, _, _ := testPreparedReservationSource()
	owned := &ownedRuntimeScan{scopeID: scopeID, scanID: reservedID, prepared: prepared}
	results := make(chan models.ScanResult, 1)
	results <- models.ScanResult{
		TargetName: "fresh.example", TargetIP: serviceIdentity.IP, Port: serviceIdentity.Port,
		Protocol: serviceIdentity.Protocol, State: "OPEN", Banner: "fresh",
	}
	close(results)
	completions := make(chan scanner.ScanCompletion, 1)
	completions <- scanner.ScanCompletion{Status: scanner.ScanStatusCompleted}
	close(completions)
	outcome := executeOwnedRuntimeScan(
		owned,
		results,
		completions,
		newRuntimeObservationPersister(db, owned),
		func(scopeID, scanID string, completion scanner.ScanCompletion) ([]scanner.ServiceChange, error) {
			return scanner.FinalizeCurrentScan(db, scopeID, scanID, completion)
		},
	)
	if !outcome.Completion.Successful() || outcome.Err != nil {
		t.Fatalf("fresh runtime outcome = %+v, want successful", outcome)
	}

	orphanAfter, orphanExists, err := scanner.LoadCurrentScan(db, scopeID, orphanScanID)
	if err != nil || !orphanExists || !reflect.DeepEqual(orphanAfter, orphanBefore) {
		t.Fatalf("scope-a orphan changed: before=%+v after=%+v exists=%t err=%v", orphanBefore, orphanAfter, orphanExists, err)
	}
	otherOrphanAfter, otherOrphanExists, err := scanner.LoadCurrentScan(db, otherScopeID, orphanScanID)
	if err != nil || !otherOrphanExists || !reflect.DeepEqual(otherOrphanAfter, otherOrphanBefore) {
		t.Fatalf("scope-b orphan changed: before=%+v after=%+v exists=%t err=%v", otherOrphanBefore, otherOrphanAfter, otherOrphanExists, err)
	}
	if _, freshExists, err := scanner.LoadCurrentScan(db, scopeID, freshScanID); err != nil || freshExists {
		t.Fatalf("fresh temporary scan after finalization = (exists=%t, err=%v), want removed", freshExists, err)
	}

	baseline, baselineExists, err := scanner.LoadCommittedBaseline(db, scopeID)
	if err != nil || !baselineExists {
		t.Fatalf("fresh baseline = (exists=%t, err=%v)", baselineExists, err)
	}
	serviceKey, err := serviceIdentity.Key()
	if err != nil {
		t.Fatal(err)
	}
	orphanKey, err := orphanIdentity.Key()
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline) != 1 || baseline[serviceKey].Banner != "fresh" {
		t.Fatalf("promoted baseline = %+v, want fresh service only", baseline)
	}
	if _, exists := baseline[orphanKey]; exists {
		t.Fatal("orphan service was reconciled or promoted")
	}
	if _, otherBaselineExists, err := scanner.LoadCommittedBaseline(db, otherScopeID); err != nil || otherBaselineExists {
		t.Fatalf("other-scope baseline = (exists=%t, err=%v), want absent", otherBaselineExists, err)
	}
	if len(outcome.Changes) != 1 || outcome.Changes[0].Kind != scanner.ChangeChanged || outcome.Changes[0].ServiceKey != serviceKey {
		t.Fatalf("fresh changes = %+v, want only changed fresh service", outcome.Changes)
	}
}
