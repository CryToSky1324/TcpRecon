package main

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/CryToSky1324/TcpRecon/internal/models"
	"github.com/CryToSky1324/TcpRecon/internal/scanner"
	"go.etcd.io/bbolt"
)

func TestRuntimeObservationPersisterMapsEveryFieldAndPreservesBaseline(t *testing.T) {
	db := openRuntimeStartupTestDB(t)
	if err := scanner.InitializeStateSchema(db); err != nil {
		t.Fatal(err)
	}
	const scopeID = "scope-a"
	const baselineScanID = "baseline-seed"
	const runtimeScanID = "00112233445566778899aabbccddeeff"
	baselineIdentity := scanner.ServiceIdentity{ScopeID: scopeID, IP: "192.0.2.5", Port: 80, Protocol: "tcp"}
	if err := scanner.EnsureCurrentScan(db, scopeID, baselineScanID); err != nil {
		t.Fatal(err)
	}
	if err := scanner.SaveCurrentService(
		db,
		scopeID,
		baselineScanID,
		baselineIdentity,
		scanner.ServiceObservation{Banner: "committed baseline"},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.PromoteCurrentScan(
		db,
		scopeID,
		baselineScanID,
		scanner.ScanCompletion{Status: scanner.ScanStatusCompleted},
	); err != nil {
		t.Fatal(err)
	}
	baselineBefore, exists, err := scanner.LoadCommittedBaseline(db, scopeID)
	if err != nil || !exists {
		t.Fatalf("LoadCommittedBaseline() before = (exists=%t, err=%v)", exists, err)
	}
	if err := scanner.CreateCurrentScanExclusive(db, scopeID, runtimeScanID); err != nil {
		t.Fatal(err)
	}

	prepared, _, _ := testPreparedReservationSource()
	owned := &ownedRuntimeScan{scopeID: scopeID, scanID: runtimeScanID, prepared: prepared}
	persist := newRuntimeObservationPersister(db, owned)
	result := models.ScanResult{
		TargetName:  "must-not-persist.example",
		TargetIP:    "192.0.2.10",
		Port:        443,
		Protocol:    "tcp",
		State:       "OPEN",
		Banner:      "banner bytes",
		OSHint:      "test-os",
		CertSubject: "test-subject",
		CertIssuer:  "test-issuer",
		SANs:        []string{"z.example", "a.example", "z.example"},
	}
	if err := persist(result); err != nil {
		t.Fatalf("runtime observation persist error = %v", err)
	}

	identity := scanner.ServiceIdentity{ScopeID: scopeID, IP: result.TargetIP, Port: result.Port, Protocol: result.Protocol}
	serviceKey, err := identity.Key()
	if err != nil {
		t.Fatal(err)
	}
	current, currentExists, err := scanner.LoadCurrentScan(db, scopeID, runtimeScanID)
	if err != nil || !currentExists {
		t.Fatalf("LoadCurrentScan() = (exists=%t, err=%v)", currentExists, err)
	}
	wantRecord := scanner.ServiceRecord{
		IP:          "192.0.2.10",
		Port:        443,
		Protocol:    "tcp",
		Status:      scanner.ServiceStatusOpen,
		Banner:      "banner bytes",
		OSHint:      "test-os",
		CertSubject: "test-subject",
		CertIssuer:  "test-issuer",
		SANs:        []string{"a.example", "z.example"},
	}
	if got := current[serviceKey]; !reflect.DeepEqual(got, wantRecord) {
		t.Fatalf("persisted record = %+v, want %+v", got, wantRecord)
	}
	if len(current) != 1 {
		t.Fatalf("current record count = %d, want 1", len(current))
	}
	baselineAfter, exists, err := scanner.LoadCommittedBaseline(db, scopeID)
	if err != nil || !exists {
		t.Fatalf("LoadCommittedBaseline() after = (exists=%t, err=%v)", exists, err)
	}
	if !reflect.DeepEqual(baselineAfter, baselineBefore) {
		t.Fatalf("observation persistence mutated baseline:\nbefore=%+v\nafter=%+v", baselineBefore, baselineAfter)
	}
	payload, err := json.Marshal(current[serviceKey])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), result.TargetName) {
		t.Fatalf("TargetName leaked into persistent comparison record: %s", payload)
	}
}

func TestRuntimeObservationPersisterAttemptsEveryResultAndRetainsFirstFailure(t *testing.T) {
	prepared, _, _ := testPreparedReservationSource()
	owned := &ownedRuntimeScan{
		scopeID:  "scope-a",
		scanID:   "00112233445566778899aabbccddeeff",
		prepared: prepared,
	}
	errFirst := errors.New("first save failure")
	errLater := errors.New("later save failure")
	var identities []scanner.ServiceIdentity
	var observations []scanner.ServiceObservation
	saveCalls := 0
	persist := newRuntimeObservationPersisterWith(
		nil,
		owned,
		func(
			_ *bbolt.DB,
			scopeID string,
			scanID string,
			identity scanner.ServiceIdentity,
			observation scanner.ServiceObservation,
		) error {
			saveCalls++
			if scopeID != owned.ScopeID() || scanID != owned.ScanID() {
				t.Errorf("save destination = (%q, %q), want immutable owner (%q, %q)", scopeID, scanID, owned.ScopeID(), owned.ScanID())
			}
			identities = append(identities, identity)
			observations = append(observations, observation)
			if saveCalls == 1 {
				return errFirst
			}
			return errLater
		},
	)

	results := make(chan models.ScanResult, 2)
	results <- models.ScanResult{
		TargetName: "first.example", TargetIP: "192.0.2.1", Port: 80,
		Protocol: "tcp", State: "OPEN", Banner: "first", SANs: []string{"b", "a"},
	}
	results <- models.ScanResult{
		TargetName: "second.example", TargetIP: "192.0.2.2", Port: 53,
		Protocol: "udp", State: "OPEN", Banner: "second", OSHint: "second-os",
	}
	close(results)
	completions := make(chan scanner.ScanCompletion, 1)
	completions <- scanner.ScanCompletion{Status: scanner.ScanStatusCompleted}
	close(completions)
	var supplied scanner.ScanCompletion

	outcome := executeOwnedRuntimeScan(
		owned,
		results,
		completions,
		persist,
		func(_, _ string, completion scanner.ScanCompletion) ([]scanner.ServiceChange, error) {
			supplied = completion
			return nil, nil
		},
	)

	if saveCalls != 2 || len(identities) != 2 || len(observations) != 2 {
		t.Fatalf("save mapping counts = (%d, %d, %d), want all 2", saveCalls, len(identities), len(observations))
	}
	if identities[0].ScopeID != owned.ScopeID() || identities[1].ScopeID != owned.ScopeID() {
		t.Fatalf("mapped identity scopes = (%q, %q), want %q", identities[0].ScopeID, identities[1].ScopeID, owned.ScopeID())
	}
	if identities[0].IP != "192.0.2.1" || identities[0].Port != 80 || identities[0].Protocol != "tcp" {
		t.Fatalf("first mapped identity = %+v", identities[0])
	}
	if identities[1].IP != "192.0.2.2" || identities[1].Port != 53 || identities[1].Protocol != "udp" {
		t.Fatalf("second mapped identity = %+v", identities[1])
	}
	if observations[0].Banner != "first" || !slices.Equal(observations[0].SANs, []string{"b", "a"}) {
		t.Fatalf("first mapped observation = %+v", observations[0])
	}
	if observations[1].Banner != "second" || observations[1].OSHint != "second-os" {
		t.Fatalf("second mapped observation = %+v", observations[1])
	}
	if supplied.Status != scanner.ScanStatusStateFailed || !errors.Is(supplied.Err, errFirst) || errors.Is(supplied.Err, errLater) {
		t.Fatalf("completion supplied to finalization = %+v, want sticky first save failure", supplied)
	}
	if outcome.OpenPorts != 2 || !errors.Is(outcome.Err, errFirst) || errors.Is(outcome.Err, errLater) {
		t.Fatalf("runtime outcome = %+v, want two drained and sticky first save failure", outcome)
	}
}
