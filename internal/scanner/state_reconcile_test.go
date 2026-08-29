package scanner

import (
	"encoding/json"
	"errors"
	"testing"

	"go.etcd.io/bbolt"
)

func reconciliationIdentity(scopeID, ip string, port int) ServiceIdentity {
	return ServiceIdentity{ScopeID: scopeID, IP: ip, Port: port, Protocol: "tcp"}
}

func successfulReconciliationCompletion() ScanCompletion {
	return ScanCompletion{Status: ScanStatusCompleted}
}

func seedCommittedRecordForTest(t *testing.T, db *bbolt.DB, identity ServiceIdentity, record ServiceRecord) string {
	t.Helper()
	serviceKey, err := identity.Key()
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal committed record: %v", err)
	}
	seedPersistentRecord(t, db, identity.ScopeID, serviceKey, string(payload))
	return serviceKey
}

func TestReconcileScopeLifecycleSemantics(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := InitializeStateSchema(db); err != nil {
		t.Fatalf("InitializeStateSchema() error = %v", err)
	}

	const scopeID = "scope-a"
	opened := reconciliationIdentity(scopeID, "192.0.2.10", 80)
	changed := reconciliationIdentity(scopeID, "192.0.2.10", 81)
	closed := reconciliationIdentity(scopeID, "192.0.2.10", 82)
	reopened := reconciliationIdentity(scopeID, "192.0.2.10", 83)
	unchanged := reconciliationIdentity(scopeID, "192.0.2.10", 84)
	stillClosed := reconciliationIdentity(scopeID, "192.0.2.10", 85)

	changedKey := seedCommittedRecordForTest(t, db, changed, recordForIdentity(t, changed, ServiceStatusOpen, "old"))
	closedKey := seedCommittedRecordForTest(t, db, closed, recordForIdentity(t, closed, ServiceStatusOpen, "closed"))
	reopenedKey := seedCommittedRecordForTest(t, db, reopened, recordForIdentity(t, reopened, ServiceStatusClosed, "reopened"))
	seedCommittedRecordForTest(t, db, unchanged, recordForIdentity(t, unchanged, ServiceStatusOpen, "same"))
	seedCommittedRecordForTest(t, db, stillClosed, recordForIdentity(t, stillClosed, ServiceStatusClosed, "still-closed"))

	if err := SaveCurrentService(db, scopeID, "scan-a", opened, ServiceObservation{Banner: "new"}); err != nil {
		t.Fatalf("save opened current service: %v", err)
	}
	if err := SaveCurrentService(db, scopeID, "scan-a", changed, ServiceObservation{Banner: "new"}); err != nil {
		t.Fatalf("save changed current service: %v", err)
	}
	if err := SaveCurrentService(db, scopeID, "scan-a", reopened, ServiceObservation{Banner: "reopened"}); err != nil {
		t.Fatalf("save reopened current service: %v", err)
	}
	if err := SaveCurrentService(db, scopeID, "scan-a", unchanged, ServiceObservation{Banner: "same"}); err != nil {
		t.Fatalf("save unchanged current service: %v", err)
	}
	openedKey, err := opened.Key()
	if err != nil {
		t.Fatalf("opened Key() error = %v", err)
	}

	changes, err := ReconcileScope(db, scopeID, "scan-a", successfulReconciliationCompletion())
	if err != nil {
		t.Fatalf("ReconcileScope() error = %v", err)
	}
	if len(changes) != 4 {
		t.Fatalf("ReconcileScope() returned %d changes, want 4: %#v", len(changes), changes)
	}
	byKey := make(map[string]ServiceChange, len(changes))
	for _, change := range changes {
		byKey[change.ServiceKey] = change
	}
	assertServiceChange(t, byKey[openedKey], ChangeOpened, false, true)
	assertServiceChange(t, byKey[changedKey], ChangeChanged, true, true)
	assertServiceChange(t, byKey[closedKey], ChangeClosed, true, false)
	assertServiceChange(t, byKey[reopenedKey], ChangeReopened, true, true)
	for i := 1; i < len(changes); i++ {
		if changes[i-1].ServiceKey >= changes[i].ServiceKey {
			t.Fatalf("changes are not sorted by service_key: %#v", changes)
		}
	}
}

func TestReconcileScopeDistinguishesMissingFromEmptyCurrentScan(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := InitializeStateSchema(db); err != nil {
		t.Fatalf("InitializeStateSchema() error = %v", err)
	}
	identity := reconciliationIdentity("scope-a", "192.0.2.10", 443)
	seedCommittedRecordForTest(t, db, identity, recordForIdentity(t, identity, ServiceStatusOpen, "open"))

	_, err := ReconcileScope(db, "scope-a", "missing-scan", successfulReconciliationCompletion())
	if !errors.Is(err, ErrCurrentScanNotFound) {
		t.Fatalf("missing scan error = %v, want ErrCurrentScanNotFound", err)
	}
	if err := EnsureCurrentScan(db, "scope-a", "empty-scan"); err != nil {
		t.Fatalf("EnsureCurrentScan() error = %v", err)
	}
	changes, err := ReconcileScope(db, "scope-a", "empty-scan", successfulReconciliationCompletion())
	if err != nil {
		t.Fatalf("empty scan ReconcileScope() error = %v", err)
	}
	if len(changes) != 1 || changes[0].Kind != ChangeClosed {
		t.Fatalf("empty scan changes = %#v, want one closed transition", changes)
	}
}

func TestReconcileScopeNeverReadsAnotherScopeBaseline(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := InitializeStateSchema(db); err != nil {
		t.Fatalf("InitializeStateSchema() error = %v", err)
	}
	other := reconciliationIdentity("scope-b", "192.0.2.10", 443)
	seedCommittedRecordForTest(t, db, other, recordForIdentity(t, other, ServiceStatusOpen, "other"))
	if err := EnsureCurrentScan(db, "scope-a", "scan-a"); err != nil {
		t.Fatalf("EnsureCurrentScan() error = %v", err)
	}

	changes, err := ReconcileScope(db, "scope-a", "scan-a", successfulReconciliationCompletion())
	if err != nil {
		t.Fatalf("ReconcileScope() error = %v", err)
	}
	if len(changes) != 0 {
		t.Fatalf("same-scope reconciliation returned cross-scope changes: %#v", changes)
	}
}

func TestReconcileScopeWithoutBaselineOpensCurrentServices(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := InitializeStateSchema(db); err != nil {
		t.Fatalf("InitializeStateSchema() error = %v", err)
	}
	identity := reconciliationIdentity("scope-a", "192.0.2.10", 443)
	if err := SaveCurrentService(db, "scope-a", "scan-a", identity, ServiceObservation{Banner: "first"}); err != nil {
		t.Fatalf("SaveCurrentService() error = %v", err)
	}

	changes, err := ReconcileScope(db, "scope-a", "scan-a", successfulReconciliationCompletion())
	if err != nil {
		t.Fatalf("ReconcileScope() error = %v", err)
	}
	if len(changes) != 1 || changes[0].Kind != ChangeOpened {
		t.Fatalf("changes = %#v, want one opened transition", changes)
	}
}

func TestReconcileScopeRejectsIncompleteEmptyScan(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := InitializeStateSchema(db); err != nil {
		t.Fatalf("InitializeStateSchema() error = %v", err)
	}
	identity := reconciliationIdentity("scope-a", "192.0.2.10", 443)
	seedCommittedRecordForTest(t, db, identity, recordForIdentity(t, identity, ServiceStatusOpen, "open"))
	if err := EnsureCurrentScan(db, "scope-a", "scan-a"); err != nil {
		t.Fatalf("EnsureCurrentScan() error = %v", err)
	}

	changes, err := ReconcileScope(db, "scope-a", "scan-a", ScanCompletion{
		Status: ScanStatusCancelled,
		Err:    errors.New("cancelled test scan"),
	})
	if !errors.Is(err, ErrReconciliationRequiresSuccessfulScan) {
		t.Fatalf("ReconcileScope() error = %v, want ErrReconciliationRequiresSuccessfulScan", err)
	}
	if changes != nil {
		t.Fatalf("incomplete scan changes = %#v, want nil", changes)
	}
}

func TestReconcileScopeSeparatesTCPAndUDPOnSamePort(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := InitializeStateSchema(db); err != nil {
		t.Fatalf("InitializeStateSchema() error = %v", err)
	}
	const scopeID = "scope-a"
	tcpIdentity := ServiceIdentity{
		ScopeID: scopeID, IP: "192.0.2.10", Port: 53, Protocol: "tcp",
	}
	udpIdentity := ServiceIdentity{
		ScopeID: scopeID, IP: "192.0.2.10", Port: 53, Protocol: "udp",
	}
	tcpKey := seedCommittedRecordForTest(
		t,
		db,
		tcpIdentity,
		recordForIdentity(t, tcpIdentity, ServiceStatusOpen, "tcp"),
	)
	if err := SaveCurrentService(db, scopeID, "scan-a", udpIdentity, ServiceObservation{Banner: "udp"}); err != nil {
		t.Fatalf("SaveCurrentService(udp) error = %v", err)
	}
	udpKey, err := udpIdentity.Key()
	if err != nil {
		t.Fatalf("udp Key() error = %v", err)
	}
	if tcpKey == udpKey {
		t.Fatal("TCP and UDP identities produced the same service key")
	}

	changes, err := ReconcileScope(db, scopeID, "scan-a", successfulReconciliationCompletion())
	if err != nil {
		t.Fatalf("ReconcileScope() error = %v", err)
	}
	if len(changes) != 2 {
		t.Fatalf("changes = %#v, want separate TCP closed and UDP opened transitions", changes)
	}
	byKey := map[string]ServiceChange{
		changes[0].ServiceKey: changes[0],
		changes[1].ServiceKey: changes[1],
	}
	assertServiceChange(t, byKey[tcpKey], ChangeClosed, true, false)
	assertServiceChange(t, byKey[udpKey], ChangeOpened, false, true)
}

func TestServiceComparisonEqualUsesEveryTypedComparisonField(t *testing.T) {
	base := ServiceRecord{
		Banner:      "banner",
		OSHint:      "linux",
		CertSubject: "subject",
		CertIssuer:  "issuer",
		SANs:        []string{"a.example", "z.example"},
	}
	if !serviceComparisonEqual(base, base) {
		t.Fatal("identical comparison fields were classified as changed")
	}

	tests := []struct {
		name   string
		mutate func(*ServiceRecord)
	}{
		{name: "banner", mutate: func(record *ServiceRecord) { record.Banner = "different" }},
		{name: "os_hint", mutate: func(record *ServiceRecord) { record.OSHint = "different" }},
		{name: "tls_subject", mutate: func(record *ServiceRecord) { record.CertSubject = "different" }},
		{name: "tls_issuer", mutate: func(record *ServiceRecord) { record.CertIssuer = "different" }},
		{name: "tls_sans value", mutate: func(record *ServiceRecord) { record.SANs = []string{"b.example", "z.example"} }},
		{name: "tls_sans length", mutate: func(record *ServiceRecord) { record.SANs = []string{"a.example"} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed := base
			changed.SANs = append([]string(nil), base.SANs...)
			tt.mutate(&changed)
			if serviceComparisonEqual(base, changed) {
				t.Fatalf("changed %s was classified as equal", tt.name)
			}
		})
	}
}

func recordForIdentity(t *testing.T, identity ServiceIdentity, status ServiceStatus, banner string) ServiceRecord {
	t.Helper()
	ip, err := normalizeServiceIP(identity.IP)
	if err != nil {
		t.Fatalf("normalize identity IP: %v", err)
	}
	return ServiceRecord{
		IP: ip, Port: identity.Port, Protocol: identity.Protocol, Status: status,
		Banner: banner, SANs: []string{},
	}
}

func assertServiceChange(t *testing.T, got ServiceChange, kind ChangeKind, hasPrevious, hasCurrent bool) {
	t.Helper()
	if got.Kind != kind {
		t.Fatalf("change kind = %q, want %q: %#v", got.Kind, kind, got)
	}
	if (got.Previous != nil) != hasPrevious {
		t.Fatalf("change previous presence = %t, want %t: %#v", got.Previous != nil, hasPrevious, got)
	}
	if (got.Current != nil) != hasCurrent {
		t.Fatalf("change current presence = %t, want %t: %#v", got.Current != nil, hasCurrent, got)
	}
}
