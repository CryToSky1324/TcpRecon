package scanner

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"go.etcd.io/bbolt"
)

func testServiceIdentity(scopeID string) ServiceIdentity {
	return ServiceIdentity{ScopeID: scopeID, IP: "192.0.2.10", Port: 443, Protocol: "tcp"}
}

func seedPersistentRecord(t *testing.T, db *bbolt.DB, scopeID, serviceKey, payload string) {
	t.Helper()
	createCommittedBaselineForTest(t, db, scopeID)
	if err := db.Update(func(tx *bbolt.Tx) error {
		scopes := tx.Bucket([]byte("scope"))
		if scopes == nil {
			t.Fatal("scope root bucket does not exist")
		}
		scope := scopes.Bucket([]byte(scopeID))
		if scope == nil {
			t.Fatalf("scope bucket %q does not exist", scopeID)
		}
		baseline := scope.Bucket([]byte("baseline"))
		if baseline == nil {
			t.Fatal("baseline bucket does not exist")
		}
		return baseline.Put([]byte(serviceKey), []byte(payload))
	}); err != nil {
		t.Fatalf("seed persistent record: %v", err)
	}
}

func seedCurrentRecord(t *testing.T, db *bbolt.DB, scopeID, scanID, serviceKey, payload string) {
	t.Helper()
	if err := EnsureCurrentScan(db, scopeID, scanID); err != nil {
		t.Fatalf("EnsureCurrentScan() error = %v", err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		scopes := tx.Bucket([]byte(stateScopeBucket))
		if scopes == nil {
			t.Fatal("scope root bucket does not exist")
		}
		scope := scopes.Bucket([]byte(scopeID))
		if scope == nil {
			t.Fatalf("scope bucket %q does not exist", scopeID)
		}
		scans := scope.Bucket([]byte(stateScanBucket))
		if scans == nil {
			t.Fatal("scan bucket does not exist")
		}
		scan := scans.Bucket([]byte(scanID))
		if scan == nil {
			t.Fatalf("scan bucket %q does not exist", scanID)
		}
		return scan.Put([]byte(serviceKey), []byte(payload))
	}); err != nil {
		t.Fatalf("seed current record: %v", err)
	}
}

func committedRecordBytes(t *testing.T, db *bbolt.DB, scopeID, serviceKey string) []byte {
	t.Helper()
	var result []byte
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
		result = bytes.Clone(baseline.Get([]byte(serviceKey)))
		return nil
	}); err != nil {
		t.Fatalf("read committed record bytes: %v", err)
	}
	return result
}

func TestStateLoadsDistinguishAbsentFromExistingEmpty(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := InitializeStateSchema(db); err != nil {
		t.Fatalf("InitializeStateSchema() error = %v", err)
	}

	baseline, exists, err := LoadCommittedBaseline(db, "scope-a")
	if err != nil || exists || len(baseline) != 0 {
		t.Fatalf("absent baseline = (%#v, %t, %v), want empty, false, nil", baseline, exists, err)
	}
	createCommittedBaselineForTest(t, db, "scope-a")
	baseline, exists, err = LoadCommittedBaseline(db, "scope-a")
	if err != nil || !exists || len(baseline) != 0 {
		t.Fatalf("empty baseline = (%#v, %t, %v), want empty, true, nil", baseline, exists, err)
	}

	current, exists, err := LoadCurrentScan(db, "scope-a", "scan-a")
	if err != nil || exists || len(current) != 0 {
		t.Fatalf("absent scan = (%#v, %t, %v), want empty, false, nil", current, exists, err)
	}
	if err := EnsureCurrentScan(db, "scope-a", "scan-a"); err != nil {
		t.Fatalf("EnsureCurrentScan() error = %v", err)
	}
	current, exists, err = LoadCurrentScan(db, "scope-a", "scan-a")
	if err != nil || !exists || len(current) != 0 {
		t.Fatalf("empty scan = (%#v, %t, %v), want empty, true, nil", current, exists, err)
	}
}

func TestLoadCommittedBaselineIsolatesScopes(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := InitializeStateSchema(db); err != nil {
		t.Fatalf("InitializeStateSchema() error = %v", err)
	}

	firstIdentity := testServiceIdentity("scope-a")
	secondIdentity := testServiceIdentity("scope-b")
	firstKey, err := firstIdentity.Key()
	if err != nil {
		t.Fatalf("first Key() error = %v", err)
	}
	secondKey, err := secondIdentity.Key()
	if err != nil {
		t.Fatalf("second Key() error = %v", err)
	}
	if firstKey == secondKey {
		t.Fatal("different scopes produced identical service keys")
	}

	const firstJSON = `{"ip":"192.0.2.10","port":443,"protocol":"tcp","status":"open","banner":"first","os_hint":"","tls_subject":"","tls_issuer":"","tls_sans":[]}`
	const secondJSON = `{"ip":"192.0.2.10","port":443,"protocol":"tcp","status":"closed","banner":"second","os_hint":"","tls_subject":"","tls_issuer":"","tls_sans":[]}`
	seedPersistentRecord(t, db, "scope-a", firstKey, firstJSON)
	seedPersistentRecord(t, db, "scope-b", secondKey, secondJSON)

	first, firstExists, err := LoadCommittedBaseline(db, "scope-a")
	if err != nil {
		t.Fatalf("LoadCommittedBaseline(scope-a) error = %v", err)
	}
	second, secondExists, err := LoadCommittedBaseline(db, "scope-b")
	if err != nil {
		t.Fatalf("LoadCommittedBaseline(scope-b) error = %v", err)
	}
	if !firstExists || len(first) != 1 || first[firstKey].Banner != "first" {
		t.Fatalf("scope-a baseline = (%#v, %t), want only first record", first, firstExists)
	}
	if _, leaked := first[secondKey]; leaked {
		t.Fatal("scope-b record leaked into scope-a baseline")
	}
	if !secondExists || len(second) != 1 || second[secondKey].Banner != "second" {
		t.Fatalf("scope-b baseline = (%#v, %t), want only second record", second, secondExists)
	}
	if _, leaked := second[firstKey]; leaked {
		t.Fatal("scope-a record leaked into scope-b baseline")
	}
}

func TestSaveCurrentServicePreservesExistingBaseline(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := InitializeStateSchema(db); err != nil {
		t.Fatalf("InitializeStateSchema() error = %v", err)
	}
	identity := testServiceIdentity("scope-a")
	serviceKey, err := identity.Key()
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	const baselineJSON = `{"ip":"192.0.2.10","port":443,"protocol":"tcp","status":"closed","banner":"old","os_hint":"old-os","tls_subject":"old-subject","tls_issuer":"old-issuer","tls_sans":["old.example"]}`
	seedPersistentRecord(t, db, "scope-a", serviceKey, baselineJSON)
	before := committedRecordBytes(t, db, "scope-a", serviceKey)

	observation := ServiceObservation{
		Banner: "new", OSHint: "linux", CertSubject: "subject", CertIssuer: "issuer",
		SANs: []string{"z.example", "a.example", "z.example"},
	}
	if err := SaveCurrentService(db, "scope-a", "scan-a", identity, observation); err != nil {
		t.Fatalf("SaveCurrentService() error = %v", err)
	}
	after := committedRecordBytes(t, db, "scope-a", serviceKey)
	if !bytes.Equal(after, before) {
		t.Fatalf("committed baseline changed from %q to %q", before, after)
	}

	baseline, baselineExists, err := LoadCommittedBaseline(db, "scope-a")
	if err != nil || !baselineExists || baseline[serviceKey].Banner != "old" {
		t.Fatalf("baseline = (%#v, %t, %v), want preserved old record", baseline, baselineExists, err)
	}
	current, currentExists, err := LoadCurrentScan(db, "scope-a", "scan-a")
	wantCurrent := ServiceRecord{
		IP: "192.0.2.10", Port: 443, Protocol: "tcp", Status: ServiceStatusOpen,
		Banner: "new", OSHint: "linux", CertSubject: "subject", CertIssuer: "issuer",
		SANs: []string{"a.example", "z.example"},
	}
	if err != nil || !currentExists || len(current) != 1 || !reflect.DeepEqual(current[serviceKey], wantCurrent) {
		t.Fatalf("current = (%#v, %t, %v), want {%q: %#v}", current, currentExists, err, serviceKey, wantCurrent)
	}

	if err := db.View(func(tx *bbolt.Tx) error {
		scopes := tx.Bucket([]byte("scope"))
		if scopes == nil {
			t.Fatal("scope root bucket does not exist")
		}
		scope := scopes.Bucket([]byte("scope-a"))
		if scope == nil {
			t.Fatal("scope-a bucket does not exist")
		}
		scans := scope.Bucket([]byte("scan"))
		if scans == nil {
			t.Fatal("scan bucket does not exist")
		}
		currentBucket := scans.Bucket([]byte("scan-a"))
		if currentBucket == nil {
			t.Fatal("scan-a bucket does not exist")
		}
		const want = `{"ip":"192.0.2.10","port":443,"protocol":"tcp","status":"open","banner":"new","os_hint":"linux","tls_subject":"subject","tls_issuer":"issuer","tls_sans":["a.example","z.example"]}`
		if got := string(currentBucket.Get([]byte(serviceKey))); got != want {
			t.Fatalf("persistent current record = %q, want %q", got, want)
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect persistent current record: %v", err)
	}
}

func TestLoadCommittedBaselineRejectsIdentityKeyMismatch(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := InitializeStateSchema(db); err != nil {
		t.Fatalf("InitializeStateSchema() error = %v", err)
	}
	matchingKey, err := testServiceIdentity("scope-a").Key()
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	const mismatched = `{"ip":"192.0.2.11","port":443,"protocol":"tcp","status":"open","banner":"","os_hint":"","tls_subject":"","tls_issuer":"","tls_sans":[]}`
	seedPersistentRecord(t, db, "scope-a", matchingKey, mismatched)

	_, _, err = LoadCommittedBaseline(db, "scope-a")
	if !errors.Is(err, ErrInvalidPersistentServiceRecord) {
		t.Fatalf("LoadCommittedBaseline() error = %v, want ErrInvalidPersistentServiceRecord", err)
	}
}

func TestLoadCommittedBaselineRejectsInvalidKeyAndRecord(t *testing.T) {
	const validJSON = `{"ip":"192.0.2.10","port":443,"protocol":"tcp","status":"open","banner":"","os_hint":"","tls_subject":"","tls_issuer":"","tls_sans":[]}`
	tests := []struct{ name, key, payload string }{
		{"uppercase key", "1093D4118DD533702FB0C83E16AC0C1A3ABCA13646E8BEEDE8B9FCABBBCFCB7C", validJSON},
		{"invalid status", "1093d4118dd533702fb0c83e16ac0c1a3abca13646e8beede8b9fcabbbcfcb7c", `{"ip":"192.0.2.10","port":443,"protocol":"tcp","status":"unknown","banner":"","os_hint":"","tls_subject":"","tls_issuer":"","tls_sans":[]}`},
		{"noncanonical IP", "1093d4118dd533702fb0c83e16ac0c1a3abca13646e8beede8b9fcabbbcfcb7c", `{"ip":"::ffff:192.0.2.10","port":443,"protocol":"tcp","status":"open","banner":"","os_hint":"","tls_subject":"","tls_issuer":"","tls_sans":[]}`},
		{"unsorted SANs", "1093d4118dd533702fb0c83e16ac0c1a3abca13646e8beede8b9fcabbbcfcb7c", `{"ip":"192.0.2.10","port":443,"protocol":"tcp","status":"open","banner":"","os_hint":"","tls_subject":"","tls_issuer":"","tls_sans":["z.example","a.example"]}`},
		{"duplicate SANs", "1093d4118dd533702fb0c83e16ac0c1a3abca13646e8beede8b9fcabbbcfcb7c", `{"ip":"192.0.2.10","port":443,"protocol":"tcp","status":"open","banner":"","os_hint":"","tls_subject":"","tls_issuer":"","tls_sans":["a.example","a.example"]}`},
		{"null SANs", "1093d4118dd533702fb0c83e16ac0c1a3abca13646e8beede8b9fcabbbcfcb7c", `{"ip":"192.0.2.10","port":443,"protocol":"tcp","status":"open","banner":"","os_hint":"","tls_subject":"","tls_issuer":"","tls_sans":null}`},
		{"unknown field", "1093d4118dd533702fb0c83e16ac0c1a3abca13646e8beede8b9fcabbbcfcb7c", `{"ip":"192.0.2.10","port":443,"protocol":"tcp","status":"open","banner":"","os_hint":"","tls_subject":"","tls_issuer":"","tls_sans":[],"future":true}`},
		{"malformed JSON", "1093d4118dd533702fb0c83e16ac0c1a3abca13646e8beede8b9fcabbbcfcb7c", "not-json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := openStateSchemaTestDB(t)
			if err := InitializeStateSchema(db); err != nil {
				t.Fatalf("InitializeStateSchema() error = %v", err)
			}
			seedPersistentRecord(t, db, "scope-test", tt.key, tt.payload)
			_, _, err := LoadCommittedBaseline(db, "scope-test")
			if !errors.Is(err, ErrInvalidPersistentServiceRecord) {
				t.Fatalf("LoadCommittedBaseline() error = %v, want ErrInvalidPersistentServiceRecord", err)
			}
		})
	}
}

func TestLoadCurrentScanRejectsClosedPersistentRecord(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := InitializeStateSchema(db); err != nil {
		t.Fatalf("InitializeStateSchema() error = %v", err)
	}
	identity := testServiceIdentity("scope-a")
	serviceKey, err := identity.Key()
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	const closedJSON = `{"ip":"192.0.2.10","port":443,"protocol":"tcp","status":"closed","banner":"","os_hint":"","tls_subject":"","tls_issuer":"","tls_sans":[]}`
	seedCurrentRecord(t, db, "scope-a", "scan-a", serviceKey, closedJSON)

	_, exists, err := LoadCurrentScan(db, "scope-a", "scan-a")
	if !exists {
		t.Fatal("LoadCurrentScan() exists = false, want true for corrupt existing scan")
	}
	if !errors.Is(err, ErrInvalidPersistentServiceRecord) {
		t.Fatalf("LoadCurrentScan() error = %v, want ErrInvalidPersistentServiceRecord", err)
	}
}

func TestSaveCurrentServiceRequiresVersionedSchemaWithoutMutation(t *testing.T) {
	db := openStateSchemaTestDB(t)
	err := SaveCurrentService(db, "scope-a", "scan-a", testServiceIdentity("scope-a"), ServiceObservation{})
	if !errors.Is(err, ErrUnversionedStateSchema) {
		t.Fatalf("SaveCurrentService() error = %v, want ErrUnversionedStateSchema", err)
	}
	if err := db.View(func(tx *bbolt.Tx) error {
		if tx.Bucket([]byte("scope")) != nil {
			t.Fatal("scope bucket created despite schema validation failure")
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect scope state: %v", err)
	}
}

func TestSaveCurrentServiceRejectsMismatchedScopeWithoutMutation(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := InitializeStateSchema(db); err != nil {
		t.Fatalf("InitializeStateSchema() error = %v", err)
	}

	err := SaveCurrentService(db, "scope-b", "scan-a", testServiceIdentity("scope-a"), ServiceObservation{})
	if !errors.Is(err, ErrServiceIdentityScopeMismatch) {
		t.Fatalf("SaveCurrentService() error = %v, want ErrServiceIdentityScopeMismatch", err)
	}
	if err := db.View(func(tx *bbolt.Tx) error {
		if tx.Bucket([]byte("scope")) != nil {
			t.Fatal("scope bucket created despite identity scope mismatch")
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect scope state: %v", err)
	}
}
