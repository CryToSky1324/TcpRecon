package scanner

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"go.etcd.io/bbolt"
)

func snapshotStateScanBucket(prefix string, bucket *bbolt.Bucket, result *[]string) error {
	return bucket.ForEach(func(key, value []byte) error {
		path := prefix + "/" + string(key)
		if value != nil {
			*result = append(*result, fmt.Sprintf("value:%s=%q", path, value))
			return nil
		}
		*result = append(*result, "bucket:"+path)
		return snapshotStateScanBucket(path, bucket.Bucket(key), result)
	})
}

func snapshotStateScanDB(t *testing.T, db *bbolt.DB) []string {
	t.Helper()
	var result []string
	if err := db.View(func(tx *bbolt.Tx) error {
		return tx.ForEach(func(name []byte, bucket *bbolt.Bucket) error {
			path := "/" + string(name)
			result = append(result, "bucket:"+path)
			return snapshotStateScanBucket(path, bucket, &result)
		})
	}); err != nil {
		t.Fatalf("snapshot state scan DB: %v", err)
	}
	slices.Sort(result)
	return result
}

func TestEnsureCurrentScanSeparatesObservationsFromBaseline(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := InitializeStateSchema(db); err != nil {
		t.Fatalf("InitializeStateSchema() error = %v", err)
	}

	const (
		scopeID = "scope-a"
		scanID  = "scan-a"
	)
	serviceKey, err := (ServiceIdentity{
		ScopeID:  scopeID,
		IP:       "192.0.2.10",
		Port:     443,
		Protocol: "tcp",
	}).Key()
	if err != nil {
		t.Fatalf("ServiceIdentity.Key() error = %v", err)
	}

	createCommittedBaselineForTest(t, db, scopeID)
	if err := EnsureCurrentScan(db, scopeID, scanID); err != nil {
		t.Fatalf("EnsureCurrentScan() error = %v", err)
	}

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
		scans := scope.Bucket([]byte("scan"))
		if scans == nil {
			t.Fatal("scan bucket does not exist")
		}
		current := scans.Bucket([]byte(scanID))
		if current == nil {
			t.Fatalf("scan bucket %q does not exist", scanID)
		}
		if err := baseline.Put([]byte(serviceKey), []byte("committed")); err != nil {
			return err
		}
		return current.Put([]byte(serviceKey), []byte("current"))
	}); err != nil {
		t.Fatalf("seed baseline and current observations: %v", err)
	}
	if err := EnsureCurrentScan(db, scopeID, scanID); err != nil {
		t.Fatalf("repeated EnsureCurrentScan() error = %v", err)
	}

	if err := db.View(func(tx *bbolt.Tx) error {
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
		scans := scope.Bucket([]byte("scan"))
		if scans == nil {
			t.Fatal("scan bucket does not exist")
		}
		current := scans.Bucket([]byte(scanID))
		if current == nil {
			t.Fatalf("scan bucket %q does not exist", scanID)
		}
		if got, want := string(baseline.Get([]byte(serviceKey))), "committed"; got != want {
			t.Fatalf("baseline value = %q, want %q", got, want)
		}
		if got, want := string(current.Get([]byte(serviceKey))), "current"; got != want {
			t.Fatalf("current value = %q, want %q", got, want)
		}
		return nil
	}); err != nil {
		t.Fatalf("read baseline and current observations: %v", err)
	}
}

func TestCreateCurrentScanExclusiveDetectsCollisionAndPreservesContents(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := InitializeStateSchema(db); err != nil {
		t.Fatal(err)
	}
	if err := CreateCurrentScanExclusive(db, "scope-a", "scan-a"); err != nil {
		t.Fatalf("first creation: %v", err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		scopes := tx.Bucket([]byte("scope"))
		if scopes == nil {
			return errors.New("scope root missing")
		}
		scope := scopes.Bucket([]byte("scope-a"))
		if scope == nil {
			return errors.New("scope-a missing")
		}
		scans := scope.Bucket([]byte("scan"))
		if scans == nil {
			return errors.New("scan root missing")
		}
		scan := scans.Bucket([]byte("scan-a"))
		if scan == nil {
			return errors.New("scan-a missing")
		}
		return scan.Put([]byte("sentinel"), []byte("preserve"))
	}); err != nil {
		t.Fatal(err)
	}

	err := CreateCurrentScanExclusive(db, "scope-a", "scan-a")
	if !errors.Is(err, ErrStateScanAlreadyExists) {
		t.Fatalf("collision error = %v, want ErrStateScanAlreadyExists", err)
	}
	if err := db.View(func(tx *bbolt.Tx) error {
		scopes := tx.Bucket([]byte("scope"))
		if scopes == nil {
			return errors.New("scope root missing after collision")
		}
		scope := scopes.Bucket([]byte("scope-a"))
		if scope == nil {
			return errors.New("scope-a missing after collision")
		}
		scans := scope.Bucket([]byte("scan"))
		if scans == nil {
			return errors.New("scan root missing after collision")
		}
		scan := scans.Bucket([]byte("scan-a"))
		if scan == nil {
			return errors.New("scan-a missing after collision")
		}
		if got := string(scan.Get([]byte("sentinel"))); got != "preserve" {
			return fmt.Errorf("sentinel = %q, want preserve", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCreateCurrentScanExclusiveRejectsInvalidInputWithoutScopeMutation(t *testing.T) {
	tests := []struct {
		name    string
		scopeID string
		scanID  string
		seed    func(*testing.T, *bbolt.DB)
		wantErr error
	}{
		{name: "empty scope", scanID: "scan-a", seed: func(t *testing.T, db *bbolt.DB) {
			t.Helper()
			if err := InitializeStateSchema(db); err != nil {
				t.Fatal(err)
			}
		}, wantErr: ErrInvalidStateScopeID},
		{name: "empty scan ID", scopeID: "scope-a", seed: func(t *testing.T, db *bbolt.DB) {
			t.Helper()
			if err := InitializeStateSchema(db); err != nil {
				t.Fatal(err)
			}
		}, wantErr: ErrInvalidStateScanID},
		{name: "unversioned", scopeID: "scope-a", scanID: "scan-a", seed: func(*testing.T, *bbolt.DB) {}, wantErr: ErrUnversionedStateSchema},
		{
			name: "unsupported schema", scopeID: "scope-a", scanID: "scan-a", wantErr: ErrUnsupportedStateSchemaVersion,
			seed: func(t *testing.T, db *bbolt.DB) {
				t.Helper()
				if err := db.Update(func(tx *bbolt.Tx) error {
					metadata, err := tx.CreateBucket([]byte("metadata"))
					if err != nil {
						return err
					}
					return metadata.Put([]byte("schema_version"), []byte("999"))
				}); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := openStateSchemaTestDB(t)
			tt.seed(t, db)
			before := snapshotStateScanDB(t, db)
			err := CreateCurrentScanExclusive(db, tt.scopeID, tt.scanID)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("CreateCurrentScanExclusive() error = %v, want %v", err, tt.wantErr)
			}
			after := snapshotStateScanDB(t, db)
			if !slices.Equal(after, before) {
				t.Fatalf("rejected exclusive creation mutated state:\nbefore=%v\nafter=%v", before, after)
			}
		})
	}
}

func TestCreateCurrentScanExclusiveScopesCollisionsAndCreatesEmptyScan(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := InitializeStateSchema(db); err != nil {
		t.Fatal(err)
	}
	for _, scopeID := range []string{"scope-a", "scope-b"} {
		if err := CreateCurrentScanExclusive(db, scopeID, "scan-a"); err != nil {
			t.Fatalf("create %s/scan-a: %v", scopeID, err)
		}
		records, exists, err := LoadCurrentScan(db, scopeID, "scan-a")
		if err != nil || !exists || len(records) != 0 {
			t.Fatalf("LoadCurrentScan(%s) = (len=%d, exists=%t, err=%v), want existing empty", scopeID, len(records), exists, err)
		}
	}
}

func TestEnsureCurrentScanPartitionsScanIDs(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := InitializeStateSchema(db); err != nil {
		t.Fatalf("InitializeStateSchema() error = %v", err)
	}

	const scopeID = "scope-a"
	for _, scanID := range []string{"scan-a", "scan-b"} {
		if err := EnsureCurrentScan(db, scopeID, scanID); err != nil {
			t.Fatalf("EnsureCurrentScan(%q) error = %v", scanID, err)
		}
	}

	if err := db.View(func(tx *bbolt.Tx) error {
		scopes := tx.Bucket([]byte("scope"))
		if scopes == nil {
			t.Fatal("scope root bucket does not exist")
		}
		scope := scopes.Bucket([]byte(scopeID))
		if scope == nil {
			t.Fatalf("scope bucket %q does not exist", scopeID)
		}
		scans := scope.Bucket([]byte("scan"))
		if scans == nil {
			t.Fatal("scan bucket does not exist")
		}
		if scans.Bucket([]byte("scan-a")) == nil || scans.Bucket([]byte("scan-b")) == nil {
			t.Fatal("current observations are not partitioned by scan_id")
		}
		if scope.Bucket([]byte("baseline")) != nil {
			t.Fatal("ensuring current scan unexpectedly created a baseline bucket")
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect scan buckets: %v", err)
	}
}

func TestEnsureCurrentScanRejectsEmptyIdentifiers(t *testing.T) {
	tests := []struct {
		name    string
		scopeID string
		scanID  string
		wantErr error
	}{
		{name: "scope_id", scanID: "scan-a", wantErr: ErrInvalidStateScopeID},
		{name: "scan_id", scopeID: "scope-a", wantErr: ErrInvalidStateScanID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := openStateSchemaTestDB(t)
			if err := InitializeStateSchema(db); err != nil {
				t.Fatalf("InitializeStateSchema() error = %v", err)
			}

			err := EnsureCurrentScan(db, tt.scopeID, tt.scanID)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("EnsureCurrentScan() error = %v, want %v", err, tt.wantErr)
			}
			if err := db.View(func(tx *bbolt.Tx) error {
				if tx.Bucket([]byte("scope")) != nil {
					t.Fatal("scope bucket created for invalid identifier")
				}
				return nil
			}); err != nil {
				t.Fatalf("inspect scope bucket: %v", err)
			}
		})
	}
}

func TestEnsureCurrentScanRequiresVersionedSchema(t *testing.T) {
	db := openStateSchemaTestDB(t)

	err := EnsureCurrentScan(db, "scope-a", "scan-a")
	if !errors.Is(err, ErrUnversionedStateSchema) {
		t.Fatalf("EnsureCurrentScan() error = %v, want ErrUnversionedStateSchema", err)
	}
	if err := db.View(func(tx *bbolt.Tx) error {
		if tx.Bucket([]byte("scope")) != nil {
			t.Fatal("scope bucket created despite schema validation failure")
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect scope bucket: %v", err)
	}
}
