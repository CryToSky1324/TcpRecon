package scanner

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"go.etcd.io/bbolt"
)

func openRestartTestDB(t *testing.T, path string) *bbolt.DB {
	t.Helper()
	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	return db
}

func closeRestartTestDB(t *testing.T, db *bbolt.DB) {
	t.Helper()
	if err := db.Close(); err != nil {
		t.Fatalf("close test db: %v", err)
	}
}

func stateMetadataValue(t *testing.T, db *bbolt.DB, key []byte) []byte {
	t.Helper()
	var value []byte
	if err := db.View(func(tx *bbolt.Tx) error {
		metadata := tx.Bucket(stateMetadataBucket)
		if metadata == nil {
			t.Fatal("metadata bucket does not exist")
		}
		value = bytes.Clone(metadata.Get(key))
		return nil
	}); err != nil {
		t.Fatalf("read metadata: %v", err)
	}
	return value
}

func TestStateSurvivesRestartAndRemainsPromotable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	db := openRestartTestDB(t, dbPath)
	if err := InitializeStateSchema(db); err != nil {
		t.Fatalf("InitializeStateSchema() error = %v", err)
	}
	createdAt := stateMetadataValue(t, db, stateCreatedAtKey)
	identity := reconciliationIdentity("scope-a", "192.0.2.10", 443)
	serviceKey, err := identity.Key()
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	if err := SaveCurrentService(db, "scope-a", "scan-a", identity, ServiceObservation{Banner: "baseline"}); err != nil {
		t.Fatalf("SaveCurrentService(scan-a) error = %v", err)
	}
	if _, err := FinalizeCurrentScan(db, "scope-a", "scan-a", successfulReconciliationCompletion()); err != nil {
		t.Fatalf("FinalizeCurrentScan(scan-a) error = %v", err)
	}
	if err := SaveCurrentService(db, "scope-a", "scan-b", identity, ServiceObservation{Banner: "after-restart"}); err != nil {
		t.Fatalf("SaveCurrentService(scan-b) error = %v", err)
	}
	closeRestartTestDB(t, db)

	db = openRestartTestDB(t, dbPath)
	if err := InitializeStateSchema(db); err != nil {
		t.Fatalf("InitializeStateSchema(after restart) error = %v", err)
	}
	if got := stateMetadataValue(t, db, stateCreatedAtKey); !bytes.Equal(got, createdAt) {
		t.Fatalf("created_at changed across restart from %q to %q", createdAt, got)
	}
	if got, want := string(stateMetadataValue(t, db, stateSchemaVersionKey)), stateSchemaVersion; got != want {
		t.Fatalf("schema_version after restart = %q, want %q", got, want)
	}
	baseline, baselineExists, err := LoadCommittedBaseline(db, "scope-a")
	if err != nil {
		t.Fatalf("LoadCommittedBaseline(after restart) error = %v", err)
	}
	if !baselineExists || len(baseline) != 1 || baseline[serviceKey].Banner != "baseline" {
		t.Fatalf("baseline after restart = (%#v, %t), want persisted baseline", baseline, baselineExists)
	}
	current, currentExists, err := LoadCurrentScan(db, "scope-a", "scan-b")
	if err != nil {
		t.Fatalf("LoadCurrentScan(after restart) error = %v", err)
	}
	if !currentExists || len(current) != 1 || current[serviceKey].Banner != "after-restart" {
		t.Fatalf("current scan after restart = (%#v, %t), want persisted scan", current, currentExists)
	}
	changes, err := FinalizeCurrentScan(db, "scope-a", "scan-b", successfulReconciliationCompletion())
	if err != nil {
		t.Fatalf("FinalizeCurrentScan(after restart) error = %v", err)
	}
	if len(changes) != 1 || changes[0].Kind != ChangeChanged || changes[0].ServiceKey != serviceKey {
		t.Fatalf("post-restart changes = %#v, want one changed service", changes)
	}
	closeRestartTestDB(t, db)

	db = openRestartTestDB(t, dbPath)
	defer closeRestartTestDB(t, db)
	baseline, baselineExists, err = LoadCommittedBaseline(db, "scope-a")
	if err != nil {
		t.Fatalf("LoadCommittedBaseline(second restart) error = %v", err)
	}
	if !baselineExists || baseline[serviceKey].Banner != "after-restart" {
		t.Fatalf("promoted baseline after second restart = (%#v, %t)", baseline, baselineExists)
	}
	_, currentExists, err = LoadCurrentScan(db, "scope-a", "scan-b")
	if err != nil || currentExists {
		t.Fatalf("promoted scan persisted after second restart: exists=%t error=%v", currentExists, err)
	}
}

func TestInitializeStateSchemaRejectsPersistentIncompatibilitiesAfterRestart(t *testing.T) {
	tests := []struct {
		name    string
		seed    func(*testing.T, *bbolt.DB)
		wantErr error
	}{
		{
			name: "unknown version",
			seed: func(t *testing.T, db *bbolt.DB) {
				t.Helper()
				if err := db.Update(func(tx *bbolt.Tx) error {
					metadata, err := tx.CreateBucket([]byte("metadata"))
					if err != nil {
						return err
					}
					if err := metadata.Put([]byte("schema_version"), []byte("999")); err != nil {
						return err
					}
					return metadata.Put([]byte("created_at"), []byte("2000-01-02T03:04:05Z"))
				}); err != nil {
					t.Fatalf("seed unknown schema: %v", err)
				}
			},
			wantErr: ErrUnsupportedStateSchemaVersion,
		},
		{
			name: "missing version",
			seed: func(t *testing.T, db *bbolt.DB) {
				t.Helper()
				if err := db.Update(func(tx *bbolt.Tx) error {
					metadata, err := tx.CreateBucket([]byte("metadata"))
					if err != nil {
						return err
					}
					return metadata.Put([]byte("created_at"), []byte("2000-01-02T03:04:05Z"))
				}); err != nil {
					t.Fatalf("seed missing version: %v", err)
				}
			},
			wantErr: ErrUnversionedStateSchema,
		},
		{
			name: "malformed created_at",
			seed: func(t *testing.T, db *bbolt.DB) {
				t.Helper()
				if err := db.Update(func(tx *bbolt.Tx) error {
					metadata, err := tx.CreateBucket([]byte("metadata"))
					if err != nil {
						return err
					}
					if err := metadata.Put([]byte("schema_version"), []byte("1")); err != nil {
						return err
					}
					return metadata.Put([]byte("created_at"), []byte("not-a-timestamp"))
				}); err != nil {
					t.Fatalf("seed malformed metadata: %v", err)
				}
			},
			wantErr: ErrInvalidStateSchemaMetadata,
		},
		{
			name: "missing created_at",
			seed: func(t *testing.T, db *bbolt.DB) {
				t.Helper()
				if err := db.Update(func(tx *bbolt.Tx) error {
					metadata, err := tx.CreateBucket([]byte("metadata"))
					if err != nil {
						return err
					}
					return metadata.Put([]byte("schema_version"), []byte("1"))
				}); err != nil {
					t.Fatalf("seed missing created_at: %v", err)
				}
			},
			wantErr: ErrInvalidStateSchemaMetadata,
		},
		{
			name: "legacy unversioned state",
			seed: func(t *testing.T, db *bbolt.DB) {
				t.Helper()
				if err := db.Update(func(tx *bbolt.Tx) error {
					_, err := tx.CreateBucket([]byte("PortStates"))
					return err
				}); err != nil {
					t.Fatalf("seed legacy state: %v", err)
				}
			},
			wantErr: ErrUnversionedStateSchema,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "state.db")
			db := openRestartTestDB(t, dbPath)
			tt.seed(t, db)
			closeRestartTestDB(t, db)

			db = openRestartTestDB(t, dbPath)
			defer closeRestartTestDB(t, db)
			err := InitializeStateSchema(db)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("InitializeStateSchema() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
