package scanner

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

func openStateSchemaTestDB(t *testing.T) *bbolt.DB {
	t.Helper()

	db, err := bbolt.Open(filepath.Join(t.TempDir(), "state.db"), 0600, nil)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close test db: %v", err)
		}
	})
	return db
}

func createCommittedBaselineForTest(t *testing.T, db *bbolt.DB, scopeID string) {
	t.Helper()
	if err := db.Update(func(tx *bbolt.Tx) error {
		if err := validateStateSchema(tx); err != nil {
			return err
		}
		scopes, err := tx.CreateBucketIfNotExists([]byte(stateScopeBucket))
		if err != nil {
			return err
		}
		scope, err := scopes.CreateBucketIfNotExists([]byte(scopeID))
		if err != nil {
			return err
		}
		_, err = scope.CreateBucketIfNotExists([]byte(stateBaselineBucket))
		return err
	}); err != nil {
		t.Fatalf("create test-only committed baseline: %v", err)
	}
}

func TestInitializeStateSchemaCreatesVersionedMetadata(t *testing.T) {
	db := openStateSchemaTestDB(t)
	before := time.Now().UTC()

	if err := InitializeStateSchema(db); err != nil {
		t.Fatalf("InitializeStateSchema() error = %v", err)
	}

	after := time.Now().UTC()
	if err := db.View(func(tx *bbolt.Tx) error {
		metadata := tx.Bucket([]byte("metadata"))
		if metadata == nil {
			t.Fatal("metadata bucket does not exist")
		}

		if got, want := string(metadata.Get([]byte("schema_version"))), "1"; got != want {
			t.Fatalf("schema_version = %q, want %q", got, want)
		}

		createdAtRaw := metadata.Get([]byte("created_at"))
		createdAt, err := time.Parse(time.RFC3339Nano, string(createdAtRaw))
		if err != nil {
			t.Fatalf("created_at = %q, want RFC3339Nano timestamp: %v", createdAtRaw, err)
		}
		if createdAt.Before(before) || createdAt.After(after) {
			t.Fatalf("created_at = %v, want timestamp between %v and %v", createdAt, before, after)
		}
		return nil
	}); err != nil {
		t.Fatalf("read metadata: %v", err)
	}
}

func TestInitializeStateSchemaPreservesCreatedAt(t *testing.T) {
	db := openStateSchemaTestDB(t)
	const sentinelCreatedAt = "2000-01-02T03:04:05.000000006Z"
	if err := db.Update(func(tx *bbolt.Tx) error {
		metadata, err := tx.CreateBucket([]byte("metadata"))
		if err != nil {
			return err
		}
		if err := metadata.Put([]byte("schema_version"), []byte("1")); err != nil {
			return err
		}
		return metadata.Put([]byte("created_at"), []byte(sentinelCreatedAt))
	}); err != nil {
		t.Fatalf("seed versioned metadata: %v", err)
	}

	if err := InitializeStateSchema(db); err != nil {
		t.Fatalf("InitializeStateSchema() error = %v", err)
	}

	if err := db.View(func(tx *bbolt.Tx) error {
		got := tx.Bucket([]byte("metadata")).Get([]byte("created_at"))
		if string(got) != sentinelCreatedAt {
			t.Fatalf("created_at = %q, want preserved sentinel %q", got, sentinelCreatedAt)
		}
		return nil
	}); err != nil {
		t.Fatalf("read preserved created_at: %v", err)
	}
}

func TestInitializeStateSchemaRejectsMissingVersion(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := db.Update(func(tx *bbolt.Tx) error {
		metadata, err := tx.CreateBucket([]byte("metadata"))
		if err != nil {
			return err
		}
		return metadata.Put([]byte("created_at"), []byte("2000-01-02T03:04:05Z"))
	}); err != nil {
		t.Fatalf("seed metadata without schema_version: %v", err)
	}

	err := InitializeStateSchema(db)
	if !errors.Is(err, ErrUnversionedStateSchema) {
		t.Fatalf("InitializeStateSchema() error = %v, want ErrUnversionedStateSchema", err)
	}
}

func TestInitializeStateSchemaRejectsMissingCreatedAt(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := db.Update(func(tx *bbolt.Tx) error {
		metadata, err := tx.CreateBucket([]byte("metadata"))
		if err != nil {
			return err
		}
		return metadata.Put([]byte("schema_version"), []byte("1"))
	}); err != nil {
		t.Fatalf("seed metadata without created_at: %v", err)
	}

	err := InitializeStateSchema(db)
	if !errors.Is(err, ErrInvalidStateSchemaMetadata) {
		t.Fatalf("InitializeStateSchema() error = %v, want ErrInvalidStateSchemaMetadata", err)
	}
}

func TestInitializeStateSchemaRejectsMalformedCreatedAt(t *testing.T) {
	db := openStateSchemaTestDB(t)
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
		t.Fatalf("seed malformed created_at: %v", err)
	}

	err := InitializeStateSchema(db)
	if !errors.Is(err, ErrInvalidStateSchemaMetadata) {
		t.Fatalf("InitializeStateSchema() error = %v, want ErrInvalidStateSchemaMetadata", err)
	}
}

func TestInitializeStateSchemaRejectsUnknownVersion(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := db.Update(func(tx *bbolt.Tx) error {
		metadata, err := tx.CreateBucket([]byte("metadata"))
		if err != nil {
			return err
		}
		return metadata.Put([]byte("schema_version"), []byte("999"))
	}); err != nil {
		t.Fatalf("seed unknown schema: %v", err)
	}

	err := InitializeStateSchema(db)
	if !errors.Is(err, ErrUnsupportedStateSchemaVersion) {
		t.Fatalf("InitializeStateSchema() error = %v, want ErrUnsupportedStateSchemaVersion", err)
	}
}

func TestInitializeStateSchemaRejectsUnversionedState(t *testing.T) {
	db := openStateSchemaTestDB(t)
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucket([]byte("PortStates"))
		return err
	}); err != nil {
		t.Fatalf("seed legacy state: %v", err)
	}

	err := InitializeStateSchema(db)
	if !errors.Is(err, ErrUnversionedStateSchema) {
		t.Fatalf("InitializeStateSchema() error = %v, want ErrUnversionedStateSchema", err)
	}
}
