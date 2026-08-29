package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/CryToSky1324/TcpRecon/internal/scanner"
	"go.etcd.io/bbolt"
)

func openRuntimeStartupTestDB(t *testing.T) *bbolt.DB {
	t.Helper()
	db, err := bbolt.Open(filepath.Join(t.TempDir(), "state.db"), 0600, nil)
	if err != nil {
		t.Fatalf("open runtime startup test DB: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close runtime startup test DB: %v", err)
		}
	})
	return db
}

func snapshotRuntimeBucket(prefix string, bucket *bbolt.Bucket, result *[]string) error {
	return bucket.ForEach(func(key, value []byte) error {
		path := prefix + "/" + string(key)
		if value != nil {
			*result = append(*result, fmt.Sprintf("value:%s=%q", path, value))
			return nil
		}
		*result = append(*result, "bucket:"+path)
		return snapshotRuntimeBucket(path, bucket.Bucket(key), result)
	})
}

func snapshotRuntimeState(t *testing.T, db *bbolt.DB) []string {
	t.Helper()
	var result []string
	if err := db.View(func(tx *bbolt.Tx) error {
		return tx.ForEach(func(name []byte, bucket *bbolt.Bucket) error {
			path := "/" + string(name)
			result = append(result, "bucket:"+path)
			return snapshotRuntimeBucket(path, bucket, &result)
		})
	}); err != nil {
		t.Fatalf("snapshot runtime state: %v", err)
	}
	slices.Sort(result)
	return result
}

func TestRuntimeStartupInitializesSchemaBeforeReservationContinuation(t *testing.T) {
	db := openRuntimeStartupTestDB(t)
	ready := false
	readyForReservation := func(*preparedTargetSource) {
		ready = true
		if err := db.View(func(tx *bbolt.Tx) error {
			metadata := tx.Bucket([]byte("metadata"))
			if metadata == nil {
				return errors.New("metadata missing at reservation continuation")
			}
			if got := string(metadata.Get([]byte("schema_version"))); got != "1" {
				return fmt.Errorf("schema_version = %q, want 1", got)
			}
			if _, err := time.Parse(time.RFC3339Nano, string(metadata.Get([]byte("created_at")))); err != nil {
				return fmt.Errorf("created_at invalid: %w", err)
			}
			if tx.Bucket([]byte("PortStates")) != nil {
				return errors.New("legacy PortStates created before reservation continuation")
			}
			return nil
		}); err != nil {
			t.Error(err)
		}
	}

	prepared, err := prepareRuntimeStartup(
		context.Background(),
		io.NopCloser(strings.NewReader("192.0.2.1\n")),
		db,
		readyForReservation,
	)
	if err != nil {
		t.Fatalf("prepareRuntimeStartup() error = %v", err)
	}
	defer prepared.Close()
	if !ready {
		t.Fatal("reservation continuation was not invoked after schema initialization")
	}

	state := snapshotRuntimeState(t, db)
	for _, entry := range state {
		if strings.Contains(entry, "/PortStates") {
			t.Fatalf("fresh runtime state contains legacy bucket: %v", state)
		}
	}
}

func TestRuntimeStartupRefusesIncompatibleStateWithoutMutation(t *testing.T) {
	tests := []struct {
		name    string
		seed    func(*testing.T, *bbolt.DB)
		wantErr error
	}{
		{
			name: "legacy PortStates",
			seed: func(t *testing.T, db *bbolt.DB) {
				t.Helper()
				if err := db.Update(func(tx *bbolt.Tx) error {
					bucket, err := tx.CreateBucket([]byte("PortStates"))
					if err != nil {
						return err
					}
					return bucket.Put([]byte("sentinel"), []byte("legacy"))
				}); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: scanner.ErrUnversionedStateSchema,
		},
		{
			name: "unknown version",
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
			wantErr: scanner.ErrUnsupportedStateSchemaVersion,
		},
		{
			name: "malformed metadata",
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
					t.Fatal(err)
				}
			},
			wantErr: scanner.ErrInvalidStateSchemaMetadata,
		},
		{
			name: "unversioned database",
			seed: func(t *testing.T, db *bbolt.DB) {
				t.Helper()
				if err := db.Update(func(tx *bbolt.Tx) error {
					bucket, err := tx.CreateBucket([]byte("unrelated"))
					if err != nil {
						return err
					}
					return bucket.Put([]byte("sentinel"), []byte("preserve"))
				}); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: scanner.ErrUnversionedStateSchema,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := openRuntimeStartupTestDB(t)
			tt.seed(t, db)
			before := snapshotRuntimeState(t, db)
			ready := false
			spool := &fakeTargetSpool{path: "tracked-schema-rejection-spool"}
			removed := false
			prepare := func(ctx context.Context, source io.ReadCloser) (*preparedTargetSource, error) {
				return prepareTargetSourceWith(
					ctx,
					source,
					func() (targetSpool, error) { return spool, nil },
					func(path string) error {
						if path != spool.path {
							t.Fatalf("removed path = %q, want %q", path, spool.path)
						}
						removed = true
						return nil
					},
				)
			}

			prepared, err := prepareRuntimeStartupWith(
				context.Background(),
				io.NopCloser(strings.NewReader("192.0.2.1\n")),
				db,
				prepare,
				func(*preparedTargetSource) { ready = true },
			)
			if prepared != nil {
				t.Fatal("prepareRuntimeStartup() returned prepared source for incompatible state")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("prepareRuntimeStartup() error = %v, want %v", err, tt.wantErr)
			}
			if ready {
				t.Fatal("reservation continuation ran for rejected schema")
			}
			if !spool.closed || !removed {
				t.Fatalf("rejected schema spool cleanup = (closed=%t, removed=%t), want both true", spool.closed, removed)
			}
			after := snapshotRuntimeState(t, db)
			if !slices.Equal(after, before) {
				t.Fatalf("rejected database mutated:\nbefore=%v\nafter=%v", before, after)
			}
		})
	}
}

func TestRuntimeStartupPreparationFailureDoesNotInitializeOrFinalize(t *testing.T) {
	db := openRuntimeStartupTestDB(t)
	ready := false
	errRead := errors.New("source read failed")

	prepared, err := prepareRuntimeStartup(
		context.Background(),
		&trackingReadCloser{Reader: failingReader{err: errRead}},
		db,
		func(*preparedTargetSource) { ready = true },
	)
	if prepared != nil {
		t.Fatal("prepareRuntimeStartup() returned prepared source after preparation failure")
	}
	if !errors.Is(err, errRead) {
		t.Fatalf("prepareRuntimeStartup() error = %v, want source read failure", err)
	}
	if ready {
		t.Fatal("reservation continuation ran after preparation failure")
	}
	if state := snapshotRuntimeState(t, db); len(state) != 0 {
		t.Fatalf("preparation failure initialized state: %v", state)
	}
}
