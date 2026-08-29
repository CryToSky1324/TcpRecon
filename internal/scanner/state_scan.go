package scanner

import (
	"errors"
	"fmt"

	"go.etcd.io/bbolt"
)

const stateScanBucket = "scan"

var (
	ErrInvalidStateScanID     = errors.New("invalid state scan ID")
	ErrStateScanAlreadyExists = errors.New("state scan already exists")
)

// EnsureCurrentScan creates the temporary observation bucket for one scan in
// one scope. It does not create or modify that scope's committed baseline.
func EnsureCurrentScan(db *bbolt.DB, scopeID, scanID string) error {
	if scopeID == "" {
		return ErrInvalidStateScopeID
	}
	if scanID == "" {
		return ErrInvalidStateScanID
	}

	return db.Update(func(tx *bbolt.Tx) error {
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
		scans, err := scope.CreateBucketIfNotExists([]byte(stateScanBucket))
		if err != nil {
			return err
		}
		_, err = scans.CreateBucketIfNotExists([]byte(scanID))
		return err
	})
}

// CreateCurrentScanExclusive reserves one previously unused opaque scan ID
// within a scope. Existing persistence helpers retain their non-empty-ID
// contract; runtime-specific scan-ID formatting is enforced by the caller.
func CreateCurrentScanExclusive(db *bbolt.DB, scopeID, scanID string) error {
	if scopeID == "" {
		return ErrInvalidStateScopeID
	}
	if scanID == "" {
		return ErrInvalidStateScanID
	}

	return db.Update(func(tx *bbolt.Tx) error {
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
		scans, err := scope.CreateBucketIfNotExists([]byte(stateScanBucket))
		if err != nil {
			return err
		}
		if _, err := scans.CreateBucket([]byte(scanID)); err != nil {
			if errors.Is(err, bbolt.ErrBucketExists) {
				return fmt.Errorf("%w: scope %q scan %q", ErrStateScanAlreadyExists, scopeID, scanID)
			}
			return err
		}
		return nil
	})
}
