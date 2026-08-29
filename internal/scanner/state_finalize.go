package scanner

import (
	"errors"
	"fmt"

	"go.etcd.io/bbolt"
)

var ErrScanIncomplete = errors.New("scan incomplete")

// FinalizeCurrentScan promotes a successful scan or discards an incomplete
// scan's temporary observations. Incomplete scans are never reconciled.
func FinalizeCurrentScan(db *bbolt.DB, scopeID, scanID string, completion ScanCompletion) ([]ServiceChange, error) {
	if scopeID == "" {
		return nil, ErrInvalidStateScopeID
	}
	if scanID == "" {
		return nil, ErrInvalidStateScanID
	}
	if completion.Successful() {
		return PromoteCurrentScan(db, scopeID, scanID, completion)
	}

	incompleteErr := fmt.Errorf("%w: status %q", ErrScanIncomplete, completion.Status)
	discardErr := discardCurrentScan(db, scopeID, scanID)
	return nil, errors.Join(incompleteErr, completion.Err, discardErr)
}

func discardCurrentScan(db *bbolt.DB, scopeID, scanID string) error {
	return db.Update(func(tx *bbolt.Tx) error {
		if err := validateStateSchema(tx); err != nil {
			return err
		}
		scopes := tx.Bucket([]byte(stateScopeBucket))
		if scopes == nil {
			return nil
		}
		scope := scopes.Bucket([]byte(scopeID))
		if scope == nil {
			return nil
		}
		scans := scope.Bucket([]byte(stateScanBucket))
		if scans == nil || scans.Bucket([]byte(scanID)) == nil {
			return nil
		}
		return scans.DeleteBucket([]byte(scanID))
	})
}
