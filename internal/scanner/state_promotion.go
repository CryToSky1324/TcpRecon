package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"go.etcd.io/bbolt"
)

var ErrPromotionRequiresSuccessfulScan = errors.New("promotion requires successful scan")

// PromoteCurrentScan atomically reconciles and replaces the committed
// baseline for one successful scan. It is the sole production owner of
// committed-baseline creation and mutation.
func PromoteCurrentScan(db *bbolt.DB, scopeID, scanID string, completion ScanCompletion) ([]ServiceChange, error) {
	if scopeID == "" {
		return nil, ErrInvalidStateScopeID
	}
	if scanID == "" {
		return nil, ErrInvalidStateScanID
	}
	if !completion.Successful() {
		return nil, fmt.Errorf(
			"%w: status %q: %v",
			ErrPromotionRequiresSuccessfulScan,
			completion.Status,
			completion.Err,
		)
	}

	var promotedChanges []ServiceChange
	err := db.Update(func(tx *bbolt.Tx) error {
		baseline, current, err := loadReconciliationState(tx, scopeID, scanID)
		if err != nil {
			return err
		}
		changes := reconcileServiceRecords(baseline, current)

		nextBaseline := make(map[string]ServiceRecord, len(current)+len(baseline))
		for serviceKey, record := range current {
			nextBaseline[serviceKey] = record
		}
		for serviceKey, record := range baseline {
			if _, observed := current[serviceKey]; observed {
				continue
			}
			record.Status = ServiceStatusClosed
			nextBaseline[serviceKey] = record
		}

		scopes := tx.Bucket([]byte(stateScopeBucket))
		scope := scopes.Bucket([]byte(scopeID))
		if scope.Bucket([]byte(stateBaselineBucket)) != nil {
			if err := scope.DeleteBucket([]byte(stateBaselineBucket)); err != nil {
				return err
			}
		}
		baselineBucket, err := scope.CreateBucket([]byte(stateBaselineBucket))
		if err != nil {
			return err
		}

		serviceKeys := make([]string, 0, len(nextBaseline))
		for serviceKey := range nextBaseline {
			serviceKeys = append(serviceKeys, serviceKey)
		}
		sort.Strings(serviceKeys)
		for _, serviceKey := range serviceKeys {
			payload, err := json.Marshal(nextBaseline[serviceKey])
			if err != nil {
				return err
			}
			if err := baselineBucket.Put([]byte(serviceKey), payload); err != nil {
				return err
			}
		}

		scans := scope.Bucket([]byte(stateScanBucket))
		if err := scans.DeleteBucket([]byte(scanID)); err != nil {
			return err
		}
		promotedChanges = changes
		return nil
	})
	if err != nil {
		return nil, err
	}
	return promotedChanges, nil
}
