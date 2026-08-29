package scanner

import (
	"errors"
	"fmt"
	"sort"

	"go.etcd.io/bbolt"
)

type ChangeKind string

const (
	ChangeOpened   ChangeKind = "opened"
	ChangeChanged  ChangeKind = "changed"
	ChangeClosed   ChangeKind = "closed"
	ChangeReopened ChangeKind = "reopened"
)

type ServiceChange struct {
	Kind       ChangeKind
	ServiceKey string
	Previous   *ServiceRecord
	Current    *ServiceRecord
}

var (
	ErrCurrentScanNotFound                  = errors.New("current scan not found")
	ErrReconciliationRequiresSuccessfulScan = errors.New("reconciliation requires successful scan")
)

func serviceComparisonEqual(first, second ServiceRecord) bool {
	if first.Banner != second.Banner ||
		first.OSHint != second.OSHint ||
		first.CertSubject != second.CertSubject ||
		first.CertIssuer != second.CertIssuer ||
		len(first.SANs) != len(second.SANs) {
		return false
	}
	for i := range first.SANs {
		if first.SANs[i] != second.SANs[i] {
			return false
		}
	}
	return true
}

func loadReconciliationState(tx *bbolt.Tx, scopeID, scanID string) (map[string]ServiceRecord, map[string]ServiceRecord, error) {
	if err := validateStateSchema(tx); err != nil {
		return nil, nil, err
	}

	baseline := make(map[string]ServiceRecord)
	scopes := tx.Bucket([]byte(stateScopeBucket))
	if scopes == nil {
		return nil, nil, ErrCurrentScanNotFound
	}
	scope := scopes.Bucket([]byte(scopeID))
	if scope == nil {
		return nil, nil, ErrCurrentScanNotFound
	}
	if baselineBucket := scope.Bucket([]byte(stateBaselineBucket)); baselineBucket != nil {
		var err error
		baseline, err = loadServiceRecords(baselineBucket, scopeID, false)
		if err != nil {
			return nil, nil, err
		}
	}

	scans := scope.Bucket([]byte(stateScanBucket))
	if scans == nil {
		return nil, nil, ErrCurrentScanNotFound
	}
	currentBucket := scans.Bucket([]byte(scanID))
	if currentBucket == nil {
		return nil, nil, ErrCurrentScanNotFound
	}
	current, err := loadServiceRecords(currentBucket, scopeID, true)
	if err != nil {
		return nil, nil, err
	}
	return baseline, current, nil
}

// ReconcileScope compares one existing current scan with the committed
// baseline for the same scope. It is read-only and emits no lifecycle events.
func ReconcileScope(db *bbolt.DB, scopeID, scanID string, completion ScanCompletion) ([]ServiceChange, error) {
	if scopeID == "" {
		return nil, ErrInvalidStateScopeID
	}
	if scanID == "" {
		return nil, ErrInvalidStateScanID
	}
	if !completion.Successful() {
		return nil, fmt.Errorf(
			"%w: status %q: %v",
			ErrReconciliationRequiresSuccessfulScan,
			completion.Status,
			completion.Err,
		)
	}

	var baseline map[string]ServiceRecord
	var current map[string]ServiceRecord
	err := db.View(func(tx *bbolt.Tx) error {
		var err error
		baseline, current, err = loadReconciliationState(tx, scopeID, scanID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return reconcileServiceRecords(baseline, current), nil
}

func reconcileServiceRecords(baseline, current map[string]ServiceRecord) []ServiceChange {
	changes := make([]ServiceChange, 0)
	for serviceKey, currentRecord := range current {
		previousRecord, existed := baseline[serviceKey]
		currentCopy := currentRecord
		if !existed {
			changes = append(changes, ServiceChange{
				Kind: ChangeOpened, ServiceKey: serviceKey, Current: &currentCopy,
			})
			continue
		}

		previousCopy := previousRecord
		switch {
		case previousRecord.Status == ServiceStatusClosed:
			changes = append(changes, ServiceChange{
				Kind: ChangeReopened, ServiceKey: serviceKey,
				Previous: &previousCopy, Current: &currentCopy,
			})
		case !serviceComparisonEqual(previousRecord, currentRecord):
			changes = append(changes, ServiceChange{
				Kind: ChangeChanged, ServiceKey: serviceKey,
				Previous: &previousCopy, Current: &currentCopy,
			})
		}
	}

	for serviceKey, previousRecord := range baseline {
		if _, observed := current[serviceKey]; observed || previousRecord.Status == ServiceStatusClosed {
			continue
		}
		previousCopy := previousRecord
		changes = append(changes, ServiceChange{
			Kind: ChangeClosed, ServiceKey: serviceKey, Previous: &previousCopy,
		})
	}

	sort.Slice(changes, func(i, j int) bool {
		return changes[i].ServiceKey < changes[j].ServiceKey
	})
	return changes
}
