package scanner

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	"go.etcd.io/bbolt"
)

type ServiceStatus string

const (
	ServiceStatusOpen   ServiceStatus = "open"
	ServiceStatusClosed ServiceStatus = "closed"
	sha256HexLength                   = 64
)

type ServiceObservation struct {
	Banner      string
	OSHint      string
	CertSubject string
	CertIssuer  string
	SANs        []string
}

// ServiceRecord is the schema-v1 comparison record. Banner, OSHint,
// CertSubject, and CertIssuer are compared byte-for-byte. SAN order and
// duplicates are the only comparison-field normalization performed here.
type ServiceRecord struct {
	IP          string        `json:"ip"`
	Port        int           `json:"port"`
	Protocol    string        `json:"protocol"`
	Status      ServiceStatus `json:"status"`
	Banner      string        `json:"banner"`
	OSHint      string        `json:"os_hint"`
	CertSubject string        `json:"tls_subject"`
	CertIssuer  string        `json:"tls_issuer"`
	SANs        []string      `json:"tls_sans"`
}

var (
	ErrInvalidPersistentServiceRecord = errors.New("invalid persistent service record")
	ErrServiceIdentityScopeMismatch   = errors.New("service identity scope mismatch")
)

func canonicalObservationStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}

func serviceRecordFromObservation(identity ServiceIdentity, observation ServiceObservation) (ServiceRecord, string, error) {
	serviceKey, err := identity.Key()
	if err != nil {
		return ServiceRecord{}, "", err
	}
	canonicalIP, err := normalizeServiceIP(identity.IP)
	if err != nil {
		return ServiceRecord{}, "", err
	}
	return ServiceRecord{
		IP:          canonicalIP,
		Port:        identity.Port,
		Protocol:    identity.Protocol,
		Status:      ServiceStatusOpen,
		Banner:      observation.Banner,
		OSHint:      observation.OSHint,
		CertSubject: observation.CertSubject,
		CertIssuer:  observation.CertIssuer,
		SANs:        canonicalObservationStrings(observation.SANs),
	}, serviceKey, nil
}

func SaveCurrentService(db *bbolt.DB, scopeID, scanID string, identity ServiceIdentity, observation ServiceObservation) error {
	if scopeID == "" {
		return ErrInvalidStateScopeID
	}
	if scanID == "" {
		return ErrInvalidStateScanID
	}
	if identity.ScopeID != scopeID {
		return fmt.Errorf(
			"%w: identity scope %q does not match destination scope %q",
			ErrServiceIdentityScopeMismatch,
			identity.ScopeID,
			scopeID,
		)
	}
	record, serviceKey, err := serviceRecordFromObservation(identity, observation)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return err
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
		scan, err := scans.CreateBucketIfNotExists([]byte(scanID))
		if err != nil {
			return err
		}
		return scan.Put([]byte(serviceKey), payload)
	})
}

func validServiceKeyV1(key []byte) bool {
	if len(key) != sha256HexLength {
		return false
	}
	decoded, err := hex.DecodeString(string(key))
	return err == nil && hex.EncodeToString(decoded) == string(key)
}

func decodeServiceRecord(value []byte) (ServiceRecord, error) {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	var record ServiceRecord
	if err := decoder.Decode(&record); err != nil {
		return ServiceRecord{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return ServiceRecord{}, errors.New("multiple JSON values")
		}
		return ServiceRecord{}, err
	}
	return record, nil
}

func validatePersistentServiceRecord(scopeID, serviceKey string, record ServiceRecord, current bool) error {
	if record.Status != ServiceStatusOpen && record.Status != ServiceStatusClosed {
		return fmt.Errorf("unsupported status %q", record.Status)
	}
	if current && record.Status != ServiceStatusOpen {
		return fmt.Errorf("current observation status must be %q", ServiceStatusOpen)
	}
	canonicalIP, err := normalizeServiceIP(record.IP)
	if err != nil || canonicalIP != record.IP {
		return fmt.Errorf("non-canonical IP %q", record.IP)
	}
	identity := ServiceIdentity{
		ScopeID:  scopeID,
		IP:       record.IP,
		Port:     record.Port,
		Protocol: record.Protocol,
	}
	expectedKey, err := identity.Key()
	if err != nil {
		return err
	}
	if expectedKey != serviceKey {
		return fmt.Errorf("service key does not match stored identity")
	}
	canonicalSANs := canonicalObservationStrings(record.SANs)
	if record.SANs == nil || !slices.Equal(record.SANs, canonicalSANs) {
		return fmt.Errorf("tls_sans are not canonical")
	}
	return nil
}

func loadServiceRecords(bucket *bbolt.Bucket, scopeID string, current bool) (map[string]ServiceRecord, error) {
	records := make(map[string]ServiceRecord)
	err := bucket.ForEach(func(key, value []byte) error {
		if value == nil || !validServiceKeyV1(key) {
			return fmt.Errorf("%w: invalid service key %q", ErrInvalidPersistentServiceRecord, key)
		}
		record, err := decodeServiceRecord(value)
		if err != nil {
			return fmt.Errorf("%w: service %q: %v", ErrInvalidPersistentServiceRecord, key, err)
		}
		if err := validatePersistentServiceRecord(scopeID, string(key), record, current); err != nil {
			return fmt.Errorf("%w: service %q: %v", ErrInvalidPersistentServiceRecord, key, err)
		}
		records[string(key)] = record
		return nil
	})
	if err != nil {
		return nil, err
	}
	return records, nil
}

func LoadCommittedBaseline(db *bbolt.DB, scopeID string) (map[string]ServiceRecord, bool, error) {
	if scopeID == "" {
		return nil, false, ErrInvalidStateScopeID
	}
	var records map[string]ServiceRecord
	var exists bool
	err := db.View(func(tx *bbolt.Tx) error {
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
		baseline := scope.Bucket([]byte(stateBaselineBucket))
		if baseline == nil {
			return nil
		}
		exists = true
		var err error
		records, err = loadServiceRecords(baseline, scopeID, false)
		return err
	})
	if records == nil && err == nil {
		records = make(map[string]ServiceRecord)
	}
	return records, exists, err
}

func LoadCurrentScan(db *bbolt.DB, scopeID, scanID string) (map[string]ServiceRecord, bool, error) {
	if scopeID == "" {
		return nil, false, ErrInvalidStateScopeID
	}
	if scanID == "" {
		return nil, false, ErrInvalidStateScanID
	}
	var records map[string]ServiceRecord
	var exists bool
	err := db.View(func(tx *bbolt.Tx) error {
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
		if scans == nil {
			return nil
		}
		scan := scans.Bucket([]byte(scanID))
		if scan == nil {
			return nil
		}
		exists = true
		var err error
		records, err = loadServiceRecords(scan, scopeID, true)
		return err
	})
	if records == nil && err == nil {
		records = make(map[string]ServiceRecord)
	}
	return records, exists, err
}
