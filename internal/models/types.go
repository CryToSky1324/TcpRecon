package models

// ScanResult structures our output for the main thread and JSON encoding
type ScanResult struct {
	TargetName    string   `json:"target"`
	TargetIP      string   `json:"ip"`
	Port          int      `json:"port"`
	Protocol      string   `json:"protocol"`
	State         string   `json:"state"`
	Banner        string   `json:"banner,omitempty"`
	OSHint        string   `json:"os_hint,omitempty"`
	CertSubject   string   `json:"tls_subject,omitempty"`
	CertIssuer    string   `json:"tls_issuer,omitempty"`
	SANs          []string `json:"tls_sans,omitempty"`
	TLSVersion    string   `json:"tls_version,omitempty"`
	CipherSuite   string   `json:"cipher_suite,omitempty"`
	CertVerified  bool     `json:"cert_verified"`
	CertNotBefore string   `json:"cert_not_before,omitempty"`
	CertNotAfter  string   `json:"cert_not_after,omitempty"`
}

// tlsMetadata encapsulates Layer 6/7 cryptographic telemetry
// extracted during the non-fatal TLS probe.
type tlsMetaData struct {
	Version      string
	CipherSuite  string
	NotBefore    string
	NotAfter     string
	CertVerified bool
}

// ScanJob defines a single atomic scanning task across the dispatcher
type ScanJob struct {
	TargetIP   string
	TargetName string
	Port       int
	Protocol   string
}

type ScannerMeta struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type AssetIdentity struct {
	IP          string `json:"ip"`
	Hostname    string `json:"hostname"`
	Environment string `json:"environment"` // e.g., "production", "staging", "development", "unassigned"
	Criticality string `json:"criticality"` // e.g., "tier-0", "tier-1", "tier-2", "low", "unassigned"
	Owner       string `json:"owner"`       // e.g., "secops", "platform-infra", "unassigned"
}

type NetworkObservation struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	State    string `json:"state"`
}

type StateChange struct {
	Type          string `json:"type"`
	PreviousState string `json:"previous_state"`
}

type LifecycleEvent struct {
	SchemaVersion string `json:"schema_version"`
	EventID       string `json:"event_id"`
	ScanID        string `json:"scan_id"`
	ScopeID       string `json:"scope_id"`
	Timestamp     string `json:"timestamp"`
	EventType     string `json:"event_type"`

	Scanner ScannerMeta        `json:"scanner"`
	Asset   AssetIdentity      `json:"asset"`
	Network NetworkObservation `json:"network"`
	Change  StateChange        `json:"change"`
	Risk		RiskMeta					 `json:"risk"`
}

type RiskMeta struct {
	PolicyVersion string `json:"policy_version"`
	Score         int    `json:"score"`
	Severity      string `json:"severity"`
	Reasons       string `json:"reasons"` // Delimited scalar string to prevent array flattening failures
}
