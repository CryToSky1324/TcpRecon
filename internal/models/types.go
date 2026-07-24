package models

// ScanResult structures our output for the main thread and JSON encoding
type ScanResult struct {
	Port        int      `json:"port"`
	State       string   `json:"state"`
	Banner      string   `json:"banner,omitempty"`
	OSHint      string   `json:"os_hint,omitempty"`
	CertSubject string   `json:"tls_subject,omitempty"`
	CertIssuer  string   `json:"tls_issuer,omitempty"`
	SANs        []string `json:"tls_sans,omitempty"`
}

// ScanReport encapsulates the entire execution telemetry for SIEM ingestion
type ScanReport struct {
	Target      string       `json:"target"`
	TargetIP    string       `json:"target_ip"`
	DurationSec float64      `json:"duration_seconds"`
	TotalOpen   int          `json:"total_open"`
	Ports       []ScanResult `json:"ports"`
}

// ScanJob defines a single atomic scanning task across the dispatcher
type ScanJob struct {
	TargetIP   string
	TargetName string
	Port       int
}

// TargetMap links the raw input name/CIDR to its resolved IPv4 slices
type TargetMap map[string][]string
