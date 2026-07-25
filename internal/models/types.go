package models

// ScanResult structures our output for the main thread and JSON encoding
type ScanResult struct {
	TargetName  string   `json:"target"`
	TargetIP    string   `json:"ip"`
	Port        int      `json:"port"`
	State       string   `json:"state"`
	Banner      string   `json:"banner,omitempty"`
	OSHint      string   `json:"os_hint,omitempty"`
	CertSubject string   `json:"tls_subject,omitempty"`
	CertIssuer  string   `json:"tls_issuer,omitempty"`
	SANs        []string `json:"tls_sans,omitempty"`
}

// ScanJob defines a single atomic scanning task across the dispatcher
type ScanJob struct {
	TargetIP   string
	TargetName string
	Port       int
}

// TargetMap links the raw input name/CIDR to its resolved IPv4 slices
type TargetMap map[string][]string
