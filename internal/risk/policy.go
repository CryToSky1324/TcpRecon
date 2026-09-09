package risk

import (
	"strings"

	"github.com/CryToSky1324/TcpRecon/internal/models"
)

const PolicyVersion = "1.0"

// EvaluateRisk computes a deterministic, bounded risk score and reason codes
// based on port exposure, cryptographic hygiene, and asset criticality.
func EvaluateRisk(eventType string, r *models.ScanResult, criticality string) models.RiskMeta {
	// Remediation gate: closed services have 0 active exposure score
	if eventType == "service.closed" || r == nil {
		return models.RiskMeta{
			PolicyVersion: PolicyVersion,
			Score:         0,
			Severity:      "informational",
			Reasons:       "",
		}
	}

	score := 0
	var reasons []string

	// 1. Port Exposure Evaluation
	switch r.Port {
	case 3306, 5432, 6379, 27017, 9200:
		score += 40
		reasons = append(reasons, "exposed_datastore")
	case 22, 3389:
		score += 35
		reasons = append(reasons, "exposed_remote_admin")
	case 23: // Telnet is both an unencrypted admin protocol and cleartext
		score += 35
		reasons = append(reasons, "exposed_remote_admin")
	}

	if r.Port == 21 || r.Port == 80 || r.Port == 23 {
		score += 15
		reasons = append(reasons, "cleartext_protocol")
	}

	// 2. Cryptographic Posture Evaluation
	tlsVer := strings.TrimSpace(r.TLSVersion)
	if tlsVer != "" {
		switch tlsVer {
		case "TLS 1.0", "TLS 1.1", "TLSv1.0", "TLSv1.1", "SSLv3":
			score += 30
			reasons = append(reasons, "deprecated_tls")
		}

		if !r.CertVerified {
			score += 20
			reasons = append(reasons, "untrusted_cert")
		}
	}

	// 3. Asset Criticality Bias
	switch strings.ToLower(strings.TrimSpace(criticality)) {
	case "tier-0":
		score += 20
		reasons = append(reasons, "critical_asset_tier0")
	case "tier-1":
		score += 10
		reasons = append(reasons, "high_asset_tier1")
	}

	// 4. Bounding and Severity Mapping
	if score > 100 {
		score = 100
	}

	var severity string
	switch {
	case score == 0:
		severity = "informational"
	case score < 30:
		severity = "low"
	case score < 60:
		severity = "medium"
	case score < 85:
		severity = "high"
	default:
		severity = "critical"
	}

	return models.RiskMeta{
		PolicyVersion: PolicyVersion,
		Score:         score,
		Severity:      severity,
		Reasons:       strings.Join(reasons, ","),
	}
}
