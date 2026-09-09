package risk

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/CryToSky1324/TcpRecon/internal/models"
)

func TestEvaluateRisk(t *testing.T) {
	tests := []struct {
		name          string
		eventType     string
		result        *models.ScanResult
		criticality   string
		wantScore     int
		wantSeverity  string
		wantReasons   []string
		wantEmptyZero bool
	}{
		{
			name:      "C3-T01: Remediated service (service.closed) resets score to 0",
			eventType: "service.closed",
			result: &models.ScanResult{
				Port:         3306,
				Protocol:     "tcp",
				TLSVersion:   "TLS 1.0",
				CertVerified: false,
			},
			criticality:   "tier-0",
			wantScore:     0,
			wantSeverity:  "informational",
			wantEmptyZero: true,
		},
		{
			name:      "C3-T02: Standard hardened TLS service on low asset has 0 score",
			eventType: "service.opened",
			result: &models.ScanResult{
				Port:         443,
				Protocol:     "tcp",
				TLSVersion:   "TLS 1.3",
				CertVerified: true,
			},
			criticality:   "unassigned",
			wantScore:     0,
			wantSeverity:  "informational",
			wantEmptyZero: true,
		},
		{
			name:      "C3-T03: Cleartext HTTP protocol adds 15 points (low)",
			eventType: "service.opened",
			result: &models.ScanResult{
				Port:     80,
				Protocol: "tcp",
			},
			criticality:  "unassigned",
			wantScore:    15,
			wantSeverity: "low",
			wantReasons:  []string{"cleartext_protocol"},
		},
		{
			name:      "C3-T04: Exposed database port adds 40 points (medium)",
			eventType: "service.opened",
			result: &models.ScanResult{
				Port:     3306,
				Protocol: "tcp",
			},
			criticality:  "unassigned",
			wantScore:    40,
			wantSeverity: "medium",
			wantReasons:  []string{"exposed_datastore"},
		},
		{
			name:      "C3-T05: Deprecated TLS (30) + Untrusted Cert (20) evaluates to 50 points (medium)",
			eventType: "service.opened",
			result: &models.ScanResult{
				Port:         8443,
				Protocol:     "tcp",
				TLSVersion:   "TLS 1.0",
				CertVerified: false,
			},
			criticality:  "unassigned",
			wantScore:    50,
			wantSeverity: "medium",
			wantReasons:  []string{"deprecated_tls", "untrusted_cert"},
		},
		{
			name:      "C3-T06: Exposed RDP (35) on tier-0 asset (20) evaluates to 55 points (medium)",
			eventType: "service.opened",
			result: &models.ScanResult{
				Port:     3389,
				Protocol: "tcp",
			},
			criticality:  "tier-0",
			wantScore:    55,
			wantSeverity: "medium",
			wantReasons:  []string{"exposed_remote_admin", "critical_asset_tier0"},
		},
		{
			name:      "C3-T07: Compound exposure clamps to max 100 points (critical)",
			eventType: "service.opened",
			result: &models.ScanResult{
				Port:         3306, // +40 datastore
				Protocol:     "tcp",
				TLSVersion:   "TLS 1.1", // +30 deprecated tls
				CertVerified: false,     // +20 untrusted cert
			},
			criticality:  "tier-0", // +20 tier0 (total 110 -> clamp 100)
			wantScore:    100,
			wantSeverity: "critical",
			wantReasons: []string{
				"exposed_datastore",
				"deprecated_tls",
				"untrusted_cert",
				"critical_asset_tier0",
			},
		},
		{
			name:      "C3-T08: Cleartext Telnet triggers both remote_admin and cleartext_protocol",
			eventType: "service.opened",
			result: &models.ScanResult{
				Port:     23,
				Protocol: "tcp",
			},
			criticality:  "tier-1", // +10
			wantScore:    60,       // 35 (admin) + 15 (cleartext) + 10 (tier-1)
			wantSeverity: "high",
			wantReasons: []string{
				"exposed_remote_admin",
				"cleartext_protocol",
				"high_asset_tier1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := EvaluateRisk(tt.eventType, tt.result, tt.criticality)

			if meta.PolicyVersion != PolicyVersion {
				t.Errorf("PolicyVersion = %q, want %q", meta.PolicyVersion, PolicyVersion)
			}
			if meta.Score != tt.wantScore {
				t.Errorf("Score = %d, want %d", meta.Score, tt.wantScore)
			}
			if meta.Severity != tt.wantSeverity {
				t.Errorf("Severity = %q, want %q", meta.Severity, tt.wantSeverity)
			}

			if tt.wantEmptyZero {
				if meta.Reasons != "" {
					t.Errorf("Reasons = %q, want empty", meta.Reasons)
				}
			} else {
				for _, reason := range tt.wantReasons {
					if !strings.Contains(meta.Reasons, reason) {
						t.Errorf("Reasons %q missing expected tag %q", meta.Reasons, reason)
					}
				}
			}

			// Invariant: Verify zero nested array serialization
			payload, err := json.Marshal(meta)
			if err != nil {
				t.Fatalf("failed to marshal RiskMeta: %v", err)
			}
			var unmarshaled map[string]any
			if err := json.Unmarshal(payload, &unmarshaled); err != nil {
				t.Fatalf("failed to unmarshal JSON: %v", err)
			}
			if _, ok := unmarshaled["reasons"].(string); !ok {
				t.Fatalf("reasons must serialize as string, got %T", unmarshaled["reasons"])
			}
		})
	}
}
