package enrichment

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"

	"github.com/CryToSky1324/TcpRecon/internal/models"
)

type matcherTestCase struct {
	name  string
	rawIP string
	addr  netip.Addr
	rules []AssetRule
	want  AssetContext
}

// unfulfilledMatcher is an unfulfilled stub implementing Matcher.
// Per constraint 4, matcher compilation and lookup logic are left unimplemented
// to maintain RED state.
type unfulfilledMatcher struct{}

func (m *unfulfilledMatcher) Match(addr netip.Addr) AssetContext {
	return AssetContext{}
}

func (m *unfulfilledMatcher) MatchString(rawIP string) AssetContext {
	return AssetContext{}
}

func newMatcher(rules []AssetRule) Matcher {
	return &unfulfilledMatcher{}
}

func getMatcherTestCases() []matcherTestCase {
	// Reusable compiled routing rules
	broadCorpRule := AssetRule{
		Prefix:      netip.MustParsePrefix("10.10.0.0/16"),
		Environment: "staging",
		Criticality: "tier-2",
		Owner:       "platform-infra",
	}

	exactHostRule := AssetRule{
		Prefix:      netip.MustParsePrefix("10.10.5.15/32"),
		Environment: "production",
		Criticality: "tier-0",
		Owner:       "pki-team",
	}

	overlappingSubnetRule := AssetRule{
		Prefix:      netip.MustParsePrefix("10.10.5.0/24"),
		Environment: "dmz",
		Criticality: "tier-1",
		Owner:       "secops",
	}

	ipv6DualStack := AssetRule{
		Prefix:      netip.MustParsePrefix("2001:db8::/32"),
		Environment: "production-v6",
		Criticality: "tier-1",
		Owner:       "netops",
	}

	return []matcherTestCase{
		{
			name:  "C2-T01: Exact host match (/32) takes priority over broad CIDR",
			rawIP: "10.10.5.15",
			addr:  netip.MustParseAddr("10.10.5.15"),
			rules: []AssetRule{broadCorpRule, exactHostRule},
			want: AssetContext{
				Environment: "production",
				Criticality: "tier-0",
				Owner:       "pki-team",
			},
		},
		{
			name:  "C2-T02: Broad subnet match when no host rule exists",
			rawIP: "10.10.20.4",
			addr:  netip.MustParseAddr("10.10.20.4"),
			rules: []AssetRule{broadCorpRule, exactHostRule},
			want: AssetContext{
				Environment: "staging",
				Criticality: "tier-2",
				Owner:       "platform-infra",
			},
		},
		{
			name:  "C2-T03: Overlapping CIDR selects most specific mask (/24 over /16)",
			rawIP: "10.10.5.99",
			addr:  netip.MustParseAddr("10.10.5.99"),
			rules: []AssetRule{broadCorpRule, overlappingSubnetRule},
			want: AssetContext{
				Environment: "dmz",
				Criticality: "tier-1",
				Owner:       "secops",
			},
		},
		{
			name:  "C2-T04: Unmatched IP defaults cleanly to unassigned context",
			rawIP: "192.168.1.1",
			addr:  netip.MustParseAddr("192.168.1.1"),
			rules: []AssetRule{broadCorpRule, exactHostRule},
			want: AssetContext{
				Environment: "unassigned",
				Criticality: "unassigned",
				Owner:       "unassigned",
			},
		},
		{
			name:  "C2-T05: Malformed string input defaults to unassigned context",
			rawIP: "invalid-ip",
			addr:  netip.Addr{}, // Zero value: represents an unparsed or invalid IP address
			rules: []AssetRule{broadCorpRule, exactHostRule},
			want: AssetContext{
				Environment: "unassigned",
				Criticality: "unassigned",
				Owner:       "unassigned",
			},
		},
		{
			name:  "C2-T06: Empty ruleset defaults to unassigned context",
			rawIP: "10.10.5.15",
			addr:  netip.MustParseAddr("10.10.5.15"),
			rules: []AssetRule{},
			want: AssetContext{
				Environment: "unassigned",
				Criticality: "unassigned",
				Owner:       "unassigned",
			},
		},
		{
			name:  "C2-T07: IPv6 Dual-Stack match",
			rawIP: "2001:db8::1",
			addr:  netip.MustParseAddr("2001:db8::1"),
			rules: []AssetRule{ipv6DualStack},
			want: AssetContext{
				Environment: "production-v6",
				Criticality: "tier-1",
				Owner:       "netops",
			},
		},
	}
}

// TestMatcher iterates over getMatcherTestCases() and asserts expected AssetContext resolution.
func TestMatcher(t *testing.T) {
	for _, tc := range getMatcherTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			matcher := NewMatcher(tc.rules)

			got := matcher.Match(tc.addr)
			if got != tc.want {
				t.Errorf("Match(%v) = %+v, want %+v", tc.addr, got, tc.want)
			}

			if tc.rawIP != "" {
				gotStr := matcher.MatchString(tc.rawIP)
				if gotStr != tc.want {
					t.Errorf("MatchString(%q) = %+v, want %+v", tc.rawIP, gotStr, tc.want)
				}
			}
		})
	}
}

// TestMatcher_Allocations evaluates C2-T08 zero-allocation invariant for Match calls.
func TestMatcher_Allocations(t *testing.T) {
	matcher := newMatcher([]AssetRule{
		{
			Prefix:      netip.MustParsePrefix("10.10.0.0/16"),
			Environment: "staging",
			Criticality: "tier-2",
			Owner:       "platform-infra",
		},
		{
			Prefix:      netip.MustParsePrefix("10.10.5.15/32"),
			Environment: "production",
			Criticality: "tier-0",
			Owner:       "pki-team",
		},
	})
	testAddr := netip.MustParseAddr("10.10.5.15")

	allocs := testing.AllocsPerRun(1000, func() {
		matcher.Match(testAddr)
	})
	if allocs > 0 {
		t.Fatalf("C2-T08: zero-allocation invariant violated: got %f allocations, want 0", allocs)
	}
}

// TestMatcher_NDJSONFlatness evaluates C2-T09 flatness requirement for Wazuh analysisd ingestion.
func TestMatcher_NDJSONFlatness(t *testing.T) {
	event := models.LifecycleEvent{
		SchemaVersion: "1.0",
		EventID:       "evt-c2-test-01",
		ScanID:        "scan-c2-test-01",
		ScopeID:       "scope-c2-test-01",
		Timestamp:     "2026-09-08T08:00:00Z",
		EventType:     "service.opened",
		Scanner: models.ScannerMeta{
			Name:    "tcprecon",
			Version: "1.0.0",
		},
		Asset: models.AssetIdentity{
			IP:          "10.10.5.15",
			Hostname:    "vault-prod-01",
			Environment: "production",
			Criticality: "tier-0",
			Owner:       "pki-team",
		},
		Network: models.NetworkObservation{
			Protocol: "tcp",
			Port:     443,
			State:    "open",
		},
		Change: models.StateChange{
			Type:          "opened",
			PreviousState: "closed",
		},
	}

	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal LifecycleEvent: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Fatalf("failed to parse JSON into map[string]any: %v", err)
	}

	var arrayInstances []string
	var walkPayload func(path string, node any)
	walkPayload = func(path string, node any) {
		switch v := node.(type) {
		case []any:
			arrayInstances = append(arrayInstances, path)
			for i, item := range v {
				walkPayload(fmt.Sprintf("%s[%d]", path, i), item)
			}
		case map[string]any:
			for k, item := range v {
				itemPath := k
				if path != "" {
					itemPath = path + "." + k
				}
				walkPayload(itemPath, item)
			}
		}
	}

	walkPayload("", parsed)

	if len(arrayInstances) > 0 {
		t.Fatalf("C2-T09: NDJSON flatness invariant violated, found %d JSON array instance(s): %v", len(arrayInstances), arrayInstances)
	}
}
