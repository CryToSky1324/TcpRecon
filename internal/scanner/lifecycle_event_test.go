package scanner

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/CryToSky1324/TcpRecon/internal/enrichment"
	"github.com/CryToSky1324/TcpRecon/internal/models"
)

// lifecycleTestCase defines the input conditions and the strict NDJSON expectations.
type lifecycleTestCase struct {
	name string

	// Prior committed baseline setup
	priorScopeID string
	priorState   *models.ScanResult // nil if prior record exists in the baseline

	// Incoming scan execution
	currentScopeID string
	currentObs     *models.ScanResult // nil if absent from current scan
	scanSuccessful bool

	//Expected Contract Assertions
	wantEmitted   bool   //true if an NDJSON line must reach stdout
	wantEventType string // e.g ., "service.opened", "service.closed" or ""
	wantScopeID   string
	wantPrevState string // "closed" or "open"
	wantCurrState string // "closed" or "open"
}

func TestLifecycleEvents(t *testing.T) {
	for _, tc := range getLifecycleTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			event, err := mapDeltaToLifecycleEvent(
				tc.currentScopeID,
				"test-scan-id",
				tc.priorState,
				tc.currentObs,
				tc.scanSuccessful,
				nil,
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.wantEmitted {
				if event != nil {
					t.Fatalf("expected no event emitted, got %+v", event)
				}
				return
			}
			if event == nil {
				t.Fatal("expected event to be emitted, got nil")
			}
			if event.EventType != tc.wantEventType {
				t.Errorf("event_type = %q, want %q", event.EventType, tc.wantEventType)
			}
			if event.ScopeID != tc.wantScopeID {
				t.Errorf("scope_id = %q, want %q", event.ScopeID, tc.wantScopeID)
			}
			if event.Change.PreviousState != tc.wantPrevState {
				t.Errorf("change.previous_state = %q, want %q", event.Change.PreviousState, tc.wantPrevState)
			}
			if event.Network.State != tc.wantCurrState {
				t.Errorf("network.state = %q, want %q", event.Network.State, tc.wantCurrState)
			}
		})
	}
}

func getLifecycleTestCases() []lifecycleTestCase {
	return []lifecycleTestCase{
		{
			name:           "TC-B7-01: Brand new service emits service.opened",
			priorScopeID:   "scope-prod",
			priorState:     nil,
			currentScopeID: "scope-prod",
			currentObs: &models.ScanResult{
				TargetIP:   "192.168.1.50",
				TargetName: "server-01",
				Port:       80,
				Protocol:   "tcp",
				State:      "open",
				Banner:     "nginx/1.24",
			},
			scanSuccessful: true,
			wantEmitted:    true,
			wantEventType:  "service.opened",
			wantScopeID:    "scope-prod",
			wantPrevState:  "closed",
			wantCurrState:  "open",
		},
		{
			name:         "TC-B7-02: Modified banner on open port emits service.changed",
			priorScopeID: "scope-prod",
			priorState: &models.ScanResult{
				TargetIP:   "192.168.1.50",
				TargetName: "server-01",
				Port:       80,
				Protocol:   "tcp",
				State:      "open",
				Banner:     "nginx/1.24",
			},
			currentScopeID: "scope-prod",
			currentObs: &models.ScanResult{
				TargetIP:   "192.168.1.50",
				TargetName: "server-01",
				Port:       80,
				Protocol:   "tcp",
				State:      "open",
				Banner:     "nginx/1.26", // Mutated banner
			},
			scanSuccessful: true,
			wantEmitted:    true,
			wantEventType:  "service.changed",
			wantScopeID:    "scope-prod",
			wantPrevState:  "open",
			wantCurrState:  "open",
		},
		{
			name:         "TC-B7-03: Reopened service emits service.reopened",
			priorScopeID: "scope-prod",
			priorState: &models.ScanResult{
				TargetIP:   "192.168.1.50",
				TargetName: "server-01",
				Port:       80,
				Protocol:   "tcp",
				State:      "closed",
				Banner:     "",
			},
			currentScopeID: "scope-prod",
			currentObs: &models.ScanResult{
				TargetIP:   "192.168.1.50",
				TargetName: "server-01",
				Port:       80,
				Protocol:   "tcp",
				State:      "open",
				Banner:     "nginx/1.24",
			},
			scanSuccessful: true,
			wantEmitted:    true,
			wantEventType:  "service.reopened",
			wantScopeID:    "scope-prod",
			wantPrevState:  "closed",
			wantCurrState:  "open",
		},
		{
			name:         "TC-B7-04:	Closed service emits service.closed",
			priorScopeID: "scope-prod",
			priorState: &models.ScanResult{
				TargetIP:   "192.168.1.50",
				TargetName: "server-01",
				Port:       80,
				Protocol:   "tcp",
				State:      "open",
				Banner:     "nginx/1.24",
			},
			currentScopeID: "scope-prod",
			currentObs:     nil,
			scanSuccessful: true,
			wantEmitted:    true,
			wantEventType:  "service.closed",
			wantScopeID:    "scope-prod",
			wantPrevState:  "open",
			wantCurrState:  "closed",
		},
		{
			name:         "TC-B7-05: Identical service does not emits",
			priorScopeID: "scope-prod",
			priorState: &models.ScanResult{
				TargetIP:   "192.168.1.50",
				TargetName: "server-01",
				Port:       80,
				Protocol:   "tcp",
				State:      "open",
				Banner:     "nginx/1.24",
			},
			currentScopeID: "scope-prod",
			currentObs: &models.ScanResult{
				TargetIP:   "192.168.1.50",
				TargetName: "server-01",
				Port:       80,
				Protocol:   "tcp",
				State:      "open",
				Banner:     "nginx/1.24",
			},
			scanSuccessful: true,
			wantEmitted:    false,
			wantEventType:  "",
			wantScopeID:    "scope-prod",
			wantPrevState:  "open",
			wantCurrState:  "open",
		},
		{
			name:         "TC-B7-06: Incomplete scan must suppress service.closed",
			priorScopeID: "scope-prod",
			priorState: &models.ScanResult{
				TargetIP:   "192.168.1.50",
				TargetName: "server-01",
				Port:       80,
				Protocol:   "tcp",
				State:      "open",
				Banner:     "nginx/1.24",
			},
			currentObs: &models.ScanResult{
				TargetIP:   "192.168.1.50",
				TargetName: "server-01",
				Port:       80,
				Protocol:   "tcp",
				State:      "closed", // Target dropped or missing
			},
			scanSuccessful: false, // Authoritative completion check failed
			wantEmitted:    false, // Must remain completely silent
			wantEventType:  "",
			wantScopeID:    "scope-prod",
			wantPrevState:  "",
			wantCurrState:  "",
		},
		{
			name:           "TC-B7-07: Port active in Scope A emits service.opened when scanned in Scope B",
			priorScopeID:   "scope-alpha",
			priorState:     nil,
			currentScopeID: "scope-bravo",
			currentObs: &models.ScanResult{
				TargetIP:   "192.168.1.50",
				TargetName: "server-01",
				Port:       80,
				Protocol:   "tcp",
				State:      "open",
				Banner:     "nginx/1.24",
			},
			scanSuccessful: true,
			wantEmitted:    true,
			wantEventType:  "service.opened",
			wantScopeID:    "scope-bravo",
			wantPrevState:  "closed",
			wantCurrState:  "open",
		},
		{
			name:         "TC-B7-08: Same port under UDP does not match TCP baseline and emits service.opened",
			priorScopeID: "scope-prod",
			priorState: &models.ScanResult{
				TargetIP:   "192.168.1.50",
				TargetName: "server-01",
				Port:       53,
				Protocol:   "tcp",
				State:      "open",
			},
			currentScopeID: "scope-prod",
			currentObs: &models.ScanResult{
				TargetIP:   "192.168.1.50",
				TargetName: "server-01",
				Port:       53,
				Protocol:   "udp",
				State:      "open",
			},
			scanSuccessful: true,
			wantEmitted:    true,
			wantEventType:  "service.opened",
			wantScopeID:    "scope-prod",
			wantPrevState:  "closed",
			wantCurrState:  "open",
		},
	}
}

func TestLifecycleEvents_EnrichedAssetContext(t *testing.T) {
	rules := []enrichment.AssetRule{
		{
			Prefix:      netip.MustParsePrefix("10.10.5.0/24"),
			Environment: "production",
			Criticality: "tier-0",
			Owner:       "secops",
		},
	}
	matcher := enrichment.NewMatcher(rules)

	t.Run("Enriches matched IP with configured context", func(t *testing.T) {
		curr := &models.ScanResult{
			TargetIP:   "10.10.5.15",
			TargetName: "vault.internal",
			Port:       443,
			Protocol:   "tcp",
			State:      "open",
		}

		event, err := mapDeltaToLifecycleEvent("scope-c2", "scan-1", nil, curr, true, matcher)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if event == nil {
			t.Fatal("expected emitted event, got nil")
		}

		if event.Asset.Environment != "production" {
			t.Errorf("Environment = %q, want %q", event.Asset.Environment, "production")
		}
		if event.Asset.Criticality != "tier-0" {
			t.Errorf("Criticality = %q, want %q", event.Asset.Criticality, "tier-0")
		}
		if event.Asset.Owner != "secops" {
			t.Errorf("Owner = %q, want %q", event.Asset.Owner, "secops")
		}

		rawJSON, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		assertNoNestedArrays(t, rawJSON)
	})

	t.Run("Unmatched IP defaults safely to unassigned context", func(t *testing.T) {
		curr := &models.ScanResult{
			TargetIP:   "192.168.1.50",
			TargetName: "dev-box.local",
			Port:       8080,
			Protocol:   "tcp",
			State:      "open",
		}

		event, err := mapDeltaToLifecycleEvent("scope-c2", "scan-2", nil, curr, true, matcher)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if event == nil {
			t.Fatal("expected emitted event, got nil")
		}

		if event.Asset.Environment != "unassigned" ||
			event.Asset.Criticality != "unassigned" ||
			event.Asset.Owner != "unassigned" {
			t.Errorf("expected all fields 'unassigned', got %+v", event.Asset)
		}

		rawJSON, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		assertNoNestedArrays(t, rawJSON)
	})
}

// assertNoNestedArrays recursively traverses unmarshaled JSON to guarantee zero []any slices exist.
// This enforces the invariant protecting wazuh-analysisd from decoding truncation.
func assertNoNestedArrays(t *testing.T, rawJSON []byte) {
	t.Helper()

	var root any
	if err := json.Unmarshal(rawJSON, &root); err != nil {
		t.Fatalf("assertNoNestedArrays: failed to unmarshal event JSON: %v", err)
	}

	var walk func(node any, path string)
	walk = func(node any, path string) {
		switch val := node.(type) {
		case []any:
			t.Fatalf("wazuh-analysisd invariant violation: nested JSON array detected at %q", path)
		case map[string]any:
			for k, v := range val {
				walk(v, path+"."+k)
			}
		}
	}

	walk(root, "$")
}
