package enrichment

import (
	"net/netip"
	"testing"
)

type configTestCase struct {
	name        string
	inputJSON   string
	wantRules   []AssetRule
	wantErr     bool
}

func getConfigTestCases() []configTestCase {
	return []configTestCase{
		{
			name: "CFG-T01: Valid full inventory",
			inputJSON: `[
				{
					"cidr": "10.10.0.0/16",
					"environment": "staging",
					"criticality": "tier-2",
					"owner": "platform-infra"
				}
			]`,
			wantRules: []AssetRule{
				{
					Prefix:      netip.MustParsePrefix("10.10.0.0/16"),
					Environment: "staging",
					Criticality: "tier-2",
					Owner:       "platform-infra",
				},
			},
			wantErr: false,
		},
		{
			name: "CFG-T02: Empty fields normalize to unassigned",
			inputJSON: `[
				{
					"cidr": "172.16.0.0/12",
					"environment": "",
					"criticality": "",
					"owner": ""
				}
			]`,
			wantRules: []AssetRule{
				{
					Prefix:      netip.MustParsePrefix("172.16.0.0/12"),
					Environment: "unassigned",
					Criticality: "unassigned",
					Owner:       "unassigned",
				},
			},
			wantErr: false,
		},
		{
			name:      "CFG-T03: Invalid CIDR prefix rejects payload",
			inputJSON: `[{"cidr": "10.0.0.1"}]`, // Missing prefix length
			wantRules: nil,
			wantErr:   true,
		},
		{
			name:      "CFG-T04: Empty input yields empty rules without error",
			inputJSON: ``,
			wantRules: []AssetRule{},
			wantErr:   false,
		},
		{
			name:      "CFG-T05: Malformed JSON syntax returns error",
			inputJSON: `[{"cidr": "10.0.0.0/8"`,
			wantRules: nil,
			wantErr:   true,
		},
	}
}

func TestLoadRulesFromJSON(t *testing.T) {
		for _, tc := range getConfigTestCases() {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				gotRules, err := LoadRulesFromJSON([]byte(tc.inputJSON))
				if tc.wantErr {
						if err == nil {
							t.Fatalf("expected error, got nil")
						}
						return
				}
				if !tc.wantErr {
						if err != nil {
							t.Fatalf("unexpected error, %v", err)
						}
						if len(gotRules) != len(tc.wantRules) {
								t.Fatalf("len(gotRules) = %d, want %d", len(gotRules), len(tc.wantRules))
						}

						for i := range gotRules {
								if gotRules[i].Prefix != tc.wantRules[i].Prefix {
										t.Errorf("rule[%d].Prefix = %v, want %v", i, gotRules[i].Prefix, tc.wantRules[i].Prefix)
								}
								if gotRules[i].Environment != tc.wantRules[i].Environment {
										t.Errorf("rule[%d].Environment = %q, want %q", i, gotRules[i].Environment, tc.wantRules[i].Environment)
								}
								if gotRules[i].Criticality != tc.wantRules[i].Criticality {
										t.Errorf("rule[%d].Criticality = %q, want %q", i, gotRules[i].Criticality, tc.wantRules[i].Criticality)
								}
								if gotRules[i].Owner != tc.wantRules[i].Owner {
										t.Errorf("rule[%d].Owner = %q, want %q", i, gotRules[i].Owner, tc.wantRules[i].Owner)
								}				
						}
				}
			})
		}
}


