package enrichment

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// AssetRule defines an in-memory, compiled routing rule for enrichment
type AssetRule struct {
	Prefix      netip.Prefix //Zero-alloc CIDR container
	Environment string
	Criticality string
	Owner       string
}

// AssetContext represents the resolved scalar context.
type AssetContext struct {
	Environment string
	Criticality string
	Owner       string
}

// AssetRuleConfig defines the raw deserialization target for inventory files (JSON/YAML).
type AssetRuleConfig struct {
	CIDR        string `json:"cidr" yaml:"cidr"`
	Environment string `json:"environment" yaml:"environment"`
	Criticality string `json:"criticality" yaml:"criticality"`
	Owner       string `json:"owner" yaml:"owner"`
}

// LoadRulesFromJSON loads and compiles static asset rules from a JSON byte stream or file.
func LoadRulesFromJSON(data []byte) ([]AssetRule, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return []AssetRule{}, nil
	}
	var rawRules []AssetRuleConfig
	if err := json.Unmarshal(data, &rawRules); err != nil {
		return nil, fmt.Errorf("failed to parse asset rules json: %w", err)
	}
	if len(rawRules) == 0 {
		return []AssetRule{}, nil
	}

	rules := make([]AssetRule, 0, len(rawRules))
	for _, cfg := range rawRules {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(cfg.CIDR))
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR prefix %q: %w", cfg.CIDR, err)
		}
		normalize := func(val string) string {
			v := strings.TrimSpace(val)
			if v == "" {
				return "unassigned"
			}
			return v
		}
		rules = append(rules, AssetRule{
			Prefix:      prefix,
			Environment: normalize(cfg.Environment),
			Criticality: normalize(cfg.Criticality),
			Owner:       normalize(cfg.Owner),
		})
	}
	return rules, nil
}

// LoadRulesFromFile reads and compiles asset rules from the given path.
// Returns an empty slice and nil error if path is empty.
func LoadRulesFromFile(path string) ([]AssetRule, error) {
	cleanpath := strings.TrimSpace(path)
	if cleanpath == "" {
		return []AssetRule{}, nil
	}
	data, err := os.ReadFile(cleanpath)
	if err != nil {
		return nil, fmt.Errorf("failed to read asset rules file: %w", err)
	}
	return LoadRulesFromJSON(data)
}
