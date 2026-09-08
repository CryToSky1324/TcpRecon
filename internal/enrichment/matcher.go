package enrichment

import (
	"cmp"
	"net/netip"
	"slices"
)

type Matcher interface {
	// Match resolves an IP address to its most specific AssetContext.
	// Must never panic on invalid or unmatched input.
	Match(addr netip.Addr) AssetContext

	// MatchString wraps Match for raw string representations, validating netip.ParseAddr.
	MatchString(rawIP string) AssetContext
}

type cidrMatcher struct {
	rules []AssetRule
}

var defaultContext = AssetContext{
	Environment: "unassigned",
	Criticality: "unassigned",
	Owner:       "unassigned",
}

// NewMatcher initializes a Matcher by copying and pre-sorting the rules.
func NewMatcher(rules []AssetRule) Matcher {
	// 1. Create a shallow copy to prevent modifying the caller's original slice
	sortedRules := slices.Clone(rules)

	// 2. Sort descending by prefix length (Bits)
	// If a /32 and a /16 both match an IP, the /32 is checked and matched first.
	slices.SortFunc(sortedRules, func(a, b AssetRule) int {
		return cmp.Compare(b.Prefix.Bits(), a.Prefix.Bits())
	})

	return &cidrMatcher{
		rules: sortedRules,
	}
}

func (m *cidrMatcher) Match(addr netip.Addr) AssetContext {
	if m == nil || !addr.IsValid() {
		return defaultContext
	}
	for _, rule := range m.rules {
		if rule.Prefix.Contains(addr) {
			return AssetContext{
				Environment: rule.Environment,
				Criticality: rule.Criticality,
				Owner:       rule.Owner,
			}
		}
	}
	return defaultContext
}

func (m *cidrMatcher) MatchString(rawIP string) AssetContext {
	ip, err := netip.ParseAddr(rawIP)
	if err != nil {
		return defaultContext
	}
	return m.Match(ip)
}
