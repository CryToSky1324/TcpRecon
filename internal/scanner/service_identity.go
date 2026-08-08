package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
)

const serviceIdentitySchemaVersion = 1

type ServiceIdentity struct {
	ScopeID  string
	IP       string
	Port     int
	Protocol string
}

type canonicalServiceIdentity struct {
	Version  int    `json:"version"`
	ScopeID  string `json:"scope_id"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

func normalizeServiceIP(raw string) (string, error) {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return "", err
	}
	return addr.Unmap().String(), nil
}

func validateServiceProtocol(raw string) error {
	switch raw {
	case "tcp", "udp":
		return nil
	default:
		return fmt.Errorf("unsupported protocol %q", raw)
	}
}

func validateServicePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid service port %d", port)
	}
	return nil
}

func validateServiceScopeID(scopeID string) error {
	if scopeID == "" {
		return fmt.Errorf("scope ID cannot be empty")
	}
	return nil
}

func (s ServiceIdentity) Key() (string, error) {

	normalizedIP, err := normalizeServiceIP(s.IP)
	if err != nil {
		return "", err
	}

	if err := validateServiceProtocol(s.Protocol); err != nil {
		return "", err
	}

	if err := validateServicePort(s.Port); err != nil {
		return "", err
	}

	if err := validateServiceScopeID(s.ScopeID); err != nil {
		return "", err
	}

	canonical := canonicalServiceIdentity{
		Version:  serviceIdentitySchemaVersion,
		ScopeID:  s.ScopeID,
		IP:       normalizedIP,
		Port:     s.Port,
		Protocol: s.Protocol,
	}

	payload, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}
