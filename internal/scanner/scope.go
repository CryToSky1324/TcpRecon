package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

type ScanScope struct {
	Targets  []string
	TCPPorts []int
	UDPPorts []int
}

const scanScopeSchemaVersion = 1

type canonicalScanScope struct {
	Version  int      `json:"version"`
	Targets  []string `json:"targets"`
	TCPPorts []int    `json:"tcp_ports"`
	UDPPorts []int    `json:"udp_ports"`
}

func normalizeScopeTarget(raw string) string {
	target := strings.TrimSpace(raw)

	if prefix, err := netip.ParsePrefix(target); err == nil {
		return prefix.Masked().String()
	}
	if addr, err := netip.ParseAddr(target); err == nil {
		return addr.Unmap().String()
	}
	return strings.TrimSuffix(strings.ToLower(target), ".")
}

func canonicalTargets(values []string) []string {
	seen := make(map[string]struct{})

	var results []string

	for _, item := range values {
		normalizedItem := normalizeScopeTarget(item)
		if _, exists := seen[normalizedItem]; normalizedItem == "" || exists {
			continue
		}
		seen[normalizedItem] = struct{}{}
		results = append(results, normalizedItem)
	}
	slices.Sort(results)
	return results
}

func canonicalPorts(values []int) []int {
	seen := make(map[int]struct{})

	var results []int

	for _, item := range values {
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		results = append(results, item)
	}
	slices.Sort(results)
	return results
}

func (s ScanScope) ID() string {
	canonical := canonicalScanScope{
		Version:  scanScopeSchemaVersion,
		Targets:  canonicalTargets(s.Targets),
		TCPPorts: canonicalPorts(s.TCPPorts),
		UDPPorts: canonicalPorts(s.UDPPorts),
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		panic(fmt.Sprintf("Error occurred during marshaling. Error: %v", err))
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
