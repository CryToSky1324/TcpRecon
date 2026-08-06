package scanner

import (
	"slices"
	"testing"
	"time"
)

func TestScanScopeIDEquivalentInputs(t *testing.T) {
	first := ScanScope{
		Targets:  []string{"example.com", "10.0.0.0/24", "example.com"},
		TCPPorts: []int{443, 80, 80},
		UDPPorts: []int{161, 53},
	}
	second := ScanScope{
		Targets:  []string{"10.0.0.0/24", "example.com"},
		TCPPorts: []int{80, 443},
		UDPPorts: []int{53, 161},
	}
	if first.ID() != second.ID() {
		t.Fatalf("equivalent scopes produced different IDs %q != %q",
			first.ID(), second.ID())
	}
}

func TestScanScopeIDDifferentTargets(t *testing.T) {
	first := ScanScope{
		Targets:  []string{"10.0.0.0/24"},
		TCPPorts: []int{80, 443},
	}
	second := ScanScope{
		Targets:  []string{"10.0.1.0/24"},
		TCPPorts: []int{80, 443},
	}
	if first.ID() == second.ID() {
		t.Fatalf("different targets produced the same scope ID")
	}
}

func TestScanScopeIDDifferentPorts(t *testing.T) {
	first := ScanScope{
		Targets:  []string{"example.com"},
		TCPPorts: []int{80, 443},
	}
	second := ScanScope{
		Targets:  []string{"example.com"},
		TCPPorts: []int{80, 443, 8080},
	}
	if first.ID() == second.ID() {
		t.Fatalf("different port sets produced the same scope ID")
	}
}

func TestScanScopeIDExcludesExecutionSettings(t *testing.T) {
	type runConfig struct {
		Scope   ScanScope
		Workers int
		Timeout time.Duration
	}
	first := runConfig{
		Scope: ScanScope{
			Targets:  []string{"example.com"},
			TCPPorts: []int{80, 443},
			UDPPorts: []int{53},
		},
		Workers: 10,
		Timeout: time.Second,
	}

	second := runConfig{
		Scope:   first.Scope,
		Workers: 500,
		Timeout: 10 * time.Second,
	}
	if first.Scope.ID() != second.Scope.ID() {
		t.Fatal("execution settings changed the scope ID")
	}
}

func TestScanScopeIDDifferentProtocolSet(t *testing.T) {
	first := ScanScope{
		Targets:  []string{"10.0.0.0/24"},
		TCPPorts: []int{53},
	}
	second := ScanScope{
		Targets:  []string{"10.0.0.0/24"},
		UDPPorts: []int{53},
	}

	if first.ID() == second.ID() {
		t.Fatal("TCP and UDP scopes produced the same scope ID")
	}
}

func TestScanScopeIDNormalizationEquivalence(t *testing.T) {
	first := ScanScope{
		Targets:  []string{" Example.COM.", "10.0.0.7/24", "2001:0db8::1"},
		TCPPorts: []int{80, 443},
	}
	second := ScanScope{
		Targets:  []string{"example.com", "10.0.0.0/24", "2001:db8::1"},
		TCPPorts: []int{80, 443},
	}
	if first.ID() != second.ID() {
		t.Fatal("pre and post-normalization have different scope ID")
	}
}

func TestScanScopeIDDoesNotMutateInputs(t *testing.T) {
	targets := []string{"example.com", "10.0.0.0/24", "example.com"}
	tcpPorts := []int{443, 80, 80}
	udpPorts := []int{161, 53, 161}

	targetsBefore := slices.Clone(targets)
	tcpPortsBefore := slices.Clone(tcpPorts)
	udpPortsBefore := slices.Clone(udpPorts)

	scope := ScanScope{
		Targets:  targets,
		TCPPorts: tcpPorts,
		UDPPorts: udpPorts,
	}

	scope.ID()
	if !slices.Equal(targets, targetsBefore) {
		t.Fatal("target after is not equal to before")
	}
	if !slices.Equal(tcpPorts, tcpPortsBefore) {
		t.Fatal("tcpPorts after is not equal to before")
	}
	if !slices.Equal(udpPorts, udpPortsBefore) {
		t.Fatal("udpPorts after is not equal to before")
	}

}
