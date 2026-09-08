package main

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/CryToSky1324/TcpRecon/internal/enrichment"
	"github.com/CryToSky1324/TcpRecon/internal/scanner"
)

func TestRuntimeOutputEmitsLifecycleEventsNDJSON(t *testing.T) {
	rules := []enrichment.AssetRule{
		{
			Prefix:      netip.MustParsePrefix("192.0.2.0/24"),
			Environment: "production",
			Criticality: "tier-1",
			Owner:       "sre-team",
		},
	}
	matcher := enrichment.NewMatcher(rules)

	for _, jsonMode := range []bool{false, true} {
		name := "non-json"
		if jsonMode {
			name = "json"
		}
		t.Run(name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			output := newRuntimeOutput(&stdout, &stderr, jsonMode)

			changes := []scanner.ServiceChange{
				{
					Kind:       scanner.ChangeOpened,
					ServiceKey: "key-1",
					Current: &scanner.ServiceRecord{
						IP:       "192.0.2.10",
						Port:     443,
						Protocol: "tcp",
						Status:   scanner.ServiceStatusOpen,
						Banner:   "nginx/1.24",
					},
				},
			}

			err := output.LifecycleChanges("scope-test", "scan-100", changes, matcher)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			rawOutput := stdout.String()
			if !strings.Contains(rawOutput, `"event_type":"service.opened"`) {
				t.Fatalf("stdout missing event_type: %q", rawOutput)
			}
			if !strings.Contains(rawOutput, `"environment":"production"`) {
				t.Fatalf("stdout missing enriched environment: %q", rawOutput)
			}
			if !strings.Contains(rawOutput, `"criticality":"tier-1"`) {
				t.Fatalf("stdout missing enriched criticality: %q", rawOutput)
			}
			if !strings.Contains(rawOutput, `"owner":"sre-team"`) {
				t.Fatalf("stdout missing enriched owner: %q", rawOutput)
			}

			if strings.Contains(rawOutput, "port_state_delta") {
				t.Fatalf("stdout contains retired port_state_delta: %q", rawOutput)
			}
		})
	}
}
func TestRuntimeOutputPreservesNonJSONSummariesOnStderr(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	output := newRuntimeOutput(&stdout, &stderr, false)

	output.ScanStarted(3, 2, 10)
	output.ScanFinished(
		1500*time.Millisecond,
		4,
		scanner.ScanCompletion{Status: scanner.ScanStatusCompleted},
	)

	want := "[*] Initiating stream scan against 5 ports (3 TCP, 2 UDP) with 10 Goroutines...\n" +
		"[*] Scan completed in 1.50 seconds. Discovered 4 open ports.\n"
	if stderr.String() != want {
		t.Fatalf("stderr = %q, want %q", stderr.String(), want)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestRuntimeOutputPreservesIncompleteDiagnosticsOnStderr(t *testing.T) {
	for _, jsonMode := range []bool{false, true} {
		name := "non-json"
		if jsonMode {
			name = "json"
		}
		t.Run(name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			output := newRuntimeOutput(&stdout, &stderr, jsonMode)

			output.ScanFinished(
				time.Second,
				0,
				scanner.ScanCompletion{
					Status: scanner.ScanStatusStateFailed,
					Err:    errors.New("state write failed"),
				},
			)

			want := "[!] Scan incomplete: status=state_failed error=state write failed\n"
			if stderr.String() != want {
				t.Fatalf("stderr = %q, want %q", stderr.String(), want)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", stdout.String())
			}
		})
	}
}

func TestRuntimeOutputRequiresSuccessfulCompletionANDCondition(t *testing.T) {
	tests := []struct {
		name       string
		completion scanner.ScanCompletion
		wantStderr string
	}{
		{
			name: "completed with error",
			completion: scanner.ScanCompletion{
				Status: scanner.ScanStatusCompleted,
				Err:    errors.New("unexpected completion error"),
			},
			wantStderr: "[!] Scan incomplete: status=completed error=unexpected completion error\n",
		},
		{
			name: "cancelled without error",
			completion: scanner.ScanCompletion{
				Status: scanner.ScanStatusCancelled,
			},
			wantStderr: "[!] Scan incomplete: status=cancelled\n",
		},
	}

	for _, tt := range tests {
		for _, jsonMode := range []bool{false, true} {
			mode := "non-json"
			if jsonMode {
				mode = "json"
			}
			t.Run(tt.name+"/"+mode, func(t *testing.T) {
				var stdout bytes.Buffer
				var stderr bytes.Buffer
				output := newRuntimeOutput(&stdout, &stderr, jsonMode)

				output.ScanFinished(time.Second, 0, tt.completion)

				if stderr.String() != tt.wantStderr {
					t.Fatalf("stderr = %q, want %q", stderr.String(), tt.wantStderr)
				}
				if stdout.Len() != 0 {
					t.Fatalf("stdout = %q, want empty", stdout.String())
				}
			})
		}
	}
}

func TestRuntimeOutputSuppressesSuccessSummaryInJSONMode(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	output := newRuntimeOutput(&stdout, &stderr, true)

	output.ScanStarted(1, 0, 1)
	output.ScanFinished(
		time.Second,
		1,
		scanner.ScanCompletion{Status: scanner.ScanStatusCompleted},
	)

	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("JSON success output = (stdout=%q, stderr=%q), want both empty", stdout.String(), stderr.String())
	}
}
