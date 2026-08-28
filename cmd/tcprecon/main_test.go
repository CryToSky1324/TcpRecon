package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/CryToSky1324/TcpRecon/internal/scanner"
)

func TestValidateCLI(t *testing.T) {
	tests := []struct {
		name      string
		workers   int
		timeout   int
		rate      int
		args      []string
		inputList string
		wantErr   bool
	}{
		{name: "valid", workers: 1, timeout: 1, rate: 1},
		{name: "zero workers", workers: 0, timeout: 1, rate: 1, wantErr: true},
		{name: "zero timeout", workers: 1, timeout: 0, rate: 1, wantErr: true},
		{name: "zero rate", workers: 1, timeout: 1, rate: 0, wantErr: true},
		{name: "extra positional", workers: 1, timeout: 1, rate: 1, args: []string{"one", "two"}, wantErr: true},
		{name: "conflicting sources", workers: 1, timeout: 1, rate: 1, args: []string{"one"}, inputList: "targets.txt", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCLI(tt.workers, tt.timeout, tt.rate, tt.args, tt.inputList)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateCLI() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSelectTargetReader(t *testing.T) {
	tempFile, err := os.CreateTemp(t.TempDir(), "targets-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tempFile.WriteString("192.0.2.1\n"); err != nil {
		t.Fatal(err)
	}
	if err := tempFile.Close(); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "198.51.100.1\n")
	}))
	defer server.Close()

	tests := []struct {
		name       string
		args       []string
		inputList  string
		targetURL  string
		stdin      io.Reader
		stdinPiped bool
		want       string
	}{
		{name: "hostname positional", args: []string{"localhost"}, want: "localhost\n"},
		{name: "IPv4 positional", args: []string{"127.0.0.1"}, want: "127.0.0.1\n"},
		{name: "IPv6 positional", args: []string{"::1"}, want: "::1\n"},
		{name: "CIDR positional", args: []string{"127.0.0.0/30"}, want: "127.0.0.0/30\n"},
		{name: "file", inputList: tempFile.Name(), want: "192.0.2.1\n"},
		{name: "stdin", stdin: strings.NewReader("203.0.113.1\n"), stdinPiped: true, want: "203.0.113.1\n"},
		{name: "positional URL", args: []string{server.URL}, want: "198.51.100.1\n"},
		{name: "environment URL", targetURL: server.URL, want: "198.51.100.1\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader, err := selectTargetReader(context.Background(), tt.args, tt.inputList, tt.targetURL, tt.stdin, tt.stdinPiped)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			got, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Fatalf("selected input = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFinalizeScanCompletionReportsStateFailure(t *testing.T) {
	stateErr := errors.New("state write failed")

	got := finalizeScanCompletion(
		scanner.ScanCompletion{
			Status: scanner.ScanStatusCompleted,
		},
		stateErr,
	)

	if got.Status != scanner.ScanStatusStateFailed {
		t.Fatalf(
			"finalizeScanCompletion() status = %q, want %q",
			got.Status,
			scanner.ScanStatusStateFailed,
		)
	}

	if !errors.Is(got.Err, stateErr) {
		t.Fatalf(
			"finalizeScanCompletion() error = %v, want %v",
			got.Err,
			stateErr,
		)
	}

	if got.Successful() {
		t.Fatal("state-failed scan reported successful")
	}
}

func TestFinalizeScanCompletionPreservesSuccess(t *testing.T) {
	got := finalizeScanCompletion(
		scanner.ScanCompletion{
			Status: scanner.ScanStatusCompleted,
		},
		nil,
	)

	if got.Status != scanner.ScanStatusCompleted {
		t.Fatalf(
			"finalizeScanCompletion() status = %q, want %q",
			got.Status,
			scanner.ScanStatusCompleted,
		)
	}

	if got.Err != nil {
		t.Fatalf(
			"finalizeScanCompletion() error = %v, want nil",
			got.Err,
		)
	}

	if !got.Successful() {
		t.Fatal("successful scan reported unsuccessful")
	}
}

func TestFinalizeScanCompletionPreservesScannerFailureAndStateError(t *testing.T) {
	stateErr := errors.New("state write failed")

	got := finalizeScanCompletion(
		scanner.ScanCompletion{
			Status: scanner.ScanStatusCancelled,
			Err:    context.Canceled,
		},
		stateErr,
	)

	if got.Status != scanner.ScanStatusCancelled {
		t.Fatalf(
			"finalizeScanCompletion() status = %q, want %q",
			got.Status,
			scanner.ScanStatusCancelled,
		)
	}

	if !errors.Is(got.Err, context.Canceled) {
		t.Fatalf(
			"finalizeScanCompletion() error = %v, want context.Canceled",
			got.Err,
		)
	}

	if !errors.Is(got.Err, stateErr) {
		t.Fatalf(
			"finalizeScanCompletion() error = %v, want state error",
			got.Err,
		)
	}

	if got.Successful() {
		t.Fatal("failed scan reported successful")
	}
}
