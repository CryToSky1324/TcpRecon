package scanner

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/CryToSky1324/TcpRecon/internal/utils"
)

func TestScanCompletionSuccessful(t *testing.T) {
	tests := []struct {
		name       string
		completion ScanCompletion
		want       bool
	}{
		{
			name:       "zero value",
			completion: ScanCompletion{},
			want:       false,
		},
		{
			name: "completed",
			completion: ScanCompletion{
				Status: ScanStatusCompleted,
			},
			want: true,
		},
		{
			name: "cancelled",
			completion: ScanCompletion{
				Status: ScanStatusCancelled,
			},
			want: false,
		},
		{
			name: "resolution failure",
			completion: ScanCompletion{
				Status: ScanStatusResolutionFailed,
			},
			want: false,
		},
		{
			name: "parse failure",
			completion: ScanCompletion{
				Status: ScanStatusParseFailed,
			},
			want: false,
		},
		{
			name: "worker failure",
			completion: ScanCompletion{
				Status: ScanStatusWorkerFailed,
			},
			want: false,
		},
		{
			name: "state failure",
			completion: ScanCompletion{
				Status: ScanStatusStateFailed,
			},
			want: false,
		},
		{
			name: "completed with error",
			completion: ScanCompletion{
				Status: ScanStatusCompleted,
				Err:    errors.New("unexpected failure"),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.completion.Successful()
			if got != tt.want {
				t.Errorf("Successful() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScanCompletionPreservesError(t *testing.T) {
	testErr := errors.New("resolution failed")

	completion := ScanCompletion{
		Status: ScanStatusResolutionFailed,
		Err:    testErr,
	}

	if completion.Err != testErr {
		t.Errorf("Err = %v, want %v", completion.Err, testErr)
	}
}

func TestScanCompletionFromProducerError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus ScanStatus
	}{
		{
			name:       "successful production",
			err:        nil,
			wantStatus: ScanStatusCompleted,
		},
		{
			name:       "cancelled",
			err:        context.Canceled,
			wantStatus: ScanStatusCancelled,
		},
		{
			name:       "parse failure",
			err:        fmt.Errorf("producer failed: %w", utils.ErrTargetParse),
			wantStatus: ScanStatusParseFailed,
		},
		{
			name:       "resolution failure",
			err:        fmt.Errorf("producer failed: %w", utils.ErrTargetResolution),
			wantStatus: ScanStatusResolutionFailed,
		},
		{
			name:       "unknown producer failure",
			err:        errors.New("unexpected producer failure"),
			wantStatus: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scanCompletionFromProducerError(tt.err)

			if got.Status != tt.wantStatus {
				t.Errorf(
					"scanCompletionFromProducerError() status = %q, want %q",
					got.Status,
					tt.wantStatus,
				)
			}
		})
	}
}
