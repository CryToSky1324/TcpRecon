package scanner

import (
	"context"
	"errors"

	"github.com/CryToSky1324/TcpRecon/internal/utils"
)

type ScanStatus string

const (
	ScanStatusCompleted        ScanStatus = "completed"
	ScanStatusCancelled        ScanStatus = "cancelled"
	ScanStatusResolutionFailed ScanStatus = "resolution_failed"
	ScanStatusParseFailed      ScanStatus = "parse_failed"
	ScanStatusWorkerFailed     ScanStatus = "worker_failed"
	ScanStatusStateFailed      ScanStatus = "state_failed"
)

type ScanCompletion struct {
	Status ScanStatus
	Err    error
}

func (c ScanCompletion) Successful() bool {
	return c.Status == ScanStatusCompleted && c.Err == nil
}

func scanCompletionFromProducerError(err error) ScanCompletion {
	if err == nil {
		return ScanCompletion{
			Status: ScanStatusCompleted,
		}
	}
	switch {
	case errors.Is(err, context.Canceled):
		return ScanCompletion{
			Status: ScanStatusCancelled,
			Err:    err,
		}

	case errors.Is(err, utils.ErrTargetParse):
		return ScanCompletion{
			Status: ScanStatusParseFailed,
			Err:    err,
		}
		// parse failure
	case errors.Is(err, utils.ErrTargetResolution):
		return ScanCompletion{
			Status: ScanStatusResolutionFailed,
			Err:    err,
		}
	}
	return ScanCompletion{
		Err: err,
	}
}
