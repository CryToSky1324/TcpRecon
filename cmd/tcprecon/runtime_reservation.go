package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/CryToSky1324/TcpRecon/internal/scanner"
	"go.etcd.io/bbolt"
)

const (
	runtimeScanIDBytes             = 16
	runtimeScanReservationAttempts = 4
)

var (
	ErrInvalidRuntimeScanID    = errors.New("invalid runtime scan ID")
	ErrRuntimeScanIDCollisions = errors.New("runtime scan ID collision limit reached")
)

type runtimeScanIDGenerator func() (string, error)
type runtimeExclusiveScanCreator func(*bbolt.DB, string, string) error

type ownedRuntimeScan struct {
	scopeID  string
	scanID   string
	prepared *preparedTargetSource
}

func (s *ownedRuntimeScan) ScopeID() string {
	return s.scopeID
}

func (s *ownedRuntimeScan) ScanID() string {
	return s.scanID
}

func (s *ownedRuntimeScan) Reader() io.Reader {
	return s.prepared.Reader()
}

func (s *ownedRuntimeScan) Close() error {
	return s.prepared.Close()
}

func generateRuntimeScanID(entropy io.Reader) (string, error) {
	value := make([]byte, runtimeScanIDBytes)
	if _, err := io.ReadFull(entropy, value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func validRuntimeScanID(scanID string) bool {
	if len(scanID) != runtimeScanIDBytes*2 {
		return false
	}
	decoded, err := hex.DecodeString(scanID)
	return err == nil && hex.EncodeToString(decoded) == scanID
}

func reserveRuntimeScan(
	ctx context.Context,
	db *bbolt.DB,
	scopeID string,
	generate runtimeScanIDGenerator,
) (string, error) {
	return reserveRuntimeScanWith(ctx, db, scopeID, generate, scanner.CreateCurrentScanExclusive)
}

func reserveRuntimeScanWith(
	ctx context.Context,
	db *bbolt.DB,
	scopeID string,
	generate runtimeScanIDGenerator,
	create runtimeExclusiveScanCreator,
) (string, error) {
	var collisionErr error
	for range runtimeScanReservationAttempts {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		scanID, err := generate()
		if err != nil {
			return "", err
		}
		if !validRuntimeScanID(scanID) {
			return "", fmt.Errorf("%w: %q", ErrInvalidRuntimeScanID, scanID)
		}
		if err := create(db, scopeID, scanID); err != nil {
			if errors.Is(err, scanner.ErrStateScanAlreadyExists) {
				collisionErr = err
				continue
			}
			return "", err
		}
		return scanID, nil
	}
	return "", errors.Join(ErrRuntimeScanIDCollisions, collisionErr)
}

func reservePreparedRuntimeScanWith(
	ctx context.Context,
	db *bbolt.DB,
	scopeID string,
	prepared *preparedTargetSource,
	generate runtimeScanIDGenerator,
	create runtimeExclusiveScanCreator,
	ready func(*ownedRuntimeScan),
) (*ownedRuntimeScan, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, prepared.Close())
	}
	scanID, err := reserveRuntimeScanWith(ctx, db, scopeID, generate, create)
	if err != nil {
		return nil, errors.Join(err, prepared.Close())
	}
	owned := &ownedRuntimeScan{
		scopeID:  scopeID,
		scanID:   scanID,
		prepared: prepared,
	}
	ready(owned)
	return owned, nil
}

func reservePreparedRuntimeScan(
	ctx context.Context,
	db *bbolt.DB,
	scopeID string,
	prepared *preparedTargetSource,
	ready func(*ownedRuntimeScan),
) (*ownedRuntimeScan, error) {
	return reservePreparedRuntimeScanWith(
		ctx,
		db,
		scopeID,
		prepared,
		func() (string, error) { return generateRuntimeScanID(rand.Reader) },
		scanner.CreateCurrentScanExclusive,
		ready,
	)
}
