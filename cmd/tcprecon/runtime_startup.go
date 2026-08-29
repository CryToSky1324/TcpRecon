package main

import (
	"context"
	"errors"
	"io"

	"github.com/CryToSky1324/TcpRecon/internal/scanner"
	"go.etcd.io/bbolt"
)

type runtimeTargetPreparation func(
	context.Context,
	io.ReadCloser,
) (*preparedTargetSource, error)

type runtimeReservationReadiness func(*preparedTargetSource)

func prepareRuntimeStartup(
	ctx context.Context,
	source io.ReadCloser,
	db *bbolt.DB,
	ready runtimeReservationReadiness,
) (*preparedTargetSource, error) {
	return prepareRuntimeStartupWith(ctx, source, db, prepareTargetSource, ready)
}

func prepareRuntimeStartupWith(
	ctx context.Context,
	source io.ReadCloser,
	db *bbolt.DB,
	prepare runtimeTargetPreparation,
	ready runtimeReservationReadiness,
) (*preparedTargetSource, error) {
	prepared, err := prepare(ctx, source)
	if err != nil {
		return nil, err
	}
	if err := scanner.InitializeStateSchema(db); err != nil {
		return nil, errors.Join(err, prepared.Close())
	}

	ready(prepared)
	return prepared, nil
}
