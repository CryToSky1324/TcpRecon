package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"sync"

	"github.com/CryToSky1324/TcpRecon/internal/utils"
)

type targetSpool interface {
	io.Reader
	io.Writer
	io.Seeker
	io.Closer
	Name() string
}

type targetSpoolFactory func() (targetSpool, error)
type targetSpoolRemove func(string) error

type preparedTargetSource struct {
	spool   targetSpool
	path    string
	targets []string
	remove  targetSpoolRemove

	closeOnce sync.Once
	closeErr  error
}

func (s *preparedTargetSource) Reader() io.Reader {
	return s.spool
}

func (s *preparedTargetSource) Targets() []string {
	return slices.Clone(s.targets)
}

func (s *preparedTargetSource) Path() string {
	return s.path
}

func (s *preparedTargetSource) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = errors.Join(
			s.spool.Close(),
			s.remove(s.path),
		)
	})
	return s.closeErr
}

func createTargetSpool() (targetSpool, error) {
	return os.CreateTemp("", "tcprecon-targets-*")
}

func prepareTargetSource(ctx context.Context, source io.ReadCloser) (*preparedTargetSource, error) {
	return prepareTargetSourceWith(ctx, source, createTargetSpool, os.Remove)
}

func prepareTargetSourceWith(
	ctx context.Context,
	source io.ReadCloser,
	create targetSpoolFactory,
	remove targetSpoolRemove,
) (*preparedTargetSource, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, source.Close())
	}

	spool, err := create()
	if err != nil {
		return nil, errors.Join(err, source.Close())
	}
	prepared := &preparedTargetSource{
		spool:  spool,
		path:   spool.Name(),
		remove: remove,
	}

	fail := func(operationErr error) (*preparedTargetSource, error) {
		return nil, errors.Join(operationErr, source.Close(), prepared.Close())
	}

	scanner := bufio.NewScanner(source)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		target, keep := utils.ParseTargetLine(scanner.Text())
		if !keep {
			continue
		}
		payload := []byte(target + "\n")
		written, err := spool.Write(payload)
		if err != nil {
			return fail(err)
		}
		if written != len(payload) {
			return fail(io.ErrShortWrite)
		}
		prepared.targets = append(prepared.targets, target)
	}
	if err := scanner.Err(); err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if err := source.Close(); err != nil {
		return nil, errors.Join(err, prepared.Close())
	}
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		return nil, errors.Join(err, prepared.Close())
	}

	return prepared, nil
}
