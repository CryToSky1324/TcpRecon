package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
)

type trackingReadCloser struct {
	io.Reader
	closed   bool
	closeErr error
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return r.closeErr
}

type failingReader struct {
	err error
}

func (r failingReader) Read([]byte) (int, error) {
	return 0, r.err
}

type cancelAfterRead struct {
	value  string
	cancel context.CancelFunc
	read   bool
}

func (r *cancelAfterRead) Read(buffer []byte) (int, error) {
	if r.read {
		return 0, io.EOF
	}
	r.read = true
	n := copy(buffer, r.value)
	r.cancel()
	return n, nil
}

type fakeTargetSpool struct {
	bytes.Buffer
	path     string
	writeErr error
	seekErr  error
	closed   bool
}

func (s *fakeTargetSpool) Write(value []byte) (int, error) {
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	return s.Buffer.Write(value)
}

func (s *fakeTargetSpool) Seek(int64, int) (int64, error) {
	if s.seekErr != nil {
		return 0, s.seekErr
	}
	return 0, nil
}

func (s *fakeTargetSpool) Close() error {
	s.closed = true
	return nil
}

func (s *fakeTargetSpool) Name() string {
	return s.path
}

func TestPrepareTargetSourceUsesSharedTokensAndCleansUp(t *testing.T) {
	source := &trackingReadCloser{Reader: strings.NewReader(
		"  # ignored\n\n Example.COM. \n 192.0.2.7/24 \nhost # value\n",
	)}

	prepared, err := prepareTargetSource(context.Background(), source)
	if err != nil {
		t.Fatalf("prepareTargetSource() error = %v", err)
	}
	if !source.closed {
		t.Fatal("prepareTargetSource() did not close the selected source")
	}

	wantTargets := []string{"Example.COM.", "192.0.2.7/24", "host # value"}
	if !slices.Equal(prepared.Targets(), wantTargets) {
		t.Fatalf("prepared targets = %q, want %q", prepared.Targets(), wantTargets)
	}

	replayed, err := io.ReadAll(prepared.Reader())
	if err != nil {
		t.Fatalf("read replay source: %v", err)
	}
	if want := "Example.COM.\n192.0.2.7/24\nhost # value\n"; string(replayed) != want {
		t.Fatalf("replayed targets = %q, want %q", replayed, want)
	}

	spoolPath := prepared.Path()
	if err := prepared.Close(); err != nil {
		t.Fatalf("close prepared source: %v", err)
	}
	if _, err := os.Stat(spoolPath); !os.IsNotExist(err) {
		t.Fatalf("spool still exists after Close: stat error = %v", err)
	}
	if err := prepared.Close(); err != nil {
		t.Fatalf("second Close() error = %v, want idempotent success", err)
	}
	exposedTargets := prepared.Targets()
	exposedTargets[0] = "mutated.example"
	if !slices.Equal(prepared.Targets(), wantTargets) {
		t.Fatal("Targets() exposed mutable prepared scope state")
	}
}

func TestPrepareTargetSourceFailureCleansUp(t *testing.T) {
	errRead := errors.New("read failed")
	errCreate := errors.New("create failed")
	errWrite := errors.New("write failed")
	errSeek := errors.New("seek failed")
	errSourceClose := errors.New("source close failed")

	tests := []struct {
		name      string
		ctx       context.Context
		source    *trackingReadCloser
		createErr error
		writeErr  error
		seekErr   error
		sourceErr error
		wantErr   error
		wantSpool bool
	}{
		{
			name:      "source read failure",
			ctx:       context.Background(),
			source:    &trackingReadCloser{Reader: failingReader{err: errRead}},
			wantErr:   errRead,
			wantSpool: true,
		},
		{
			name:      "spool creation failure",
			ctx:       context.Background(),
			source:    &trackingReadCloser{Reader: strings.NewReader("192.0.2.1\n")},
			createErr: errCreate,
			wantErr:   errCreate,
		},
		{
			name:      "spool write failure",
			ctx:       context.Background(),
			source:    &trackingReadCloser{Reader: strings.NewReader("192.0.2.1\n")},
			writeErr:  errWrite,
			wantErr:   errWrite,
			wantSpool: true,
		},
		{
			name:      "spool rewind failure",
			ctx:       context.Background(),
			source:    &trackingReadCloser{Reader: strings.NewReader("192.0.2.1\n")},
			seekErr:   errSeek,
			wantErr:   errSeek,
			wantSpool: true,
		},
		{
			name:      "selected source close failure",
			ctx:       context.Background(),
			source:    &trackingReadCloser{Reader: strings.NewReader("192.0.2.1\n")},
			sourceErr: errSourceClose,
			wantErr:   errSourceClose,
			wantSpool: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.source.closeErr = tt.sourceErr
			spool := &fakeTargetSpool{path: "test-spool", writeErr: tt.writeErr, seekErr: tt.seekErr}
			created := false
			removed := false
			create := func() (targetSpool, error) {
				created = true
				if tt.createErr != nil {
					return nil, tt.createErr
				}
				return spool, nil
			}
			remove := func(path string) error {
				if path != spool.path {
					t.Fatalf("removed path = %q, want %q", path, spool.path)
				}
				removed = true
				return nil
			}

			prepared, err := prepareTargetSourceWith(tt.ctx, tt.source, create, remove)
			if prepared != nil {
				t.Fatal("prepareTargetSourceWith() returned prepared source on failure")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("prepareTargetSourceWith() error = %v, want %v", err, tt.wantErr)
			}
			if !tt.source.closed {
				t.Fatal("selected source was not closed")
			}
			if !created {
				t.Fatal("spool create callback was not called")
			}
			if tt.wantSpool && (!spool.closed || !removed) {
				t.Fatalf("spool cleanup = (closed=%t, removed=%t), want both true", spool.closed, removed)
			}
			if !tt.wantSpool && (spool.closed || removed) {
				t.Fatalf("spool cleanup = (closed=%t, removed=%t), want neither after creation failure", spool.closed, removed)
			}
		})
	}
}

func TestPrepareTargetSourcePreCancelledDoesNotCreateSpool(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	source := &trackingReadCloser{Reader: strings.NewReader("192.0.2.1\n")}
	created := false
	removed := false

	prepared, err := prepareTargetSourceWith(
		ctx,
		source,
		func() (targetSpool, error) {
			created = true
			return &fakeTargetSpool{path: "unexpected-spool"}, nil
		},
		func(string) error {
			removed = true
			return nil
		},
	)
	if prepared != nil {
		t.Fatal("prepareTargetSourceWith() returned prepared source on cancellation")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("prepareTargetSourceWith() error = %v, want context.Canceled", err)
	}
	if !source.closed {
		t.Fatal("selected source was not closed")
	}
	if created || removed {
		t.Fatalf("pre-cancelled preparation = (created=%t, removed=%t), want neither", created, removed)
	}
}

func TestPrepareTargetSourceCancellationDuringReadCleansUpSpool(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	source := &trackingReadCloser{Reader: &cancelAfterRead{
		value:  "192.0.2.1\n198.51.100.2\n",
		cancel: cancel,
	}}
	spool := &fakeTargetSpool{path: "test-spool"}
	created := false
	removed := false

	prepared, err := prepareTargetSourceWith(
		ctx,
		source,
		func() (targetSpool, error) {
			created = true
			return spool, nil
		},
		func(path string) error {
			if path != spool.path {
				t.Fatalf("removed path = %q, want %q", path, spool.path)
			}
			removed = true
			return nil
		},
	)
	if prepared != nil {
		t.Fatal("prepareTargetSourceWith() returned prepared source on cancellation")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("prepareTargetSourceWith() error = %v, want context.Canceled", err)
	}
	if !source.closed || !created || !spool.closed || !removed {
		t.Fatalf(
			"cancellation cleanup = (source_closed=%t, created=%t, spool_closed=%t, removed=%t), want all true",
			source.closed,
			created,
			spool.closed,
			removed,
		)
	}
}
