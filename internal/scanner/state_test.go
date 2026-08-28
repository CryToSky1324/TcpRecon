package scanner

import (
	"path/filepath"
	"testing"

	"go.etcd.io/bbolt"

	"github.com/CryToSky1324/TcpRecon/internal/models"
)

func TestStateManagerReportsPersistenceFailure(t *testing.T) {
	db, err := bbolt.Open(
		filepath.Join(t.TempDir(), "state.db"),
		0600,
		nil,
	)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}

	if err := db.Close(); err != nil {
		t.Fatalf("close test db: %v", err)
	}

	results := make(chan models.ScanResult, 1)
	results <- models.ScanResult{
		TargetIP: "127.0.0.1",
		Port:     80,
		Protocol: "tcp",
		State:    "OPEN",
	}
	close(results)

	_, err = StateManager(db, results, false)
	if err == nil {
		t.Fatal("StateManager() error = nil, want persistence failure")
	}
}

func TestStateManagerDrainsResultsAfterPersistenceFailure(t *testing.T) {
	db, err := bbolt.Open(
		filepath.Join(t.TempDir(), "state.db"),
		0600,
		nil,
	)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}

	if err := db.Close(); err != nil {
		t.Fatalf("close test db: %v", err)
	}

	const totalResults = 1001

	results := make(chan models.ScanResult, totalResults)

	for i := 0; i < totalResults; i++ {
		results <- models.ScanResult{
			TargetIP: "127.0.0.1",
			Port:     80,
			Protocol: "tcp",
			State:    "OPEN",
		}
	}
	close(results)

	openPorts, err := StateManager(db, results, false)

	if err == nil {
		t.Fatal("StateManager() error = nil, want persistence failure")
	}

	if openPorts != totalResults {
		t.Fatalf(
			"StateManager() openPorts = %d, want %d; results were not fully drained",
			openPorts,
			totalResults,
		)
	}
}
