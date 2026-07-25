package scanner

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/CryToSky1324/TcpRecon/internal/models"
	"github.com/cespare/xxhash/v2"
	"go.etcd.io/bbolt"
)

// StateManager consumes results and micro-batches them into bbolt to prevent fsync exhaustion.
func StateManager(db *bbolt.DB, results <-chan models.ScanResult, jsonMode bool) int {
	openPorts := 0
	const maxBatchSize = 1000

	// Pre-allocate contiguous memory to prevent heap fragmentation
	buffer := make([]models.ScanResult, 0, maxBatchSize)

	// Time-based flush to prevent low-volume scans from stalling in memory
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Anonymous function to execute the monolithic transaction
	flush := func(batch []models.ScanResult) {
		if len(batch) == 0 {
			return
		}

		type deltaPayload struct {
			models.ScanResult
			PreviousState string `json:"previous_state"`
			Event         string `json:"event"`
		}

		var emissions []deltaPayload

		// 1. Single Transaction Lock
		err := db.Update(func(tx *bbolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists([]byte("PortStates"))
			if err != nil {
				return err
			}

			// 2. Iterate in-memory buffer against the B-Tree
			for _, result := range batch {
				statePayload := fmt.Sprintf("%s|%s|%s|%s|%v", result.State, result.Banner, result.CertSubject, result.CertIssuer, result.SANs)
				hashVal := xxhash.Sum64String(statePayload)

				newHash := make([]byte, 8)
				binary.LittleEndian.PutUint64(newHash, hashVal)

				// Strict Protocol Namespace Isolation
				targetKey := []byte(fmt.Sprintf("%s:%d/%s", result.TargetIP, result.Port, result.Protocol))

				var prevState string
				isDelta := false

				oldHash := b.Get(targetKey)
				if oldHash == nil {
					isDelta = true
					prevState = "UNKNOWN"
				} else if !bytes.Equal(oldHash, newHash) {
					isDelta = true
					prevState = "MUTATED"
				}

				if isDelta {
					if err := b.Put(targetKey, newHash); err != nil {
						return err
					}
					// Queue for emission (do not block the DB lock with I/O waits)
					emissions = append(emissions, deltaPayload{
						ScanResult:    result,
						PreviousState: prevState,
						Event:         "port_state_delta",
					})
				}
			}
			return nil
		})

		if err != nil {
			slog.Error("Failed to flush state batch to disk", slog.String("error", err.Error()))
			return
		}

		// 3. Strict UNIX stdout emission completely decoupled from DB locks
		if jsonMode {
			for _, emission := range emissions {
				jsonData, err := json.Marshal(emission)
				if err == nil {
					fmt.Fprintln(os.Stdout, string(jsonData))
				}
			}
		}
	}

	// Channel consumption routing
	for {
		select {
		case result, ok := <-results:
			if !ok {
				// Channel closed by dispatcher: flush remaining buffer and exit Goroutine
				flush(buffer)
				return openPorts
			}

			if result.State == "OPEN" {
				openPorts++
			}

			buffer = append(buffer, result)
			if len(buffer) >= maxBatchSize {
				flush(buffer)
				buffer = buffer[:0] // Reslice to 0, retaining allocated capacity
			}

		case <-ticker.C:
			flush(buffer)
			buffer = buffer[:0]
		}
	}
}
