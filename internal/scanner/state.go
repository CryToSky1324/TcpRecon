package scanner

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"

	"github.com/cespare/xxhash/v2"
	"go.etcd.io/bbolt"
	"github.com/CryToSky1324/TcpRecon/internal/models"
)

// StateManager consumes results, performs O(1) hash comparisons via mmap, and commits deltas to disk.
func StateManager(db *bbolt.DB, results <-chan models.ScanResult, jsonMode bool) int {
	openPorts := 0

	for result := range results {
		if result.State == "OPEN" {
			openPorts++
		}

		// 1. Deterministic State Hashing
		statePayload := fmt.Sprintf("%s|%s|%s|%s|%v", result.State, result.Banner, result.CertSubject, result.CertIssuer, result.SANs)
		hashVal := xxhash.Sum64String(statePayload)
		
		newHash := make([]byte, 8)
		binary.LittleEndian.PutUint64(newHash, hashVal)
		targetKey := []byte(fmt.Sprintf("%s:%d", result.TargetIP, result.Port))

		var isDelta bool
		var prevState string

		// 2. Read-First Fast Path (Zero-Copy OS Page Cache)
		if err := db.View(func(tx *bbolt.Tx) error {
			b := tx.Bucket([]byte("PortStates"))
			if b == nil {
				return fmt.Errorf("bucket PortStates not found.")
			}
			oldHash := b.Get(targetKey)

			if oldHash == nil {
				isDelta = true
				prevState = "UNKNOWN"
			} else if !bytes.Equal(oldHash, newHash) {
				isDelta = true
				prevState = "MUTATED"
			}
			return nil
		}); err != nil {
			slog.Error ("Failed to execute read transaction", slog.String("error", err.Error()))
		}

		// 3. Slow Path (fsync) and SIEM Emission ONLY on Delta
		if isDelta {
			if err := db.Update(func(tx *bbolt.Tx) error {
				b := tx.Bucket([]byte("PortStates"))
				if b == nil {
					return fmt.Errorf("bucket Porstates not found.")
				}
				return b.Put(targetKey, newHash)
			}); err != nil {
				slog.Error("Failed to execute write transaction", slog.String("error", err.Error()))
				continue
			}

			if jsonMode {
				slog.Info("delta_detected",
					slog.String("target", result.TargetName),
					slog.String("ip", result.TargetIP),
					slog.Int("port", result.Port),
					slog.String("previous_state", prevState),
					slog.String("current_state", result.State),
					slog.String("tls_subject", result.CertSubject),
				)
			}
		}
	}

	return openPorts
}
