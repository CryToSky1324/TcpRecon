package main

import (
	"slices"

	"github.com/CryToSky1324/TcpRecon/internal/models"
	"github.com/CryToSky1324/TcpRecon/internal/scanner"
	"go.etcd.io/bbolt"
)

type runtimeServiceSaver func(
	db *bbolt.DB,
	scopeID string,
	scanID string,
	identity scanner.ServiceIdentity,
	observation scanner.ServiceObservation,
) error

func newRuntimeObservationPersister(
	db *bbolt.DB,
	owned *ownedRuntimeScan,
) runtimeObservationPersister {
	return newRuntimeObservationPersisterWith(db, owned, scanner.SaveCurrentService)
}

func newRuntimeObservationPersisterWith(
	db *bbolt.DB,
	owned *ownedRuntimeScan,
	save runtimeServiceSaver,
) runtimeObservationPersister {
	scopeID := owned.ScopeID()
	scanID := owned.ScanID()

	return func(result models.ScanResult) error {
		identity := scanner.ServiceIdentity{
			ScopeID:  scopeID,
			IP:       result.TargetIP,
			Port:     result.Port,
			Protocol: result.Protocol,
		}
		observation := scanner.ServiceObservation{
			Banner:      result.Banner,
			OSHint:      result.OSHint,
			CertSubject: result.CertSubject,
			CertIssuer:  result.CertIssuer,
			SANs:        slices.Clone(result.SANs),
		}
		return save(db, scopeID, scanID, identity, observation)
	}
}
