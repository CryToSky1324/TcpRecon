package scanner

import (
	"fmt"
	"strings"
	"time"

	"github.com/CryToSky1324/TcpRecon/internal/models"
	"github.com/cespare/xxhash/v2"
)

func hashScanResult(r *models.ScanResult) uint64 {
	if r == nil {
		return 0
	}
	statePayload := fmt.Sprintf("%s|%s|%s|%s|%s",
		r.State,
		r.Banner,
		r.CertSubject,
		r.CertIssuer,
		strings.Join(r.SANs, ","),
	)
	return xxhash.Sum64String(statePayload)
}

func mapDeltaToLifecycleEvent(
	scopeID string,
	scanID string,
	prior *models.ScanResult,
	curr *models.ScanResult,
	scanSuccessful bool,
) (*models.LifecycleEvent, error) {

	// Incomplete scans must NEVER emit closures or advance state
	if !scanSuccessful {
		if curr == nil || (curr != nil && curr.State == "closed") {
			return nil, nil
		}
	}

	// B7-01, B7-07, B7-08: New Discovery
	// A service is brand-new if:
	// 1. prior is nil
	// 2. prior protocol does not match current protocol (TCP vs UDP)
	isNewService := (prior == nil) || (prior != nil && curr != nil && prior.Protocol != curr.Protocol)

	if isNewService && curr != nil && curr.State == "open" {
		return &models.LifecycleEvent{
			SchemaVersion: "1.0",
			EventID:       fmt.Sprintf("%s-%s-%s-%d", scanID, curr.TargetIP, curr.Protocol, curr.Port),
			ScanID:        scanID,
			ScopeID:       scopeID,
			Timestamp:     time.Now().UTC().Format(time.RFC3339),
			EventType:     "service.opened",

			Scanner: models.ScannerMeta{
				Name:    "tcprecon",
				Version: "1.0.0",
			},
			Asset: models.AssetIdentity{
				IP:       curr.TargetIP,
				Hostname: curr.TargetName,
			},
			Network: models.NetworkObservation{
				Protocol: curr.Protocol,
				Port:     curr.Port,
				State:    "open",
			},
			Change: models.StateChange{
				Type:          "new_service",
				PreviousState: "closed",
			},
		}, nil
	}

	//B7-02: Changed Service
	if prior != nil && prior.State == "open" && curr != nil && curr.State == "open" {
		if hashScanResult(prior) != hashScanResult(curr) {
			return &models.LifecycleEvent{
				SchemaVersion: "1.0",
				EventID:       fmt.Sprintf("%s-%s-%s-%d", scanID, curr.TargetIP, curr.Protocol, curr.Port),
				ScanID:        scanID,
				ScopeID:       scopeID,
				Timestamp:     time.Now().UTC().Format(time.RFC3339),
				EventType:     "service.changed",

				Scanner: models.ScannerMeta{
					Name:    "tcprecon",
					Version: "1.0.0",
				},
				Asset: models.AssetIdentity{
					IP:       curr.TargetIP,
					Hostname: curr.TargetName,
				},
				Network: models.NetworkObservation{
					Protocol: curr.Protocol,
					Port:     curr.Port,
					State:    "open",
				},
				Change: models.StateChange{
					Type:          "service_mutation",
					PreviousState: "open",
				},
			}, nil
		}
		// Nothing updated or emitted if identical
		return nil, nil
	}

	//B7-03: Reopened Service
	if prior != nil && prior.State == "closed" && curr != nil && curr.State == "open" {
		return &models.LifecycleEvent{
			SchemaVersion: "1.0",
			EventID:       fmt.Sprintf("%s-%s-%s-%d", scanID, curr.TargetIP, curr.Protocol, curr.Port),
			ScanID:        scanID,
			ScopeID:       scopeID,
			Timestamp:     time.Now().UTC().Format(time.RFC3339),
			EventType:     "service.reopened",

			Scanner: models.ScannerMeta{
				Name:    "tcprecon",
				Version: "1.0.0",
			},
			Asset: models.AssetIdentity{
				IP:       curr.TargetIP,
				Hostname: curr.TargetName,
			},
			Network: models.NetworkObservation{
				Protocol: curr.Protocol,
				Port:     curr.Port,
				State:    "open",
			},
			Change: models.StateChange{
				Type:          "service_reopened",
				PreviousState: "closed",
			},
		}, nil
	}

	//B7-04: Closed Service
	if scanSuccessful && prior != nil && prior.State == "open" && (curr == nil || curr.State == "closed") {
		// Identity resolution: Fallback to prior if curr was dropped / unobserved
		ip := prior.TargetIP
		hostname := prior.TargetName
		proto := prior.Protocol
		port := prior.Port

		if curr != nil {
			ip = curr.TargetIP
			hostname = curr.TargetName
			proto = curr.Protocol
			port = curr.Port
		}

		return &models.LifecycleEvent{
			SchemaVersion: "1.0",
			EventID:       fmt.Sprintf("%s-%s-%s-%d", scanID, ip, proto, port),
			ScanID:        scanID,
			ScopeID:       scopeID,
			Timestamp:     time.Now().UTC().Format(time.RFC3339),
			EventType:     "service.closed",

			Scanner: models.ScannerMeta{
				Name:    "tcprecon",
				Version: "1.0.0",
			},
			Asset: models.AssetIdentity{
				IP:       ip,
				Hostname: hostname,
			},
			Network: models.NetworkObservation{
				Protocol: proto,
				Port:     port,
				State:    "closed",
			},
			Change: models.StateChange{
				Type:          "service_closed",
				PreviousState: "open",
			},
		}, nil
	}
	return nil, nil
}
