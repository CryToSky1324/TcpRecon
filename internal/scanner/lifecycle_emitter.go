package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/CryToSky1324/TcpRecon/internal/enrichment"
	"github.com/CryToSky1324/TcpRecon/internal/models"
	"github.com/CryToSky1324/TcpRecon/internal/risk"
	"github.com/cespare/xxhash/v2"
)

// serviceRecordToScanResult maps an internal bbolt ServiceRecord into a models.ScanResult.
func serviceRecordToScanResult(r *ServiceRecord) *models.ScanResult {
	if r == nil {
		return nil
	}
	return &models.ScanResult{
		TargetIP:    r.IP,
		Port:        r.Port,
		Protocol:    r.Protocol,
		State:       string(r.Status),
		Banner:      r.Banner,
		OSHint:      r.OSHint,
		CertSubject: r.CertSubject,
		CertIssuer:  r.CertIssuer,
		SANs:        r.SANs,
	}
}

// EmitLifecycleChanges maps committed ServiceChange deltas into enriched LifecycleEvents
// and writes them as newline-delimited JSON (NDJSON) to w.
func EmitLifecycleChanges(
	w io.Writer,
	scopeID string,
	scanID string,
	changes []ServiceChange,
	matcher enrichment.Matcher,
) error {
	enc := json.NewEncoder(w)
	for _, change := range changes {
		prior := serviceRecordToScanResult(change.Previous)
		curr := serviceRecordToScanResult(change.Current)

		// Authoritative scan completion is guaranteed true here because
		// FinalizeCurrentScan only returns changes on successful promotion.
		event, err := mapDeltaToLifecycleEvent(scopeID, scanID, prior, curr, true, matcher)
		if err != nil {
			return err
		}
		if event == nil {
			continue
		}
		if err := enc.Encode(event); err != nil {
			return fmt.Errorf("failed to encode lifecycle event NDJSON: %w", err)
		}
	}
	return nil
}

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
	matcher enrichment.Matcher,
) (*models.LifecycleEvent, error) {

	// Incomplete scans must NEVER emit closures or advance state
	if !scanSuccessful {
		if curr == nil || (curr != nil && curr.State == "closed") {
			return nil, nil
		}
	}

	var targetIP, hostname string
	if curr != nil {
		targetIP = curr.TargetIP
		hostname = curr.TargetName
	} else if prior != nil {
		// service.closed fallback: curr is nil, extract identity from baseline
		targetIP = prior.TargetIP
		hostname = prior.TargetName
	}

	env, crit, owner := "unassigned", "unassigned", "unassigned"
	if matcher != nil && targetIP != "" {
		ctx := matcher.MatchString(targetIP)
		env = ctx.Environment
		crit = ctx.Criticality
		owner = ctx.Owner
	}

	asset := models.AssetIdentity{
		IP:          targetIP,
		Hostname:    hostname,
		Environment: env,
		Criticality: crit,
		Owner:       owner,
	}

	// curr holds target metrics for active services; prior holds metrics if curr is nil (service.closed)
	targetResult := curr
	if targetResult == nil {
		targetResult = prior
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
			Asset: asset,
			Network: models.NetworkObservation{
				Protocol: curr.Protocol,
				Port:     curr.Port,
				State:    "open",
			},
			Change: models.StateChange{
				Type:          "new_service",
				PreviousState: "closed",
			},
			Risk: risk.EvaluateRisk("service.opened", curr, asset.Criticality),
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
				Asset: asset,
				Network: models.NetworkObservation{
					Protocol: curr.Protocol,
					Port:     curr.Port,
					State:    "open",
				},
				Change: models.StateChange{
					Type:          "service_mutation",
					PreviousState: "open",
				},
				Risk: risk.EvaluateRisk("service.changed", curr, asset.Criticality),
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
			Asset: asset,
			Network: models.NetworkObservation{
				Protocol: curr.Protocol,
				Port:     curr.Port,
				State:    "open",
			},
			Change: models.StateChange{
				Type:          "service_reopened",
				PreviousState: "closed",
			},
			Risk: risk.EvaluateRisk("service.reopened", curr, asset.Criticality),
		}, nil
	}

	//B7-04: Closed Service
	if scanSuccessful && prior != nil && prior.State == "open" && (curr == nil || curr.State == "closed") {
		// Identity resolution: Fallback to prior if curr was dropped / unobserved
		proto := prior.Protocol
		port := prior.Port

		if curr != nil {
			proto = curr.Protocol
			port = curr.Port
		}

		return &models.LifecycleEvent{
			SchemaVersion: "1.0",
			EventID:       fmt.Sprintf("%s-%s-%s-%d", scanID, targetIP, proto, port),
			ScanID:        scanID,
			ScopeID:       scopeID,
			Timestamp:     time.Now().UTC().Format(time.RFC3339),
			EventType:     "service.closed",

			Scanner: models.ScannerMeta{
				Name:    "tcprecon",
				Version: "1.0.0",
			},
			Asset: asset,
			Network: models.NetworkObservation{
				Protocol: proto,
				Port:     port,
				State:    "closed",
			},
			Change: models.StateChange{
				Type:          "service_closed",
				PreviousState: "open",
			},
			Risk: risk.EvaluateRisk("service.closed", targetResult, asset.Criticality),
		}, nil
	}
	return nil, nil
}
