package main

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CryToSky1324/TcpRecon/internal/models"
	"github.com/CryToSky1324/TcpRecon/internal/scanner"
	"go.etcd.io/bbolt"
)

const integrationScanID = "00112233445566778899aabbccddeeff"

func integrationPrepared(targets ...string) (*preparedTargetSource, *fakeTargetSpool, *bool) {
	prepared, spool, removed := testPreparedReservationSource()
	prepared.targets = append([]string(nil), targets...)
	for _, target := range targets {
		_, _ = spool.WriteString(target + "\n")
	}
	return prepared, spool, removed
}

func integrationConfig(dbPath string, stdout, stderr io.Writer, jsonMode bool) lifecycleRuntimeConfig {
	return lifecycleRuntimeConfig{
		DBPath: dbPath, TCPPorts: []int{443}, UDPPorts: []int{53}, Workers: 2,
		Timeout: time.Second, RateLimit: 10, JSONMode: jsonMode, Stdout: stdout, Stderr: stderr,
	}
}

func integrationDBOpener(order *[]string) runtimeStateOpener {
	return func(path string) (*bbolt.DB, error) {
		if order != nil {
			*order = append(*order, "open")
		}
		return bbolt.Open(path, 0600, nil)
	}
}

func integrationScanner(
	results []models.ScanResult,
	completion *scanner.ScanCompletion,
	started func(),
) runtimeScannerStart {
	return func(
		context.Context, io.Reader, []int, []int, int, time.Duration, int, bool, bool,
	) (<-chan models.ScanResult, <-chan scanner.ScanCompletion, time.Time) {
		if started != nil {
			started()
		}
		resultCh := make(chan models.ScanResult, len(results))
		for _, result := range results {
			resultCh <- result
		}
		close(resultCh)
		completionCh := make(chan scanner.ScanCompletion, 1)
		if completion != nil {
			completionCh <- *completion
		}
		close(completionCh)
		return resultCh, completionCh, time.Unix(100, 0)
	}
}

func integrationScannerExpectReplay(t *testing.T, want string, completion scanner.ScanCompletion, started func()) runtimeScannerStart {
	t.Helper()
	return func(
		_ context.Context, reader io.Reader, _ []int, _ []int, _ int, _ time.Duration, _ int, _ bool, _ bool,
	) (<-chan models.ScanResult, <-chan scanner.ScanCompletion, time.Time) {
		replay, err := io.ReadAll(reader)
		if err != nil || string(replay) != want {
			t.Errorf("scanner replay = %q, err=%v; want %q", replay, err, want)
		}
		if started != nil {
			started()
		}
		results := make(chan models.ScanResult)
		close(results)
		completions := make(chan scanner.ScanCompletion, 1)
		completions <- completion
		close(completions)
		return results, completions, time.Unix(100, 0)
	}
}

func seedIntegrationBaseline(t *testing.T, path, scopeID string, identity scanner.ServiceIdentity, banner string) map[string]scanner.ServiceRecord {
	t.Helper()
	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := scanner.InitializeStateSchema(db); err != nil {
		t.Fatal(err)
	}
	if err := scanner.EnsureCurrentScan(db, scopeID, "baseline-seed"); err != nil {
		t.Fatal(err)
	}
	if err := scanner.SaveCurrentService(db, scopeID, "baseline-seed", identity, scanner.ServiceObservation{Banner: banner}); err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.FinalizeCurrentScan(db, scopeID, "baseline-seed", scanner.ScanCompletion{Status: scanner.ScanStatusCompleted}); err != nil {
		t.Fatal(err)
	}
	baseline, exists, err := scanner.LoadCommittedBaseline(db, scopeID)
	if err != nil || !exists {
		t.Fatalf("seeded baseline = (exists=%t, err=%v)", exists, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return baseline
}

func TestLifecycleRuntimeStartupAndOwnershipOrdering(t *testing.T) {
	t.Run("preparation failure stops before database ownership", func(t *testing.T) {
		for _, jsonMode := range []bool{false, true} {
			name := "non-json"
			if jsonMode {
				name = "json"
			}
			t.Run(name, func(t *testing.T) {
				errPrepare := errors.New("prepare targets")
				opened := false
				generated := false
				started := false
				var stdout bytes.Buffer
				var stderr bytes.Buffer
				outcome := runLifecycleRuntime(
					context.Background(), integrationConfig(filepath.Join(t.TempDir(), "state.db"), &stdout, &stderr, jsonMode),
					lifecycleRuntimeDependencies{
						PrepareTargets: func(context.Context) (*preparedTargetSource, error) { return nil, errPrepare },
						OpenState: func(string) (*bbolt.DB, error) {
							opened = true
							return nil, errors.New("unexpected database open")
						},
						GenerateScanID: func() (string, error) {
							generated = true
							return integrationScanID, nil
						},
						StartScanner: integrationScanner(nil, nil, func() { started = true }),
					},
				)
				if !errors.Is(outcome.Err, errPrepare) {
					t.Fatalf("preparation outcome = %+v, want %v", outcome, errPrepare)
				}
				if opened || generated || started {
					t.Fatalf("post-preparation calls = (open=%t, generate=%t, scan=%t), want all false", opened, generated, started)
				}
				if stdout.Len() != 0 {
					t.Fatalf("startup failure stdout = %q, want empty", stdout.String())
				}
				if want := "[!] FATAL: prepare targets\n"; stderr.String() != want {
					t.Fatalf("startup failure stderr = %q, want %q", stderr.String(), want)
				}
			})
		}
	})

	t.Run("preparation before database opening and reservation before scanner", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "state.db")
		prepared, spool, removed := integrationPrepared("Example.COM.")
		order := []string{}
		expectedScope := scanner.ScanScope{Targets: []string{"Example.COM."}, TCPPorts: []int{443}, UDPPorts: []int{53}}.ID()
		started := false
		var openedDB *bbolt.DB
		outcome := runLifecycleRuntime(
			context.Background(), integrationConfig(dbPath, io.Discard, io.Discard, true),
			lifecycleRuntimeDependencies{
				PrepareTargets: func(context.Context) (*preparedTargetSource, error) {
					order = append(order, "prepare")
					return prepared, nil
				},
				OpenState: func(path string) (*bbolt.DB, error) {
					order = append(order, "open")
					db, err := bbolt.Open(path, 0600, nil)
					openedDB = db
					return db, err
				},
				GenerateScanID: func() (string, error) {
					order = append(order, "reserve")
					return integrationScanID, nil
				},
				StartScanner: integrationScannerExpectReplay(t, "Example.COM.\n", scanner.ScanCompletion{Status: scanner.ScanStatusCompleted}, func() {
					order = append(order, "scan")
					started = true
					if openedDB == nil {
						t.Error("scanner started before database opening")
						return
					}
					_, exists, loadErr := scanner.LoadCurrentScan(openedDB, expectedScope, integrationScanID)
					if loadErr != nil || !exists {
						t.Errorf("owned scan before scanner start = (exists=%t, err=%v)", exists, loadErr)
					}
				}),
			},
		)
		if outcome.Err != nil || !outcome.Execution.Completion.Successful() || !started {
			t.Fatalf("runtime outcome = %+v, started=%t", outcome, started)
		}
		if !reflect.DeepEqual(order, []string{"prepare", "open", "reserve", "scan"}) {
			t.Fatalf("startup order = %v", order)
		}
		if outcome.ScopeID != expectedScope || outcome.ScanID != integrationScanID {
			t.Fatalf("runtime identity = (%q, %q), want (%q, %q)", outcome.ScopeID, outcome.ScanID, expectedScope, integrationScanID)
		}
		if !spool.closed || !*removed {
			t.Fatal("owned prepared input was not cleaned")
		}
	})

	t.Run("schema refusal prevents scanner and cleans preparation", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "legacy.db")
		db, err := bbolt.Open(dbPath, 0600, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Update(func(tx *bbolt.Tx) error { _, err := tx.CreateBucket([]byte("PortStates")); return err }); err != nil {
			t.Fatal(err)
		}
		before := snapshotRuntimeState(t, db)
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		prepared, spool, removed := integrationPrepared("192.0.2.1")
		started := false
		outcome := runLifecycleRuntime(context.Background(), integrationConfig(dbPath, io.Discard, io.Discard, true), lifecycleRuntimeDependencies{
			PrepareTargets: func(context.Context) (*preparedTargetSource, error) { return prepared, nil },
			OpenState:      integrationDBOpener(nil), GenerateScanID: func() (string, error) { return integrationScanID, nil },
			StartScanner: integrationScanner(nil, nil, func() { started = true }),
		})
		if !errors.Is(outcome.Err, scanner.ErrUnversionedStateSchema) || started {
			t.Fatalf("legacy outcome = %+v, started=%t", outcome, started)
		}
		if !spool.closed || !*removed {
			t.Fatal("schema refusal leaked prepared input")
		}
		reopened, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 200 * time.Millisecond})
		if err != nil {
			t.Fatalf("runtime did not close rejected database: %v", err)
		}
		after := snapshotRuntimeState(t, reopened)
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(after, before) {
			t.Fatalf("rejected schema mutated: before=%v after=%v", before, after)
		}
	})

	t.Run("reservation failure prevents scanner and cleans preparation", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "state.db")
		prepared, spool, removed := integrationPrepared("192.0.2.1")
		started := false
		outcome := runLifecycleRuntime(context.Background(), integrationConfig(dbPath, io.Discard, io.Discard, true), lifecycleRuntimeDependencies{
			PrepareTargets: func(context.Context) (*preparedTargetSource, error) { return prepared, nil }, OpenState: integrationDBOpener(nil),
			GenerateScanID: func() (string, error) { return "invalid", nil }, StartScanner: integrationScanner(nil, nil, func() { started = true }),
		})
		if !errors.Is(outcome.Err, ErrInvalidRuntimeScanID) || started {
			t.Fatalf("reservation outcome = %+v, started=%t", outcome, started)
		}
		if !spool.closed || !*removed {
			t.Fatal("reservation failure leaked prepared input")
		}
	})
}

func TestLifecycleRuntimeSuccessfulExecutionAndEmptyScan(t *testing.T) {
	for _, tt := range []struct {
		name       string
		results    []models.ScanResult
		wantStatus scanner.ServiceStatus
		wantBanner string
		wantChange scanner.ChangeKind
	}{
		{name: "observation promotes", results: []models.ScanResult{{TargetIP: "192.0.2.10", Port: 443, Protocol: "tcp", State: "OPEN", Banner: "fresh"}}, wantStatus: scanner.ServiceStatusOpen, wantBanner: "fresh", wantChange: scanner.ChangeChanged},
		{name: "zero observations close baseline", wantStatus: scanner.ServiceStatusClosed, wantBanner: "old", wantChange: scanner.ChangeClosed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "state.db")
			targets := []string{"192.0.2.10"}
			scopeID := scanner.ScanScope{Targets: targets, TCPPorts: []int{443}, UDPPorts: []int{53}}.ID()
			identity := scanner.ServiceIdentity{ScopeID: scopeID, IP: "192.0.2.10", Port: 443, Protocol: "tcp"}
			seedIntegrationBaseline(t, dbPath, scopeID, identity, "old")
			prepared, _, _ := integrationPrepared(targets...)
			outcome := runLifecycleRuntime(context.Background(), integrationConfig(dbPath, io.Discard, io.Discard, true), lifecycleRuntimeDependencies{
				PrepareTargets: func(context.Context) (*preparedTargetSource, error) { return prepared, nil }, OpenState: integrationDBOpener(nil),
				GenerateScanID: func() (string, error) { return integrationScanID, nil },
				StartScanner:   integrationScanner(tt.results, &scanner.ScanCompletion{Status: scanner.ScanStatusCompleted}, nil),
			})
			if outcome.Err != nil || !outcome.Execution.Completion.Successful() {
				t.Fatalf("successful outcome = %+v", outcome)
			}
			db, err := bbolt.Open(dbPath, 0600, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			baseline, exists, err := scanner.LoadCommittedBaseline(db, scopeID)
			if err != nil || !exists {
				t.Fatalf("baseline = (exists=%t, err=%v)", exists, err)
			}
			key, _ := identity.Key()
			record, found := baseline[key]
			if len(baseline) != 1 || !found {
				t.Fatalf("baseline keys = %+v, want only %q", baseline, key)
			}
			if record.Status != tt.wantStatus || record.Banner != tt.wantBanner {
				t.Fatalf("baseline record = %+v", record)
			}
			if _, exists, err := scanner.LoadCurrentScan(db, scopeID, integrationScanID); err != nil || exists {
				t.Fatalf("temporary scan = (exists=%t, err=%v), want removed", exists, err)
			}
			if len(outcome.Execution.Changes) != 1 || outcome.Execution.Changes[0].Kind != tt.wantChange {
				t.Fatalf("changes = %+v, want %s", outcome.Execution.Changes, tt.wantChange)
			}
		})
	}
}

func TestLifecycleRuntimeIncompleteExecutionPreservesBaseline(t *testing.T) {
	for _, tt := range []struct {
		name       string
		completion *scanner.ScanCompletion
		wantErr    error
	}{
		{name: "cancelled partial scan", completion: &scanner.ScanCompletion{Status: scanner.ScanStatusCancelled, Err: context.Canceled}, wantErr: context.Canceled},
		{name: "missing completion", wantErr: ErrScanCompletionMissing},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "state.db")
			targets := []string{"192.0.2.10"}
			scopeID := scanner.ScanScope{Targets: targets, TCPPorts: []int{443}, UDPPorts: []int{53}}.ID()
			identity := scanner.ServiceIdentity{ScopeID: scopeID, IP: "192.0.2.10", Port: 443, Protocol: "tcp"}
			before := seedIntegrationBaseline(t, dbPath, scopeID, identity, "old")
			prepared, _, _ := integrationPrepared(targets...)
			partial := []models.ScanResult{{TargetIP: "192.0.2.20", Port: 8443, Protocol: "tcp", State: "OPEN"}}
			outcome := runLifecycleRuntime(context.Background(), integrationConfig(dbPath, io.Discard, io.Discard, true), lifecycleRuntimeDependencies{
				PrepareTargets: func(context.Context) (*preparedTargetSource, error) { return prepared, nil }, OpenState: integrationDBOpener(nil),
				GenerateScanID: func() (string, error) { return integrationScanID, nil }, StartScanner: integrationScanner(partial, tt.completion, nil),
			})
			if outcome.Execution.Completion.Successful() || !errors.Is(outcome.Err, tt.wantErr) {
				t.Fatalf("incomplete outcome = %+v, want %v", outcome, tt.wantErr)
			}
			db, err := bbolt.Open(dbPath, 0600, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			after, exists, err := scanner.LoadCommittedBaseline(db, scopeID)
			if err != nil || !exists || !reflect.DeepEqual(after, before) {
				t.Fatalf("baseline changed: before=%+v after=%+v exists=%t err=%v", before, after, exists, err)
			}
			if _, exists, err := scanner.LoadCurrentScan(db, scopeID, integrationScanID); err != nil || exists {
				t.Fatalf("incomplete temporary scan = (exists=%t, err=%v), want discarded", exists, err)
			}
		})
	}
}

func TestLifecycleRuntimeOutputBoundary(t *testing.T) {
	for _, jsonMode := range []bool{false, true} {
		name := "non-json"
		if jsonMode {
			name = "json"
		}
		t.Run(name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			prepared, _, _ := integrationPrepared("192.0.2.10")
			outcome := runLifecycleRuntime(context.Background(), integrationConfig(filepath.Join(t.TempDir(), "state.db"), &stdout, &stderr, jsonMode), lifecycleRuntimeDependencies{
				PrepareTargets: func(context.Context) (*preparedTargetSource, error) { return prepared, nil }, OpenState: integrationDBOpener(nil),
				GenerateScanID: func() (string, error) { return integrationScanID, nil },
				StartScanner:   integrationScanner([]models.ScanResult{{TargetIP: "192.0.2.10", Port: 443, Protocol: "tcp", State: "OPEN"}}, &scanner.ScanCompletion{Status: scanner.ScanStatusCompleted}, nil),
			})
			if outcome.Err != nil {
				t.Fatal(outcome.Err)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", stdout.String())
			}
			for _, forbidden := range []string{"port_state_delta", `"ip"`, "service.opened", "service.changed", "service.closed", "service.reopened"} {
				if strings.Contains(stdout.String(), forbidden) {
					t.Fatalf("stdout contains forbidden %q", forbidden)
				}
			}
			if jsonMode && stderr.Len() != 0 {
				t.Fatalf("JSON success stderr = %q, want empty", stderr.String())
			}
			if !jsonMode && (!strings.Contains(stderr.String(), "Initiating stream scan") || !strings.Contains(stderr.String(), "Scan completed")) {
				t.Fatalf("non-JSON stderr = %q, want runtimeOutput summaries", stderr.String())
			}
		})
	}
}

func TestMainDelegatesToLifecycleRuntimeWithoutLegacyStatePath(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	calledRuntime := false
	legacyStateManager := false
	legacyBucket := false
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Name.Name != "main" || function.Body == nil {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				if call, ok := node.(*ast.CallExpr); ok {
					if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "runLifecycleRuntime" {
						calledRuntime = true
					}
				}
				return true
			})
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.CallExpr:
				if selector, ok := value.Fun.(*ast.SelectorExpr); ok {
					if pkg, ok := selector.X.(*ast.Ident); ok && pkg.Name == "scanner" && selector.Sel.Name == "StateManager" {
						legacyStateManager = true
					}
				}
			case *ast.BasicLit:
				if value.Kind == token.STRING && strings.Trim(value.Value, `"`) == "PortStates" {
					legacyBucket = true
				}
			}
			return true
		})
	}
	if !calledRuntime || legacyStateManager || legacyBucket {
		t.Fatalf("main delegation = (runtime=%t, StateManager=%t, PortStates=%t), want true/false/false", calledRuntime, legacyStateManager, legacyBucket)
	}
}
