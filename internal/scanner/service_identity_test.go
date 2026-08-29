package scanner

import (
	"testing"
)

func TestServiceIdentityKeyV1KnownVector(t *testing.T) {
	identity := ServiceIdentity{
		ScopeID:  "scope-test",
		IP:       "192.0.2.10",
		Port:     443,
		Protocol: "tcp",
	}

	got, err := identity.Key()
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}

	const want = "1093d4118dd533702fb0c83e16ac0c1a3abca13646e8beede8b9fcabbbcfcb7c"
	if got != want {
		t.Fatalf("Key() = %q, want persistent service_key v1 %q", got, want)
	}
}

func TestServiceIdentityKeyStableForSameService(t *testing.T) {
	first := ServiceIdentity{
		ScopeID:  "scope-test",
		IP:       "192.0.2.10",
		Port:     443,
		Protocol: "tcp",
	}
	second := ServiceIdentity{
		ScopeID:  "scope-test",
		IP:       "192.0.2.10",
		Port:     443,
		Protocol: "tcp",
	}
	firstKey, firstErr := first.Key()
	secondKey, secondErr := second.Key()

	if firstErr != nil {
		t.Fatal("failed to generate first service key")
	}
	if secondErr != nil {
		t.Fatal("failed to generate second service key")
	}

	if firstKey != secondKey {
		t.Fatal("identical services produced different service keys")
	}
}

func TestServiceIdentityKeyDifferentForDifferentPort(t *testing.T) {
	first := ServiceIdentity{
		ScopeID:  "scope-test",
		IP:       "192.0.2.10",
		Port:     443,
		Protocol: "tcp",
	}
	second := ServiceIdentity{
		ScopeID:  "scope-test",
		IP:       "192.0.2.10",
		Port:     80,
		Protocol: "tcp",
	}
	firstKey, firstErr := first.Key()
	secondKey, secondErr := second.Key()

	if firstErr != nil {
		t.Fatal("failed to generate first service key")
	}
	if secondErr != nil {
		t.Fatal("failed to generate second service key")
	}

	if firstKey == secondKey {
		t.Fatal("different services produced identical service keys")
	}
}

func TestServiceIdentityKeyDifferentForDifferentProtocol(t *testing.T) {
	first := ServiceIdentity{
		ScopeID:  "scope-test",
		IP:       "192.0.2.10",
		Port:     443,
		Protocol: "tcp",
	}
	second := ServiceIdentity{
		ScopeID:  "scope-test",
		IP:       "192.0.2.10",
		Port:     443,
		Protocol: "udp",
	}
	firstKey, firstErr := first.Key()
	secondKey, secondErr := second.Key()

	if firstErr != nil {
		t.Fatal("failed to generate first service key")
	}
	if secondErr != nil {
		t.Fatal("failed to generate second service key")
	}
	if firstKey == secondKey {
		t.Fatal("different services produced identical service keys")
	}
}

func TestServiceIdentityKeyDifferentForDifferentIP(t *testing.T) {
	first := ServiceIdentity{
		ScopeID:  "scope-test",
		IP:       "192.0.2.10",
		Port:     443,
		Protocol: "tcp",
	}
	second := ServiceIdentity{
		ScopeID:  "scope-test",
		IP:       "192.0.0.10",
		Port:     443,
		Protocol: "tcp",
	}
	firstKey, firstErr := first.Key()
	secondKey, secondErr := second.Key()

	if firstErr != nil {
		t.Fatal("failed to generate first service key")
	}
	if secondErr != nil {
		t.Fatal("failed to generate second service key")
	}
	if firstKey == secondKey {
		t.Fatal("different services produced identical service key")
	}
}

func TestServiceIdentityKeyDifferentForDifferentScope(t *testing.T) {
	first := ServiceIdentity{
		ScopeID:  "scope-test1",
		IP:       "192.0.2.10",
		Port:     443,
		Protocol: "tcp",
	}
	second := ServiceIdentity{
		ScopeID:  "scope-test",
		IP:       "192.0.2.10",
		Port:     443,
		Protocol: "tcp",
	}
	firstKey, firstErr := first.Key()
	secondKey, secondErr := second.Key()

	if firstErr != nil {
		t.Fatal("failed to generate first service key")
	}
	if secondErr != nil {
		t.Fatal("failed to generate second service key")
	}
	if firstKey == secondKey {
		t.Fatal("services in different scopes produced identical service keys")
	}
}

func TestServiceIdentityKeyStableForEquivalentIPv6(t *testing.T) {
	first := ServiceIdentity{
		ScopeID:  "scope-test",
		IP:       "2001:0db8:0000:0000:0000:0000:0000:0001",
		Port:     443,
		Protocol: "tcp",
	}
	second := ServiceIdentity{
		ScopeID:  "scope-test",
		IP:       "2001:db8::1",
		Port:     443,
		Protocol: "tcp",
	}
	firstKey, firstErr := first.Key()
	secondKey, secondErr := second.Key()

	if firstErr != nil {
		t.Fatal("failed to generate first service key")
	}
	if secondErr != nil {
		t.Fatal("failed to generate second service key")
	}
	if firstKey != secondKey {
		t.Fatal("identical services produced different service keys")
	}
}

func TestServiceIdentityKeyRejectsInvalidIP(t *testing.T) {
	first := ServiceIdentity{
		ScopeID:  "scope-test1",
		IP:       "not-an-ip",
		Port:     443,
		Protocol: "tcp",
	}

	_, err := first.Key()

	if err == nil {
		t.Fatal("invalid IPs should return an error")
	}
}

func TestServiceIdentityKeyRejectsInvalidProtocol(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
	}{
		{"mixed-case-tcp", "TcP"},
		{"mixed-case-udp", "uDp"},
		{"unsupported", "icmp"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := ServiceIdentity{
				ScopeID:  "scope-test",
				IP:       "192.0.2.10",
				Port:     443,
				Protocol: tt.protocol,
			}

			_, err := service.Key()

			if err == nil {
				t.Fatal("non-canonical protocl should produces errors")
			}
		})
	}
}

func TestServiceIdentityKeyRejectsInvalidPort(t *testing.T) {
	tests := []struct {
		name string
		port int
	}{
		{"zero", 0},
		{"negative", -1},
		{"above maximum", 65536},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := ServiceIdentity{
				ScopeID:  "scope-test",
				IP:       "192.0.2.10",
				Port:     tt.port,
				Protocol: "tcp",
			}

			_, err := service.Key()

			if err == nil {
				t.Fatal("invalid port should return an error")
			}
		})
	}
}

func TestServiceIdentityKeyAcceptsValidPortBoundaries(t *testing.T) {
	tests := []struct {
		name string
		port int
	}{
		{"minimum", 1},
		{"maximum", 65535},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := ServiceIdentity{
				ScopeID:  "scope-test",
				IP:       "192.0.2.10",
				Port:     tt.port,
				Protocol: "tcp",
			}

			_, err := service.Key()

			if err != nil {
				t.Fatalf("valid port %d returned an error: %v", tt.port, err)
			}
		})
	}
}

func TestServiceIdentityKeyRejectsEmptyScopeID(t *testing.T) {
	first := ServiceIdentity{
		ScopeID:  "",
		IP:       "192.0.2.10",
		Port:     443,
		Protocol: "tcp",
	}
	_, err := first.Key()

	if err == nil {
		t.Fatal("missing scope_id should return an error")
	}
}

func TestServiceIdentityKeyStableForIPv4MappedIPv6(t *testing.T) {
	first := ServiceIdentity{
		ScopeID:  "scope-test",
		IP:       "192.0.2.10",
		Port:     443,
		Protocol: "tcp",
	}
	second := ServiceIdentity{
		ScopeID:  "scope-test",
		IP:       "::ffff:192.0.2.10",
		Port:     443,
		Protocol: "tcp",
	}
	firstKey, firstErr := first.Key()
	secondKey, secondErr := second.Key()

	if firstErr != nil {
		t.Fatal("failed to generate first service key")
	}
	if secondErr != nil {
		t.Fatal("failed to generate second service key")
	}
	if firstKey != secondKey {
		t.Fatal("identical services produced different service keys")
	}
}
