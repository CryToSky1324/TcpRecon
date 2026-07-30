package scanner

import "testing"

func TestJoinHostPort(t *testing.T) {
	tests := []struct {
		name string
		host string
		port int
		want string
	}{
		{name: "IPv4", host: "127.0.0.1", port: 443, want: "127.0.0.1:443"},
		{name: "IPv6", host: "::1", port: 443, want: "[::1]:443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := joinHostPort(tt.host, tt.port); got != tt.want {
				t.Fatalf("joinHostPort(%q, %d) = %q, want %q", tt.host, tt.port, got, tt.want)
			}
		})
	}
}
