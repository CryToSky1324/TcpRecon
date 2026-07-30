package utils

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/CryToSky1324/TcpRecon/internal/models"
)

func TestParsePortRange(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []int
		wantErr bool
	}{
		{name: "single", input: "443", want: []int{443}},
		{name: "list and range", input: "22, 80-82", want: []int{22, 80, 81, 82}},
		{name: "zero", input: "0", wantErr: true},
		{name: "too large", input: "65536", wantErr: true},
		{name: "reversed range", input: "82-80", wantErr: true},
		{name: "trailing text", input: "80oops", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePortRange(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParsePortRange(%q) unexpectedly succeeded", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePortRange(%q): %v", tt.input, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParsePortRange(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestFingerprintOS(t *testing.T) {
	tests := []struct {
		banner string
		want   string
	}{
		{banner: "", want: ""},
		{banner: "OpenSSH Ubuntu", want: "Ubuntu Linux"},
		{banner: "Microsoft-IIS/10.0", want: "Microsoft Windows"},
		{banner: "unknown service", want: "Unknown/Obfuscated"},
	}

	for _, tt := range tests {
		if got := FingerprintOS(tt.banner); got != tt.want {
			t.Errorf("FingerprintOS(%q) = %q, want %q", tt.banner, got, tt.want)
		}
	}
}

func TestStreamTargetsIPv4AndIPv6(t *testing.T) {
	jobs := make(chan models.ScanJob, 2)
	go func() {
		defer close(jobs)
		StreamTargets(context.Background(), strings.NewReader("127.0.0.1\n::1\n"), []int{80}, nil, jobs)
	}()

	var got []string
	for job := range jobs {
		got = append(got, job.TargetIP)
	}
	want := []string{"127.0.0.1", "::1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("target IPs = %v, want %v", got, want)
	}
}
