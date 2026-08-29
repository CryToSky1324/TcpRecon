package utils

import "testing"

func TestParseTargetLinePreservesStreamTargetsSemantics(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
		keep bool
	}{
		{name: "empty", line: "  \t ", keep: false},
		{name: "full-line comment", line: "  # ignored target ", keep: false},
		{name: "trimmed hostname", line: "  Example.COM.  ", want: "Example.COM.", keep: true},
		{name: "CIDR remains unexpanded", line: " 192.0.2.7/24 ", want: "192.0.2.7/24", keep: true},
		{name: "inline hash remains data", line: "host # value", want: "host # value", keep: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, keep := ParseTargetLine(tt.line)
			if keep != tt.keep || got != tt.want {
				t.Fatalf("ParseTargetLine(%q) = (%q, %t), want (%q, %t)", tt.line, got, keep, tt.want, tt.keep)
			}
		})
	}
}
