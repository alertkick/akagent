//go:build linux

package agent

import "testing"

func TestUnionSourceIPs(t *testing.T) {
	tests := []struct {
		name  string
		lists [][]string
		want  []string
	}{
		{
			name:  "both empty yields nil so classify falls back to unverified",
			lists: [][]string{nil, {}},
			want:  nil,
		},
		{
			name:  "lockdown only",
			lists: [][]string{{"10.0.0.1"}, nil},
			want:  []string{"10.0.0.1"},
		},
		{
			name:  "ac-007 only (alerting without lockdown)",
			lists: [][]string{nil, {"203.0.113.5", "198.51.100.0/24"}},
			want:  []string{"203.0.113.5", "198.51.100.0/24"},
		},
		{
			name:  "union dedupes overlap, lockdown first, blanks dropped",
			lists: [][]string{{"10.0.0.1", " ", "203.0.113.5"}, {"203.0.113.5", "198.51.100.0/24"}},
			want:  []string{"10.0.0.1", "203.0.113.5", "198.51.100.0/24"},
		},
		{
			name:  "trims surrounding whitespace",
			lists: [][]string{{" 10.0.0.1 "}, {"10.0.0.1"}},
			want:  []string{"10.0.0.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unionSourceIPs(tt.lists...)
			if len(got) != len(tt.want) {
				t.Fatalf("unionSourceIPs() = %v, want %v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("unionSourceIPs()[%d] = %q, want %q (full %v)", i, got[i], tt.want[i], got)
				}
			}
		})
	}
}
