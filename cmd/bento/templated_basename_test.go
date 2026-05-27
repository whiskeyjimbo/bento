package main

import "testing"

func TestTemplatedBasename(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		// templated: should match
		{"backup-1779910675.tar.gz", true},   // unix timestamp
		{"report-2026-05-27.csv", true},      // ISO date
		{"snap-20260527.json", true},         // YYYYMMDD
		{"trace-20260527T120000.log", true},  // ISO compact
		{"out-1234.txt", true},               // PID-shaped
		{"out_98765.txt", true},              // PID-shaped underscore
		{"out.aB3xY9.txt", true},             // mktemp-style mixed alnum
		{"f-c9bf9e57-1685-4c89-bafb-ff5af830be8a.json", true}, // UUID
		{"d41d8cd98f00b204e9800998ecf8427e.bin", true},        // bare md5/uuid hex

		// not templated: should NOT match
		{"report.csv", false},
		{"data.json", false},
		{"v1.txt", false},
		{"log2.txt", false},
		{"my-output.txt", false},
		{"weather.txt", false},
		{"a.b", false},
	}
	for _, c := range cases {
		if got := templatedBasename(c.name); got != c.want {
			t.Errorf("templatedBasename(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}
