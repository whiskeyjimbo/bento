//go:build linux && amd64

package main

import (
	"reflect"
	"testing"
)

func TestParsePorts(t *testing.T) {
	cases := []struct {
		in   string
		want []uint64
	}{
		{"", nil},
		{"443", []uint64{443}},
		{"443,8080", []uint64{443, 8080}},
		{" 443 , 8080 ", []uint64{443, 8080}}, // whitespace tolerant
		{"443,abc,8080", []uint64{443, 8080}}, // skip malformed
		{"0,443", []uint64{443}},              // skip zero
		{"65535", []uint64{65535}},            // max valid TCP port
		{"65536", nil},                        // out of uint16 range
		{",,", nil},
	}
	for _, c := range cases {
		got := parsePorts(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("parsePorts(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
