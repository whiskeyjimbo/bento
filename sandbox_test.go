package bento

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestSandboxLifecycle(t *testing.T) {
	sb, err := NewSandbox()
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}
	// First Close: succeeds.
	if err := sb.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// Second Close: still nil (idempotent).
	if err := sb.Close(); err != nil {
		t.Errorf("Close (second): %v", err)
	}
	// Run after Close: errors.
	m := &Manifest{Interpreter: "true", Script: "/dev/null"}
	_, err = sb.Run(context.Background(), m)
	if err == nil || !strings.Contains(err.Error(), "closed") {
		t.Errorf("Run after Close should return closed error, got %v", err)
	}
	_ = errors.New
}
