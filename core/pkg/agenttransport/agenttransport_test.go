package agenttransport

import (
	"context"
	"io"
	"testing"
)

type testDialer struct{ name string }

func (d testDialer) Name() string { return d.name }

func (d testDialer) Dial(context.Context, Target) (io.ReadWriteCloser, error) {
	return nil, nil
}

func TestRegisterAndGet(t *testing.T) {
	Register(testDialer{name: "test-transport"})
	d, err := Get("test-transport")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if d.Name() != "test-transport" {
		t.Fatalf("dialer name = %q", d.Name())
	}

	if _, err := Get("missing"); err == nil {
		t.Fatal("Get(missing) succeeded, want error")
	}
	if _, err := Get(""); err == nil {
		t.Fatal("Get(empty) succeeded, want error")
	}

	names := Names()
	found := false
	for _, name := range names {
		if name == "test-transport" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Names() = %v, missing test transport", names)
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	Register(testDialer{name: "duplicate-transport"})
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate registration did not panic")
		}
	}()
	Register(testDialer{name: "duplicate-transport"})
}

func TestRegisterRejectsEmptyName(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("empty-name registration did not panic")
		}
	}()
	Register(testDialer{})
}
