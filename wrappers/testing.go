package wrappers

import (
	"testing"
)

// TestWrapper is a nil-safe implementation of *testing.TB. You can use it the same as *testing.T or *testing.B even if
// {T,B} are empty. For implementations that cannot be wrapped, check the docs.
type TestWrapper struct {
	*testing.T
}

func (t *TestWrapper) Error(args ...interface{}) {
	if t.T != nil {
		t.T.Error(args...)
	}
}

func (t *TestWrapper) Errorf(format string, args ...interface{}) {
	if t.T != nil {
		t.T.Errorf(format, args...)
	}
}

func (t *TestWrapper) Fail() {
	if t.T != nil {
		t.T.Fail()
	}
}

func (t *TestWrapper) FailNow() {
	if t.T != nil {
		t.T.FailNow()
	}
}

// Returns false by default if T is not set.
func (t *TestWrapper) Failed() bool {
	if t.T != nil {
		return t.T.Failed()
	}
	return false
}

func (t *TestWrapper) Fatal(args ...interface{}) {
	if t.T != nil {
		t.T.Fatal(args...)
	}
}

func (t *TestWrapper) Fatalf(format string, args ...interface{}) {
	if t.T != nil {
		t.T.Fatalf(format, args...)
	}
}

func (t *TestWrapper) Log(args ...interface{}) {
	if t.T != nil {
		t.T.Log(args...)
	}
}

func (t *TestWrapper) Logf(format string, args ...interface{}) {
	if t.T != nil {
		t.T.Logf(format, args...)
	}
}

// Returns `TestWrapper` if T is nil.
func (t *TestWrapper) Name() string {
	if t.T != nil {
		return t.T.Name()
	}
	return "TestWrapper"
}

func (t *TestWrapper) Skip(args ...interface{}) {
	if t.T != nil {
		t.T.Skip(args...)
	}
}

// No-op if T is nil.
func (t *TestWrapper) SkipNow() {
	if t.T != nil {
		t.T.SkipNow()
	}
}

func (t *TestWrapper) Skipf(format string, args ...interface{}) {
	if t.T != nil {
		t.T.Skipf(format, args...)
	}
}

// Returns false if T is nil.
func (t *TestWrapper) Skipped() bool {
	if t.T != nil {
		return t.T.Skipped()
	}
	return false
}

func (t *TestWrapper) Helper() {}

func (t *TestWrapper) private() {}
