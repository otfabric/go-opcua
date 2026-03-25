package errors

import (
	stderrors "errors"
	"fmt"
	"testing"
)

func TestIs(t *testing.T) {
	base := stderrors.New("base")
	wrapped := stderrors.Join(base, stderrors.New("other"))
	if !Is(wrapped, base) {
		t.Error("Is should find base in joined error")
	}
	if Is(base, stderrors.New("other")) {
		t.Error("Is should be false for unrelated target")
	}
}

func TestAs(t *testing.T) {
	var target *customErr
	err := &customErr{msg: "x"}
	if !As(err, &target) {
		t.Fatal("As should succeed for matching type")
	}
	if target.msg != "x" {
		t.Errorf("target.msg = %q", target.msg)
	}
}

type customErr struct{ msg string }

func (e *customErr) Error() string { return e.msg }

func TestUnwrap(t *testing.T) {
	inner := stderrors.New("inner")
	w := fmt.Errorf("wrap: %w", inner)
	if Unwrap(w) != inner {
		t.Errorf("Unwrap = %v, want %v", Unwrap(w), inner)
	}
}

func TestJoin(t *testing.T) {
	e1 := stderrors.New("a")
	e2 := stderrors.New("b")
	j := Join(e1, e2)
	if j == nil {
		t.Fatal("Join returned nil")
	}
	if !Is(j, e1) || !Is(j, e2) {
		t.Error("joined error should contain both")
	}
}
