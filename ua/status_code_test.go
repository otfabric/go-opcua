// SPDX-License-Identifier: MIT

package ua

import (
	"testing"
)

func TestStatusCode_Symbol(t *testing.T) {
	tests := []struct {
		code StatusCode
		want string
	}{
		{StatusGood, "Good"}, // StatusOK is same value 0x0, map yields StatusGood
		{StatusBad, "Bad"},
		{StatusUncertain, "Uncertain"},
		{StatusBadServiceUnsupported, "BadServiceUnsupported"},
		{StatusBadUserAccessDenied, "BadUserAccessDenied"},
		{StatusBadTimeout, "BadTimeout"},
		{StatusBadNodeIDUnknown, "BadNodeIDUnknown"},
		{StatusCode(0xDEADBEEF), "0xDEADBEEF"},
	}
	for _, tt := range tests {
		got := tt.code.Symbol()
		if got != tt.want {
			t.Errorf("StatusCode(0x%X).Symbol() = %q, want %q", uint32(tt.code), got, tt.want)
		}
	}
}

func TestStatusCode_Uint32(t *testing.T) {
	if got := StatusGood.Uint32(); got != 0 {
		t.Errorf("StatusGood.Uint32() = %d, want 0", got)
	}
	if got := StatusBadNodeIDUnknown.Uint32(); got != 0x80340000 {
		t.Errorf("StatusBadNodeIDUnknown.Uint32() = 0x%X, want 0x80340000", got)
	}
	sc := StatusCode(0xDEADBEEF)
	if got := sc.Uint32(); got != 0xDEADBEEF {
		t.Errorf("StatusCode(0xDEADBEEF).Uint32() = 0x%X, want 0xDEADBEEF", got)
	}
}
