// SPDX-License-Identifier: MIT

package fakeclock

import (
	"testing"
	"time"
)

func TestClock(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := New(start)
	var got []string
	at := func(name string) func() {
		return func() { got = append(got, name+"@"+c.Now().Sub(start).String()) }
	}
	c.AfterFunc(2*time.Second, at("b"))
	c.AfterFunc(time.Second, func() {
		at("a")()
		c.AfterFunc(500*time.Millisecond, at("a2")) // due within the span
	})
	c.AfterFunc(2*time.Second, at("c")) // same time as b, after it
	stop := c.AfterFunc(3*time.Second, at("never"))
	late := c.AfterFunc(10*time.Second, at("late"))
	if c.Pending() != 5 {
		t.Fatalf("Pending = %d", c.Pending())
	}
	if !stop() || stop() {
		t.Fatal("stop must report the first stop only")
	}
	c.Advance(5 * time.Second)
	want := []string{"a@1s", "a2@1.5s", "b@2s", "c@2s"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if c.Now() != start.Add(5*time.Second) || c.Pending() != 1 {
		t.Fatalf("now %v, pending %d", c.Now(), c.Pending())
	}
	c.Advance(5 * time.Second)
	if got[len(got)-1] != "late@10s" || late() {
		t.Fatalf("got %v", got)
	}
}
