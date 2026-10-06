package ratelimit

import (
	"testing"
	"time"
)

func TestBucket(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	l := New(60, time.Minute, 2)
	l.SetClock(func() time.Time { return now })
	if !l.Allow("a").OK || !l.Allow("a").OK {
		t.Fatal("burst refused")
	}
	d := l.Allow("a")
	if d.OK || d.RetryAfter <= 0 || d.RetryAfter > time.Second {
		t.Fatalf("third request: %+v", d)
	}
	if !l.Allow("b").OK {
		t.Fatal("another client limited")
	}
	now = now.Add(time.Second)
	if !l.Allow("a").OK {
		t.Fatal("not refilled")
	}
	// Idle buckets go away.
	now = now.Add(time.Minute)
	l.Sweep()
	if n := l.Clients(); n != 0 {
		t.Fatalf("%d buckets after sweep", n)
	}
}

// The key changes every day and old buckets are dropped with it.
func TestDailyKey(t *testing.T) {
	now := time.Date(2026, 10, 5, 23, 59, 0, 0, time.UTC)
	l := New(1, time.Hour, 1)
	l.SetClock(func() time.Time { return now })
	l.Allow("a")
	k1 := string(l.key)
	now = now.Add(2 * time.Minute)
	if !l.Allow("a").OK {
		t.Fatal("bucket survived the key change")
	}
	if string(l.key) == k1 {
		t.Fatal("key not replaced")
	}
}
