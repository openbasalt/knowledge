// Package ratelimit is a per-client token bucket that keeps no client
// address: a client is known only by an HMAC of its address under a random
// key that lives in memory and is replaced every day, so the limiter
// cannot be turned into a log of who asked, and yesterday's buckets cannot
// be linked to today's.
package ratelimit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"time"
)

// Limiter limits requests per client.
type Limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	key     []byte
	keyDay  int64
	buckets map[[16]byte]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// Decision is the result of Allow.
type Decision struct {
	OK         bool
	Remaining  int
	RetryAfter time.Duration // when not OK
	Reset      time.Duration // until the bucket is full again
}

// New allows requests per period, with a burst.
func New(requests int, per time.Duration, burst int) *Limiter {
	return &Limiter{rate: float64(requests) / per.Seconds(), burst: float64(burst),
		buckets: map[[16]byte]*bucket{}, now: time.Now}
}

// SetClock replaces the clock (tests).
func (l *Limiter) SetClock(now func() time.Time) { l.now = now }

func (l *Limiter) id(client string, now time.Time) [16]byte {
	day := now.Unix() / 86400
	if l.key == nil || day != l.keyDay {
		l.key = make([]byte, 32)
		if _, err := rand.Read(l.key); err != nil {
			panic(err)
		}
		l.keyDay = day
		// A new key makes every old bucket unreachable: drop them.
		clear(l.buckets)
	}
	m := hmac.New(sha256.New, l.key)
	m.Write([]byte(client))
	var id [16]byte
	copy(id[:], m.Sum(nil))
	return id
}

// Allow spends a token of client's bucket.
func (l *Limiter) Allow(client string) Decision {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	id := l.id(client, now)
	bk, ok := l.buckets[id]
	if !ok {
		bk = &bucket{tokens: l.burst, last: now}
		l.buckets[id] = bk
	}
	bk.tokens = min(l.burst, bk.tokens+now.Sub(bk.last).Seconds()*l.rate)
	bk.last = now
	if len(l.buckets) > 100000 {
		l.evict(now)
	}
	reset := time.Duration((l.burst - bk.tokens) / l.rate * float64(time.Second))
	if bk.tokens < 1 {
		wait := time.Duration((1 - bk.tokens) / l.rate * float64(time.Second))
		return Decision{OK: false, RetryAfter: wait, Reset: reset}
	}
	bk.tokens--
	return Decision{OK: true, Remaining: int(bk.tokens), Reset: reset + time.Duration(float64(time.Second)/l.rate)}
}

// evict drops buckets that are full again (idle clients).
func (l *Limiter) evict(now time.Time) {
	for id, bk := range l.buckets {
		if bk.tokens+now.Sub(bk.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, id)
		}
	}
}

// Sweep drops idle buckets; call it periodically.
func (l *Limiter) Sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evict(l.now())
}

// Clients returns how many buckets are held (tests and health).
func (l *Limiter) Clients() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
