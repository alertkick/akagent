package ebpf

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultRateLimitIntervalMs is the default minimum interval between events per rule (100ms)
	DefaultRateLimitIntervalMs = 100
	// DefaultRateLimitBurst is the default burst allowance per rule
	DefaultRateLimitBurst = 40
)

// RateLimiterConfig holds configuration for per-rule rate limiting
type RateLimiterConfig struct {
	// Enabled controls whether rate limiting is active
	Enabled bool `yaml:"enabled"`

	// DefaultRateMs is the minimum interval between events in milliseconds (default 100)
	DefaultRateMs int `yaml:"default_rate_ms"`

	// DefaultBurst is the burst allowance (default 40)
	DefaultBurst int `yaml:"default_burst"`

	// RuleOverrides allows per-rule rate limit customization
	// Key is the rule name (e.g., "ssh_connection", "privilege_escalation")
	RuleOverrides map[string]RuleRateConfig `yaml:"rule_overrides,omitempty"`
}

// RuleRateConfig allows per-rule rate limit customization
type RuleRateConfig struct {
	// RateMs is the minimum interval in milliseconds (0 = use default)
	RateMs int `yaml:"rate_ms"`

	// Burst is the burst allowance (0 = use default)
	Burst int `yaml:"burst"`

	// Unlimited disables rate limiting for this rule entirely
	Unlimited bool `yaml:"unlimited,omitempty"`
}

// RuleLimiterStats contains per-rule rate limiting statistics
type RuleLimiterStats struct {
	Rule    string `json:"rule"`
	Allowed uint64 `json:"allowed"`
	Dropped uint64 `json:"dropped"`
}

// RateLimiterStats contains aggregate rate limiting statistics
type RateLimiterStats struct {
	Enabled      bool               `json:"enabled"`
	TotalAllowed uint64             `json:"total_allowed"`
	TotalDropped uint64             `json:"total_dropped"`
	RuleStats    []RuleLimiterStats `json:"rule_stats,omitempty"`
}

// tokenBucket implements a token bucket rate limiter for a single rule.
// Tokens are replenished at a fixed rate; each event consumes one token.
// When no tokens are available, events are dropped.
type tokenBucket struct {
	mu        sync.Mutex
	tokens    float64
	maxTokens float64
	rate      float64   // tokens per nanosecond
	lastTime  time.Time

	// Stats (atomic for lock-free reads from other goroutines)
	allowed atomic.Uint64
	dropped atomic.Uint64
}

func newTokenBucket(interval time.Duration, burst int) *tokenBucket {
	tokensPerNs := 1.0 / float64(interval.Nanoseconds())
	return &tokenBucket{
		tokens:    float64(burst), // start full
		maxTokens: float64(burst),
		rate:      tokensPerNs,
		lastTime:  time.Now(),
	}
}

// allow checks if an event should be allowed through the rate limiter.
func (tb *tokenBucket) allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastTime)
	tb.lastTime = now

	// Replenish tokens based on elapsed time
	tb.tokens += float64(elapsed.Nanoseconds()) * tb.rate
	if tb.tokens > tb.maxTokens {
		tb.tokens = tb.maxTokens
	}

	if tb.tokens >= 1.0 {
		tb.tokens -= 1.0
		tb.allowed.Add(1)
		return true
	}

	tb.dropped.Add(1)
	return false
}

// swapStats returns and resets the allowed/dropped counters.
func (tb *tokenBucket) swapStats() (allowed, dropped uint64) {
	return tb.allowed.Swap(0), tb.dropped.Swap(0)
}

// RateLimiter applies per-rule token bucket rate limiting to prevent
// a single noisy rule from drowning out critical alerts.
//
// Thread-safe: buckets are lazily created under a write lock and accessed
// under a read lock. Each tokenBucket has its own internal mutex.
type RateLimiter struct {
	mu      sync.RWMutex
	config  RateLimiterConfig
	buckets map[string]*tokenBucket // keyed by rule name

	// Global stats
	totalAllowed atomic.Uint64
	totalDropped atomic.Uint64
}

// NewRateLimiter creates a new per-rule rate limiter.
func NewRateLimiter(config RateLimiterConfig) *RateLimiter {
	if config.DefaultRateMs <= 0 {
		config.DefaultRateMs = DefaultRateLimitIntervalMs
	}
	if config.DefaultBurst <= 0 {
		config.DefaultBurst = DefaultRateLimitBurst
	}
	return &RateLimiter{
		config:  config,
		buckets: make(map[string]*tokenBucket),
	}
}

// Allow returns true if the event for the given rule should be allowed.
// Returns true immediately if rate limiting is disabled.
func (rl *RateLimiter) Allow(rule string) bool {
	if !rl.config.Enabled {
		return true
	}

	// Check for unlimited override
	if override, ok := rl.config.RuleOverrides[rule]; ok && override.Unlimited {
		rl.totalAllowed.Add(1)
		return true
	}

	bucket := rl.getBucket(rule)
	if bucket.allow() {
		rl.totalAllowed.Add(1)
		return true
	}

	rl.totalDropped.Add(1)
	return false
}

// getBucket returns the token bucket for a rule, creating one if needed.
func (rl *RateLimiter) getBucket(rule string) *tokenBucket {
	// Fast path: read lock
	rl.mu.RLock()
	bucket, ok := rl.buckets[rule]
	rl.mu.RUnlock()
	if ok {
		return bucket
	}

	// Slow path: write lock to create bucket
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Double-check after acquiring write lock
	if bucket, ok := rl.buckets[rule]; ok {
		return bucket
	}

	interval, burst := rl.configForRule(rule)
	bucket = newTokenBucket(interval, burst)
	rl.buckets[rule] = bucket
	return bucket
}

// configForRule returns the rate limit interval and burst for a specific rule.
func (rl *RateLimiter) configForRule(rule string) (interval time.Duration, burst int) {
	if override, ok := rl.config.RuleOverrides[rule]; ok {
		interval = time.Duration(override.RateMs) * time.Millisecond
		burst = override.Burst
		if interval <= 0 {
			interval = time.Duration(rl.config.DefaultRateMs) * time.Millisecond
		}
		if burst <= 0 {
			burst = rl.config.DefaultBurst
		}
		return interval, burst
	}
	return time.Duration(rl.config.DefaultRateMs) * time.Millisecond, rl.config.DefaultBurst
}

// Stats returns rate limiting statistics and resets per-rule counters.
func (rl *RateLimiter) Stats() RateLimiterStats {
	stats := RateLimiterStats{
		Enabled:      rl.config.Enabled,
		TotalAllowed: rl.totalAllowed.Swap(0),
		TotalDropped: rl.totalDropped.Swap(0),
	}

	rl.mu.RLock()
	defer rl.mu.RUnlock()

	for rule, bucket := range rl.buckets {
		allowed, dropped := bucket.swapStats()
		if allowed > 0 || dropped > 0 {
			stats.RuleStats = append(stats.RuleStats, RuleLimiterStats{
				Rule:    rule,
				Allowed: allowed,
				Dropped: dropped,
			})
		}
	}

	return stats
}

// UpdateConfig replaces the rate limiter configuration.
// Existing buckets are cleared so new rates take effect immediately.
func (rl *RateLimiter) UpdateConfig(config RateLimiterConfig) {
	if config.DefaultRateMs <= 0 {
		config.DefaultRateMs = DefaultRateLimitIntervalMs
	}
	if config.DefaultBurst <= 0 {
		config.DefaultBurst = DefaultRateLimitBurst
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.config = config
	rl.buckets = make(map[string]*tokenBucket) // reset buckets for new config
}
