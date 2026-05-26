package ebpf

import (
	"testing"
	"time"
)

func TestRateLimiterDisabled(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Enabled:       false,
		DefaultRateMs: 100,
		DefaultBurst:  40,
	})

	// All events should be allowed when disabled
	for i := 0; i < 100; i++ {
		if !rl.Allow("test_rule") {
			t.Fatalf("event %d should be allowed when rate limiting is disabled", i)
		}
	}
}

func TestRateLimiterBurst(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Enabled:       true,
		DefaultRateMs: 1000, // 1 second between events (slow refill)
		DefaultBurst:  5,    // small burst for easy testing
	})

	// First 5 events should be allowed (burst)
	for i := 0; i < 5; i++ {
		if !rl.Allow("test_rule") {
			t.Fatalf("event %d should be allowed (within burst)", i)
		}
	}

	// Next event should be dropped (burst exhausted, no time to refill)
	if rl.Allow("test_rule") {
		t.Fatal("event 6 should be dropped (burst exhausted)")
	}
}

func TestRateLimiterRefill(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Enabled:       true,
		DefaultRateMs: 10, // 10ms between events
		DefaultBurst:  2,
	})

	// Exhaust burst
	rl.Allow("test_rule")
	rl.Allow("test_rule")

	// Should be dropped immediately
	if rl.Allow("test_rule") {
		t.Fatal("should be dropped after burst exhausted")
	}

	// Wait for refill
	time.Sleep(15 * time.Millisecond)

	// Should be allowed after refill
	if !rl.Allow("test_rule") {
		t.Fatal("should be allowed after refill period")
	}
}

func TestRateLimiterPerRule(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Enabled:       true,
		DefaultRateMs: 1000,
		DefaultBurst:  2,
	})

	// Each rule gets its own bucket
	rl.Allow("rule_a")
	rl.Allow("rule_a")
	// rule_a exhausted

	// rule_b should still work (separate bucket)
	if !rl.Allow("rule_b") {
		t.Fatal("rule_b should have its own bucket")
	}
}

func TestRateLimiterUnlimitedOverride(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Enabled:       true,
		DefaultRateMs: 1000,
		DefaultBurst:  1,
		RuleOverrides: map[string]RuleRateConfig{
			"heartbeat": {Unlimited: true},
		},
	})

	// Unlimited rule should never be dropped
	for i := 0; i < 100; i++ {
		if !rl.Allow("heartbeat") {
			t.Fatalf("heartbeat event %d should never be rate limited", i)
		}
	}
}

func TestRateLimiterCustomOverride(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Enabled:       true,
		DefaultRateMs: 1000,
		DefaultBurst:  1,
		RuleOverrides: map[string]RuleRateConfig{
			"noisy_rule": {RateMs: 5000, Burst: 2},
		},
	})

	// noisy_rule gets custom burst of 2
	if !rl.Allow("noisy_rule") {
		t.Fatal("first event should be allowed")
	}
	if !rl.Allow("noisy_rule") {
		t.Fatal("second event should be allowed (burst=2)")
	}
	if rl.Allow("noisy_rule") {
		t.Fatal("third event should be dropped (burst exhausted)")
	}
}

func TestRateLimiterStats(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Enabled:       true,
		DefaultRateMs: 1000,
		DefaultBurst:  2,
	})

	rl.Allow("rule_a") // allowed
	rl.Allow("rule_a") // allowed
	rl.Allow("rule_a") // dropped

	stats := rl.Stats()
	if stats.TotalAllowed != 2 {
		t.Fatalf("expected 2 allowed, got %d", stats.TotalAllowed)
	}
	if stats.TotalDropped != 1 {
		t.Fatalf("expected 1 dropped, got %d", stats.TotalDropped)
	}

	// Verify per-rule stats
	if len(stats.RuleStats) != 1 {
		t.Fatalf("expected 1 rule stat, got %d", len(stats.RuleStats))
	}
	if stats.RuleStats[0].Rule != "rule_a" {
		t.Fatalf("expected rule_a, got %s", stats.RuleStats[0].Rule)
	}
	if stats.RuleStats[0].Allowed != 2 {
		t.Fatalf("expected 2 allowed for rule_a, got %d", stats.RuleStats[0].Allowed)
	}
	if stats.RuleStats[0].Dropped != 1 {
		t.Fatalf("expected 1 dropped for rule_a, got %d", stats.RuleStats[0].Dropped)
	}

	// Stats should be reset after reading
	stats2 := rl.Stats()
	if stats2.TotalAllowed != 0 || stats2.TotalDropped != 0 {
		t.Fatal("stats should be reset after reading")
	}
}

func TestRateLimiterUpdateConfig(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Enabled:       true,
		DefaultRateMs: 1000,
		DefaultBurst:  2,
	})

	// Exhaust burst
	rl.Allow("test_rule")
	rl.Allow("test_rule")
	if rl.Allow("test_rule") {
		t.Fatal("should be dropped")
	}

	// Update config with larger burst - buckets are reset
	rl.UpdateConfig(RateLimiterConfig{
		Enabled:       true,
		DefaultRateMs: 1000,
		DefaultBurst:  5,
	})

	// New bucket should have full burst of 5
	for i := 0; i < 5; i++ {
		if !rl.Allow("test_rule") {
			t.Fatalf("event %d should be allowed after config update", i)
		}
	}
}

func TestRateLimiterDefaultConfig(t *testing.T) {
	// Zero values should get defaults
	rl := NewRateLimiter(RateLimiterConfig{
		Enabled: true,
	})

	// Should use DefaultRateLimitBurst (40)
	for i := 0; i < 40; i++ {
		if !rl.Allow("test_rule") {
			t.Fatalf("event %d should be allowed (default burst=40)", i)
		}
	}
}
