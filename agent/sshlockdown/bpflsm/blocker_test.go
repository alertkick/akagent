//go:build linux

package bpflsm

import (
	"bytes"
	"net"
	"testing"
	"time"
	"unsafe"
)

func TestParseCIDROrIP_BareV4(t *testing.T) {
	ip, ones, isV6, ok := parseCIDROrIP("10.0.0.7")
	if !ok || isV6 {
		t.Fatalf("expected v4 ok=true v6=false, got ok=%v v6=%v", ok, isV6)
	}
	if ones != 32 {
		t.Errorf("bare IP should imply /32, got /%d", ones)
	}
	if !bytes.Equal(ip, []byte{10, 0, 0, 7}) {
		t.Errorf("bytes = %v, want [10 0 0 7]", ip)
	}
}

func TestParseCIDROrIP_V4CIDR(t *testing.T) {
	ip, ones, isV6, ok := parseCIDROrIP("10.0.0.0/24")
	if !ok || isV6 {
		t.Fatalf("expected v4 cidr ok, got ok=%v v6=%v", ok, isV6)
	}
	if ones != 24 {
		t.Errorf("ones = %d, want 24", ones)
	}
	if !bytes.Equal(ip, []byte{10, 0, 0, 0}) {
		t.Errorf("network bytes = %v, want [10 0 0 0]", ip)
	}
}

func TestParseCIDROrIP_V6CIDR(t *testing.T) {
	ip, ones, isV6, ok := parseCIDROrIP("2001:db8::/32")
	if !ok || !isV6 {
		t.Fatalf("expected v6 cidr ok, got ok=%v v6=%v", ok, isV6)
	}
	if ones != 32 {
		t.Errorf("ones = %d, want 32", ones)
	}
	if len(ip) != 16 {
		t.Errorf("ip len = %d, want 16", len(ip))
	}
}

func TestParseCIDROrIP_BareV6(t *testing.T) {
	ip, ones, isV6, ok := parseCIDROrIP("2001:db8::1")
	if !ok || !isV6 {
		t.Fatalf("expected v6 bare ok, got ok=%v v6=%v", ok, isV6)
	}
	if ones != 128 {
		t.Errorf("bare v6 should imply /128, got /%d", ones)
	}
	if len(ip) != 16 {
		t.Errorf("ip len = %d, want 16", len(ip))
	}
}

func TestParseCIDROrIP_Bad(t *testing.T) {
	for _, in := range []string{"", "not-an-ip", "999.999.999.999", "10.0.0.0/99"} {
		if _, _, _, ok := parseCIDROrIP(in); ok {
			t.Errorf("parseCIDROrIP(%q) should fail, got ok=true", in)
		}
	}
}

func TestWallToMonoNs_ZeroBootReturnsNeg(t *testing.T) {
	got := wallToMonoNs(time.Time{}, time.Now().Add(time.Hour))
	if got != -1 {
		t.Errorf("wallToMonoNs with zero boot = %d, want -1", got)
	}
}

func TestWallToMonoNs_PastTargetReturnsNeg(t *testing.T) {
	boot := time.Now().Add(-time.Hour)
	got := wallToMonoNs(boot, boot.Add(-time.Minute)) // before boot
	if got != -1 {
		t.Errorf("past target = %d, want -1", got)
	}
}

func TestWallToMonoNs_FutureTargetMatchesDelta(t *testing.T) {
	boot := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	target := boot.Add(123 * time.Second)
	got := wallToMonoNs(boot, target)
	if want := int64(123 * 1e9); got != want {
		t.Errorf("wallToMonoNs = %d, want %d", got, want)
	}
}

func TestLPMV4KeyLayout(t *testing.T) {
	// Verify the struct lays out as {u32 prefixlen, u8[4] data} with no
	// padding. The kernel's LPM trie is strict about this — a wrong
	// layout means silently rejected inserts (or worse, storing under
	// the wrong key).
	var k lpmV4Key
	k.Prefixlen = 0x11223344
	copy(k.Data[:], net.IPv4(10, 0, 0, 7).To4())
	const want = 4 + 4
	if got := unsafe.Sizeof(k); got != want {
		t.Fatalf("lpmV4Key size = %d, want %d (struct padding regression)", got, want)
	}
}

func TestLPMV6KeyLayout(t *testing.T) {
	var k lpmV6Key
	const want = 4 + 16
	if got := unsafe.Sizeof(k); got != want {
		t.Fatalf("lpmV6Key size = %d, want %d", got, want)
	}
}
