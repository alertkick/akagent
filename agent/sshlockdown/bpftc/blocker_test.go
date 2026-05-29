//go:build linux

package bpftc

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
	_, ones, isV6, ok := parseCIDROrIP("10.0.0.0/24")
	if !ok || isV6 {
		t.Fatalf("expected v4 cidr ok, got ok=%v v6=%v", ok, isV6)
	}
	if ones != 24 {
		t.Errorf("ones = %d, want 24", ones)
	}
}

func TestParseCIDROrIP_V6CIDR(t *testing.T) {
	_, ones, isV6, ok := parseCIDROrIP("2001:db8::/32")
	if !ok || !isV6 || ones != 32 {
		t.Fatalf("v6 cidr parse: ok=%v v6=%v ones=%d", ok, isV6, ones)
	}
}

func TestParseCIDROrIP_Bad(t *testing.T) {
	for _, in := range []string{"", "not-an-ip", "999.999.999.999", "10.0.0.0/99"} {
		if _, _, _, ok := parseCIDROrIP(in); ok {
			t.Errorf("parseCIDROrIP(%q) should fail, got ok=true", in)
		}
	}
}

func TestWallToMonoNs(t *testing.T) {
	if got := wallToMonoNs(time.Time{}, time.Now().Add(time.Hour)); got != -1 {
		t.Errorf("zero boot should return -1, got %d", got)
	}
	boot := time.Now().Add(-time.Hour)
	if got := wallToMonoNs(boot, boot.Add(-time.Second)); got != -1 {
		t.Errorf("past target should return -1, got %d", got)
	}
	boot = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if got := wallToMonoNs(boot, boot.Add(123*time.Second)); got != int64(123*1e9) {
		t.Errorf("wallToMonoNs delta = %d, want %d", got, int64(123*1e9))
	}
}

func TestLPMKeySizes(t *testing.T) {
	// LPM trie keys must be packed exactly — kernel rejects otherwise.
	var v4 lpmV4Key
	if got := unsafe.Sizeof(v4); got != 4+4 {
		t.Fatalf("lpmV4Key size = %d, want 8 (padding regression)", got)
	}
	var v6 lpmV6Key
	if got := unsafe.Sizeof(v6); got != 4+16 {
		t.Fatalf("lpmV6Key size = %d, want 20", got)
	}
}

func TestEligibleByNameAndFlags(t *testing.T) {
	cases := []struct {
		name         string
		flags        net.Flags
		ifaceName    string
		wantEligible bool
	}{
		{"loopback skipped", net.FlagLoopback | net.FlagUp, "lo", false},
		{"down link skipped", 0, "eth0", false},
		{"docker bridge skipped", net.FlagUp, "docker0", false},
		{"cni bridge skipped", net.FlagUp, "cni0", false},
		{"normal eth0 eligible", net.FlagUp, "eth0", true},
		{"wireguard up eligible", net.FlagUp, "wg0", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := eligibleByNameAndFlags(c.ifaceName, c.flags)
			if got != c.wantEligible {
				t.Errorf("eligibleByNameAndFlags(%s, flags=%v) = %v, want %v", c.ifaceName, c.flags, got, c.wantEligible)
			}
		})
	}
}
