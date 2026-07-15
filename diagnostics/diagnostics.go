// Package diagnostics is the fixed catalog of read-only host diagnostics
// the cloud SRE agent may request. Design rules (see
// fleet/docs/features/sre-agent-remote-execution.md §5):
//
//   - Fixed catalog, never arbitrary shell: every command is a named Go
//     function with typed, validated arguments. External binaries are
//     invoked with a fixed argv (exec.CommandContext, no shell) and a
//     missing binary degrades to an inline note, never an error.
//   - Read-only: nothing here mutates host state.
//   - Hard output caps: each section and the total are byte-capped so a
//     noisy journal can never bloat the command result document.
//
// This file is deliberately self-contained and boring — customers are
// expected to read it to see exactly what "run diagnostics" can do.
package diagnostics

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const (
	// MaxTotalBytes caps a whole diagnostics result.
	MaxTotalBytes = 256 * 1024
	// maxSectionBytes caps each bundle section.
	maxSectionBytes = 32 * 1024

	maxJournalLines  = 500
	maxSinceMinutes  = 24 * 60
	maxProcessRows   = 50
	execTimeout      = 10 * time.Second
	truncationNotice = "\n[output truncated]"
)

var unitNameRe = regexp.MustCompile(`^[a-zA-Z0-9@:._-]{1,128}$`)

// JournalArgs — diagnostics.journal.
type JournalArgs struct {
	Unit         string `json:"unit"`
	SinceMinutes int    `json:"since_minutes"`
	Grep         string `json:"grep"`
	Lines        int    `json:"lines"`
}

// ProcessesArgs — diagnostics.processes.
type ProcessesArgs struct {
	Sort  string `json:"sort"` // cpu|mem
	Limit int    `json:"limit"`
}

// BundleArgs — diagnostics.bundle.
type BundleArgs struct {
	Units        []string `json:"units"`
	SinceMinutes int      `json:"since_minutes"`
}

// Result is the uniform payload returned for every diagnostics command.
type Result struct {
	Kind        string `json:"kind"`
	Output      string `json:"output"`
	Truncated   bool   `json:"truncated"`
	CollectedAt string `json:"collected_at"`
}

func newResult(kind, output string) Result {
	truncated := false
	if len(output) > MaxTotalBytes {
		output = output[:MaxTotalBytes] + truncationNotice
		truncated = true
	}
	return Result{
		Kind:        kind,
		Output:      output,
		Truncated:   truncated,
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// runFixed executes a binary with a fixed argv and returns capped output.
// No shell is ever involved. A missing binary or failure returns an inline
// note so bundle sections stay best-effort.
func runFixed(ctx context.Context, cap int, name string, args ...string) string {
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		var stderr string
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = strings.TrimSpace(string(ee.Stderr))
		}
		if stderr != "" {
			return fmt.Sprintf("(%s failed: %s)", name, firstLine(stderr))
		}
		return fmt.Sprintf("(%s unavailable: %v)", name, err)
	}
	s := string(bytes.TrimSpace(out))
	if len(s) > cap {
		s = s[:cap] + truncationNotice
	}
	return s
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func readProcFile(path string, cap int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("(%s unreadable: %v)", path, err)
	}
	s := strings.TrimSpace(string(data))
	if len(s) > cap {
		s = s[:cap] + truncationNotice
	}
	return s
}

// Journal returns recent journal lines for one validated unit.
func Journal(ctx context.Context, args JournalArgs) (Result, error) {
	if args.Unit != "" && !unitNameRe.MatchString(args.Unit) {
		return Result{}, fmt.Errorf("invalid unit name")
	}
	lines := args.Lines
	if lines <= 0 || lines > maxJournalLines {
		lines = 200
	}
	since := args.SinceMinutes
	if since <= 0 || since > maxSinceMinutes {
		since = 60
	}

	argv := []string{"--no-pager", "-o", "short-iso",
		"-n", fmt.Sprintf("%d", lines),
		"--since", fmt.Sprintf("-%dmin", since)}
	if args.Unit != "" {
		argv = append(argv, "-u", args.Unit)
	}
	out := runFixed(ctx, MaxTotalBytes, "journalctl", argv...)

	// Grep is applied in-process (plain case-insensitive substring, never a
	// journalctl arg) so no user input reaches an external binary's parser.
	if args.Grep != "" {
		needle := strings.ToLower(args.Grep)
		var kept []string
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(strings.ToLower(line), needle) {
				kept = append(kept, line)
			}
		}
		out = strings.Join(kept, "\n")
		if out == "" {
			out = fmt.Sprintf("(no lines matched %q in the last %d minutes)", args.Grep, since)
		}
	}
	return newResult("journal", out), nil
}

// Processes returns the top processes by CPU or memory.
func Processes(ctx context.Context, args ProcessesArgs) (Result, error) {
	sortKey := "-%cpu"
	if args.Sort == "mem" {
		sortKey = "-rss"
	} else if args.Sort != "" && args.Sort != "cpu" {
		return Result{}, fmt.Errorf("sort must be cpu or mem")
	}
	limit := args.Limit
	if limit <= 0 || limit > maxProcessRows {
		limit = 15
	}

	// args column is capped via ps's own column width so secrets passed as
	// long CLI flags don't leak wholesale into evidence.
	out := runFixed(ctx, MaxTotalBytes, "ps", "axo",
		"pid,ppid,user:16,%cpu,%mem,rss,etime,args:120", "--sort", sortKey)
	rows := strings.Split(out, "\n")
	if len(rows) > limit+1 {
		rows = rows[:limit+1] // header + limit
	}
	return newResult("processes", strings.Join(rows, "\n")), nil
}

// Bundle collects the whole incident picture in one round trip. Sections
// are independent and best-effort; a failing section reports inline.
func Bundle(ctx context.Context, args BundleArgs) (Result, error) {
	var b strings.Builder

	section := func(title, body string) {
		fmt.Fprintf(&b, "== %s ==\n%s\n\n", title, body)
	}

	section("uptime/load", readProcFile("/proc/loadavg", 256)+"\nuptime: "+readProcFile("/proc/uptime", 256))
	section("memory", memorySummary())
	section("disk", runFixed(ctx, maxSectionBytes, "df", "-hP",
		"-x", "tmpfs", "-x", "devtmpfs", "-x", "overlay", "-x", "squashfs"))

	if procs, err := Processes(ctx, ProcessesArgs{Sort: "cpu", Limit: 10}); err == nil {
		section("top processes by cpu", procs.Output)
	}
	if procs, err := Processes(ctx, ProcessesArgs{Sort: "mem", Limit: 10}); err == nil {
		section("top processes by memory", procs.Output)
	}

	section("kernel log tail", tailLines(runFixed(ctx, maxSectionBytes, "dmesg", "--time-format", "iso"), 60))
	section("socket summary", runFixed(ctx, maxSectionBytes, "ss", "-s"))

	since := args.SinceMinutes
	if since <= 0 || since > maxSinceMinutes {
		since = 30
	}
	units := args.Units
	if len(units) > 5 {
		units = units[:5]
	}
	for _, unit := range units {
		if !unitNameRe.MatchString(unit) {
			section("journal "+unit, "(skipped: invalid unit name)")
			continue
		}
		j, err := Journal(ctx, JournalArgs{Unit: unit, SinceMinutes: since, Lines: 80})
		if err == nil {
			section("journal "+unit+" (last "+fmt.Sprintf("%d", since)+"m)", capString(j.Output, maxSectionBytes))
		}
	}

	return newResult("bundle", b.String()), nil
}

// memorySummary extracts the load-bearing lines from /proc/meminfo.
func memorySummary() string {
	raw := readProcFile("/proc/meminfo", maxSectionBytes)
	want := map[string]bool{
		"MemTotal": true, "MemFree": true, "MemAvailable": true,
		"Buffers": true, "Cached": true, "SwapTotal": true,
		"SwapFree": true, "Dirty": true, "Slab": true,
	}
	var kept []string
	for _, line := range strings.Split(raw, "\n") {
		key, _, ok := strings.Cut(line, ":")
		if ok && want[strings.TrimSpace(key)] {
			kept = append(kept, line)
		}
	}
	if len(kept) == 0 {
		return raw
	}
	return strings.Join(kept, "\n")
}

func tailLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func capString(s string, cap int) string {
	if len(s) > cap {
		return s[:cap] + truncationNotice
	}
	return s
}
