//go:build linux

package ebpf

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SSHDConfig holds the discovered listening-port set for the local sshd.
// Defaults to {22} when no Port directive is found — that's how sshd
// behaves itself, so any tooling that consults this resolver gets the
// kernel-correct answer even with an empty config.
//
// Why a struct and not a bare []int: we also want to cache the source
// path resolved + the last refresh time so the agent's status surface
// can show "ports discovered from /etc/ssh/sshd_config.d/50-custom.conf
// at 12:34". Ops asking "why did lockdown fail to block port X" can
// answer themselves without reading agent source.
type SSHDConfig struct {
	Ports        []int     // distinct listening ports, sorted ascending
	SourcePaths  []string  // every config file consulted (root + Include matches)
	RefreshedAt  time.Time // when the snapshot was taken
}

// HasPort returns whether p is one of the listening ports. Sentinel for
// the always-default behaviour: if the snapshot is empty (zero-value
// SSHDConfig — never refreshed), we fall back to "yes" only for 22 so
// stale-snapshot pathways don't silently miss SSH detection on a default
// install.
func (c *SSHDConfig) HasPort(p int) bool {
	if c == nil || len(c.Ports) == 0 {
		return p == 22
	}
	for _, port := range c.Ports {
		if port == p {
			return true
		}
	}
	return false
}

// SSHDConfigReader resolves the listening ports of the local sshd by
// parsing sshd_config plus any `Include` files. The reader is goroutine-
// safe; in-place atomic-store of the parsed snapshot lets the hot path
// read without taking a lock.
type SSHDConfigReader struct {
	rootPath        string
	includeRootGlob string // expanded relative to rootPath when Include patterns are relative
	mu              sync.RWMutex
	snapshot        *SSHDConfig
}

// NewSSHDConfigReader returns a reader pointing at the canonical Linux
// sshd_config location. Callers wanting a different path (tests,
// chroots) use NewSSHDConfigReaderAt.
func NewSSHDConfigReader() *SSHDConfigReader {
	return NewSSHDConfigReaderAt("/etc/ssh/sshd_config")
}

// NewSSHDConfigReaderAt builds a reader for a specific sshd_config path.
// Include patterns are resolved relative to the directory of this path,
// matching sshd's own behaviour.
func NewSSHDConfigReaderAt(path string) *SSHDConfigReader {
	return &SSHDConfigReader{rootPath: path}
}

// Snapshot returns the most recently parsed config, or nil if Refresh
// has not yet been called. Callers should treat nil as "use defaults".
func (r *SSHDConfigReader) Snapshot() *SSHDConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.snapshot
}

// Refresh re-reads sshd_config + its includes and atomically swaps in a
// new snapshot. Returns the new snapshot and any error encountered. Even
// on error the previous snapshot is retained so a transient FS hiccup
// doesn't roll the agent back to bare defaults mid-flight.
func (r *SSHDConfigReader) Refresh() (*SSHDConfig, error) {
	snap, err := parseSSHDConfig(r.rootPath)
	if err != nil {
		// Don't overwrite a good snapshot with a partial/failed read.
		// Callers see the error; the snapshot accessor returns the last
		// known good state.
		return r.Snapshot(), err
	}
	r.mu.Lock()
	r.snapshot = snap
	r.mu.Unlock()
	return snap, nil
}

// parseSSHDConfig is the core parser. Exported via Refresh; kept free
// of the reader struct so tests can drive it with a path string and
// nothing else.
//
// Semantics mirror sshd:
//   - Comments start with '#'.
//   - Tokens are space-separated; the first is the directive.
//   - "Port N" — each occurrence adds N to the port set.
//   - "Include <glob>" — globs are expanded; relative globs are taken
//     relative to the directory of the file containing the directive.
//   - Match blocks: sshd treats Port inside a Match block as a per-
//     condition override of the default. We treat any Port directive,
//     in or out of Match, as a candidate listener — wrong for a hardened
//     setup, but the agent's goal is "what could legitimately be SSH
//     traffic" which is a superset, not a strict configuration replica.
//
// Includes are followed depth-first and de-duplicated by absolute path
// so an Include cycle terminates cleanly.
func parseSSHDConfig(rootPath string) (*SSHDConfig, error) {
	seen := make(map[string]bool)
	ports := make(map[int]struct{})
	var sourcePaths []string

	var walk func(path string) error
	walk = func(path string) error {
		abs, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if seen[abs] {
			return nil
		}
		seen[abs] = true

		f, err := os.Open(abs)
		if err != nil {
			return err
		}
		defer f.Close()

		sourcePaths = append(sourcePaths, abs)
		scanner := bufio.NewScanner(f)
		// sshd_config lines are short, but Include patterns can balloon.
		scanner.Buffer(make([]byte, 8*1024), 128*1024)
		for scanner.Scan() {
			tok := tokeniseSSHDLine(scanner.Text())
			if len(tok) == 0 {
				continue
			}
			directive := strings.ToLower(tok[0])
			switch directive {
			case "port":
				if len(tok) < 2 {
					continue
				}
				if n, err := strconv.Atoi(tok[1]); err == nil && n > 0 && n < 65536 {
					ports[n] = struct{}{}
				}
			case "include":
				baseDir := filepath.Dir(abs)
				for _, raw := range tok[1:] {
					pattern := raw
					if !filepath.IsAbs(pattern) {
						pattern = filepath.Join(baseDir, pattern)
					}
					matches, _ := filepath.Glob(pattern)
					for _, m := range matches {
						_ = walk(m)
					}
				}
			}
		}
		// scanner.Err() ignored on purpose — a partial read still gives us
		// the directives we managed to parse, which is better than zero.
		_ = scanner.Err()
		return nil
	}

	if err := walk(rootPath); err != nil {
		return nil, err
	}

	out := make([]int, 0, len(ports))
	for p := range ports {
		out = append(out, p)
	}
	if len(out) == 0 {
		// sshd's documented default. Avoid surfacing an empty slice so
		// downstream HasPort doesn't need a "if empty assume 22" branch
		// at every call site.
		out = []int{22}
	}
	sortInts(out)
	return &SSHDConfig{
		Ports:       out,
		SourcePaths: sourcePaths,
		RefreshedAt: time.Now(),
	}, nil
}

// tokeniseSSHDLine strips comments and splits on whitespace. Quoted
// tokens are preserved literally — sshd_config rarely uses them but
// some Include patterns get quoted.
func tokeniseSSHDLine(line string) []string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	// Cheap quoted-string handling: split on whitespace, then strip
	// matched outer quotes per token.
	fields := strings.Fields(line)
	for i, f := range fields {
		if len(f) >= 2 {
			if (f[0] == '"' && f[len(f)-1] == '"') || (f[0] == '\'' && f[len(f)-1] == '\'') {
				fields[i] = f[1 : len(f)-1]
			}
		}
	}
	return fields
}

// sortInts — tiny helper so we don't pull in "sort" for one call.
func sortInts(s []int) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
