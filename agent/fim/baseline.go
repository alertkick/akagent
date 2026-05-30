// Package fim implements file integrity monitoring: a checksum baseline of
// system binaries and /etc, re-verified when an eBPF file event touches a
// monitored path, raising a finding when a file's content changes.
//
// The package is deliberately free of any ebpf dependency so it can be unit
// tested in isolation; the agent wiring translates between ebpf events/config
// and this package's Trigger/Config/Change types.
package fim

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Entry is a single file's baseline: its digest plus size+mtime, which act as
// a cheap "probably unchanged" fast-path so a rescan doesn't re-hash the whole
// tree.
type Entry struct {
	Hash    string `json:"hash"`
	Size    int64  `json:"size"`
	MtimeNs int64  `json:"mtime_ns"`
}

// Baseline maps an absolute file path to its recorded Entry.
type Baseline map[string]Entry

// hashFile returns the hex digest of path under algo ("sha256" default, or
// "md5"). Reads the file streaming so a large binary doesn't balloon memory.
func hashFile(path, algo string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var h hash.Hash
	switch algo {
	case "md5":
		h = md5.New()
	default:
		h = sha256.New()
	}
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// IsExcluded reports whether path falls under any exclude prefix.
func IsExcluded(path string, exclude []string) bool {
	for _, ex := range exclude {
		if ex == "" {
			continue
		}
		if path == ex || strings.HasPrefix(path, ex+"/") || strings.HasPrefix(path, ex) {
			return true
		}
	}
	return false
}

// Scan walks every path in roots (recursively), skipping excluded prefixes and
// anything that isn't a regular file (symlinks, sockets, devices), and returns
// a fresh Baseline. When prev is non-nil, a file whose size and mtime match the
// previous Entry is carried over without re-hashing — the fast-path that keeps
// a rescan cheap. Unreadable files/dirs are skipped rather than failing the
// whole scan.
func Scan(roots, exclude []string, algo string, prev Baseline) Baseline {
	out := make(Baseline)
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				// Unreadable path — skip it (and its subtree if a dir) but
				// keep scanning the rest.
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if IsExcluded(p, exclude) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			if IsExcluded(p, exclude) {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			size := info.Size()
			mtime := info.ModTime().UnixNano()
			if prev != nil {
				if e, ok := prev[p]; ok && e.Size == size && e.MtimeNs == mtime && e.Hash != "" {
					out[p] = e
					return nil
				}
			}
			digest, err := hashFile(p, algo)
			if err != nil {
				return nil
			}
			out[p] = Entry{Hash: digest, Size: size, MtimeNs: mtime}
			return nil
		})
	}
	return out
}

// hashOne is the single-file equivalent used by the runtime re-check. Returns
// ("", nil) when the file no longer exists (a removal), and an Entry otherwise.
func hashOne(path, algo string) (Entry, bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Entry{}, false, nil
		}
		return Entry{}, false, err
	}
	if !info.Mode().IsRegular() {
		// A monitored path replaced by a symlink/special file is itself a
		// change worth surfacing, but we can't hash it — report as missing.
		return Entry{}, false, nil
	}
	digest, err := hashFile(path, algo)
	if err != nil {
		return Entry{}, false, err
	}
	return Entry{Hash: digest, Size: info.Size(), MtimeNs: info.ModTime().UnixNano()}, true, nil
}
