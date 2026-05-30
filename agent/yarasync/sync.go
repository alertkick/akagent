// Package yarasync keeps the host's YARA ruleset up to date by polling the
// control plane for the current bundle and atomically swapping it into place.
// It is transport-simple on purpose: a conditional GET keyed on the bundle
// version, an atomic temp-file+rename write, and a callback so the scanner can
// pick up the new rules without a restart.
package yarasync

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Config controls the syncer.
type Config struct {
	URL             string // ruleset endpoint, e.g. https://api.example.com/api/v1/agent/yara-rules/current
	Token           string // bearer token for the endpoint (optional)
	RulesPath       string // where to write the bundle (the scanner reads this)
	IntervalSeconds int    // poll interval (default 3600)
}

// Syncer periodically refreshes the local ruleset.
type Syncer struct {
	cfg      Config
	onUpdate func(rulesPath string)
	client   *http.Client
	version  string
	stop     chan struct{}
}

// New builds a Syncer. onUpdate is invoked after a successful swap so the
// scanner can re-point at the new rules.
func New(cfg Config, onUpdate func(rulesPath string)) *Syncer {
	if cfg.IntervalSeconds <= 0 {
		cfg.IntervalSeconds = 3600
	}
	return &Syncer{
		cfg:      cfg,
		onUpdate: onUpdate,
		client:   &http.Client{Timeout: 60 * time.Second},
		stop:     make(chan struct{}),
	}
}

// Start syncs immediately, then on the configured interval. No-op without a URL.
func (s *Syncer) Start() {
	if s.cfg.URL == "" {
		return
	}
	go func() {
		s.SyncOnce()
		t := time.NewTicker(time.Duration(s.cfg.IntervalSeconds) * time.Second)
		defer t.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-t.C:
				s.SyncOnce()
			}
		}
	}()
}

// Stop ends the poll loop.
func (s *Syncer) Stop() { close(s.stop) }

// SyncOnce performs one conditional fetch. Returns (updated, error): updated is
// true when a new bundle was written. Exported for tests.
func (s *Syncer) SyncOnce() (bool, error) {
	req, err := http.NewRequest(http.MethodGet, s.cfg.URL, nil)
	if err != nil {
		return false, err
	}
	if s.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	}
	if s.version != "" {
		req.Header.Set("If-None-Match", s.version)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, &httpError{resp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024*1024))
	if err != nil {
		return false, err
	}
	if len(body) == 0 {
		return false, nil
	}
	if err := writeAtomic(s.cfg.RulesPath, body); err != nil {
		return false, err
	}
	s.version = resp.Header.Get("ETag")
	if s.onUpdate != nil {
		s.onUpdate(s.cfg.RulesPath)
	}
	return true, nil
}

// writeAtomic writes data to path via a temp file + rename so a concurrent
// scan never reads a half-written ruleset.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".yara-rules-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

type httpError struct{ code int }

func (e *httpError) Error() string { return "yara-rules sync: unexpected status " + itoa(e.code) }

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [12]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
