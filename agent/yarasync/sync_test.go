package yarasync

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestSyncOnceWritesAndConditional(t *testing.T) {
	const version = "v1-abc"
	var serveBody = "rule x { condition: true }"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == version {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", version)
		w.Write([]byte(serveBody))
	}))
	defer srv.Close()

	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.yar")
	var updates int
	s := New(Config{URL: srv.URL, RulesPath: rules}, func(string) { updates++ })

	// First sync writes the bundle.
	updated, err := s.SyncOnce()
	if err != nil || !updated {
		t.Fatalf("first sync: updated=%v err=%v", updated, err)
	}
	b, _ := os.ReadFile(rules)
	if string(b) != serveBody {
		t.Fatalf("rules not written: %q", b)
	}
	if updates != 1 {
		t.Fatalf("expected 1 onUpdate, got %d", updates)
	}

	// Second sync sends If-None-Match and gets 304 — no rewrite, no callback.
	updated, err = s.SyncOnce()
	if err != nil || updated {
		t.Fatalf("second sync should be no-op: updated=%v err=%v", updated, err)
	}
	if updates != 1 {
		t.Fatalf("onUpdate should not fire on 304, got %d", updates)
	}
}

func TestSyncOnceServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	s := New(Config{URL: srv.URL, RulesPath: filepath.Join(t.TempDir(), "r.yar")}, nil)
	if _, err := s.SyncOnce(); err == nil {
		t.Fatal("expected error on 500")
	}
}
