package selfupdate

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The agent's release assets are named "exnode-<os>-<arch>" (see the release
// workflow and install.sh); the fallback URL must match that.
func TestAssetURLUsesReleaseNaming(t *testing.T) {
	t.Setenv("EXNODE_REPO", "")
	got := assetURL("v1.2.3")
	want := "https://github.com/nexpool/exnode/releases/download/v1.2.3/exnode-" + runtime.GOOS + "-" + runtime.GOARCH
	if got != want {
		t.Fatalf("assetURL = %q, want %q", got, want)
	}

	t.Setenv("EXNODE_REPO", "acme/mirror/")
	if got := assetURL("v1.2.3"); !strings.HasPrefix(got, "https://github.com/acme/mirror/releases/download/") {
		t.Fatalf("EXNODE_REPO override ignored: %q", got)
	}
}

func TestDownloadRejectsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	if _, err := download(srv.URL, t.TempDir()); err == nil {
		t.Fatal("expected an error for a 404 download")
	}
}

// A truncated body (or an HTML error page served with 200) must never be
// installed over a working binary.
func TestDownloadRejectsTinyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("<html>"), 10))
	}))
	defer srv.Close()

	_, err := download(srv.URL, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "too small") {
		t.Fatalf("expected a size rejection, got %v", err)
	}
}

// A real executable of plausible size is accepted and lands in the target dir.
func TestDownloadAcceptsExecutable(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skipf("cannot locate the test binary: %v", err)
	}
	blob, err := os.ReadFile(self)
	if err != nil || len(blob) < minBinarySize {
		t.Skipf("test binary too small to exercise the size check (%d bytes)", len(blob))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(blob)
	}))
	defer srv.Close()

	dir := t.TempDir()
	path, err := download(srv.URL, dir)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if filepath.Dir(path) != dir {
		t.Fatalf("temp file %q not created in %q", path, dir)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(got) != len(blob) {
		t.Fatalf("downloaded %d bytes, want %d", len(got), len(blob))
	}
}

// An order for the version we already run is a no-op: nothing is downloaded and
// no error is recorded.
func TestMaybeUpgradeIgnoresCurrentVersion(t *testing.T) {
	ClearError()
	Maybe(nil, "v1.0.0")
	Maybe(&Order{Version: "v1.0.0", URL: "http://127.0.0.1:1/none"}, "v1.0.0")
	if msg := PendingError(); msg != "" {
		t.Fatalf("no-op upgrade recorded an error: %q", msg)
	}
}

// A failed download is remembered once for the next heartbeat and cleared after
// it has been reported.
func TestMaybeUpgradeRecordsFailure(t *testing.T) {
	ClearError()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusGone)
	}))
	defer srv.Close()

	Maybe(&Order{Version: "v9.9.9", URL: srv.URL}, "v1.0.0")

	msg := PendingError()
	if !strings.Contains(msg, "v9.9.9") || !strings.Contains(msg, "status 410") {
		t.Fatalf("unexpected upgrade error: %q", msg)
	}
	ClearError()
	if msg := PendingError(); msg != "" {
		t.Fatalf("error not cleared: %q", msg)
	}
}
