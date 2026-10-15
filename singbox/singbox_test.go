package singbox

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// resetRetry clears the install cooldown so tests do not influence each other.
func resetRetry() {
	mu.Lock()
	defer mu.Unlock()
	lastAttempt = time.Time{}
	lastErr = nil
}

// The release asset naming has to match what GitHub publishes.
func TestAssetName(t *testing.T) {
	if got, want := assetName("v1.14.3", "linux", "amd64"), "sing-box-1.14.3-linux-amd64.tar.gz"; got != want {
		t.Fatalf("assetName = %q, want %q", got, want)
	}
	if got := assetName("1.14.3", "darwin", "arm64"); got != "sing-box-1.14.3-darwin-arm64.tar.gz" {
		t.Fatalf("assetName without v = %q", got)
	}
}

func tarball(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, data := range files {
		hdr := &tar.Header{Name: name, Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A tarball with the usual layout is unpacked down to the binary.
func TestExtractBinary(t *testing.T) {
	blob := tarball(t, map[string][]byte{
		"sing-box-1.14.3-linux-amd64/LICENSE":  []byte("license"),
		"sing-box-1.14.3-linux-amd64/sing-box": []byte("BINARY"),
	})
	bin, err := extractBinary(blob)
	if err != nil {
		t.Fatalf("extractBinary: %v", err)
	}
	if string(bin) != "BINARY" {
		t.Fatalf("extracted %q", bin)
	}
	if _, err := extractBinary([]byte("not a tarball")); err == nil {
		t.Fatal("a non-tarball must fail")
	}
	if _, err := extractBinary(tarball(t, map[string][]byte{"x/README": []byte("hi")})); err == nil {
		t.Fatal("a tarball without sing-box must fail")
	}
}

// An executable we point at directly is used as is (no download).
func TestUsableFindsExecutable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sing-box")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, ok := Usable(path); !ok || got != path {
		t.Fatalf("Usable(%q) = %q, %v", path, got, ok)
	}
	if got, ok := Usable(filepath.Join(dir, "missing")); ok {
		t.Fatalf("Usable(missing) = %q, true", got)
	}
}

// The full happy path: ask GitHub, download the asset, unpack and install it
// with the executable bit set.
func TestEnsureInstallsFromRelease(t *testing.T) {
	resetRetry()
	bin := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{0}, 1<<20)...)
	blob := tarball(t, map[string][]byte{"sing-box-9.9.9-linux-amd64/sing-box": bin})
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		switch {
		case strings.HasSuffix(r.URL.Path, "/releases/latest"):
			_, _ = io.WriteString(w, `{"tag_name":"v9.9.9"}`)
		case strings.Contains(r.URL.Path, "/releases/download/v9.9.9/"):
			_, _ = w.Write(blob)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	target := filepath.Join(t.TempDir(), "bin", "sing-box")
	got, err := Ensure("", Options{Target: target, APIBase: srv.URL, DownloadBase: srv.URL, Client: srv.Client()})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if got != target {
		t.Fatalf("Ensure returned %q, want %q", got, target)
	}
	st, err := os.Stat(target)
	if err != nil {
		t.Fatalf("installed binary missing: %v", err)
	}
	if st.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %v, want 0755", st.Mode().Perm())
	}
	data, err := os.ReadFile(target)
	if err != nil || !bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}) {
		t.Fatalf("installed content wrong (err=%v, %d bytes)", err, len(data))
	}
	if len(asked) == 0 {
		t.Fatal("no request reached the server")
	}
}

// A failed download is reported and nothing is installed; a second call inside
// the cooldown does not hammer GitHub again.
func TestEnsureFailureAndCooldown(t *testing.T) {
	resetRetry()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.NotFound(w, r)
	}))
	defer srv.Close()

	target := filepath.Join(t.TempDir(), "sing-box")
	if _, err := Ensure("", Options{Target: target, APIBase: srv.URL, DownloadBase: srv.URL, Client: srv.Client()}); err == nil {
		t.Fatal("a 404 release must fail")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("nothing may be installed on failure")
	}
	before := hits
	if _, err := Ensure("", Options{Target: target, APIBase: srv.URL, DownloadBase: srv.URL, Client: srv.Client()}); err == nil {
		t.Fatal("the retry inside the cooldown must still fail")
	}
	if hits != before {
		t.Fatalf("cooldown did not stop the second attempt (hits %d -> %d)", before, hits)
	}
}
