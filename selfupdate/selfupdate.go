// Package selfupdate implements the agent's self-upgrade: the panel queues a
// version, the agent downloads the release asset, atomically replaces its own
// binary and re-executes itself (systemd then keeps running the same unit, new
// binary). Only the panel decides *when*; the URL comes from the order, so a
// fork or a mirror needs no agent change.
//
// It deliberately depends on nothing but the standard library, so the logic is
// testable on any platform even though the agent itself is Linux-only.
package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// upgradeHTTPTimeout bounds the release download.
const upgradeHTTPTimeout = 5 * time.Minute

// minBinarySize rejects a truncated download before it can replace a working
// binary (the real agent is ~20 MB).
const minBinarySize = 1 << 20

// retryAfter throttles upgrade attempts after a failure: the panel re-sends the
// directive on every heartbeat (15s), which would otherwise hammer an unreachable
// download URL and flood the log.
const retryAfter = 5 * time.Minute

// upgrading guards the process-wide replacement: one upgrade replaces every
// controller, so only the first order is acted on.
var (
	upgrading atomic.Bool

	attemptMu      sync.Mutex
	lastAttempt    time.Time
	attemptVersion string
)

var (
	upgradeErrMu sync.Mutex
	upgradeErr   string
)

// PendingError returns the last upgrade failure, if any (not cleared).
func PendingError() string {
	upgradeErrMu.Lock()
	defer upgradeErrMu.Unlock()
	return upgradeErr
}

// ClearError forgets the last failure (called once it has been reported).
func ClearError() {
	upgradeErrMu.Lock()
	defer upgradeErrMu.Unlock()
	upgradeErr = ""
}

func setUpgradeError(format string, args ...any) {
	upgradeErrMu.Lock()
	upgradeErr = fmt.Sprintf(format, args...)
	msg := upgradeErr
	upgradeErrMu.Unlock()
	log.Printf("self-upgrade failed: %s", msg)
}

// Adopt runs the executable on disk when it is a newer build than this process.
// After a binary is replaced outside systemd (docker cp, install.sh, a copy that
// a supervisor never restarted) the old process keeps running the replaced file,
// so the panel sees the old version forever while "exnode version" (which reads the
// file) prints the new one. Called once at startup; a no-op when they match.
func Adopt(current string) {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		return
	}
	adopt(exe, current, "checked at startup")
}

// Watch keeps the process on the newest binary on disk: whenever the file behind
// this process changes (an upgrade that replaced it without a restart, a manual
// install) and its version is newer, the process re-executes into it. Called once
// at startup it heals a node that would otherwise report the old version forever.
func Watch(ctx context.Context, current string, every time.Duration) {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		return
	}
	stamp := fileStamp(exe)
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		next := fileStamp(exe)
		if next == stamp {
			continue // the file did not change: nothing to do, no version probe
		}
		stamp = next
		adopt(exe, current, "the binary on disk changed")
	}
}

// fileStamp identifies the current contents of a file cheaply (no exec).
func fileStamp(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d-%d", st.Size(), st.ModTime().UnixNano())
}

// adopt re-executes into exe when its version is newer than current.
func adopt(exe, current, why string) {
	out, err := exec.Command(exe, "-version").Output()
	if err != nil {
		log.Printf("self-check: %s but %s -version failed: %v", why, exe, err)
		return
	}
	fileVersion := firstLine(string(out))
	if fileVersion == "" || fileVersion == current || !newerVersion(fileVersion, current) {
		return
	}
	log.Printf("self-check: running %s while %s is %s (%s): re-executing into the newer build", current, exe, fileVersion, why)
	if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
		log.Printf("self-check: re-exec %s failed: %v — restart the service to pick up %s", exe, err, fileVersion)
	}
}

// firstLine is the version line of "-version" output (older builds printed the
// path on a second line).
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// newerVersion reports whether a is a higher version than b ("v1.3.5" > "v1.3.2").
func newerVersion(a, b string) bool {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x > y
		}
	}
	return false
}

// versionParts turns "v1.3.5" into [1 3 5], ignoring prefixes and suffixes.
func versionParts(v string) []int {
	v = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), "v"))
	if v == "" {
		return nil
	}
	var out []int
	for _, part := range strings.Split(v, ".") {
		n := 0
		for _, r := range part {
			if r < '0' || r > '9' {
				break
			}
			n = n*10 + int(r-'0')
		}
		out = append(out, n)
	}
	return out
}

// Order is one upgrade instruction from the panel.
type Order struct {
	Version string
	URL     string
}

// Maybe acts on an upgrade order. On success the process is replaced and this
// never returns; on failure the error is kept for the next heartbeat.
func Maybe(order *Order, current string) {
	if order == nil || order.Version == "" || order.Version == current {
		return
	}
	if strings.TrimSpace(order.URL) == "" {
		// The panel would otherwise keep re-sending an order that can never run and
		// the node would look stuck in "upgrading".
		setUpgradeError("upgrade to %s: the panel sent no download URL", order.Version)
		return
	}
	if !upgrading.CompareAndSwap(false, true) {
		return // another controller already started the upgrade
	}
	defer upgrading.Store(false)

	attemptMu.Lock()
	if order.Version != attemptVersion { // a new version starts with a clean slate
		attemptVersion = order.Version
		lastAttempt = time.Time{}
	}
	tooSoon := !lastAttempt.IsZero() && time.Since(lastAttempt) < retryAfter
	lastAttempt = time.Now()
	attemptMu.Unlock()
	if tooSoon {
		log.Printf("self-upgrade to %s skipped: retrying at most every %s (last error: %s)", order.Version, retryAfter, PendingError())
		return // keep reporting the previous error, retry after the cooldown
	}

	if err := selfUpgrade(order); err != nil {
		setUpgradeError("upgrade to %s failed: %v", order.Version, err)
	}
}

// selfUpgrade downloads the release and swaps it in. It returns only on failure:
// after a successful swap the process is re-executed (or exited so systemd
// restarts it with the new binary).
func selfUpgrade(order *Order) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate own binary: %w", err)
	}
	url := strings.TrimSpace(order.URL)
	if url == "" {
		url = assetURL(order.Version)
	}

	log.Printf("self-upgrade: downloading %s (%s)", order.Version, url)
	tmp, err := download(url, filepath.Dir(exe))
	if err != nil {
		return err
	}
	defer os.Remove(tmp) // no-op once renamed

	if err := os.Chmod(tmp, 0o755); err != nil {
		return fmt.Errorf("chmod download: %w", err)
	}
	// Prove the new binary actually runs before touching the working one: a wrong
	// architecture, a truncated file or a noexec mount would otherwise leave the
	// node without a usable agent (and there may be nothing to restart it).
	if out, err := exec.Command(tmp, "-version").CombinedOutput(); err != nil {
		return fmt.Errorf("downloaded binary does not run: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	if err := os.Rename(tmp, exe); err != nil {
		return fmt.Errorf("replace %s: %w", exe, err)
	}
	log.Printf("self-upgrade: %s installed, restarting", order.Version)

	// Re-exec in place: same PID, new binary, no dependency on systemd. When that
	// fails we must NOT exit: this agent may have no supervisor at all (no systemd
	// unit, no container restart policy), and a dead agent is far worse than a
	// stale one. Keep running the current image, report the failure, and let the
	// next restart pick up the new binary from disk.
	if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
		log.Printf("self-upgrade: exec %s failed: %v (keeping the running agent)", exe, err)
		return fmt.Errorf("exec %s: %w", exe, err)
	}
	return nil
}

// download fetches url into a temp file in dir and returns its path, rejecting
// anything that is not a plausible agent binary.
func download(url, dir string) (string, error) {
	client := &http.Client{Timeout: upgradeHTTPTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download: status %d", resp.StatusCode)
	}

	f, err := os.CreateTemp(dir, ".exnode-download-*")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	path := f.Name()

	written, err := io.Copy(f, io.LimitReader(resp.Body, minBinarySize*200))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return "", fmt.Errorf("write download: %w", err)
	}
	if written < minBinarySize {
		os.Remove(path)
		return "", fmt.Errorf("download too small (%d bytes)", written)
	}
	if err := checkExecutable(path); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

// checkExecutable makes sure we are not about to install an HTML error page.
func checkExecutable(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return fmt.Errorf("read download: %w", err)
	}
	if runtime.GOOS == "linux" && magic != [4]byte{0x7f, 'E', 'L', 'F'} {
		return errors.New("download is not an ELF binary")
	}
	return nil
}

// assetURL mirrors the release asset naming convention used by install.sh, for
// panels that state a version without a URL.
func assetURL(version string) string {
	repo := strings.Trim(strings.TrimSpace(os.Getenv("EXNODE_REPO")), "/")
	if repo == "" {
		repo = "nexpool/exnode"
	}
	return fmt.Sprintf("https://github.com/%s/releases/download/%s/exnode-%s-%s",
		repo, version, runtime.GOOS, runtime.GOARCH)
}
