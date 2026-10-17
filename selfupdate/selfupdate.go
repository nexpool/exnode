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
