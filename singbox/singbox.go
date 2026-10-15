// Package singbox installs the sing-box binary the optional datapath engine
// needs. The panel can switch a node to that engine at any time, so the agent
// fetches the binary on demand instead of failing every sync with
// `exec: "sing-box": executable file not found in $PATH`.
//
// Only the standard library is used, so the logic is testable off-Linux.
package singbox

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
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
	"time"
)

const (
	// DefaultRepo is where sing-box releases are published.
	DefaultRepo = "SagerNet/sing-box"
	// DefaultTarget is where the binary is installed. It must live on PATH so
	// the engine's default BinPath ("sing-box") resolves to it.
	DefaultTarget = "/usr/local/bin/sing-box"
	// maxAssetSize caps the download (the release tarball is ~20 MB).
	maxAssetSize = 200 << 20
	// httpTimeout bounds one download.
	httpTimeout = 5 * time.Minute
	// retryAfter throttles re-install attempts after a failure, so a node
	// without internet does not re-download on every sync.
	retryAfter = 10 * time.Minute
)

// Options tune one install; the zero value means "latest release from GitHub".
type Options struct {
	// Repo overrides DefaultRepo (env SINGBOX_REPO is honoured too).
	Repo string
	// Target is where to install the binary (default DefaultTarget).
	Target string
	// Client is the HTTP client to use (default: 5 min timeout).
	Client *http.Client
	// APIBase / DownloadBase point at a mirror or a test server.
	APIBase      string
	DownloadBase string
}

var (
	mu          sync.Mutex // one install at a time
	lastAttempt time.Time
	lastErr     error
)

// Usable returns the path of a runnable sing-box for the configured value.
// An empty value means "sing-box on PATH"; an absolute path is used as is.
func Usable(binPath string) (string, bool) {
	binPath = strings.TrimSpace(binPath)
	if binPath == "" {
		binPath = "sing-box"
	}
	if path, err := exec.LookPath(binPath); err == nil {
		return path, true
	}
	if filepath.IsAbs(binPath) {
		if st, err := os.Stat(binPath); err == nil && !st.IsDir() {
			return binPath, true
		}
	}
	return "", false
}

// Ensure returns a usable sing-box path, downloading and unpacking a release
// when the configured binary cannot be found. Note that it blocks while the
// download runs and that concurrent callers share one attempt.
func Ensure(binPath string, opts Options) (string, error) {
	if path, ok := Usable(binPath); ok {
		return path, nil
	}
	target := strings.TrimSpace(opts.Target)
	if target == "" {
		target = DefaultTarget
	}

	mu.Lock()
	defer mu.Unlock()
	// Someone else may have installed it while we waited for the lock.
	if path, ok := Usable(target); ok {
		return path, nil
	}
	if path, ok := Usable(binPath); ok {
		return path, nil
	}
	if lastErr != nil && time.Since(lastAttempt) < retryAfter {
		return "", fmt.Errorf("上次安装失败（%v），%s 后再试", lastErr, (retryAfter - time.Since(lastAttempt)).Round(time.Second))
	}

	lastAttempt = time.Now()
	if err := install(target, opts); err != nil {
		lastErr = err
		return "", err
	}
	lastErr = nil
	return target, nil
}

// assetName is the release asset for one version/platform, e.g.
// sing-box-1.14.3-linux-amd64.tar.gz. The tag keeps its leading "v", the asset
// name does not.
func assetName(version, goos, goarch string) string {
	return fmt.Sprintf("sing-box-%s-%s-%s.tar.gz", strings.TrimPrefix(version, "v"), goos, goarch)
}

func install(target string, opts Options) error {
	repo := strings.TrimSpace(opts.Repo)
	if repo == "" {
		repo = strings.TrimSpace(os.Getenv("SINGBOX_REPO"))
	}
	if repo == "" {
		repo = DefaultRepo
	}
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: httpTimeout}
	}
	apiBase := strings.TrimSpace(opts.APIBase)
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	downloadBase := strings.TrimSpace(opts.DownloadBase)
	if downloadBase == "" {
		downloadBase = "https://github.com"
	}

	version := strings.TrimSpace(os.Getenv("SINGBOX_VERSION"))
	if version == "" {
		v, err := latestVersion(client, apiBase, repo)
		if err != nil {
			return fmt.Errorf("查询 sing-box 版本: %w", err)
		}
		version = v
	}

	name := assetName(version, runtime.GOOS, runtime.GOARCH)
	url := fmt.Sprintf("%s/%s/releases/download/%s/%s", downloadBase, repo, version, name)
	log.Printf("[singbox] 未找到 sing-box，正在安装 %s (%s)", version, url)

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("下载 %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载 %s: HTTP %d", url, resp.StatusCode)
	}
	blob, err := io.ReadAll(io.LimitReader(resp.Body, maxAssetSize))
	if err != nil {
		return fmt.Errorf("读取 %s: %w", url, err)
	}
	bin, err := extractBinary(blob)
	if err != nil {
		return fmt.Errorf("解压 %s: %w", name, err)
	}
	if len(bin) < 1<<20 {
		return fmt.Errorf("%s 里的 sing-box 太小（%d 字节）", name, len(bin))
	}

	if dir := filepath.Dir(target); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("创建 %s: %w", dir, err)
		}
	}
	tmp := target + ".new"
	if err := os.WriteFile(tmp, bin, 0o755); err != nil {
		return fmt.Errorf("写入 %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("安装到 %s: %w", target, err)
	}
	log.Printf("[singbox] 已安装 %s → %s", version, target)
	return nil
}

// latestVersion asks the releases API for the newest tag.
func latestVersion(client *http.Client, apiBase, repo string) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/latest", strings.TrimRight(apiBase, "/"), repo)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "exnode-agent")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return "", err
	}
	if strings.TrimSpace(rel.TagName) == "" {
		return "", fmt.Errorf("release 没有 tag")
	}
	return rel.TagName, nil
}

// extractBinary pulls the sing-box executable out of the release tarball.
func extractBinary(tarball []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg || filepath.Base(hdr.Name) != "sing-box" {
			continue
		}
		return io.ReadAll(io.LimitReader(tr, maxAssetSize))
	}
	return nil, fmt.Errorf("压缩包里没有 sing-box")
}
