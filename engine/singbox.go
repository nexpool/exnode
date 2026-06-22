package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/nexpool/exnode/wg"
)

// SingboxConfig configures the sing-box backend.
type SingboxConfig struct {
	// BinPath is the sing-box executable (default "sing-box", resolved on PATH).
	BinPath string
	// ConfigPath is where the rendered sing-box config is written.
	ConfigPath string
	// System selects the datapath: false uses the gVisor userspace netstack
	// (no kernel module, peers reach the internet via the host's sockets — no
	// iptables needed); true creates a system tun named after the interface and
	// relies on iptables masquerade like the kernel engine.
	System bool
	// LogLevel for sing-box (default "warn").
	LogLevel string
}

// SingboxEngine drives a sing-box process from a rendered config. It re-renders
// and reloads (restarts) sing-box whenever the desired state changes.
//
// Trade-offs vs the kernel engine: a peer add/remove rewrites the config and
// restarts the datapath, briefly disrupting all peers' tunnels; and per-peer
// WireGuard handshake/transfer stats are not exposed by the binary, so Stats()
// returns empty. Use this only where the kernel module cannot be used.
type SingboxEngine struct {
	cfg SingboxConfig

	mu         sync.Mutex
	cmd        *exec.Cmd
	running    bool
	lastConfig []byte
	managed    map[string]wg.Interface
}

// NewSingboxEngine builds a SingboxEngine, filling in defaults.
func NewSingboxEngine(cfg SingboxConfig) *SingboxEngine {
	if cfg.BinPath == "" {
		cfg.BinPath = "sing-box"
	}
	if cfg.ConfigPath == "" {
		cfg.ConfigPath = "/etc/exnode/sing-box.json"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "warn"
	}
	return &SingboxEngine{cfg: cfg, managed: map[string]wg.Interface{}}
}

// Apply renders the config for the desired interfaces and, if it changed (or
// the process is not running), rewrites it and restarts sing-box.
func (e *SingboxEngine) Apply(desired []wg.Interface) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	rendered, err := e.render(desired)
	if err != nil {
		return err
	}

	want := make(map[string]wg.Interface, len(desired))
	for _, iface := range desired {
		want[iface.Name] = iface
	}

	if bytes.Equal(rendered, e.lastConfig) && e.running {
		return nil // nothing changed and process is healthy
	}

	if err := writeFileAtomic(e.cfg.ConfigPath, rendered); err != nil {
		return fmt.Errorf("write sing-box config: %w", err)
	}
	if err := e.restartLocked(); err != nil {
		return err
	}
	e.lastConfig = rendered

	// In system-tun mode sing-box exposes real interfaces; clients reach the
	// internet through the host uplink only with NAT, mirroring the kernel
	// engine. In gVisor mode this is unnecessary (direct outbound handles it).
	if e.cfg.System {
		e.applyNATLocked(want)
	}
	e.managed = want
	return nil
}

// Stats is best-effort: the sing-box binary does not expose per-peer WireGuard
// handshake/transfer counters, so the panel shows liveness via node heartbeat
// only. (A future improvement could read sing-box's Clash API.)
func (e *SingboxEngine) Stats() ([]wg.PeerStat, error) {
	return nil, nil
}

// Close stops the sing-box process (which tears down its tunnel) and removes
// any NAT rules it installed.
func (e *SingboxEngine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cfg.System {
		for _, old := range e.managed {
			_ = wg.TeardownNAT(old)
		}
	}
	return e.stopLocked()
}

// --- config rendering ---

func (e *SingboxEngine) render(desired []wg.Interface) ([]byte, error) {
	endpoints := make([]map[string]any, 0, len(desired))
	for _, iface := range desired {
		peers := make([]map[string]any, 0, len(iface.Peers))
		for _, p := range iface.Peers {
			peer := map[string]any{
				"public_key":  p.PublicKey,
				"allowed_ips": splitCIDRs(p.AllowedIPs),
			}
			if p.PresharedKey != "" {
				peer["pre_shared_key"] = p.PresharedKey
			}
			if p.PersistentKeepalive > 0 {
				peer["persistent_keepalive_interval"] = p.PersistentKeepalive
			}
			peers = append(peers, peer)
		}
		ep := map[string]any{
			"type":        "wireguard",
			"tag":         "ep-" + iface.Name,
			"system":      e.cfg.System,
			"name":        iface.Name,
			"listen_port": iface.ListenPort,
			"address":     splitCIDRs(iface.Address),
			"private_key": iface.PrivateKey,
			"peers":       peers,
		}
		if iface.MTU > 0 {
			ep["mtu"] = iface.MTU
		}
		endpoints = append(endpoints, ep)
	}

	conf := map[string]any{
		"log":       map[string]any{"level": e.cfg.LogLevel},
		"endpoints": endpoints,
		// Decrypted peer traffic is routed out via the host's sockets.
		"outbounds": []map[string]any{{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "direct"},
	}
	return json.MarshalIndent(conf, "", "  ")
}

func splitCIDRs(list string) []string {
	parts := strings.Split(list, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// --- process management ---

func (e *SingboxEngine) restartLocked() error {
	if err := e.stopLocked(); err != nil {
		return err
	}
	cmd := exec.Command(e.cfg.BinPath, "run", "-c", e.cfg.ConfigPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start sing-box: %w", err)
	}
	e.cmd = cmd
	e.running = true
	log.Printf("[singbox] started (pid %d, config %s)", cmd.Process.Pid, e.cfg.ConfigPath)

	go func() {
		_ = cmd.Wait()
		e.mu.Lock()
		if e.cmd == cmd {
			e.running = false
		}
		e.mu.Unlock()
	}()
	return nil
}

func (e *SingboxEngine) stopLocked() error {
	if e.cmd == nil || e.cmd.Process == nil {
		return nil
	}
	_ = e.cmd.Process.Kill()
	_, _ = e.cmd.Process.Wait()
	e.cmd = nil
	e.running = false
	return nil
}

func (e *SingboxEngine) applyNATLocked(want map[string]wg.Interface) {
	for _, iface := range want {
		if wg.NATEnabled(iface) {
			if _, err := wg.SetupNAT(iface); err != nil {
				log.Printf("[singbox] nat setup %s failed: %v", iface.Name, err)
			}
		} else {
			_ = wg.TeardownNAT(iface)
		}
		// Policy routes, removing any lines dropped since last apply.
		wg.ReconcilePolicyRoutes(e.managed[iface.Name].PolicyRoutes, iface.PolicyRoutes)
	}
	for name, old := range e.managed {
		if _, ok := want[name]; !ok {
			wg.RemovePolicyRoutes(old.PolicyRoutes)
			_ = wg.TeardownNAT(old)
		}
	}
}

func writeFileAtomic(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
