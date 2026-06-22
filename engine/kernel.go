package engine

import (
	"log"
	"sync"

	"github.com/nexpool/exnode/wg"
)

// KernelEngine drives the Linux kernel WireGuard module via netlink/wgctrl.
type KernelEngine struct {
	mu      sync.Mutex
	managed map[string]wg.Interface // interface name -> last applied state
}

// NewKernelEngine builds a KernelEngine.
func NewKernelEngine() *KernelEngine {
	return &KernelEngine{managed: map[string]wg.Interface{}}
}

// Apply reconciles each desired interface and removes any previously managed
// interface no longer desired. Peer changes are applied incrementally so
// unaffected peers keep their handshake state.
func (e *KernelEngine) Apply(desired []wg.Interface) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	want := make(map[string]wg.Interface, len(desired))
	for _, iface := range desired {
		want[iface.Name] = iface
		if err := wg.Reconcile(iface); err != nil {
			log.Printf("[kernel] reconcile %s failed: %v", iface.Name, err)
		}
		// Apply policy routes, removing any lines dropped since last apply.
		wg.ReconcilePolicyRoutes(e.managed[iface.Name].PolicyRoutes, iface.PolicyRoutes)
	}

	for name, old := range e.managed {
		if _, ok := want[name]; ok {
			continue
		}
		wg.RemovePolicyRoutes(old.PolicyRoutes)
		_ = wg.TeardownNAT(old)
		if err := wg.RemoveLink(name); err != nil {
			log.Printf("[kernel] remove stale interface %s failed: %v", name, err)
		} else {
			log.Printf("[kernel] removed stale interface %s", name)
		}
	}

	e.managed = want
	return nil
}

// Stats reads per-peer stats from each managed kernel device.
func (e *KernelEngine) Stats() ([]wg.PeerStat, error) {
	e.mu.Lock()
	names := make([]string, 0, len(e.managed))
	for name := range e.managed {
		names = append(names, name)
	}
	e.mu.Unlock()

	var out []wg.PeerStat
	for _, name := range names {
		stats, err := wg.DeviceStats(name)
		if err != nil {
			log.Printf("[kernel] read stats %s failed: %v", name, err)
			continue
		}
		out = append(out, stats...)
	}
	return out, nil
}

// Close is a no-op: kernel devices are intentionally left up so the VPN keeps
// serving traffic across agent restarts.
func (e *KernelEngine) Close() error { return nil }
