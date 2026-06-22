// Package engine abstracts the exnode datapath so the same control loop can
// drive different WireGuard backends:
//
//   - kernel: the Linux kernel WireGuard module via netlink/wgctrl (default).
//     Fastest, supports incremental peer changes without disrupting other
//     peers, and exposes accurate per-peer handshake/transfer stats. Needs
//     root/CAP_NET_ADMIN and the wireguard kernel module.
//   - singbox: a sing-box process driven by a rendered config. Runs in
//     userspace (gVisor or system tun) and can work where the kernel module is
//     unavailable, at the cost of reload-on-change (peer churn briefly disrupts
//     the datapath) and coarser stats.
//
// The panel side is identical for both: it stores desired state and the agent
// converges the datapath toward it.
package engine

import "github.com/nexpool/exnode/wg"

// Build constructs the engine for the given type. "singbox" builds the
// sing-box backend (using the supplied local options); anything else builds the
// kernel engine.
func Build(engineType string, sb SingboxConfig) Engine {
	if engineType == "singbox" {
		return NewSingboxEngine(sb)
	}
	return NewKernelEngine()
}

// Engine converges a WireGuard datapath toward a desired set of interfaces and
// reports runtime stats.
type Engine interface {
	// Apply makes the datapath match exactly the given set of interfaces,
	// creating/updating present ones and removing any it previously managed
	// that are no longer desired.
	Apply(desired []wg.Interface) error

	// Stats returns per-peer runtime stats across all managed interfaces. An
	// engine that cannot expose per-peer stats returns an empty slice.
	Stats() ([]wg.PeerStat, error)

	// Close releases engine resources. Whether the live datapath survives is
	// engine-specific (the kernel engine leaves devices up; the sing-box engine
	// stops its process, which tears down its tunnel).
	Close() error
}
