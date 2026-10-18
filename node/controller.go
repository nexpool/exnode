// Package node runs the agent control loops for a single panel: heartbeat
// (revision check), desired-state reconcile, and status reporting. The actual
// datapath work is delegated to a pluggable engine.Engine.
package node

import (
	"context"
	"log"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/nexpool/exnode/conf"
	"github.com/nexpool/exnode/engine"
	"github.com/nexpool/exnode/overlay"
	"github.com/nexpool/exnode/panel"
	"github.com/nexpool/exnode/selfupdate"
	"github.com/nexpool/exnode/wg"
)

// Controller drives one panel connection. The datapath engine is built lazily
// from the engine type the panel reports, and rebuilt if the panel changes it.
type Controller struct {
	client    *panel.Client
	singbox   engine.SingboxConfig
	hbEvery   time.Duration
	statEvery time.Duration
	version   string
	osName    string
	// primaryIf is the default-route NIC, reported to the panel so tunnel
	// underlay devices can be prefilled instead of looked up by hand.
	primaryIf string

	mu         sync.Mutex
	engine     engine.Engine
	engineType string
	revKnown   bool
	revision   uint
	desired    []wg.Interface   // last applied desired state (for the policy watchdog)
	vxlan      []overlay.Config // overlay links currently applied
}

// policyWatchdogEvery is how often the agent re-checks policy routes and re-adds
// any that went missing (e.g. after a NIC restart flushed a device-bound route).
const policyWatchdogEvery = 30 * time.Second

// NewController builds a Controller for one configured panel. singbox holds the
// node-local sing-box options (binary path etc.) used when the panel selects
// the sing-box engine.
func NewController(p conf.PanelConfig, singbox engine.SingboxConfig, version, osName string) *Controller {
	return &Controller{
		client:    panel.New(p.ApiHost, p.NodeID, p.SecretKey, p.HTTPTimeout()),
		singbox:   singbox,
		hbEvery:   p.HeartbeatInterval(),
		statEvery: p.StatusInterval(),
		version:   version,
		osName:    osName,
		primaryIf: primaryInterface(),
	}
}

// Close releases the active datapath engine.
func (c *Controller) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.engine != nil {
		_ = c.engine.Close()
		c.engine = nil
	}
}

// Run blocks until ctx is cancelled, driving the heartbeat and status loops.
func (c *Controller) Run(ctx context.Context) {
	host := c.client.Label()
	log.Printf("[%s] controller started (heartbeat %s, status %s)", host, c.hbEvery, c.statEvery)

	// Force an initial sync on startup regardless of revision.
	c.heartbeatTick(true)

	hb := time.NewTicker(c.hbEvery)
	defer hb.Stop()
	stat := time.NewTicker(c.statEvery)
	defer stat.Stop()
	wd := time.NewTicker(policyWatchdogEvery)
	defer wd.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("[%s] controller stopping", host)
			c.Close()
			return
		case <-hb.C:
			c.heartbeatTick(false)
		case <-stat.C:
			c.statusTick()
		case <-wd.C:
			c.policyWatchdogTick()
		}
	}
}

// policyWatchdogTick re-adds any policy route that has gone missing since the
// last sync, without churning the ones still in place.
func (c *Controller) policyWatchdogTick() {
	c.mu.Lock()
	desired := c.desired
	c.mu.Unlock()
	for _, iface := range desired {
		if iface.PolicyRoutes != "" {
			wg.EnsurePolicyRoutes(iface.PolicyRoutes)
		}
	}
}

// ensureEngine builds or rebuilds the datapath engine to match the requested
// type. When switching, the old engine tears down its interfaces and closes.
func (c *Controller) ensureEngine(engineType string) {
	if engineType == "" {
		engineType = "kernel"
	}
	if c.engine != nil && engineType == c.engineType {
		return
	}
	if c.engine != nil {
		_ = c.engine.Apply(nil) // remove the old engine's interfaces
		_ = c.engine.Close()
	}
	c.engine = engine.Build(engineType, c.singbox)
	c.engineType = engineType
	log.Printf("[%s] datapath engine: %s", c.client.Label(), engineType)
}

// primaryInterface is the NIC the default route leaves through ("" when the
// host has no default route).
func primaryInterface() string {
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err == nil {
		if dev := overlay.RouteDev(string(out)); dev != "" {
			return dev
		}
	}
	out, err = exec.Command("ip", "-4", "route", "get", "1.1.1.1").Output()
	if err == nil {
		return overlay.RouteDev(string(out))
	}
	return ""
}

// heartbeatTick checks in and, when the revision changed (or force), re-syncs.
// A pending self-upgrade order is acted on before the sync: on success the
// process is replaced and this loop never continues.
func (c *Controller) heartbeatTick(force bool) {
	host := c.client.Label()
	resp, err := c.client.Heartbeat(panel.HeartbeatRequest{
		AgentVersion:     c.version,
		OS:               c.osName,
		Arch:             runtime.GOARCH,
		UpgradeError:     selfupdate.PendingError(),
		PrimaryInterface: c.primaryIf,
	})
	if err != nil {
		log.Printf("[%s] heartbeat failed: %v", host, err)
		return
	}
	selfupdate.ClearError()

	if resp.Upgrade != nil {
		log.Printf("[%s] panel requested upgrade to %s", host, resp.Upgrade.Version)
		selfupdate.Maybe(&selfupdate.Order{Version: resp.Upgrade.Version, URL: resp.Upgrade.URL}, c.version)
	}

	c.mu.Lock()
	changed := force || !c.revKnown || resp.ConfigRevision != c.revision
	c.mu.Unlock()
	if changed {
		c.sync()
	}
}

// sync pulls the full desired state and hands it to the engine to converge.
func (c *Controller) sync() {
	host := c.client.Label()
	resp, err := c.client.Sync()
	if err != nil {
		log.Printf("[%s] sync failed: %v", host, err)
		return
	}

	desired := make([]wg.Interface, 0, len(resp.Interfaces))
	for _, in := range resp.Interfaces {
		desired = append(desired, toEngineInterface(in))
	}

	c.mu.Lock()
	prevVXLAN := c.vxlan
	c.ensureEngine(resp.Engine)
	eng := c.engine
	c.mu.Unlock()

	// The datapath engine and the overlay links are independent: a failing
	// engine (e.g. sing-box without its binary) must not stop VXLAN/IPIP/GRE
	// links from being built. The revision only advances when everything is
	// healthy, so the engine is retried on the next heartbeat.
	applyErr := eng.Apply(desired)
	nextVXLAN := overlayConfigs(resp.Interfaces)
	c.mu.Lock()
	c.vxlan = nextVXLAN
	c.mu.Unlock()
	overlay.Reconcile(prevVXLAN, nextVXLAN)
	if applyErr != nil {
		log.Printf("[%s] engine apply failed (overlay links still applied): %v", host, applyErr)
		return
	}

	c.mu.Lock()
	c.revision = resp.ConfigRevision
	c.revKnown = true
	c.desired = desired
	c.mu.Unlock()

	// Overlay links ride on top of the tunnel, so they are converged once the
	// datapath itself is in place.
	overlay.Reconcile(prevVXLAN, nextVXLAN)

	log.Printf("[%s] synced revision %d, engine %s (%d interface(s), %d overlay link(s): %s)",
		host, resp.ConfigRevision, c.engineType, len(desired), len(nextVXLAN), overlayNames(nextVXLAN))
}

// overlayNames lists the overlay links of a sync for the log line, so "the panel
// configured a tunnel but the node created nothing" is visible at a glance.
func overlayNames(cfgs []overlay.Config) string {
	if len(cfgs) == 0 {
		return "-"
	}
	names := make([]string, 0, len(cfgs))
	for _, c := range cfgs {
		names = append(names, c.Name)
	}
	return strings.Join(names, ",")
}

// statusTick reads stats from the engine and reports them to the panel.
func (c *Controller) statusTick() {
	host := c.client.Label()
	c.mu.Lock()
	eng := c.engine
	c.mu.Unlock()
	if eng == nil {
		return // no engine until the first successful sync
	}
	stats, err := eng.Stats()
	if err != nil {
		log.Printf("[%s] read stats failed: %v", host, err)
		return
	}
	if len(stats) == 0 {
		return
	}
	peers := make([]panel.StatusPeer, 0, len(stats))
	for _, s := range stats {
		sp := panel.StatusPeer{PublicKey: s.PublicKey, RxBytes: s.RxBytes, TxBytes: s.TxBytes, Endpoint: s.Endpoint}
		if !s.LastHandshake.IsZero() {
			hs := s.LastHandshake
			sp.LastHandshake = &hs
		}
		peers = append(peers, sp)
	}
	if err := c.client.ReportStatus(panel.StatusRequest{Peers: peers}); err != nil {
		log.Printf("[%s] report status failed: %v", host, err)
	}
}

// overlayConfigs turns the panel's overlay blocks into the links this node must
// have. A member may carry several tunnels at once (VXLAN, IPIP, GRE); panels
// that predate the list send the single VXLAN field instead. The tunnel MTU rides
// along so each overlay link is sized correctly.
func overlayConfigs(ifaces []panel.Interface) []overlay.Config {
	var out []overlay.Config
	for _, in := range ifaces {
		tunnels := in.Tunnels
		if len(tunnels) == 0 && in.VXLAN != nil {
			tunnels = []panel.VXLAN{*in.VXLAN} // legacy single-tunnel payload
		}
		for _, t := range tunnels {
			if t.Name == "" {
				continue
			}
			out = append(out, overlay.Config{
				Kind:      t.Kind,
				Name:      t.Name,
				VNI:       t.VNI,
				Key:       t.Key,
				Port:      t.Port,
				Dev:       t.Dev,
				Local:     t.Local,
				LocalIP:   t.LocalIP,
				Remote:    t.Remote,
				Routes:    t.Routes,
				MTU:       t.MTU,
				TunnelMTU: in.MTU,
			})
		}
	}
	return out
}

func toEngineInterface(in panel.Interface) wg.Interface {
	peers := make([]wg.Peer, 0, len(in.Peers))
	for _, p := range in.Peers {
		peers = append(peers, wg.Peer{
			PublicKey:           p.PublicKey,
			PresharedKey:        p.PresharedKey,
			AllowedIPs:          p.AllowedIPs,
			PersistentKeepalive: p.PersistentKeepalive,
		})
	}
	return wg.Interface{
		Name:            in.Name,
		PrivateKey:      in.PrivateKey,
		ListenPort:      in.ListenPort,
		Address:         in.Address,
		MTU:             in.MTU,
		Masquerade:      in.Masquerade,
		EgressInterface: in.EgressInterface,
		NATSubnets:      in.NATSubnets,
		PolicyRoutes:    in.PolicyRoutes,
		Peers:           peers,
	}
}
