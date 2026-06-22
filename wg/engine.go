// Package wg is the exnode agent's kernel boundary: it creates WireGuard
// devices via netlink, programs them via wgctrl, reads runtime stats, and
// reconciles the live kernel state toward the desired state pulled from the
// panel. Requires CAP_NET_ADMIN (root).
package wg

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Interface is the desired state of one WireGuard device on this node.
type Interface struct {
	Name            string
	PrivateKey      string
	ListenPort      int
	Address         string
	MTU             int
	Masquerade      bool
	EgressInterface string
	NATSubnets      string
	PolicyRoutes    string
	Peers           []Peer
}

// Peer is the desired state of one peer (only public material the kernel needs).
type Peer struct {
	PublicKey           string
	PresharedKey        string
	AllowedIPs          string
	PersistentKeepalive int
}

// PeerStat is a runtime snapshot read from the kernel for a single peer.
type PeerStat struct {
	PublicKey     string
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
	// Endpoint is the client's last-seen source address (ip:port), if any.
	Endpoint string
}

// EnsureLink creates the WireGuard netlink device if missing, (re)assigns the
// CIDR address and brings it up.
func EnsureLink(name, address string, mtu int) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		la := netlink.NewLinkAttrs()
		la.Name = name
		if mtu > 0 {
			la.MTU = mtu
		}
		wglink := &netlink.Wireguard{LinkAttrs: la}
		if err := netlink.LinkAdd(wglink); err != nil {
			return fmt.Errorf("create link %s: %w", name, err)
		}
		link = wglink
	}

	addr, err := netlink.ParseAddr(address)
	if err != nil {
		return fmt.Errorf("parse address %q: %w", address, err)
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("assign address: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring up link: %w", err)
	}
	return nil
}

// RemoveLink deletes the WireGuard device (idempotent).
func RemoveLink(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil // already gone
	}
	return netlink.LinkDel(link)
}

// Reconcile converges the live kernel device toward the desired interface
// state. It sets the device key/port, then adds/updates/removes peers
// incrementally so unaffected peers keep their handshake state. NAT rules are
// installed or removed to match Masquerade.
func Reconcile(iface Interface) error {
	if err := EnsureLink(iface.Name, iface.Address, iface.MTU); err != nil {
		return err
	}

	priv, err := wgtypes.ParseKey(iface.PrivateKey)
	if err != nil {
		return fmt.Errorf("parse interface private key: %w", err)
	}

	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open wgctrl: %w", err)
	}
	defer client.Close()

	// Set device-level settings without touching the peer set.
	port := iface.ListenPort
	if err := client.ConfigureDevice(iface.Name, wgtypes.Config{
		PrivateKey:   &priv,
		ListenPort:   &port,
		ReplacePeers: false,
	}); err != nil {
		return fmt.Errorf("configure device %s: %w", iface.Name, err)
	}

	// Read current peers to compute the delta.
	dev, err := client.Device(iface.Name)
	if err != nil {
		return fmt.Errorf("read device %s: %w", iface.Name, err)
	}
	current := make(map[string]struct{}, len(dev.Peers))
	for _, p := range dev.Peers {
		current[p.PublicKey.String()] = struct{}{}
	}

	desired := make(map[string]struct{}, len(iface.Peers))
	var configs []wgtypes.PeerConfig
	for _, p := range iface.Peers {
		desired[p.PublicKey] = struct{}{}
		pc, err := buildPeerConfig(p)
		if err != nil {
			return err
		}
		configs = append(configs, pc)
	}

	// Remove peers no longer desired.
	for pub := range current {
		if _, ok := desired[pub]; ok {
			continue
		}
		key, err := wgtypes.ParseKey(pub)
		if err != nil {
			continue
		}
		configs = append(configs, wgtypes.PeerConfig{PublicKey: key, Remove: true})
	}

	if len(configs) > 0 {
		if err := client.ConfigureDevice(iface.Name, wgtypes.Config{ReplacePeers: false, Peers: configs}); err != nil {
			return fmt.Errorf("configure peers on %s: %w", iface.Name, err)
		}
	}

	// NAT (masquerade toggle, or custom egress / extra subnets set on their own).
	if NATEnabled(iface) {
		if _, err := SetupNAT(iface); err != nil {
			return fmt.Errorf("nat setup: %w", err)
		}
	} else {
		_ = TeardownNAT(iface)
	}
	return nil
}

// DeviceStats returns runtime stats per peer public key.
func DeviceStats(name string) ([]PeerStat, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("open wgctrl: %w", err)
	}
	defer client.Close()

	dev, err := client.Device(name)
	if err != nil {
		return nil, fmt.Errorf("read device %s: %w", name, err)
	}
	stats := make([]PeerStat, 0, len(dev.Peers))
	for _, p := range dev.Peers {
		endpoint := ""
		if p.Endpoint != nil {
			endpoint = p.Endpoint.String()
		}
		stats = append(stats, PeerStat{
			PublicKey:     p.PublicKey.String(),
			LastHandshake: p.LastHandshakeTime,
			RxBytes:       p.ReceiveBytes,
			TxBytes:       p.TransmitBytes,
			Endpoint:      endpoint,
		})
	}
	return stats, nil
}

func buildPeerConfig(p Peer) (wgtypes.PeerConfig, error) {
	pub, err := wgtypes.ParseKey(p.PublicKey)
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("peer public key: %w", err)
	}
	allowed, err := parseCIDRList(p.AllowedIPs)
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("peer allowed_ips: %w", err)
	}
	pc := wgtypes.PeerConfig{
		PublicKey:         pub,
		ReplaceAllowedIPs: true,
		AllowedIPs:        allowed,
	}
	if p.PresharedKey != "" {
		psk, err := wgtypes.ParseKey(p.PresharedKey)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("peer preshared key: %w", err)
		}
		pc.PresharedKey = &psk
	}
	if p.PersistentKeepalive > 0 {
		ka := time.Duration(p.PersistentKeepalive) * time.Second
		pc.PersistentKeepaliveInterval = &ka
	}
	return pc, nil
}

func parseCIDRList(list string) ([]net.IPNet, error) {
	parts := strings.Split(list, ",")
	out := make([]net.IPNet, 0, len(parts))
	for _, raw := range parts {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		out = append(out, *ipNet)
	}
	return out, nil
}
