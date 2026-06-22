package wg

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/vishvananda/netlink"
)

// This file gives an interface's clients internet access: IPv4 forwarding plus
// MASQUERADE/FORWARD rules from the tunnel subnet out the WAN interface. Rules
// are scoped by subnet and device name so they can be removed again without
// touching unrelated rules.

type rule struct {
	table string
	chain string
	args  []string
}

// natRules builds the POSTROUTING + FORWARD rules. Each source subnet gets one
// POSTROUTING rule: SNAT to snatIP when set (egress was given as an IP), else
// MASQUERADE out the egress device.
func natRules(subnets []string, device, egress, snatIP string) []rule {
	rules := make([]rule, 0, len(subnets)+2)
	for _, s := range subnets {
		post := []string{"-s", s, "-o", egress}
		if snatIP != "" {
			post = append(post, "-j", "SNAT", "--to-source", snatIP)
		} else {
			post = append(post, "-j", "MASQUERADE")
		}
		rules = append(rules, rule{table: "nat", chain: "POSTROUTING", args: post})
	}
	rules = append(rules,
		rule{chain: "FORWARD", args: []string{"-i", device, "-o", egress, "-j", "ACCEPT"}},
		rule{chain: "FORWARD", args: []string{"-i", egress, "-o", device, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"}},
	)
	return rules
}

// NATEnabled reports whether NAT should be installed for this interface: either
// the "上网访问" toggle is on, or a custom egress / extra source subnet was set
// (custom NAT applies on its own, independent of the toggle).
func NATEnabled(iface Interface) bool {
	return iface.Masquerade ||
		strings.TrimSpace(iface.EgressInterface) != "" ||
		strings.TrimSpace(iface.NATSubnets) != ""
}

// natParamsDiffer reports whether the rule-affecting NAT params changed.
func natParamsDiffer(a, b Interface) bool {
	return a.Masquerade != b.Masquerade ||
		a.EgressInterface != b.EgressInterface ||
		a.NATSubnets != b.NATSubnets ||
		a.Address != b.Address
}

// ReconcileNAT converges NAT from the previously-applied state (old) to the
// desired one (new). It tears down the OLD rules (using the old params, so the
// exact installed rules are removed) when NAT was turned off or its params
// changed, then installs the new rules. This is why disabling custom NAT
// actually removes the rules instead of computing a delete from the new (empty)
// config.
func ReconcileNAT(old, new Interface) error {
	if NATEnabled(old) && (!NATEnabled(new) || natParamsDiffer(old, new)) {
		_ = TeardownNAT(old)
	}
	if NATEnabled(new) {
		if _, err := SetupNAT(new); err != nil {
			return err
		}
	}
	return nil
}

// natSources returns the source CIDRs to masquerade. When the operator set one
// or more custom subnets they are used verbatim (they replace the default);
// otherwise the tunnel subnet is masqueraded.
func natSources(iface Interface) ([]string, error) {
	var custom []string
	seen := map[string]struct{}{}
	for _, s := range strings.Split(iface.NATSubnets, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		norm, err := subnetFor(s)
		if err != nil {
			return nil, fmt.Errorf("invalid nat subnet %q: %w", s, err)
		}
		if _, dup := seen[norm]; dup {
			continue
		}
		seen[norm] = struct{}{}
		custom = append(custom, norm)
	}
	if len(custom) > 0 {
		return custom, nil
	}
	wgSubnet, err := subnetFor(iface.Address)
	if err != nil {
		return nil, err
	}
	return []string{wgSubnet}, nil
}

// resolveEgress turns the configured egress spec into the device to use and an
// optional SNAT source IP. Empty = auto-detect the default-route interface; an
// IP = SNAT to it out the interface that owns it; otherwise an interface name.
func resolveEgress(spec string) (device, snatIP string, err error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		device, err = DefaultEgressInterface()
		return device, "", err
	}
	if ip := net.ParseIP(spec); ip != nil {
		device, err = linkForIP(ip)
		if err != nil {
			return "", "", err
		}
		return device, spec, nil
	}
	return spec, "", nil
}

// linkForIP finds the interface that owns the given local IP.
func linkForIP(ip net.IP) (string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return "", fmt.Errorf("list links: %w", err)
	}
	for _, l := range links {
		addrs, err := netlink.AddrList(l, netlink.FAMILY_ALL)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if a.IP.Equal(ip) {
				return l.Attrs().Name, nil
			}
		}
	}
	return "", fmt.Errorf("no interface owns IP %s", ip)
}

// SetupNAT enables forwarding and installs the rules (idempotent), returning the
// egress interface actually used.
func SetupNAT(iface Interface) (string, error) {
	subnets, err := natSources(iface)
	if err != nil {
		return "", err
	}
	device, snatIP, err := resolveEgress(iface.EgressInterface)
	if err != nil {
		return "", fmt.Errorf("resolve egress: %w", err)
	}
	if err := EnableForwarding(); err != nil {
		return device, err
	}
	for _, r := range natRules(subnets, iface.Name, device, snatIP) {
		if err := ensureRule(r); err != nil {
			return device, err
		}
	}
	return device, nil
}

// TeardownNAT removes the rules (safe to call repeatedly). IPv4 forwarding is
// left enabled because other tunnels may rely on it.
func TeardownNAT(iface Interface) error {
	subnets, err := natSources(iface)
	if err != nil {
		return err
	}
	device, snatIP, err := resolveEgress(iface.EgressInterface)
	if err != nil || device == "" {
		return nil // can't determine the device; nothing to remove deterministically
	}
	var firstErr error
	for _, r := range natRules(subnets, iface.Name, device, snatIP) {
		if err := deleteRule(r); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// EnableForwarding turns on IPv4 forwarding.
func EnableForwarding() error {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644); err != nil {
		return fmt.Errorf("enable ip_forward: %w", err)
	}
	return nil
}

// DefaultEgressInterface returns the interface carrying the IPv4 default route.
func DefaultEgressInterface() (string, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return "", fmt.Errorf("list routes: %w", err)
	}
	for _, r := range routes {
		if r.Dst != nil && !r.Dst.IP.IsUnspecified() {
			continue
		}
		link, err := netlink.LinkByIndex(r.LinkIndex)
		if err != nil {
			return "", fmt.Errorf("resolve egress link: %w", err)
		}
		return link.Attrs().Name, nil
	}
	return "", fmt.Errorf("no IPv4 default route found")
}

func subnetFor(address string) (string, error) {
	_, ipNet, err := net.ParseCIDR(strings.TrimSpace(address))
	if err != nil {
		return "", fmt.Errorf("invalid interface address %q: %w", address, err)
	}
	return ipNet.String(), nil
}

func ensureRule(r rule) error {
	if runIptables(iptablesArgs("-C", r)...) == nil {
		return nil
	}
	return runIptables(iptablesArgs("-A", r)...)
}

func deleteRule(r rule) error {
	if runIptables(iptablesArgs("-C", r)...) != nil {
		return nil
	}
	return runIptables(iptablesArgs("-D", r)...)
}

func iptablesArgs(action string, r rule) []string {
	var args []string
	if r.table != "" {
		args = append(args, "-t", r.table)
	}
	args = append(args, action, r.chain)
	return append(args, r.args...)
}

func runIptables(args ...string) error {
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %v (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
