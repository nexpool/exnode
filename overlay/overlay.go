// Package overlay applies the panel's point-to-point overlay links — VXLAN, IPIP
// or GRE — one per network member, created with the ip binary (argv, no shell):
//
//	ip link add vxlan3002 type vxlan id 3002 remote 38.91.117.189 dstport 3002 dev eth0
//	ip link set vxlan3002 up
//	ip addr add 10.1.3.1/30 dev vxlan3002
//
// Links are recreated only when their parameters change and deleted once the panel
// stops asking for them, so removing the overlay (or the member) cleans up after
// itself. The package depends on nothing but the standard library, so the
// reconcile rules are testable without a Linux kernel.
package overlay

import (
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
)

// VXLANOverhead is how many bytes VXLAN adds around the inner packet (outer IPv4
// + UDP + the VXLAN header).
const VXLANOverhead = 50

// Link kinds the panel can ask for.
const (
	KindVXLAN = "vxlan"
	KindIPIP  = "ipip"
	KindGRE   = "gre"
)

// Config is one overlay link the panel wants on this node.
type Config struct {
	// Kind is KindVXLAN (default), KindIPIP or KindGRE.
	Kind   string
	Name   string // link name, e.g. vxlan3002 / gre3 / ipip3
	VNI    int    // VXLAN network identifier
	Port   int    // VXLAN UDP destination port
	Key    int    // GRE key (0 = none)
	Dev    string // optional underlay NIC
	Local  string // address assigned to the link (CIDR)
	Remote string // peer address (VTEP for VXLAN, tunnel endpoint for ipip/gre)
	// MTU overrides the link MTU. 0 = derive it from TunnelMTU.
	MTU int
	// TunnelMTU is the MTU of the tunnel this link rides on (0 = leave the kernel
	// default). The link is sized down by VXLANOverhead.
	TunnelMTU int
	// Routes are routes to install on the link, each one the argument list of
	// "ip route replace" (e.g. "192.168.200.0/24 via 10.10.13.2 dev vxlan1133").
	Routes []string
}

// routeArgs builds the "ip route replace" argv for one route spec.
func routeArgs(spec string) []string {
	return append([]string{"route", "replace"}, strings.Fields(spec)...)
}

// routeDelArgs builds the "ip route del" argv for one route spec.
func routeDelArgs(spec string) []string {
	return append([]string{"route", "del"}, strings.Fields(spec)...)
}

// staleRoutes lists the routes of links that survive prev -> next but whose route
// is no longer wanted. Routes of links that disappear need no cleanup: deleting
// the device removes them with it.
func staleRoutes(prev, next []Config) []string {
	wanted := map[string]map[string]struct{}{}
	for _, c := range next {
		set := make(map[string]struct{}, len(c.Routes))
		for _, r := range c.Routes {
			set[r] = struct{}{}
		}
		wanted[c.Name] = set
	}
	var out []string
	for _, c := range prev {
		set, kept := wanted[c.Name]
		if !kept {
			continue
		}
		for _, r := range c.Routes {
			if _, ok := set[r]; !ok {
				out = append(out, r)
			}
		}
	}
	return out
}

// overhead is the encapsulation cost of a kind: 50 bytes for VXLAN (outer IPv4
// 20 + UDP 8 + VXLAN 8 + inner Ethernet 14), 20 for IPIP and 24 for GRE.
func overhead(c Config) int {
	switch kind(c) {
	case KindIPIP:
		return 20
	case KindGRE:
		return 24
	default:
		return VXLANOverhead
	}
}

// linkMTU is the MTU to put on the link: the explicit one when set, otherwise the
// tunnel MTU minus the encapsulation overhead, otherwise 0 (= leave the kernel
// default).
func linkMTU(c Config) int {
	if c.MTU > 0 {
		return c.MTU
	}
	if o := overhead(c); c.TunnelMTU > o {
		return c.TunnelMTU - o
	}
	return 0
}

// kind normalises Kind ("" means vxlan, so a panel that predates the field still
// works).
func kind(c Config) string {
	switch c.Kind {
	case KindIPIP, KindGRE:
		return c.Kind
	default:
		return KindVXLAN
	}
}

// addArgs builds the argv that creates the link:
//
//	vxlan: ip link add vxlan3002 type vxlan id 3002 remote … dstport … dev …
//	ipip:  ip tunnel add ipip3 mode ipip remote … dev …
//	gre:   ip tunnel add gre3 mode gre remote … dev … key …
func addArgs(c Config) []string {
	if k := kind(c); k != KindVXLAN {
		args := []string{"tunnel", "add", c.Name, "mode", k}
		if c.Remote != "" {
			args = append(args, "remote", c.Remote)
		}
		if c.Dev != "" {
			args = append(args, "dev", c.Dev)
		}
		if k == KindGRE && c.Key > 0 {
			args = append(args, "key", strconv.Itoa(c.Key))
		}
		return args
	}
	args := []string{"link", "add", c.Name, "type", "vxlan", "id", strconv.Itoa(c.VNI)}
	if c.Remote != "" {
		args = append(args, "remote", c.Remote)
	}
	if c.Dev != "" {
		args = append(args, "dev", c.Dev)
	}
	if c.Port > 0 {
		args = append(args, "dstport", strconv.Itoa(c.Port))
	}
	return args
}

// matches reports whether the output of "ip -d link show dev <name>" describes
// exactly this config.
func matches(show string, c Config) bool {
	if strings.TrimSpace(show) == "" {
		return false
	}
	if k := kind(c); k != KindVXLAN {
		// ip -d prints "link/ipip …" / "link/gre …" plus "<kind> remote <ip>".
		if !strings.Contains(show, "link/"+k) {
			return false
		}
		if c.Remote != "" && !strings.Contains(show, k+" remote "+c.Remote) {
			return false
		}
		if k == KindGRE && c.Key > 0 && !strings.Contains(show, "key "+strconv.Itoa(c.Key)) {
			return false
		}
		return true
	}
	checks := []string{fmt.Sprintf("vxlan id %d ", c.VNI)}
	if c.Remote != "" {
		checks = append(checks, "remote "+c.Remote)
	}
	if c.Port > 0 {
		checks = append(checks, fmt.Sprintf("dstport %d", c.Port))
	}
	if c.Dev != "" {
		checks = append(checks, "dev "+c.Dev)
	}
	for _, want := range checks {
		if !strings.Contains(show, want) {
			return false
		}
	}
	return true
}

// Plan splits a prev -> next transition into the links to delete and the links to
// (re)apply. Pure, so the reconcile rules are unit-tested.
func Plan(prev, next []Config) (remove []string, ensure []Config) {
	wanted := map[string]struct{}{}
	for _, c := range next {
		if c.Name != "" {
			wanted[c.Name] = struct{}{}
		}
	}
	for _, c := range prev {
		if c.Name == "" {
			continue
		}
		if _, keep := wanted[c.Name]; !keep {
			remove = append(remove, c.Name)
		}
	}
	for _, c := range next {
		if c.Name != "" {
			ensure = append(ensure, c)
		}
	}
	return remove, ensure
}

// ip runs "ip <args>" and wraps failures with the command output.
func ip(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %v (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// showLink returns the detailed link info ("" when the link does not exist).
func showLink(name string) string {
	out, err := exec.Command("ip", "-d", "link", "show", "dev", name).CombinedOutput()
	if err != nil {
		return ""
	}
	return string(out)
}

// showAddr returns the IPv4 addresses currently on the link.
func showAddr(name string) string {
	out, err := exec.Command("ip", "-4", "addr", "show", "dev", name).CombinedOutput()
	if err != nil {
		return ""
	}
	return string(out)
}

// Ensure creates or updates one overlay link and assigns its address.
func Ensure(c Config) {
	if c.Name == "" || c.VNI < 1 || strings.TrimSpace(c.Local) == "" {
		return
	}

	show := showLink(c.Name)
	if !matches(show, c) {
		if strings.TrimSpace(show) != "" {
			if err := ip("link", "del", c.Name); err != nil {
				log.Printf("[overlay] delete stale %s: %v", c.Name, err)
			}
		}
		if err := ip(addArgs(c)...); err != nil {
			log.Printf("[overlay] create %s: %v", c.Name, err)
			return
		}
		log.Printf("[overlay] created %s (%s, remote %s)", c.Name, kind(c), c.Remote)
	}
	if err := ip("link", "set", c.Name, "up"); err != nil {
		log.Printf("[overlay] up %s: %v", c.Name, err)
	}
	if mtu := linkMTU(c); mtu > 0 {
		if err := ip("link", "set", c.Name, "mtu", strconv.Itoa(mtu)); err != nil {
			log.Printf("[overlay] mtu %s: %v", c.Name, err)
		}
	}
	// Only touch addresses when they differ: flushing on every sync would drop
	// traffic through the overlay.
	if !strings.Contains(showAddr(c.Name), " "+c.Local+" ") {
		_ = ip("addr", "flush", "dev", c.Name)
		if err := ip("addr", "add", c.Local, "dev", c.Name); err != nil {
			log.Printf("[overlay] addr %s: %v", c.Name, err)
		}
	}
	// Routes through the overlay (e.g. the LAN behind the peer). "route replace"
	// is idempotent, so repeating a sync never duplicates or flaps them.
	for _, r := range c.Routes {
		if err := ip(routeArgs(r)...); err != nil {
			log.Printf("[overlay] route %q: %v", r, err)
		}
	}
}

// Remove deletes one overlay link (safe when it is already gone).
func Remove(name string) {
	if name == "" {
		return
	}
	if err := ip("link", "del", name); err != nil {
		log.Printf("[overlay] remove %s: %v", name, err)
	}
}

// Reconcile converges the node's overlay links from prev to next.
func Reconcile(prev, next []Config) {
	remove, ensure := Plan(prev, next)
	for _, name := range remove {
		Remove(name)
	}
	for _, spec := range staleRoutes(prev, next) {
		if err := ip(routeDelArgs(spec)...); err != nil {
			log.Printf("[overlay] remove route %q: %v", spec, err)
		}
	}
	for _, c := range ensure {
		Ensure(c)
	}
}
