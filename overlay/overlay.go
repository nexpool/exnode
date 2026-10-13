// Package overlay applies the panel's VXLAN overlay links: one point-to-point
// link per network member, created with the ip binary (argv, no shell):
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

// Config is one overlay link the panel wants on this node.
type Config struct {
	Name   string // link name, e.g. vxlan3002
	VNI    int
	Port   int    // UDP destination port
	Dev    string // optional underlay NIC
	Local  string // address assigned to the link (CIDR)
	Remote string // peer VTEP address
	// TunnelMTU is the MTU of the tunnel this link rides on (0 = leave the kernel
	// default). The link is sized down by VXLANOverhead.
	TunnelMTU int
}

// addArgs builds the "ip link add" argv for one config.
func addArgs(c Config) []string {
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
				log.Printf("[vxlan] delete stale %s: %v", c.Name, err)
			}
		}
		if err := ip(addArgs(c)...); err != nil {
			log.Printf("[vxlan] create %s: %v", c.Name, err)
			return
		}
		log.Printf("[vxlan] created %s (vni %d remote %s)", c.Name, c.VNI, c.Remote)
	}
	if err := ip("link", "set", c.Name, "up"); err != nil {
		log.Printf("[vxlan] up %s: %v", c.Name, err)
	}
	if c.TunnelMTU > VXLANOverhead {
		if err := ip("link", "set", c.Name, "mtu", strconv.Itoa(c.TunnelMTU-VXLANOverhead)); err != nil {
			log.Printf("[vxlan] mtu %s: %v", c.Name, err)
		}
	}
	// Only touch addresses when they differ: flushing on every sync would drop
	// traffic through the overlay.
	if !strings.Contains(showAddr(c.Name), " "+c.Local+" ") {
		_ = ip("addr", "flush", "dev", c.Name)
		if err := ip("addr", "add", c.Local, "dev", c.Name); err != nil {
			log.Printf("[vxlan] addr %s: %v", c.Name, err)
		}
	}
}

// Remove deletes one overlay link (safe when it is already gone).
func Remove(name string) {
	if name == "" {
		return
	}
	if err := ip("link", "del", name); err != nil {
		log.Printf("[vxlan] remove %s: %v", name, err)
	}
}

// Reconcile converges the node's overlay links from prev to next.
func Reconcile(prev, next []Config) {
	remove, ensure := Plan(prev, next)
	for _, name := range remove {
		Remove(name)
	}
	for _, c := range ensure {
		Ensure(c)
	}
}
