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
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
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
	Kind string
	Name string // link name, e.g. vxlan3002 / gre3 / ipip3
	VNI  int    // VXLAN network identifier
	Port int    // VXLAN UDP destination port
	Key  int    // GRE key (0 = none)
	// LocalIP pins the tunnel's underlay (source) address; empty lets the kernel
	// pick it from the route to Remote.
	LocalIP string
	Dev     string // optional underlay NIC
	Local   string // address assigned to the link (CIDR)
	Remote  string // peer address (VTEP for VXLAN, tunnel endpoint for ipip/gre)
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

// RouteDev pulls the "dev <name>" interface out of ip route output, e.g.
// "default via 15.235.143.1 dev ens3 proto dhcp src 15.235.143.151" -> ens3.
// The controller reports this node's default-route NIC to the panel, which
// prefills the tunnel underlay device with it.
func RouteDev(text string) string {
	fields := strings.Fields(text)
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
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
		if c.LocalIP != "" {
			args = append(args, "local", c.LocalIP)
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
	if c.LocalIP != "" {
		args = append(args, "local", c.LocalIP)
	}
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
		// A tunnel pinned to an underlay NIC must have picked that NIC's address
		// as its source; "local any" means the link was built before the device
		// was configured, so recreate it instead of reusing it.
		if c.LocalIP != "" && !strings.Contains(show, "local "+c.LocalIP) {
			return false
		}
		if c.Dev != "" {
			if strings.Contains(show, "local any") {
				return false
			}
			if strings.Contains(show, "dev ") && !strings.Contains(show, "dev "+c.Dev) {
				return false
			}
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
	if c.LocalIP != "" {
		checks = append(checks, "local "+c.LocalIP)
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

// fwSpecs are the INPUT match specs a tunnel needs: the encapsulation protocols
// (ipip = 4, gre = 47) and the link itself. Without them a host whose firewall
// only accepts established/related silently drops the peer's packets: the
// tunnel then only works in the direction that was dialled last.
func fwSpecs(c Config) [][]string {
	specs := [][]string{{"-p", "4"}, {"-p", "47"}}
	if c.Name != "" {
		specs = append(specs, []string{"-i", c.Name})
	}
	return specs
}

// firewallAllow opens the host firewall for one tunnel. Best effort: a host
// without iptables still gets a working tunnel, we only log the rejection.
func firewallAllow(c Config) {
	for _, spec := range fwSpecs(c) {
		check := append(append([]string{"-C", "INPUT"}, spec...), "-j", "ACCEPT")
		if exec.Command("iptables", check...).Run() == nil {
			continue // already allowed
		}
		args := append([]string{"-I", "INPUT"}, spec...)
		args = append(args, "-j", "ACCEPT")
		if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
			log.Printf("[overlay] firewall allow %v: %v (%s)", spec, err, strings.TrimSpace(string(out)))
		}
	}
}

// firewallForget drops the link-specific rule of a removed tunnel.
func firewallForget(name string) {
	if name == "" {
		return
	}
	for i := 0; i < 8; i++ {
		args := []string{"-D", "INPUT", "-i", name, "-j", "ACCEPT"}
		if err := exec.Command("iptables", args...).Run(); err != nil {
			return // no more copies
		}
	}
}

// forwardSpecs are the FORWARD match specs a tunnel needs: traffic arriving
// from it (the peer's LAN heading out) and traffic going into it (answers).
func forwardSpecs(c Config) [][]string {
	if c.Name == "" {
		return nil
	}
	return [][]string{{"-i", c.Name}, {"-o", c.Name}}
}

// ensureForwarding turns IPv4 forwarding on. A host with it disabled silently
// drops everything that arrives from the tunnel but is not addressed to the node
// itself, which looks exactly like "the tunnel is up but there is no internet".
func ensureForwarding() {
	const path = "/proc/sys/net/ipv4/ip_forward"
	if b, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(b)) == "1" {
		return
	}
	if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
		log.Printf("[overlay] enable ip_forward: %v (traffic between this tunnel and the uplink will be dropped)", err)
	}
}

// forwardAllow lets a tunnel's traffic be routed through this node. Hosts whose
// FORWARD policy is DROP (docker installs that) otherwise drop every packet that
// arrives from the tunnel and is not addressed to the node itself.
func forwardAllow(c Config) {
	for _, spec := range forwardSpecs(c) {
		check := append(append([]string{"-C", "FORWARD"}, spec...), "-j", "ACCEPT")
		if exec.Command("iptables", check...).Run() == nil {
			continue
		}
		args := append([]string{"-I", "FORWARD"}, spec...)
		args = append(args, "-j", "ACCEPT")
		if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
			log.Printf("[overlay] forward allow %v: %v (%s)", spec, err, strings.TrimSpace(string(out)))
		}
	}
}

// forwardForget drops the FORWARD rules of a removed tunnel.
func forwardForget(name string) {
	for _, spec := range forwardSpecs(Config{Name: name}) {
		for i := 0; i < 8; i++ {
			args := append([]string{"-D", "FORWARD"}, spec...)
			args = append(args, "-j", "ACCEPT")
			if err := exec.Command("iptables", args...).Run(); err != nil {
				break
			}
		}
	}
}

// relaxRPFilter turns reverse-path filtering down to loose mode for the tunnel
// link (strict mode drops packets that arrive on a tunnel whose reverse route
// looks asymmetric). The kernel takes the maximum of all/rp_filter and the
// per-device value, so a global 1 is relaxed too.
func relaxRPFilter(name string) {
	if name == "" {
		return
	}
	write := func(path, why string) {
		if err := os.WriteFile(path, []byte("2\n"), 0o644); err != nil {
			log.Printf("[overlay] rp_filter %s (%s): %v", path, why, err)
		}
	}
	all := "/proc/sys/net/ipv4/conf/all/rp_filter"
	if b, err := os.ReadFile(all); err == nil && strings.TrimSpace(string(b)) == "1" {
		write(all, "global strict mode drops tunnel packets")
	}
	write("/proc/sys/net/ipv4/conf/"+name+"/rp_filter", "tunnel link")
}

// Ensure creates or updates one overlay link and assigns its address.
// applicable reports whether a link is worth building: a name and an address
// always, plus a VNI for VXLAN (ipip/gre have no VNI, the panel sends 0).
func applicable(c Config) bool {
	if c.Name == "" || strings.TrimSpace(c.Local) == "" {
		return false
	}
	if kind(c) == KindVXLAN && c.VNI < 1 {
		return false
	}
	return true
}

func Ensure(c Config) {
	if !applicable(c) {
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
	// The link exists now: make sure the host firewall lets the peer in and
	// that reverse-path filtering does not silently drop its packets.
	relaxRPFilter(c.Name)
	firewallAllow(c)
	ensureForwarding()
	forwardAllow(c)
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
	firewallForget(name)
	forwardForget(name)
	if err := ip("link", "del", name); err != nil {
		log.Printf("[overlay] remove %s: %v", name, err)
	}
}

// managedInputRules are the INPUT specs this package owns; managedForwardRules
// the FORWARD ones. Only these are ever deduplicated or removed.
func managedInputRules(links []Config) map[string]struct{} {
	out := map[string]struct{}{"-p 4 -j ACCEPT": {}, "-p 47 -j ACCEPT": {}}
	for _, c := range links {
		if c.Name != "" {
			out["-i "+c.Name+" -j ACCEPT"] = struct{}{}
		}
	}
	return out
}

func managedForwardRules(links []Config) map[string]struct{} {
	out := map[string]struct{}{}
	for _, c := range links {
		if c.Name == "" {
			continue
		}
		out["-i "+c.Name+" -j ACCEPT"] = struct{}{}
		out["-o "+c.Name+" -j ACCEPT"] = struct{}{}
	}
	return out
}

// dedupeRules deletes repeated copies of the rules listed in keep, leaving one.
// Earlier agents added a copy on every sync (the -C check omitted -j ACCEPT), so
// a long-running node accumulated dozens of identical lines.
func dedupeRules(chain string, keep map[string]struct{}) int {
	if len(keep) == 0 {
		return 0
	}
	out, err := exec.Command("iptables", "-S", chain).Output()
	if err != nil {
		return 0
	}
	counts := map[string]int{}
	for _, line := range strings.Split(string(out), "\n") {
		spec := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "-A "))
		if _, ok := keep[spec]; ok {
			counts[spec]++
		}
	}
	removed := 0
	for spec, n := range counts {
		for i := 1; i < n; i++ {
			args := append([]string{"-D", chain}, strings.Fields(spec)...)
			if exec.Command("iptables", args...).Run() != nil {
				break
			}
			removed++
		}
	}
	return removed
}

// SelfCheck reports the host-side prerequisites a working tunnel needs and that
// are easy to lose: IPv4 forwarding and a FORWARD accept rule for the link.
// It only logs when something is wrong, at most once every five minutes per
// problem, so a broken node is visible without flooding the journal.
func SelfCheck(links []Config) {
	if len(links) == 0 {
		return
	}
	if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil && strings.TrimSpace(string(b)) != "1" {
		warnOnce("ip_forward", "ip_forward is 0: packets that arrive from a tunnel and are not addressed to this node are dropped")
	}
	if n := dedupeRules("INPUT", managedInputRules(links)) + dedupeRules("FORWARD", managedForwardRules(links)); n > 0 {
		warnOnce("dedupe", "removed duplicate tunnel firewall rules (older agents added one per sync)", n)
	}
	for _, c := range links {
		for _, spec := range forwardSpecs(c) {
			check := append(append([]string{"-C", "FORWARD"}, spec...), "-j", "ACCEPT")
			if exec.Command("iptables", check...).Run() != nil {
				warnOnce("forward"+c.Name+strings.Join(spec, ""), "no FORWARD accept for "+strings.Join(spec, " ")+": traffic through "+c.Name+" is dropped")
			}
		}
	}
}

// warnOnce logs a self-check problem at most once per five minutes.
func warnOnce(key, msg string, args ...any) {
	warnMu.Lock()
	defer warnMu.Unlock()
	if warnSeen == nil {
		warnSeen = map[string]time.Time{}
	}
	if last, ok := warnSeen[key]; ok && time.Since(last) < 5*time.Minute {
		return
	}
	warnSeen[key] = time.Now()
	msg = fmt.Sprintf(msg, args...)
	log.Printf("[overlay] self-check: %s", msg)
}

var (
	warnMu   sync.Mutex
	warnSeen map[string]time.Time
)

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
	SelfCheck(next)
}
