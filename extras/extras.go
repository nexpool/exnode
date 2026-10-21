package extras

// Custom routing entries: the operator writes plain lines in the panel and the
// agent keeps exactly those in place. Three kinds are supported:
//
//	route  10.10.200.0/24 via 10.10.37.1 [table 1001]
//	rule   from 192.168.200.240/32 [to 10.10.200.0/24] lookup main [priority 32000]
//	nat    -s 192.168.200.240/32 -d 10.10.200.0/24 -o ens160 -j MASQUERADE
//
// Routes use "ip route replace" so repeating a sync never duplicates them; rules
// are deleted before being added (ip rule has no replace) and NAT rules are
// checked with -C first. Entries removed in the panel are deleted again.
import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// Extras holds the custom entries of one interface.
type Extras struct {
	Routes []string
	Rules  []string
	NAT    []string
}

// IsZero reports whether no custom entry is configured.
func (e Extras) IsZero() bool {
	return len(e.Routes) == 0 && len(e.Rules) == 0 && len(e.NAT) == 0
}

// normalizeLines trims lines, dropping blanks and comments.
func normalizeLines(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out
}

// stripPrefix removes a leading command word sequence, so the operator can paste
// the exact shell line ("ip route add 10.0.0.0/8 via 1.1.1.1") instead of the bare
// arguments. Only the prefixes in prefixes are removed, longest first.
func stripPrefix(line string, prefixes []string) string {
	line = strings.TrimSpace(line)
	for _, p := range prefixes {
		if strings.HasPrefix(line, p+" ") {
			return strings.TrimSpace(strings.TrimPrefix(line, p))
		}
	}
	return line
}

// ParseRouteLine turns "DST via GW [table N]" into the argv of ip route replace.
func ParseRouteLine(line string) ([]string, error) {
	line = stripPrefix(line, []string{
		"ip route add", "ip route replace", "ip -4 route add", "ip -4 route replace",
		"ip route", "ip -4 route",
	})
	f := strings.Fields(line)
	if len(f) < 3 || f[1] != "via" {
		return nil, fmt.Errorf("route %q: expected \"<cidr> via <gateway> [table N]\"", line)
	}
	args := []string{"route", "replace", f[0], "via", f[2]}
	if len(f) > 3 {
		if len(f) != 5 || f[3] != "table" {
			return nil, fmt.Errorf("route %q: only \"table <n>\" may follow the gateway", line)
		}
		args = append(args, "table", f[4])
	}
	return args, nil
}

// ParseRuleLine validates "from … [to …] lookup … [priority N]" and returns the
// argv of ip rule add without the leading "rule add".
func ParseRuleLine(line string) ([]string, error) {
	line = stripPrefix(line, []string{"ip rule add", "ip -4 rule add", "ip rule", "ip -4 rule"})
	f := strings.Fields(line)
	if len(f) < 3 || f[0] != "from" {
		return nil, fmt.Errorf("rule %q: expected \"from <cidr> [to <cidr>] lookup <table> [priority N]\"", line)
	}
	hasLookup := false
	for i := 0; i < len(f); i++ {
		switch f[i] {
		case "from", "to":
			if i+1 >= len(f) {
				return nil, fmt.Errorf("rule %q: %s needs a value", line, f[i])
			}
			i++
		case "lookup":
			if i+1 >= len(f) {
				return nil, fmt.Errorf("rule %q: lookup needs a table", line)
			}
			hasLookup = true
			i++
		case "priority":
			if i+1 >= len(f) {
				return nil, fmt.Errorf("rule %q: priority needs a number", line)
			}
			i++
		default:
			return nil, fmt.Errorf("rule %q: unexpected %q", line, f[i])
		}
	}
	if !hasLookup {
		return nil, fmt.Errorf("rule %q: missing \"lookup <table>\"", line)
	}
	return f, nil
}

// ParseNATLine accepts the iptables arguments of a POSTROUTING rule
// ("-s … -d … -o … -j MASQUERADE"), rejecting anything that is not a match or a
// MASQUERADE/SNAT target.
func ParseNATLine(line string) ([]string, error) {
	line = stripPrefix(line, []string{
		"iptables -t nat -A POSTROUTING",
		"iptables -A POSTROUTING -t nat",
		"iptables -t nat -I POSTROUTING",
		"iptables -t nat -A",
		"iptables -t nat",
	})
	f := strings.Fields(line)
	if len(f) == 0 {
		return nil, fmt.Errorf("empty nat rule")
	}
	allowed := map[string]bool{
		"-s": true, "--source": true, "-d": true, "--destination": true,
		"-o": true, "--out-interface": true, "-p": true, "--protocol": true,
		"--dport": true, "--sport": true, "-j": true, "--to-source": true,
	}
	for i := 0; i < len(f); i++ {
		if !allowed[f[i]] {
			return nil, fmt.Errorf("nat %q: %q is not allowed here", line, f[i])
		}
		if i+1 >= len(f) {
			return nil, fmt.Errorf("nat %q: %s needs a value", line, f[i])
		}
		if f[i] == "-j" {
			target := strings.ToUpper(f[i+1])
			if target != "MASQUERADE" && target != "SNAT" {
				return nil, fmt.Errorf("nat %q: only MASQUERADE or SNAT targets are allowed", line)
			}
		}
		i++
	}
	return f, nil
}

func run(name string, args ...string) error {
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %v (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// applyRoutes installs the desired routes and deletes the ones that disappeared.
func applyRoutes(prev, next []string) {
	desired := map[string]bool{}
	for _, line := range normalizeLines(next) {
		args, err := ParseRouteLine(line)
		if err != nil {
			log.Printf("[custom] route skipped: %v", err)
			continue
		}
		desired[strings.Join(args, " ")] = true
		if err := run("ip", args...); err != nil {
			log.Printf("[custom] route %q: %v", line, err)
		}
	}
	for _, line := range normalizeLines(prev) {
		args, err := ParseRouteLine(line)
		if err != nil || desired[strings.Join(args, " ")] {
			continue
		}
		_ = exec.Command("ip", append([]string{"route", "del"}, args[2:]...)...).Run()
	}
}

// applyRules re-adds the desired rules (ip rule has no replace) and drops the
// ones that disappeared.
func applyRules(prev, next []string) {
	desired := map[string]bool{}
	for _, line := range normalizeLines(next) {
		args, err := ParseRuleLine(line)
		if err != nil {
			log.Printf("[custom] rule skipped: %v", err)
			continue
		}
		desired[strings.Join(args, " ")] = true
		for i := 0; i < 8; i++ { // rules are not idempotent: drop copies first
			if exec.Command("ip", append([]string{"rule", "del"}, args...)...).Run() != nil {
				break
			}
		}
		if err := run("ip", append([]string{"rule", "add"}, args...)...); err != nil {
			log.Printf("[custom] rule %q: %v", line, err)
		}
	}
	for _, line := range normalizeLines(prev) {
		args, err := ParseRuleLine(line)
		if err != nil || desired[strings.Join(args, " ")] {
			continue
		}
		for i := 0; i < 8; i++ {
			if exec.Command("ip", append([]string{"rule", "del"}, args...)...).Run() != nil {
				break
			}
		}
	}
}

// applyNAT adds missing POSTROUTING rules and removes the ones that disappeared.
func applyNAT(prev, next []string) {
	desired := map[string]bool{}
	for _, line := range normalizeLines(next) {
		args, err := ParseNATLine(line)
		if err != nil {
			log.Printf("[custom] nat skipped: %v", err)
			continue
		}
		desired[strings.Join(args, " ")] = true
		check := append([]string{"-t", "nat", "-C", "POSTROUTING"}, args...)
		if exec.Command("iptables", check...).Run() == nil {
			continue
		}
		if err := run("iptables", append([]string{"-t", "nat", "-A", "POSTROUTING"}, args...)...); err != nil {
			log.Printf("[custom] nat %q: %v", line, err)
		}
	}
	for _, line := range normalizeLines(prev) {
		args, err := ParseNATLine(line)
		if err != nil || desired[strings.Join(args, " ")] {
			continue
		}
		for i := 0; i < 8; i++ {
			if exec.Command("iptables", append([]string{"-t", "nat", "-D", "POSTROUTING"}, args...)...).Run() != nil {
				break
			}
		}
	}
}

// Reconcile converges the custom routes, rules and NAT entries of one
// interface from prev to next. Safe to call on every sync: each step is
// idempotent and entries removed in the panel are torn down.
func Reconcile(prev, next Extras) {
	applyRoutes(prev.Routes, next.Routes)
	applyRules(prev.Rules, next.Rules)
	applyNAT(prev.NAT, next.NAT)
}
