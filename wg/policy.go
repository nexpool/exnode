package wg

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// This file applies operator-supplied policy routing. Each configured line is an
// `ip route`/`ip rule` *add* command (e.g. source-based routing into a custom
// table). The agent runs it directly (argv, no shell) and derives the matching
// `del` for teardown by swapping the add/del verb, so the operator only writes
// the add side.

// policyLines splits the config into trimmed, non-empty, non-comment lines.
func policyLines(text string) []string {
	var out []string
	for _, ln := range strings.Split(text, "\n") {
		if ln = strings.TrimSpace(ln); ln != "" && !strings.HasPrefix(ln, "#") {
			out = append(out, ln)
		}
	}
	return out
}

// runPolicyLine executes one `ip ...` line with its add/del verb forced to verb.
// Only the `ip` binary is allowed and it is invoked without a shell.
func runPolicyLine(line, verb string) error {
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "ip" {
		return fmt.Errorf("unsupported policy line %q (must start with ip)", line)
	}
	swapped := make([]string, len(fields))
	copy(swapped, fields)
	for i, f := range swapped {
		if f == "add" || f == "del" {
			swapped[i] = verb
			break
		}
	}
	out, err := exec.Command(swapped[0], swapped[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %v (%s)", strings.Join(swapped[1:], " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// applyPolicyLine makes one line idempotent: delete first (ignore "not found"),
// then add. This avoids duplicate `ip rule` entries on repeated applies.
func applyPolicyLine(line string) {
	_ = runPolicyLine(line, "del")
	if err := runPolicyLine(line, "add"); err != nil {
		log.Printf("[policy] apply failed: %v", err)
	}
}

// policyFromSubnets extracts the source CIDRs from the `ip rule ... from <cidr>`
// lines, used to install FORWARD accept rules so the routed traffic is not
// dropped when the host's FORWARD policy is DROP and NAT is off.
func policyFromSubnets(text string) []string {
	var subs []string
	for _, ln := range policyLines(text) {
		f := strings.Fields(ln)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "from" {
				subs = append(subs, f[i+1])
			}
		}
	}
	return subs
}

// policyForwardRules builds FORWARD accept rules (out + return) per source CIDR.
func policyForwardRules(subnets []string) []rule {
	rules := make([]rule, 0, len(subnets)*2)
	for _, s := range subnets {
		rules = append(rules,
			rule{chain: "FORWARD", args: []string{"-s", s, "-j", "ACCEPT"}},
			rule{chain: "FORWARD", args: []string{"-d", s, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"}},
		)
	}
	return rules
}

// ApplyPolicyRoutes installs every desired line idempotently. Forwarding is
// enabled and FORWARD accept rules are added whenever there is anything to
// route, since policy routing forwards traffic through the host even when
// NAT/masquerade is off.
func ApplyPolicyRoutes(text string) {
	lines := policyLines(text)
	if len(lines) == 0 {
		return
	}
	if err := EnableForwarding(); err != nil {
		log.Printf("[policy] enable forwarding failed: %v", err)
	}
	for _, ln := range lines {
		applyPolicyLine(ln)
	}
	for _, r := range policyForwardRules(policyFromSubnets(text)) {
		if err := ensureRule(r); err != nil {
			log.Printf("[policy] forward rule failed: %v", err)
		}
	}
}

// RemovePolicyRoutes deletes every line and its FORWARD rule (safe when absent).
func RemovePolicyRoutes(text string) {
	for _, ln := range policyLines(text) {
		_ = runPolicyLine(ln, "del")
	}
	for _, r := range policyForwardRules(policyFromSubnets(text)) {
		_ = deleteRule(r)
	}
}

// ipShow runs `ip <args>` and returns stdout (best-effort, "" on error).
func ipShow(args ...string) string {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return ""
	}
	return string(out)
}

// fieldAfter returns the token following key in fields ("" if absent).
func fieldAfter(fields []string, key string) string {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == key {
			return fields[i+1]
		}
	}
	return ""
}

func hasField(fields []string, v string) bool {
	for _, f := range fields {
		if f == v {
			return true
		}
	}
	return false
}

// policyLinePresent reports whether the route/rule described by line currently
// exists in the kernel. Used by the watchdog to re-add only what went missing.
func policyLinePresent(line string) bool {
	f := strings.Fields(line)
	table := fieldAfter(f, "table")
	if table == "" {
		return true // can't determine; assume present to avoid churn
	}
	switch {
	case hasField(f, "rule"):
		from := fieldAfter(f, "from")
		for _, ln := range strings.Split(ipShow("rule", "show"), "\n") {
			if (from == "" || strings.Contains(ln, "from "+from)) && strings.Contains(ln, "lookup "+table) {
				return true
			}
		}
		return false
	case hasField(f, "route"):
		// Our composed table holds exactly the one default route; empty = gone.
		return strings.TrimSpace(ipShow("route", "show", "table", table)) != ""
	}
	return true
}

// EnsurePolicyRoutes re-adds any configured route/rule that has gone missing
// (e.g. a NIC restart flushed a device-bound route) without churning the ones
// still present. Cheap to call on a timer. FORWARD rules and ip_forward are
// re-checked too (both no-ops when already in place).
func EnsurePolicyRoutes(text string) {
	lines := policyLines(text)
	if len(lines) == 0 {
		return
	}
	_ = EnableForwarding()
	for _, ln := range lines {
		if policyLinePresent(ln) {
			continue
		}
		_ = runPolicyLine(ln, "del") // clear any half-state first
		if err := runPolicyLine(ln, "add"); err != nil {
			log.Printf("[policy] re-add failed: %v", err)
		}
	}
	for _, r := range policyForwardRules(policyFromSubnets(text)) {
		_ = ensureRule(r) // -C then -A; no-op if present
	}
}

// ReconcilePolicyRoutes converges from oldText to newText: lines and FORWARD
// rules dropped from the config are deleted, then the desired set is (re)applied
// idempotently.
func ReconcilePolicyRoutes(oldText, newText string) {
	wantLines := make(map[string]struct{})
	for _, ln := range policyLines(newText) {
		wantLines[ln] = struct{}{}
	}
	for _, ln := range policyLines(oldText) {
		if _, ok := wantLines[ln]; !ok {
			_ = runPolicyLine(ln, "del")
		}
	}
	wantSubs := make(map[string]struct{})
	for _, s := range policyFromSubnets(newText) {
		wantSubs[s] = struct{}{}
	}
	var staleSubs []string
	for _, s := range policyFromSubnets(oldText) {
		if _, ok := wantSubs[s]; !ok {
			staleSubs = append(staleSubs, s)
		}
	}
	for _, r := range policyForwardRules(staleSubs) {
		_ = deleteRule(r)
	}
	ApplyPolicyRoutes(newText)
}
