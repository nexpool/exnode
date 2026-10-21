package extras

import "testing"

func TestParseRouteLine(t *testing.T) {
	got, err := ParseRouteLine("10.10.200.0/24 via 10.10.37.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "route replace 10.10.200.0/24 via 10.10.37.1"
	if joinArgs(got) != want {
		t.Fatalf("got %q, want %q", joinArgs(got), want)
	}
	got, err = ParseRouteLine("10.10.200.0/24 via 10.10.37.1 table 1001")
	if err != nil || joinArgs(got) != "route replace 10.10.200.0/24 via 10.10.37.1 table 1001" {
		t.Fatalf("table variant: %v %q", err, joinArgs(got))
	}
	for _, bad := range []string{"", "10.10.200.0/24", "10.10.200.0/24 dev ens160", "10.0.0.0/8 via 1.1.1.1 metric 5"} {
		if _, err := ParseRouteLine(bad); err == nil {
			t.Fatalf("expected an error for %q", bad)
		}
	}
}

func TestParseRuleLine(t *testing.T) {
	got, err := ParseRuleLine("from 192.168.200.240/32 to 10.10.200.0/24 lookup main priority 32000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "from 192.168.200.240/32 to 10.10.200.0/24 lookup main priority 32000"
	if joinArgs(got) != want {
		t.Fatalf("got %q, want %q", joinArgs(got), want)
	}
	if _, err := ParseRuleLine("from 10.0.0.0/8 lookup 1001 priority 100"); err != nil {
		t.Fatalf("no-to variant rejected: %v", err)
	}
	for _, bad := range []string{"from 10.0.0.0/8", "lookup main", "from 10.0.0.0/8 lookup", "from 10.0.0.0/8 dev eth0"} {
		if _, err := ParseRuleLine(bad); err == nil {
			t.Fatalf("expected an error for %q", bad)
		}
	}
}

func TestParseNATLine(t *testing.T) {
	line := "-s 192.168.200.240/32 -d 10.10.200.0/24 -o ens160 -j MASQUERADE"
	got, err := ParseNATLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if joinArgs(got) != line {
		t.Fatalf("got %q, want %q", joinArgs(got), line)
	}
	for _, bad := range []string{"-s 10.0.0.0/8 -j DROP", "-A POSTROUTING -s 10.0.0.0/8 -j MASQUERADE", "--owner 1000 -j MASQUERADE"} {
		if _, err := ParseNATLine(bad); err == nil {
			t.Fatalf("expected an error for %q", bad)
		}
	}
}

func joinArgs(f []string) string {
	out := ""
	for i, s := range f {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}

// The operator may paste the exact shell line, not just the arguments.
func TestParseFullCommands(t *testing.T) {
	if got, err := ParseRouteLine("ip route add 10.10.200.0/24 via 10.10.37.1"); err != nil ||
		joinArgs(got) != "route replace 10.10.200.0/24 via 10.10.37.1" {
		t.Fatalf("route: %v %q", err, joinArgs(got))
	}
	if got, err := ParseRuleLine("ip rule add from 192.168.200.240/32 to 10.10.200.0/24 lookup main priority 32000"); err != nil ||
		joinArgs(got) != "from 192.168.200.240/32 to 10.10.200.0/24 lookup main priority 32000" {
		t.Fatalf("rule: %v %q", err, joinArgs(got))
	}
	want := "-s 192.168.200.240/32 -d 10.10.200.0/24 -o ens160 -j MASQUERADE"
	if got, err := ParseNATLine("iptables -t nat -A POSTROUTING " + want); err != nil || joinArgs(got) != want {
		t.Fatalf("nat: %v %q", err, joinArgs(got))
	}
}
