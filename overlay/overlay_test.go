package overlay

import (
	"reflect"
	"strings"
	"testing"
)

// The link has to come out exactly like the documented iproute2 incantation.
func TestAddArgsBuildsVXLANLink(t *testing.T) {
	got := addArgs(Config{Name: "vxlan3002", VNI: 3002, Port: 3002, Dev: "eth0", Remote: "38.91.117.189"})
	want := []string{"link", "add", "vxlan3002", "type", "vxlan", "id", "3002", "remote", "38.91.117.189", "dev", "eth0", "dstport", "3002"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("addArgs = %v, want %v", got, want)
	}
}

// Optional parts are omitted instead of sent empty.
func TestAddArgsOmitsOptionalParts(t *testing.T) {
	got := addArgs(Config{Name: "vxlan7", VNI: 7})
	want := []string{"link", "add", "vxlan7", "type", "vxlan", "id", "7"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("addArgs = %v, want %v", got, want)
	}
}

func TestMatchesAcceptsSameParameters(t *testing.T) {
	show := `9: vxlan3002: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1370 qdisc noqueue state UNKNOWN
    vxlan id 3002 remote 38.91.117.189 dev eth0 srcport 0 0 dstport 3002 ageing 300`
	c := Config{Name: "vxlan3002", VNI: 3002, Port: 3002, Dev: "eth0", Remote: "38.91.117.189"}
	if !matches(show, c) {
		t.Fatal("identical link should match")
	}
}

// A changed VNI, port or peer means the link has to be recreated.
func TestMatchesRejectsChangedParameters(t *testing.T) {
	show := "    vxlan id 3002 remote 38.91.117.189 dev eth0 dstport 3002"
	for _, c := range []Config{
		{Name: "vxlan3002", VNI: 3003, Port: 3002, Dev: "eth0", Remote: "38.91.117.189"},
		{Name: "vxlan3002", VNI: 3002, Port: 4789, Dev: "eth0", Remote: "38.91.117.189"},
		{Name: "vxlan3002", VNI: 3002, Port: 3002, Dev: "eth0", Remote: "1.2.3.4"},
		{Name: "vxlan3002", VNI: 3002, Port: 3002, Dev: "ens3", Remote: "38.91.117.189"},
	} {
		if matches(show, c) {
			t.Fatalf("link must not match %+v", c)
		}
	}
	if matches("", Config{Name: "vxlan3002", VNI: 3002}) {
		t.Fatal("a missing link must not match")
	}
}

// Dropping the overlay (or the member) removes the link; a changed VNI replaces
// it; unchanged links are simply re-applied.
func TestPlanReconcilesLinks(t *testing.T) {
	prev := []Config{
		{Name: "vxlan100", VNI: 100}, // still wanted
		{Name: "vxlan200", VNI: 200}, // member removed
		{Name: "vxlan300", VNI: 300}, // VNI changed -> replaced
	}
	next := []Config{
		{Name: "vxlan100", VNI: 100},
		{Name: "vxlan400", VNI: 400},
	}

	remove, ensure := Plan(prev, next)

	if !reflect.DeepEqual(remove, []string{"vxlan200", "vxlan300"}) {
		t.Fatalf("remove = %v", remove)
	}
	names := make([]string, 0, len(ensure))
	for _, c := range ensure {
		names = append(names, c.Name)
	}
	if !reflect.DeepEqual(names, []string{"vxlan100", "vxlan400"}) {
		t.Fatalf("ensure = %v", names)
	}
}

// Entries without a name never reach the kernel.
func TestPlanIgnoresUnnamedConfigs(t *testing.T) {
	remove, ensure := Plan([]Config{{VNI: 1}}, []Config{{VNI: 2}})
	if len(remove) != 0 || len(ensure) != 0 {
		t.Fatalf("unnamed configs must be ignored, got remove=%v ensure=%v", remove, ensure)
	}
	if !strings.Contains(addArgs(Config{Name: "vxlan1", VNI: 1})[2], "vxlan1") {
		t.Fatal("sanity: link name must be in the argv")
	}
}

// Routes are applied with "route replace" (idempotent) and removed with "del".
func TestRouteArgs(t *testing.T) {
	spec := "192.168.200.0/24 via 10.10.13.2 dev vxlan1133"
	if got, want := routeArgs(spec), []string{"route", "replace", "192.168.200.0/24", "via", "10.10.13.2", "dev", "vxlan1133"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("routeArgs = %v, want %v", got, want)
	}
	if got, want := routeDelArgs(spec), []string{"route", "del", "192.168.200.0/24", "via", "10.10.13.2", "dev", "vxlan1133"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("routeDelArgs = %v, want %v", got, want)
	}
}

// Dropped routes are cleaned up only while their link survives; when the whole
// link goes away the kernel removes its routes with the device.
func TestStaleRoutes(t *testing.T) {
	prev := []Config{
		{Name: "vxlan1133", Routes: []string{"a", "b"}},
		{Name: "vxlan2000", Routes: []string{"gone-with-the-link"}},
	}
	next := []Config{
		{Name: "vxlan1133", Routes: []string{"b", "d"}},
	}

	got := staleRoutes(prev, next)
	if !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("staleRoutes = %v, want [a]", got)
	}
	if again := staleRoutes(next, next); len(again) != 0 {
		t.Fatalf("no-op reconcile must leave routes alone, got %v", again)
	}
}

// An explicit MTU wins; otherwise the link is sized down from the tunnel MTU.
func TestLinkMTU(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want int
	}{
		{"explicit mtu wins", Config{MTU: 1400, TunnelMTU: 1420}, 1400},
		{"auto from the tunnel", Config{TunnelMTU: 1420}, 1370},
		{"no tunnel mtu -> kernel default", Config{}, 0},
		{"tunnel smaller than the overhead -> kernel default", Config{TunnelMTU: 40}, 0},
	}
	for _, c := range cases {
		if got := linkMTU(c.cfg); got != c.want {
			t.Fatalf("%s: linkMTU = %d, want %d", c.name, got, c.want)
		}
	}
}
