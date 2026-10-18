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
		{"ipip pays 20 bytes", Config{Kind: KindIPIP, TunnelMTU: 1420}, 1400},
		{"gre pays 24 bytes", Config{Kind: KindGRE, TunnelMTU: 1420}, 1396},
		{"explicit mtu still wins for gre", Config{Kind: KindGRE, MTU: 1300, TunnelMTU: 1420}, 1300},
		{"tunnel smaller than the overhead -> kernel default", Config{TunnelMTU: 40}, 0},
	}
	for _, c := range cases {
		if got := linkMTU(c.cfg); got != c.want {
			t.Fatalf("%s: linkMTU = %d, want %d", c.name, got, c.want)
		}
	}
}

// ipip/gre have no VNI, so the link is applicable with vni 0; VXLAN still
// requires one.
func TestApplicable(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"ipip without a vni", Config{Kind: KindIPIP, Name: "ipip7", Local: "10.1.14.1/30"}, true},
		{"gre without a vni", Config{Kind: KindGRE, Name: "gre7", Local: "10.1.14.1/30"}, true},
		{"vxlan needs a vni", Config{Name: "vxlan1144", Local: "10.1.14.1/30"}, false},
		{"vxlan with a vni", Config{Name: "vxlan1144", VNI: 1144, Local: "10.1.14.1/30"}, true},
		{"no address", Config{Kind: KindIPIP, Name: "ipip7"}, false},
	}
	for _, c := range cases {
		if got := applicable(c.cfg); got != c.want {
			t.Fatalf("%s: applicable = %v, want %v", c.name, got, c.want)
		}
	}
}

// Adding the underlay NIC later must recreate the tunnel: a link whose source
// is still "local any" would keep sending from the wrong address.
func TestMatchesTunnelDev(t *testing.T) {
	anyLocal := "link/ipip 0.0.0.0 brd 0.0.0.0\n    ipip remote 38.91.117.189 local any ttl inherit"
	pinned := "link/ipip 0.0.0.0 brd 0.0.0.0\n    ipip remote 38.91.117.189 local 15.235.143.151 dev ens3 ttl inherit"
	if matches(anyLocal, Config{Kind: KindIPIP, Remote: "38.91.117.189", Dev: "ens3"}) {
		t.Fatal("a tunnel with local any must be recreated once a dev is configured")
	}
	if !matches(pinned, Config{Kind: KindIPIP, Remote: "38.91.117.189", Dev: "ens3"}) {
		t.Fatal("a tunnel pinned to the right dev must be reused")
	}
	if matches(pinned, Config{Kind: KindIPIP, Remote: "38.91.117.189", Dev: "ens4"}) {
		t.Fatal("a tunnel pinned to another dev must be recreated")
	}
	if !matches(anyLocal, Config{Kind: KindIPIP, Remote: "38.91.117.189"}) {
		t.Fatal("without a dev the kernel picks the source, so the link still matches")
	}
}

func TestRouteDev(t *testing.T) {
	cases := []struct{ in, want string }{
		{"default via 15.235.143.1 dev ens3 proto dhcp src 15.235.143.151 metric 100", "ens3"},
		{"8.8.8.8 via 10.0.0.1 dev eth0 src 10.0.0.5 uid 0", "eth0"},
		{"default dev wg0 scope link", "wg0"},
		{"", ""},
		{"default via 192.168.1.1 proto static", ""},
	}
	for _, c := range cases {
		if got := RouteDev(c.in); got != c.want {
			t.Fatalf("RouteDev(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Every tunnel needs the encapsulation protocols and its own link allowed in.
func TestFwSpecs(t *testing.T) {
	specs := fwSpecs(Config{Name: "ipip7"})
	if len(specs) != 3 {
		t.Fatalf("got %d specs, want 3: %v", len(specs), specs)
	}
	if specs[0][1] != "4" || specs[1][1] != "47" {
		t.Fatalf("protocol rules wrong: %v", specs[:2])
	}
	if specs[2][0] != "-i" || specs[2][1] != "ipip7" {
		t.Fatalf("link rule wrong: %v", specs[2])
	}
	if len(fwSpecs(Config{})) != 2 {
		t.Fatal("an unnamed config must not add a link rule")
	}
}

// ipip/gre are created with "ip tunnel add … mode <kind>"; vxlan keeps its own
// incantation (and an empty Kind still means vxlan).
func TestAddArgsTunnelKinds(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want []string
	}{
		{
			"ipip",
			Config{Kind: KindIPIP, Name: "ipip3", Remote: "38.91.117.189", Dev: "enX0"},
			[]string{"tunnel", "add", "ipip3", "mode", "ipip", "remote", "38.91.117.189", "dev", "enX0"},
		},
		{
			"gre with key",
			Config{Kind: KindGRE, Name: "gre3", Remote: "38.91.117.189", Key: 7},
			[]string{"tunnel", "add", "gre3", "mode", "gre", "remote", "38.91.117.189", "key", "7"},
		},
		{
			"ipip ignores the gre key",
			Config{Kind: KindIPIP, Name: "ipip3", Remote: "1.2.3.4", Key: 7},
			[]string{"tunnel", "add", "ipip3", "mode", "ipip", "remote", "1.2.3.4"},
		},
		{
			"empty kind is vxlan",
			Config{Name: "vxlan1133", VNI: 1133},
			[]string{"link", "add", "vxlan1133", "type", "vxlan", "id", "1133"},
		},
	}
	for _, c := range cases {
		if got := addArgs(c.cfg); !reflect.DeepEqual(got, c.want) {
			t.Fatalf("%s: addArgs = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestMatchesTunnelKinds(t *testing.T) {
	gre := "link/gre 0.0.0.0 brd 0.0.0.0\n    gre remote 38.91.117.189 local 172.31.32.227 ttl inherit key 7"
	if !matches(gre, Config{Kind: KindGRE, Name: "gre3", Remote: "38.91.117.189", Key: 7}) {
		t.Fatal("matching gre link must be accepted")
	}
	for _, c := range []Config{
		{Kind: KindGRE, Remote: "1.2.3.4", Key: 7},       // other peer
		{Kind: KindGRE, Remote: "38.91.117.189", Key: 9}, // other key
		{Kind: KindIPIP, Remote: "38.91.117.189"},        // other mode
	} {
		if matches(gre, c) {
			t.Fatalf("gre link must not match %+v", c)
		}
	}

	ipip := "link/ipip 0.0.0.0 brd 0.0.0.0\n    ipip remote 38.91.117.189 local 172.31.32.227 ttl inherit"
	if !matches(ipip, Config{Kind: KindIPIP, Remote: "38.91.117.189"}) {
		t.Fatal("matching ipip link must be accepted")
	}
	if matches(ipip, Config{Kind: KindGRE, Remote: "38.91.117.189"}) {
		t.Fatal("an ipip link must not look like gre")
	}
}
