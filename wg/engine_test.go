package wg

import (
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestBuildPeerConfig(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	pc, err := buildPeerConfig(Peer{
		PublicKey:           key.PublicKey().String(),
		AllowedIPs:          "10.8.0.2/32",
		PersistentKeepalive: 25,
	})
	if err != nil {
		t.Fatalf("buildPeerConfig() error = %v", err)
	}
	if pc.Remove {
		t.Fatalf("peer.Remove = true, want false for add/update")
	}
	if !pc.ReplaceAllowedIPs {
		t.Fatalf("ReplaceAllowedIPs = false, want true")
	}
	if len(pc.AllowedIPs) != 1 {
		t.Fatalf("len(AllowedIPs) = %d, want 1", len(pc.AllowedIPs))
	}
	if pc.PersistentKeepaliveInterval == nil || *pc.PersistentKeepaliveInterval != 25*time.Second {
		t.Fatalf("PersistentKeepaliveInterval = %v, want 25s", pc.PersistentKeepaliveInterval)
	}
}

func TestParseCIDRListRejectsInvalid(t *testing.T) {
	if _, err := parseCIDRList("0.0.0.0/0, not-a-cidr"); err == nil {
		t.Fatalf("parseCIDRList() error = nil, want invalid CIDR error")
	}
	out, err := parseCIDRList("10.8.0.0/24, 192.168.0.0/16")
	if err != nil {
		t.Fatalf("parseCIDRList() error = %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("len = %d, want 2", len(out))
	}
}
