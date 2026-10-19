// Package panel is the exnode agent's client for the panel's node-facing API.
// It defines its own request/response types (decoupled from the panel's Go
// structs) and unwraps the panel's standard {success,message,data} envelope.
package panel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client talks to one panel as one node.
type Client struct {
	apiHost string
	nodeID  uint
	secret  string
	http    *http.Client
}

// New builds a Client. apiHost is the panel base URL (e.g.
// https://panel.example.com); the node-API path is appended automatically.
func New(apiHost string, nodeID uint, secret string, timeout time.Duration) *Client {
	return &Client{
		apiHost: strings.TrimRight(apiHost, "/"),
		nodeID:  nodeID,
		secret:  secret,
		http:    &http.Client{Timeout: timeout},
	}
}

// ApiHost exposes the configured panel host (for internal use only — do NOT
// log it; use Label for a non-sensitive tag).
func (c *Client) ApiHost() string { return c.apiHost }

// NodeID exposes the configured node id.
func (c *Client) NodeID() uint { return c.nodeID }

// Label is a non-sensitive log tag for this panel connection. It deliberately
// omits the panel host/domain so the domain never appears in logs; the node id
// is enough to tell multiple panels apart.
func (c *Client) Label() string { return "node " + strconv.FormatUint(uint64(c.nodeID), 10) }

// panelHost is the bare hostname of the configured panel, used for redaction.
func (c *Client) panelHost() string {
	if u, err := url.Parse(c.apiHost); err == nil {
		return u.Hostname()
	}
	return ""
}

// sanitize strips the panel URL and hostname from a message so the domain never
// leaks into logs (transport errors embed the full request URL, e.g.
// `Get "https://panel/api/...": dial tcp ...`).
func (c *Client) sanitize(s string) string {
	if c.apiHost != "" {
		s = strings.ReplaceAll(s, c.apiHost, "[panel]")
	}
	if h := c.panelHost(); h != "" {
		s = strings.ReplaceAll(s, h, "[panel]")
	}
	return s
}

// envelope is the panel's standard response wrapper.
type envelope struct {
	Success bool            `json:"success"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// --- wire types (match dto/node_dto.go on the panel side) ---

type HeartbeatRequest struct {
	AgentVersion string `json:"agent_version"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	// UpgradeError reports why the last self-upgrade attempt failed (empty when
	// there is nothing to report).
	UpgradeError string `json:"upgrade_error,omitempty"`
	// PrimaryInterface is the node's default-route NIC, so the panel can propose
	// the right underlay device for tunnels instead of asking the operator.
	PrimaryInterface string `json:"primary_interface,omitempty"`
	// BinaryPath is the executable this agent runs from: two agents on one host
	// that share a file overwrite each other during self-update.
	BinaryPath string `json:"binary_path,omitempty"`
	// PID and StartedAt identify this process: one NodeID must not be served by
	// two agents, and alternating versions are the symptom when it is.
	PID       int   `json:"pid,omitempty"`
	StartedAt int64 `json:"started_at,omitempty"`
}

// UpgradeDirective is a self-upgrade order from the panel: download URL, replace
// this binary, restart.
type UpgradeDirective struct {
	Version string `json:"version"`
	URL     string `json:"url"`
}

type HeartbeatResponse struct {
	ConfigRevision uint              `json:"config_revision"`
	Upgrade        *UpgradeDirective `json:"upgrade,omitempty"`
}

type SyncResponse struct {
	ConfigRevision uint        `json:"config_revision"`
	Engine         string      `json:"engine"`
	Interfaces     []Interface `json:"interfaces"`
}

// VXLAN is one overlay link the panel wants on this node.
type VXLAN struct {
	// Kind is "vxlan" (default), "ipip" or "gre".
	Kind string `json:"kind,omitempty"`
	Name string `json:"name"`
	VNI  int    `json:"vni"`
	Port int    `json:"port"`
	// Key is the GRE key (0 = none).
	// LocalIP pins the tunnel's underlay (source) address; empty = kernel choice.
	LocalIP string `json:"local_ip,omitempty"`
	Key     int    `json:"key,omitempty"`
	// MTU overrides the link MTU; 0 = derive it from the tunnel MTU.
	MTU    int    `json:"mtu,omitempty"`
	Dev    string `json:"dev,omitempty"`
	Local  string `json:"local"`
	Remote string `json:"remote"`
	// Routes are already rendered as "ip route replace" arguments.
	Routes []string `json:"routes,omitempty"`
}

type Interface struct {
	Name            string `json:"name"`
	PrivateKey      string `json:"private_key"`
	ListenPort      int    `json:"listen_port"`
	Address         string `json:"address"`
	MTU             int    `json:"mtu"`
	Masquerade      bool   `json:"masquerade"`
	EgressInterface string `json:"egress_interface"`
	NATSubnets      string `json:"nat_subnets"`
	PolicyRoutes    string `json:"policy_routes"`
	Peers           []Peer `json:"peers"`
	// Tunnels are every overlay link this interface needs; VXLAN is the
	// single-tunnel field of older panels, read only when Tunnels is empty.
	Tunnels []VXLAN `json:"tunnels,omitempty"`
	VXLAN   *VXLAN  `json:"vxlan,omitempty"`
}

type Peer struct {
	PublicKey           string `json:"public_key"`
	PresharedKey        string `json:"preshared_key"`
	AllowedIPs          string `json:"allowed_ips"`
	PersistentKeepalive int    `json:"persistent_keepalive"`
}

type StatusRequest struct {
	Peers []StatusPeer `json:"peers"`
}

type StatusPeer struct {
	PublicKey     string     `json:"public_key"`
	LastHandshake *time.Time `json:"last_handshake"`
	RxBytes       int64      `json:"rx_bytes"`
	TxBytes       int64      `json:"tx_bytes"`
	Endpoint      string     `json:"endpoint"`
}

// Heartbeat checks in and returns the current desired-state revision.
func (c *Client) Heartbeat(req HeartbeatRequest) (*HeartbeatResponse, error) {
	var out HeartbeatResponse
	if err := c.do(http.MethodPost, "/api/v1/node/heartbeat", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Sync fetches the full desired state for this node.
func (c *Client) Sync() (*SyncResponse, error) {
	var out SyncResponse
	if err := c.do(http.MethodGet, "/api/v1/node/sync", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ReportStatus pushes per-peer runtime stats to the panel.
func (c *Client) ReportStatus(req StatusRequest) error {
	return c.do(http.MethodPost, "/api/v1/node/status", req, nil)
}

// do performs an authenticated request, unwraps the envelope, and decodes the
// data field into out (when non-nil). Any error it returns is scrubbed of the
// panel host/domain before it reaches a caller (and thus the log).
func (c *Client) do(method, path string, body any, out any) (err error) {
	defer func() {
		if err != nil {
			err = errors.New(c.sanitize(err.Error()))
		}
	}()

	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		reader = bytes.NewReader(buf)
	}

	req, err := http.NewRequest(method, c.apiHost+path, reader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Node-ID", strconv.FormatUint(uint64(c.nodeID), 10))
	req.Header.Set("Authorization", "Bearer "+c.secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	if out == nil {
		return nil
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("decode envelope: %w", err)
	}
	if len(env.Data) == 0 || string(env.Data) == "null" {
		return nil
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("decode data: %w", err)
	}
	return nil
}
