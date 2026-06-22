// Package panel is the exnode agent's client for the panel's node-facing API.
// It defines its own request/response types (decoupled from the panel's Go
// structs) and unwraps the panel's standard {success,message,data} envelope.
package panel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

// ApiHost exposes the configured panel host (for logging).
func (c *Client) ApiHost() string { return c.apiHost }

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
}

type HeartbeatResponse struct {
	ConfigRevision uint `json:"config_revision"`
}

type SyncResponse struct {
	ConfigRevision uint        `json:"config_revision"`
	Engine         string      `json:"engine"`
	Interfaces     []Interface `json:"interfaces"`
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
// data field into out (when non-nil).
func (c *Client) do(method, path string, body any, out any) error {
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
