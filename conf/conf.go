// Package conf loads the exnode agent configuration. The layout mirrors the
// kknode/fami-node convention: a top-level Nodes list lets one agent serve
// several panels at once, each panel identified by its API host, node id and
// secret.
package conf

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Conf is the root configuration.
type Conf struct {
	Log    LogConfig     `yaml:"Log"`
	Engine EngineConfig  `yaml:"Engine"`
	Nodes  []PanelConfig `yaml:"Nodes"`
}

// LogConfig controls logging verbosity.
type LogConfig struct {
	Level string `yaml:"Level"`
}

// EngineConfig selects and configures the datapath backend.
type EngineConfig struct {
	// Type is "kernel" (default) or "singbox".
	Type string `yaml:"Type"`
	// Singbox holds sing-box backend options (used when Type == "singbox").
	Singbox SingboxConfig `yaml:"Singbox"`
}

// SingboxConfig configures the sing-box datapath.
type SingboxConfig struct {
	// BinPath is the sing-box executable (default "sing-box" on PATH).
	BinPath string `yaml:"BinPath"`
	// ConfigPath is where the rendered sing-box config is written.
	ConfigPath string `yaml:"ConfigPath"`
	// System uses a system tun (needs CAP_NET_ADMIN + iptables for NAT). When
	// false (default) sing-box uses the gVisor userspace netstack and peers
	// reach the internet via the host's sockets — no kernel module required.
	System bool `yaml:"System"`
	// LogLevel for sing-box (default "warn").
	LogLevel string `yaml:"LogLevel"`
}

// EngineType returns the configured engine type, defaulting to "kernel".
func (c *Conf) EngineType() string {
	if c.Engine.Type == "" {
		return "kernel"
	}
	return c.Engine.Type
}

// PanelConfig describes one control-plane endpoint this agent reports to.
type PanelConfig struct {
	// ApiHost is the panel base URL, e.g. https://panel.example.com (the agent
	// appends /api/v1/node/...). HTTPS is strongly recommended: /node/sync
	// returns interface private keys.
	ApiHost string `yaml:"ApiHost"`
	// NodeID and SecretKey are issued by the panel when the node is created.
	NodeID    uint   `yaml:"NodeID"`
	SecretKey string `yaml:"SecretKey"`
	// Timeout is the per-request HTTP timeout in seconds (default 30).
	Timeout int `yaml:"Timeout"`
	// HeartbeatSeconds / StatusSeconds tune the agent loops (defaults 15 / 20).
	HeartbeatSeconds int `yaml:"HeartbeatSeconds"`
	StatusSeconds    int `yaml:"StatusSeconds"`
}

// HeartbeatInterval returns the configured heartbeat period, with a default.
func (p PanelConfig) HeartbeatInterval() time.Duration {
	if p.HeartbeatSeconds <= 0 {
		return 15 * time.Second
	}
	return time.Duration(p.HeartbeatSeconds) * time.Second
}

// StatusInterval returns the configured status-report period, with a default.
func (p PanelConfig) StatusInterval() time.Duration {
	if p.StatusSeconds <= 0 {
		return 20 * time.Second
	}
	return time.Duration(p.StatusSeconds) * time.Second
}

// HTTPTimeout returns the configured HTTP timeout, with a default.
func (p PanelConfig) HTTPTimeout() time.Duration {
	if p.Timeout <= 0 {
		return 30 * time.Second
	}
	return time.Duration(p.Timeout) * time.Second
}

// Load reads and validates the config, taking the AES passphrase from the
// EXNODE_KEY environment variable. See LoadWithKey.
func Load(path string) (*Conf, error) {
	return LoadWithKey(path, os.Getenv("EXNODE_KEY"))
}

// LoadWithKey reads and validates the YAML config. The config bytes come from
// the EXNODE_CONFIG environment variable when set, otherwise from the file at
// path. If the bytes are an AES-encrypted blob (see Encrypt), they are
// decrypted with passphrase first. Plaintext YAML continues to work unchanged.
func LoadWithKey(path, passphrase string) (*Conf, error) {
	var data []byte
	if env := os.Getenv("EXNODE_CONFIG"); env != "" {
		data = []byte(env)
	} else {
		var err error
		data, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config %q: %w", path, err)
		}
	}

	if IsEncrypted(data) {
		plain, err := Decrypt(data, passphrase)
		if err != nil {
			return nil, err
		}
		data = plain
	}

	var c Conf
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if len(c.Nodes) == 0 {
		return nil, fmt.Errorf("no panels configured under Nodes")
	}
	for i, n := range c.Nodes {
		if n.ApiHost == "" || n.NodeID == 0 || n.SecretKey == "" {
			return nil, fmt.Errorf("Nodes[%d]: ApiHost, NodeID and SecretKey are required", i)
		}
	}
	return &c, nil
}
