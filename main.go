// Command exnode is the WireGuard Panel node agent. It runs on each WireGuard
// server host, dials one or more panels, pulls the desired interface/peer
// state, applies it to the local kernel, and reports runtime stats back.
//
// Requires CAP_NET_ADMIN (root) and the `iptables` binary for masquerade.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"

	"github.com/nexpool/exnode/conf"
	"github.com/nexpool/exnode/engine"
	"github.com/nexpool/exnode/node"
)

// singboxConfig builds the node-local sing-box options for one panel. The
// engine *type* (kernel vs singbox) is chosen by the panel; these are the
// machine-local details used when the panel selects sing-box. Each panel gets a
// distinct rendered-config path so concurrent agents don't clash.
func singboxConfig(cfg *conf.Conf, nodeID uint) engine.SingboxConfig {
	sb := cfg.Engine.Singbox
	configPath := sb.ConfigPath
	if configPath == "" {
		configPath = fmt.Sprintf("/etc/exnode/sing-box-node%d.json", nodeID)
	}
	return engine.SingboxConfig{
		BinPath:    sb.BinPath,
		ConfigPath: configPath,
		System:     sb.System,
		LogLevel:   sb.LogLevel,
	}
}

// version is the agent version reported to the panel; override at build time
// with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	configPath := flag.String("c", "/etc/exnode/config.yml", "config file path")
	flag.Parse()

	cfg, err := conf.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	osName := runtime.GOOS
	var wg sync.WaitGroup
	for _, p := range cfg.Nodes {
		ctrl := node.NewController(p, singboxConfig(cfg, p.NodeID), version, osName)
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctrl.Run(ctx) // builds/owns its engine based on the panel-selected type
		}()
	}

	log.Printf("exnode %s started for %d panel(s)", version, len(cfg.Nodes))
	<-ctx.Done()
	wg.Wait()
	log.Println("exnode stopped")
}
