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
	"io"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
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
	keyFlag := flag.String("k", "", "AES passphrase for an encrypted config (overrides EXNODE_KEY)")
	encrypt := flag.Bool("encrypt", false, "encrypt the -c config file in place and exit")
	decrypt := flag.Bool("decrypt", false, "decrypt the -c config to stdout and exit")
	flag.Parse()

	passphrase := *keyFlag
	if passphrase == "" {
		passphrase = os.Getenv("EXNODE_KEY")
	}

	if *encrypt {
		if err := encryptConfigFile(*configPath, passphrase); err != nil {
			log.Fatalf("encrypt config: %v", err)
		}
		log.Printf("encrypted %s in place", *configPath)
		return
	}

	if *decrypt {
		plain, err := decryptConfigFile(*configPath, passphrase)
		if err != nil {
			log.Fatalf("decrypt config: %v", err)
		}
		os.Stdout.Write(plain)
		return
	}

	cfg, err := conf.LoadWithKey(*configPath, passphrase)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	switch strings.ToLower(cfg.Log.Level) {
	case "none", "off", "silent", "quiet", "disabled":
		log.SetOutput(io.Discard)
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

// decryptConfigFile returns the plaintext YAML for path. An already-plaintext
// file is returned unchanged so the command is safe to run on either form.
func decryptConfigFile(path, passphrase string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !conf.IsEncrypted(data) {
		return data, nil
	}
	return conf.Decrypt(data, passphrase)
}

// encryptConfigFile reads the plaintext YAML at path, validates it parses, and
// rewrites the file as an AES-encrypted blob. Re-encrypting an already
// encrypted file is a no-op error so a passphrase typo can't double-wrap it.
func encryptConfigFile(path, passphrase string) error {
	if passphrase == "" {
		return fmt.Errorf("no passphrase: pass -k or set EXNODE_KEY")
	}
	plain, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if conf.IsEncrypted(plain) {
		return fmt.Errorf("%s is already encrypted", path)
	}
	if _, err := conf.LoadWithKey(path, ""); err != nil {
		return fmt.Errorf("refusing to encrypt invalid config: %w", err)
	}
	blob, err := conf.Encrypt(plain, passphrase)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	mode := os.FileMode(0o600)
	if err == nil {
		mode = info.Mode().Perm()
	}
	return os.WriteFile(path, blob, mode)
}
