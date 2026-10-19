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
	"github.com/nexpool/exnode/selfupdate"
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

// defaultKey is the built-in AES passphrase used when neither -k nor EXNODE_KEY
// is given, so the agent decrypts its config without any runtime environment.
// Override at build time with -ldflags "-X main.defaultKey=...".
//
// SECURITY: this key is embedded in the binary — anyone who obtains the binary
// can recover it (e.g. `strings`). It protects the config file at rest and in
// backups/transit, NOT against someone who already has the binary itself.
var defaultKey = "exnodeKey-1123123"

func main() {
	// Version is handy to check without a shell wrapper: exnode version / -v /
	// --version / -version all print the same line and exit.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "v", "-v", "--version":
			fmt.Println(version)
			if exe, err := os.Executable(); err == nil {
				fmt.Println("path:", exe)
			}
			return
		}
	}

	configPath := flag.String("c", "/etc/exnode/config.yml", "config file path")
	keyFlag := flag.String("k", "", "AES passphrase for an encrypted config (overrides EXNODE_KEY)")
	encrypt := flag.Bool("encrypt", false, "encrypt the -c config file in place and exit")
	decrypt := flag.Bool("decrypt", false, "decrypt the -c config to stdout and exit")
	showVersion := flag.Bool("version", false, "print the agent version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	passphrase := *keyFlag
	if passphrase == "" {
		passphrase = os.Getenv("EXNODE_KEY")
	}
	if passphrase == "" {
		passphrase = defaultKey
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

	// A binary replaced while this process kept running (docker cp, install.sh, a
	// supervisor that did not restart it) would otherwise keep the old version
	// forever: "exnode version" reads the file, the panel reads this process.
	selfupdate.Adopt(version)

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

	exe, _ := os.Executable()
	log.Printf("exnode %s started (pid %d, %s) for %d panel(s)", version, os.Getpid(), exe, len(cfg.Nodes))
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
