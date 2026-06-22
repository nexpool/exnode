# exnode

WireGuard Panel **node agent**. Runs on each WireGuard server host and is the
only component that touches the kernel. The panel is a pure control plane: it
stores desired state; `exnode` pulls it and applies it locally.

## How it works

Pull model (works behind NAT — the panel never needs inbound access to the node):

1. **Heartbeat** (`POST /api/v1/node/heartbeat`, ~15s): check in and read the
   panel's current `config_revision`. The panel marks the node _online_ from
   these check-ins, so it appears in the "new interface" node picker.
2. **Sync** (`GET /api/v1/node/sync`): whenever the revision changes, pull the
   full desired state (this node's enabled interfaces + peers) and reconcile the
   kernel toward it — `netlink` to create/bring up devices, `wgctrl` to program
   keys/peers **incrementally** (so unaffected peers keep their handshake), and
   `iptables` for masquerade. Stale interfaces the agent created are removed.
3. **Status** (`POST /api/v1/node/status`, ~20s): read per-peer handshake/RX/TX
   from the kernel and report them back so the panel dashboard shows live state.

## Datapath engines

The datapath is pluggable (`Engine.Type` in the config):

|                            | `kernel` (default)                | `singbox`                              |
| -------------------------- | --------------------------------- | -------------------------------------- |
| Backend                    | kernel WireGuard (netlink/wgctrl) | sing-box process (userspace)           |
| Speed                      | fastest                           | slower (gVisor/system tun)             |
| Peer add/remove            | incremental, no disruption        | config reload, brief disruption        |
| Per-peer stats             | accurate (`wg show`)              | not reported (heartbeat liveness only) |
| Needs kernel module / root | yes                               | no (gVisor mode)                       |

Use `kernel` on normal Linux hosts with root. Use `singbox` only where the
kernel module isn't available (restricted containers, userspace-only).

**The engine type is selected in the panel** (per node, on create or via the
node list), and pushed to the agent over sync — switching it makes the agent
rebuild its datapath on the next heartbeat. `config.yml` only provides
node-local sing-box options (binary path, System mode) used when the panel
picks `singbox`.

## Requirements

- **kernel engine**: Linux with the WireGuard kernel module
  (`modprobe wireguard`), `CAP_NET_ADMIN`/root, and `iptables` for masquerade.
- **singbox engine**: a `sing-box` binary on the host (≥ the version with the
  `wireguard` endpoint). gVisor mode needs no kernel module; `System: true`
  needs `CAP_NET_ADMIN` + `iptables`.

## Configure

The panel admin creates a node (panel UI → Nodes → New) and gets a one-time
**NodeID + SecretKey**. Put them in `config.yml`:

```yaml
Log:
  Level: info
Nodes:
  - ApiHost: https://panel.example.com # HTTPS strongly recommended
    NodeID: 1
    SecretKey: <secret-from-panel>
    Timeout: 30
    HeartbeatSeconds: 15
    StatusSeconds: 20
```

> **Use HTTPS.** `/node/sync` returns interface private keys (the device needs
> them). One agent can serve several panels — add more entries under `Nodes`.

## Install (no Go toolchain needed)

`scripts/install.sh` downloads a prebuilt binary, writes a config template and an
(inlined) systemd unit, and enables the service:

```bash
sudo bash scripts/install.sh \
  --api-host https://panel.example.com --node-id 1 --secret-key <secret-from-panel>
```

Options: `--version vX.Y.Z` (default: latest release), `--system` (sing-box
system-tun mode). To install a binary you built yourself instead of downloading:
`sudo EXNODE_BIN=./exnode bash scripts/install.sh`.

It also installs an `exnode` management command:

```bash
exnode start | stop | restart | status | log | update | uninstall | config
```

## Build from source (optional)

```bash
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=$(git describe --tags --always 2>/dev/null || echo dev)" -o exnode .
sudo ./exnode -c /etc/exnode/config.yml
```

## Verify

```bash
sudo wg show                 # devices + peers programmed by the agent
journalctl -u exnode -f      # agent logs (sync revisions, errors)
```
