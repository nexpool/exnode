#!/usr/bin/env bash
# Install the exnode agent: download a prebuilt binary, write a config template,
# a systemd unit, and an `exnode` management command. No Go toolchain required.
#
# Usage:
#   ./install.sh [--version vX.Y.Z] [--api-host URL] [--node-id N] [--secret-key KEY] [--system]
#
# Env:
#   EXNODE_REPO  GitHub repo to download from (default: nexpool/exnode)
#   EXNODE_BIN   Local exnode binary to install instead of downloading
set -euo pipefail

red='\033[0;31m'; green='\033[0;32m'; yellow='\033[0;33m'; plain='\033[0m'
say()  { echo -e "${green}==>${plain} $*"; }
warn() { echo -e "${yellow}警告:${plain} $*"; }
die()  { echo -e "${red}错误:${plain} $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] && die "必须使用 root 运行此脚本"

REPO="${EXNODE_REPO:-nexpool/exnode}"
VERSION=""; API_HOST=""; NODE_ID=""; SECRET_KEY=""; SYSTEM_TUN="false"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)    VERSION="$2"; shift 2 ;;
    --api-host)   API_HOST="$2"; shift 2 ;;
    --node-id)    NODE_ID="$2"; shift 2 ;;
    --secret-key) SECRET_KEY="$2"; shift 2 ;;
    --system)     SYSTEM_TUN="true"; shift ;;
    -h|--help)    echo "用法: $0 [--version vX.Y.Z] [--api-host URL] [--node-id N] [--secret-key KEY] [--system]"; exit 0 ;;
    *) die "未知参数: $1" ;;
  esac
done

INSTALL_DIR=/usr/local/exnode
CONFIG_DIR=/etc/exnode
BIN="$INSTALL_DIR/exnode"

case "$(uname -m)" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) die "不支持的架构: $(uname -m)（仅 amd64 / arm64）" ;;
esac

say "检查 WireGuard 内核模块"
modprobe wireguard 2>/dev/null || warn "无法 modprobe wireguard（内核可能内置,或将用 singbox 引擎）"
command -v iptables >/dev/null 2>&1 || warn "未找到 iptables,开启 NAT 时需要它"

# --- binary ---
mkdir -p "$INSTALL_DIR"
if [[ -n "${EXNODE_BIN:-}" ]]; then
  say "安装本地二进制 $EXNODE_BIN"
  install -m 0755 "$EXNODE_BIN" "$BIN"
else
  if [[ -z "$VERSION" ]]; then
    say "查询最新版本"
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/') || true
    [[ -z "$VERSION" ]] && die "无法获取版本,请用 --version 指定,或用 EXNODE_BIN 提供本地二进制"
  fi
  say "下载 exnode ${VERSION} (${arch})"
  curl -fSL "https://github.com/${REPO}/releases/download/${VERSION}/exnode-linux-${arch}" -o "$BIN" || die "下载失败"
  chmod +x "$BIN"
fi

# --- config template ---
mkdir -p "$CONFIG_DIR"
if [[ -f "$CONFIG_DIR/config.yml" ]]; then
  warn "$CONFIG_DIR/config.yml 已存在,保留不覆盖"
else
  cat > "$CONFIG_DIR/config.yml" <<EOF
Log:
  Level: info

# 数据面引擎类型(kernel/singbox)由面板下发;此处仅 sing-box 本机选项
# Engine:
#   Singbox:
#     BinPath: sing-box
#     System: ${SYSTEM_TUN}

Nodes:
  - ApiHost: ${API_HOST:-https://panel.example.com}
    NodeID: ${NODE_ID:-0}
    SecretKey: ${SECRET_KEY:-replace-with-node-secret-from-panel}
    Timeout: 30
    HeartbeatSeconds: 15
    StatusSeconds: 20
EOF
  warn "请编辑 $CONFIG_DIR/config.yml 填入面板的 ApiHost / NodeID / SecretKey"
fi

# --- systemd unit ---
cat > /etc/systemd/system/exnode.service <<EOF
[Unit]
Description=WireGuard Panel node agent (exnode)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN} -c ${CONFIG_DIR}/config.yml
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

# --- management command: exnode {start|stop|restart|status|log|update|uninstall|config} ---
cat > /usr/bin/exnode <<'EXNODE_CLI'
#!/usr/bin/env bash
set -euo pipefail
g='\033[0;32m'; r='\033[0;31m'; p='\033[0m'
[[ $EUID -ne 0 ]] && echo -e "${r}请用 root 运行${p}" && exit 1
REPO="${EXNODE_REPO:-nexpool/exnode}"
BIN=/usr/local/exnode/exnode
arch(){ case "$(uname -m)" in x86_64|amd64) echo amd64;; aarch64|arm64) echo arm64;; *) echo amd64;; esac; }
case "${1:-}" in
  start)   systemctl start exnode ;;
  stop)    systemctl stop exnode ;;
  restart) systemctl restart exnode ;;
  status)  systemctl status exnode --no-pager ;;
  log)     journalctl -u exnode -f ;;
  config)  ${EDITOR:-vi} /etc/exnode/config.yml ;;
  update)
    v=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    [[ -z "$v" ]] && echo -e "${r}获取版本失败${p}" && exit 1
    echo "下载 $v ..."; curl -fSL "https://github.com/${REPO}/releases/download/${v}/exnode-linux-$(arch)" -o "$BIN"
    chmod +x "$BIN"; systemctl restart exnode; echo -e "${g}已更新并重启${p}" ;;
  uninstall)
    systemctl disable --now exnode 2>/dev/null || true
    rm -f /etc/systemd/system/exnode.service /usr/local/exnode/exnode /usr/bin/exnode
    systemctl daemon-reload; echo -e "${g}已卸载${p}(配置 /etc/exnode 保留)" ;;
  *) echo "用法: exnode {start|stop|restart|status|log|update|uninstall|config}" ;;
esac
EXNODE_CLI
chmod +x /usr/bin/exnode

systemctl daemon-reload
systemctl enable exnode >/dev/null 2>&1 || true

echo
say "完成。编辑 ${CONFIG_DIR}/config.yml 后执行: exnode start"
echo "    管理命令: exnode {start|stop|restart|status|log|update|uninstall|config}"

# 安装完成后删除本脚本(仅当从文件运行时;管道执行 $0 为 bash 则跳过)
if [[ -f "$0" ]]; then rm -f -- "$0"; fi
