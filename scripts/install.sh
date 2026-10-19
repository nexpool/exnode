#!/usr/bin/env bash
# Install (or repair) the exnode agent on this host: prebuilt binary, config
# template, systemd unit and an `exnode` management command.
#
# sing-box is NOT installed here: the agent fetches it by itself the first time
# the panel selects the sing-box datapath engine (see the singbox package).
#
# Every step is idempotent: running the script again keeps what is already there,
# skips what is already installed, and only replaces the agent binary when you ask
# for a specific (different) version.
#
# Usage:
#   ./install.sh [--version vX.Y.Z] [--api-host URL] [--node-id N] [--secret-key KEY]
#                [--system] [--force] [--cleanup]
#
#   --version vX.Y.Z      install this exnode release (default: only when nothing
#                         is installed yet, otherwise keep the current binary)
#   --system              sing-box TUN mode (System: true)
#   --force               reinstall the agent binary even if it is already there
#   --cleanup             delete this script after a successful run
#
# Env:
#   EXNODE_REPO      GitHub repo for the agent  (default: nexpool/exnode)
#   EXNODE_BIN       local exnode binary to install instead of downloading
set -euo pipefail

red=$'\e[0;31m'; green=$'\e[0;32m'; yellow=$'\e[0;33m'; plain=$'\e[0m'
# printf 而不是 echo -e：BSD/GNU、bash/zsh 下行为一致
say()  { printf '%s==>%s %s\n' "$green" "$plain" "$*"; }
warn() { printf '%s警告:%s %s\n' "$yellow" "$plain" "$*"; }
die()  { printf '%s错误:%s %s\n' "$red" "$plain" "$*" >&2; exit 1; }

REPO="${EXNODE_REPO:-nexpool/exnode}"
INSTALL_DIR=/usr/local/exnode
CONFIG_DIR=/etc/exnode
BIN="$INSTALL_DIR/exnode"
SINGBOX_BIN=/usr/local/bin/sing-box
UNIT=/etc/systemd/system/exnode.service
CLI=/usr/bin/exnode

VERSION=""; API_HOST=""; NODE_ID=""; SECRET_KEY=""; SYSTEM_TUN="false"
FORCE="no"; CLEANUP="no"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)         VERSION="$2"; shift 2 ;;
    --api-host)        API_HOST="$2"; shift 2 ;;
    --node-id)         NODE_ID="$2"; shift 2 ;;
    --secret-key)      SECRET_KEY="$2"; shift 2 ;;
    --system)          SYSTEM_TUN="true"; shift ;;
    --force)           FORCE="yes"; shift ;;
    --cleanup)         CLEANUP="yes"; shift ;;
    -h|--help)         sed -n "2,31p" "$0" | sed -e "s/^# //" -e "s/^#$//"; exit 0 ;;
    *) die "未知参数: $1" ;;
  esac
done

[[ $EUID -ne 0 ]] && die "必须使用 root 运行此脚本（--help 除外）"

case "$(uname -m)" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) die "不支持的架构: $(uname -m)（仅 amd64 / arm64）" ;;
esac

sha() { command -v sha256sum >/dev/null 2>&1 && sha256sum "$1" | awk '{print $1}' || echo ""; }
same_file() { [[ -f "$1" && -f "$2" ]] && [[ -n "$(sha "$1")" && "$(sha "$1")" == "$(sha "$2")" ]]; }
github_latest() {
  curl -fsSL "https://api.github.com/repos/$1/releases/latest" 2>/dev/null \
    | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || true
}
installed_version() { "$BIN" -version 2>/dev/null | head -1 || true; }

say "检查 WireGuard 内核模块"
modprobe wireguard 2>/dev/null || warn "无法 modprobe wireguard（内核可能内置，或将用 sing-box 引擎）"
command -v iptables >/dev/null 2>&1 || warn "未找到 iptables，开启 NAT 时需要它"

# --- 1. agent 二进制（已装且版本一致就跳过）---
mkdir -p "$INSTALL_DIR"
agent_state=""; agent_changed="no"
if [[ -n "${EXNODE_BIN:-}" ]]; then
  [[ -f "$EXNODE_BIN" ]] || die "EXNODE_BIN 指向的文件不存在: $EXNODE_BIN"
  if [[ "$FORCE" == "no" ]] && same_file "$EXNODE_BIN" "$BIN"; then
    agent_state="本地二进制与已装版本一致，跳过"
  else
    say "安装本地二进制 $EXNODE_BIN"
    install -m 0755 "$EXNODE_BIN" "${BIN}.new"
    mv -f "${BIN}.new" "$BIN"
    agent_state="已从本地文件安装"; agent_changed="yes"
  fi
else
  current="$(installed_version)"
  if [[ -z "$VERSION" && -x "$BIN" && "$FORCE" == "no" ]]; then
    agent_state="已安装${current:+ $current}，跳过（换版本用 --version，或 exnode update）"
  else
    if [[ -z "$VERSION" ]]; then
      say "查询最新版本"
      VERSION="$(github_latest "$REPO")"
      [[ -z "$VERSION" ]] && die "无法获取版本，请用 --version 指定，或用 EXNODE_BIN 提供本地二进制"
    fi
    if [[ "$FORCE" == "no" && -n "$current" && "$current" == "$VERSION" ]]; then
      agent_state="已是最新 ${VERSION}，跳过"
    else
      say "下载 exnode ${VERSION} (${arch})"
      curl -fSL "https://github.com/${REPO}/releases/download/${VERSION}/exnode-linux-${arch}" -o "${BIN}.new" \
        || { rm -f "${BIN}.new"; die "下载失败"; }
      chmod +x "${BIN}.new"; mv -f "${BIN}.new" "$BIN"
      agent_state="已安装 $VERSION"; agent_changed="yes"
    fi
  fi
fi

# --- 2. 配置模板（永远不覆盖已有的）---
mkdir -p "$CONFIG_DIR"
if [[ -f "$CONFIG_DIR/config.yml" ]]; then
  config_state="已存在，保留不覆盖"
else
  cat > "$CONFIG_DIR/config.yml" <<EOF
Log:
  Level: info

# 数据面引擎类型(kernel/singbox)由面板下发;此处仅 sing-box 本机选项
Engine:
  Singbox:
    BinPath: ${SINGBOX_BIN}
    System: ${SYSTEM_TUN}

Nodes:
  - ApiHost: ${API_HOST:-https://panel.example.com}
    NodeID: ${NODE_ID:-0}
    SecretKey: ${SECRET_KEY:-replace-with-node-secret-from-panel}
    Timeout: 30
    HeartbeatSeconds: 15
    StatusSeconds: 20
EOF
  chmod 600 "$CONFIG_DIR/config.yml"
  config_state="已生成（记得填 ApiHost / NodeID / SecretKey）"
fi


# --- 4. systemd unit（内容变了才写）---
unit_new="$(mktemp)"
cat > "$unit_new" <<EOF
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
unit_state="未变化"
if ! same_file "$unit_new" "$UNIT"; then
  install -m 0644 "$unit_new" "$UNIT"
  systemctl daemon-reload
  unit_state="已更新"
fi
rm -f "$unit_new"
systemctl enable exnode >/dev/null 2>&1 || true

# --- 5. 管理命令 exnode {start|stop|restart|status|log|version|update|uninstall|config}
cat > "$CLI" <<"EXNODE_CLI"
#!/usr/bin/env bash
set -euo pipefail
g=$'\e[0;32m'; r=$'\e[0;31m'; p=$'\e[0m'
[[ $EUID -ne 0 ]] && printf '%s请用 root 运行%s\n' "$r" "$p" && exit 1
REPO="${EXNODE_REPO:-nexpool/exnode}"
BIN=/usr/local/exnode/exnode
arch(){ case "$(uname -m)" in x86_64|amd64) echo amd64;; aarch64|arm64) echo arm64;; *) echo amd64;; esac; }
case "${1:-}" in
  start)   systemctl start exnode ;;
  stop)    systemctl stop exnode ;;
  restart) systemctl restart exnode ;;
  status)  systemctl status exnode --no-pager ;;
  log)     journalctl -u exnode -f ;;
  version|v|-v|--version) "$BIN" -version ;;
  config)  ${EDITOR:-vi} /etc/exnode/config.yml ;;
  update)
    v=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    [[ -z "$v" ]] && printf '%s获取版本失败%s\n' "$r" "$p" && exit 1
    cur=$("$BIN" -version 2>/dev/null || true)
    if [[ "$cur" == "$v" ]]; then printf '%s已是最新 %s%s\n' "$g" "$v" "$p"; exit 0; fi
    echo "下载 $v ..."
    curl -fSL "https://github.com/${REPO}/releases/download/${v}/exnode-linux-$(arch)" -o "${BIN}.new" || { printf '%s下载失败%s\n' "$r" "$p"; rm -f "${BIN}.new"; exit 1; }
    chmod +x "${BIN}.new"; mv -f "${BIN}.new" "$BIN"
    systemctl restart exnode; printf '%s已更新并重启 %s%s\n' "$g" "$v" "$p" ;;
  uninstall)
    systemctl disable --now exnode 2>/dev/null || true
    rm -f /etc/systemd/system/exnode.service /usr/local/exnode/exnode /usr/bin/exnode
    systemctl daemon-reload; printf '%s已卸载%s(配置 /etc/exnode 保留)\n' "$g" "$p" ;;
  *) echo "usage: exnode {start|stop|restart|status|log|version|update|uninstall|config}" ;;
esac
EXNODE_CLI
chmod +x "$CLI"

# 换了二进制且服务本来在跑 → 立刻生效（首次安装不自动启动，等配置填好）
if [[ "$agent_changed" == "yes" ]] && systemctl is-active --quiet exnode; then
  say "重启 exnode 以加载新二进制"
  systemctl restart exnode
fi

echo
say "完成"
echo "  exnode   : $agent_state"
echo "  config   : ${config_state}（$CONFIG_DIR/config.yml）"
echo "  systemd  : $UNIT ${unit_state}，已 enable"
if [[ "$config_state" == 已生成* ]]; then
  echo "  下一步   : 编辑 $CONFIG_DIR/config.yml 后执行 exnode start"
else
  echo "  下一步   : 改了配置就 exnode restart；查看状态 exnode status"
fi
echo "  本脚本可重复执行（幂等）：已装好的部分会自动跳过"

if [[ "$CLEANUP" == "yes" && -f "$0" ]]; then rm -f -- "$0"; fi
