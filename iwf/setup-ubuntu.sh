#!/usr/bin/env bash
# =============================================================================
# IWF — full Ubuntu (and Debian) setup: build + configure + optional install
# =============================================================================
#
# STEP-BY-STEP (manual, if you prefer not to use this script)
# -----------------------------------------------------------------------------
#  1. Clone or copy the IWF repo onto the Ubuntu host.
#  2. sudo apt update && sudo apt install -y build-essential
#  3. cd iwf && make
#  4. Edit iwf.conf:
#       [iwf]  listen_ip = address to bind (0.0.0.0 = all interfaces)
#              listen_port = 2123
#              local_ip = YOUR Gn/S4-facing IP (required if listen is 0.0.0.0)
#       [sgwc] ip / port = Open5GS SGW-C
#       [logging] level, file path
#  5. Run: sudo ./iwf -c /path/to/iwf.conf
#     Or use this script with --install to install binary + systemd service.
#
# AUTOMATED USAGE
# -----------------------------------------------------------------------------
#   Build only (compiles in repo; uses sudo for apt if not root):
#     ./setup-ubuntu.sh --build-only
#
#   Full system install (needs root; re-invokes with sudo if needed):
#     sudo ./setup-ubuntu.sh --install
#
#   Override defaults with environment variables (see defaults below):
#     sudo IWF_LOCAL_IP=10.0.0.5 IWF_SGWC_IP=10.0.0.30 ./setup-ubuntu.sh --install
#
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# --- configurable defaults (override with env) ---
IWF_LISTEN_IP="${IWF_LISTEN_IP:-0.0.0.0}"
IWF_LISTEN_PORT="${IWF_LISTEN_PORT:-2123}"
IWF_LOCAL_IP="${IWF_LOCAL_IP:-}"           # if empty, set equal to listen_ip when listen != 0.0.0.0
IWF_SGSN_IP="${IWF_SGSN_IP:-127.0.0.1}"    # informational in config
IWF_SGWC_IP="${IWF_SGWC_IP:-127.0.0.1}"
IWF_SGWC_PORT="${IWF_SGWC_PORT:-2123}"
IWF_LOG_LEVEL="${IWF_LOG_LEVEL:-info}"
IWF_LOG_FILE="${IWF_LOG_FILE:-/var/log/iwf/iwf.log}"
PREFIX="${PREFIX:-/usr/local}"
SYSTEMD_UNIT="${SYSTEMD_UNIT:-/etc/systemd/system/iwf.service}"
CONFIG_PATH="${CONFIG_PATH:-/etc/iwf/iwf.conf}"

BUILD_ONLY=0
INSTALL=0
YES=0

usage() {
  cat <<'USAGE'
IWF setup for Ubuntu/Debian — build and optionally install system-wide.

Options:
  --build-only   Install build deps and run make (no system install).
  --install      Build + install binary, config, log dir, systemd unit.
  -y, --yes      Non-interactive (use defaults / env for --install).
  -h, --help     Show this help.

Environment (for --install; required when listen is 0.0.0.0):
  IWF_LISTEN_IP   Bind address (default 0.0.0.0)
  IWF_LISTEN_PORT UDP port (default 2123)
  IWF_LOCAL_IP    IP advertised in GTP IEs (required if listen is 0.0.0.0)
  IWF_SGWC_IP     Open5GS SGW-C address
  IWF_SGWC_PORT   SGW-C port (default 2123)
  IWF_SGSN_IP     Informational osmo-sgsn IP for config file
  IWF_LOG_LEVEL   error|warn|info|debug|trace
  IWF_LOG_FILE    Log file path
  PREFIX          Install prefix (default /usr/local)
  CONFIG_PATH     Config path (default /etc/iwf/iwf.conf)

Example:
  sudo IWF_LOCAL_IP=10.0.0.5 IWF_SGWC_IP=10.0.0.30 ./setup-ubuntu.sh --install -y
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-only) BUILD_ONLY=1 ;;
    --install)    INSTALL=1 ;;
    -y|--yes)     YES=1 ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [[ "$BUILD_ONLY" -eq 0 && "$INSTALL" -eq 0 ]]; then
  echo "Choose --build-only or --install (see: $0 --help)" >&2
  exit 2
fi

need_cmd() { command -v "$1" >/dev/null 2>&1; }

if [[ "$OSTYPE" != linux-gnu* ]]; then
  echo "This script targets Linux (Ubuntu/Debian). OSTYPE=$OSTYPE" >&2
  exit 1
fi

if [[ "$INSTALL" -eq 1 && "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Re-running with sudo for --install ..."
  exec sudo env \
    IWF_LISTEN_IP="$IWF_LISTEN_IP" \
    IWF_LISTEN_PORT="$IWF_LISTEN_PORT" \
    IWF_LOCAL_IP="$IWF_LOCAL_IP" \
    IWF_SGSN_IP="$IWF_SGSN_IP" \
    IWF_SGWC_IP="$IWF_SGWC_IP" \
    IWF_SGWC_PORT="$IWF_SGWC_PORT" \
    IWF_LOG_LEVEL="$IWF_LOG_LEVEL" \
    IWF_LOG_FILE="$IWF_LOG_FILE" \
    PREFIX="$PREFIX" \
    SYSTEMD_UNIT="$SYSTEMD_UNIT" \
    CONFIG_PATH="$CONFIG_PATH" \
    YES="$YES" \
    bash "$0" --install ${YES:+-y}
fi

SUDO_APT=""
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  if need_cmd sudo && sudo -n true 2>/dev/null; then
    SUDO_APT="sudo -n"
  elif need_cmd sudo; then
    SUDO_APT="sudo"
  fi
fi

echo "==> Step 1/5: Install build dependencies (build-essential)"
if need_cmd apt-get; then
  export DEBIAN_FRONTEND=noninteractive
  if [[ "${EUID:-$(id -u)}" -ne 0 && -z "$SUDO_APT" ]]; then
    echo "ERROR: Need root or sudo to run apt-get. Try:" >&2
    echo "  sudo $0 --build-only   OR   sudo $0 --install" >&2
    exit 1
  fi
  $SUDO_APT apt-get update -qq
  $SUDO_APT apt-get install -y -qq build-essential
else
  echo "apt-get not found; install gcc and make manually, then re-run." >&2
  exit 1
fi

echo "==> Step 2/5: Compile IWF ($SCRIPT_DIR)"
make clean >/dev/null 2>&1 || true
make -j"$(nproc 2>/dev/null || echo 4)"

if [[ ! -x "$SCRIPT_DIR/iwf" ]]; then
  echo "Build failed: $SCRIPT_DIR/iwf not found or not executable" >&2
  exit 1
fi

if [[ "$BUILD_ONLY" -eq 1 ]]; then
  echo ""
  echo "Build complete. Binary: $SCRIPT_DIR/iwf"
  echo "Run manually:  $SCRIPT_DIR/iwf -c $SCRIPT_DIR/iwf.conf -l debug"
  exit 0
fi

# --- install path ---
echo "==> Step 3/5: Install binary to $PREFIX/sbin/iwf"
install -d "$PREFIX/sbin"
install -m 0755 "$SCRIPT_DIR/iwf" "$PREFIX/sbin/iwf"

echo "==> Step 4/5: Write configuration $CONFIG_PATH"
if [[ -z "$IWF_LOCAL_IP" ]]; then
  if [[ "$IWF_LISTEN_IP" == "0.0.0.0" ]]; then
    echo "ERROR: When listen_ip is 0.0.0.0 you must set IWF_LOCAL_IP (your Gn/S4 IP)." >&2
    echo "Example: sudo IWF_LOCAL_IP=10.0.0.5 IWF_SGWC_IP=10.0.0.30 $0 --install" >&2
    exit 1
  fi
  IWF_LOCAL_IP="$IWF_LISTEN_IP"
fi

CONFIG_SKIP=0
if [[ "$YES" -ne 1 && -f "$CONFIG_PATH" ]]; then
  read -r -p "Overwrite existing $CONFIG_PATH? [y/N] " ans || true
  case "${ans:-}" in
    y|Y|yes|YES) ;;
    *) echo "Keeping existing config; skipping config write."; CONFIG_SKIP=1 ;;
  esac
fi

install -d "$(dirname "$CONFIG_PATH")"
if [[ "${CONFIG_SKIP:-0}" -ne 1 ]]; then
  cat >"$CONFIG_PATH" <<EOF
# Generated by setup-ubuntu.sh — edit and restart: systemctl restart iwf

[iwf]
listen_ip   = ${IWF_LISTEN_IP}
listen_port = ${IWF_LISTEN_PORT}
local_ip    = ${IWF_LOCAL_IP}

[sgsn]
ip          = ${IWF_SGSN_IP}

[sgwc]
ip          = ${IWF_SGWC_IP}
port        = ${IWF_SGWC_PORT}

[logging]
level       = ${IWF_LOG_LEVEL}
file        = ${IWF_LOG_FILE}
EOF
  chmod 0644 "$CONFIG_PATH"
  echo "Wrote $CONFIG_PATH"
else
  echo "Using existing $CONFIG_PATH"
fi

echo "==> Log directory"
install -d "$(dirname "$IWF_LOG_FILE")"
touch "$IWF_LOG_FILE" 2>/dev/null || true
chmod 0644 "$IWF_LOG_FILE" 2>/dev/null || true

echo "==> Step 5/5: Install systemd unit ($SYSTEMD_UNIT)"
cat >"$SYSTEMD_UNIT" <<EOF
[Unit]
Description=GTPv1-C to GTPv2-C Interworking Function (IWF)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PREFIX/sbin/iwf -c $CONFIG_PATH
Restart=on-failure
RestartSec=3
StandardOutput=journal
StandardError=journal

# Hardening (optional; comment out if something breaks in your environment)
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$SYSTEMD_UNIT"

systemctl daemon-reload
systemctl enable iwf.service
echo ""
echo "-------------------------------------------------------------------"
echo "  Install finished."
echo "  Config:  $CONFIG_PATH"
echo "  Binary:  $PREFIX/sbin/iwf"
echo "  Logs:    $IWF_LOG_FILE"
echo ""
echo "  Commands:"
echo "    sudo systemctl start iwf"
echo "    sudo systemctl status iwf"
echo "    sudo journalctl -u iwf -f"
echo "-------------------------------------------------------------------"

if [[ "$YES" -eq 1 ]]; then
  systemctl restart iwf.service 2>/dev/null || systemctl start iwf.service
  echo "Started iwf.service (non-interactive -y)."
else
  read -r -p "Start and enable iwf now? [Y/n] " start_ans || true
  case "${start_ans:-Y}" in
    n|N|no|NO) ;;
    *) systemctl restart iwf.service 2>/dev/null || systemctl start iwf.service
       echo "Started iwf.service"
       ;;
  esac
fi

exit 0
