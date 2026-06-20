#!/usr/bin/env bash
# Install patched osmo-sgsn and restart service (needs sudo).
set -euo pipefail

SRC="${OSMO_SGSN_SRC:-$HOME/osmo-sgsn}"
BIN="$SRC/src/osmo-sgsn"

test -x "$BIN" || { echo "missing built binary: $BIN — run build-osmo-sgsn-static-ip-only.sh first" >&2; exit 1; }

sudo install -m755 "$BIN" /usr/local/sbin/osmo-sgsn
sudo install -m755 "$BIN" /usr/bin/osmo-sgsn
sudo systemctl restart osmo-sgsn.service
sleep 2
systemctl is-active osmo-sgsn.service
/usr/local/sbin/osmo-sgsn --version | head -1
journalctl -u osmo-sgsn -n 15 --no-pager
