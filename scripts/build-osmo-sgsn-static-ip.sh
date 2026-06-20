#!/usr/bin/env bash
# Build patched osmo-sgsn with GSUP static PDP address support.
# Run on lab-msc01 as deploy-user (sudo required for install/restart).
set -euo pipefail

PATCH="${1:-$HOME/osmo-sgsn-static-pdp-address.patch}"
SRC="${OSMO_SGSN_SRC:-$HOME/osmo-sgsn}"
TAG="${OSMO_SGSN_TAG:-1.13.1}"
JOBS="${JOBS:-$(nproc)}"

if ! dpkg -s build-essential autoconf automake libtool pkg-config \
        libosmocore-dev libosmo-gsup-client-dev libosmo-sigtran-dev \
        libgtp-dev libosmo-ranap-dev libosmo-abis-dev libosmo-netif-dev \
        libosmo-pfcp-dev libosmo-asn1-tcap-dev libosmo-mgcp-client-dev \
        libosmocodec-dev libosmocoding-dev libgtpnl-dev libcares-dev git >/dev/null 2>&1; then
    echo "==> Installing build dependencies (needs sudo)..."
    sudo apt-get update -qq
    sudo apt-get install -y --no-install-recommends \
        build-essential autoconf automake libtool pkg-config git \
        libosmocore-dev libosmo-gsup-client-dev libosmo-sigtran-dev \
        libgtp-dev libosmo-ranap-dev libosmo-abis-dev libosmo-netif-dev \
        libosmo-pfcp-dev libosmo-asn1-tcap-dev libosmo-mgcp-client-dev \
        libosmocodec-dev libosmocoding-dev libgtpnl-dev libcares-dev
fi

if [[ ! -d "$SRC/.git" ]]; then
    echo "==> Cloning osmo-sgsn $TAG..."
    git clone --depth 1 --branch "$TAG" https://gitea.osmocom.org/cellular-infrastructure/osmo-sgsn.git "$SRC"
else
    echo "==> Updating existing clone in $SRC..."
    git -C "$SRC" fetch --tags origin
    git -C "$SRC" checkout -f "$TAG"
    git -C "$SRC" clean -fdx
fi

echo "==> Applying static IP changes..."
cd "$SRC"
SCRIPT="${APPLY_SCRIPT:-$HOME/apply-osmo-sgsn-static-ip.py.sh}"
bash "$SCRIPT"

echo "==> Building osmo-sgsn..."
autoreconf -fi
./configure --disable-werror
make -j"$JOBS"

test -x src/osmo-sgsn
echo "==> Installing binary (needs sudo)..."
sudo install -m755 src/osmo-sgsn /usr/local/sbin/osmo-sgsn
if [[ -x /usr/bin/osmo-sgsn ]]; then
    sudo install -m755 src/osmo-sgsn /usr/bin/osmo-sgsn
fi

echo "==> Restarting osmo-sgsn..."
sudo systemctl restart osmo-sgsn.service
sleep 2
systemctl is-active osmo-sgsn.service
/usr/local/sbin/osmo-sgsn --version | head -1
echo "Done. Check: journalctl -u osmo-sgsn -n 30 --no-pager"
