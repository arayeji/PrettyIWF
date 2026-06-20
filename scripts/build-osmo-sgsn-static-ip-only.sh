#!/usr/bin/env bash
# Build-only: clone, patch, compile osmo-sgsn (no sudo).
set -euo pipefail

PATCH="${1:-$HOME/osmo-sgsn-static-pdp-address.patch}"
SRC="${OSMO_SGSN_SRC:-$HOME/osmo-sgsn}"
TAG="${OSMO_SGSN_TAG:-1.13.1}"
JOBS="${JOBS:-$(nproc)}"

# patch file optional; apply script is preferred

if [[ ! -d "$SRC/.git" ]]; then
    echo "==> Cloning osmo-sgsn $TAG..."
    git clone --depth 1 --branch "$TAG" \
        https://gitea.osmocom.org/cellular-infrastructure/osmo-sgsn.git "$SRC"
else
    echo "==> Refreshing $SRC at $TAG..."
    git -C "$SRC" fetch --tags origin || true
    git -C "$SRC" checkout -f "$TAG"
    git -C "$SRC" clean -fdx
fi

echo "==> Applying static IP changes..."
cd "$SRC"
SCRIPT="${APPLY_SCRIPT:-$HOME/apply-osmo-sgsn-static-ip.py.sh}"
bash "$SCRIPT"

echo "==> Building..."
autoreconf -fi
./configure --disable-werror
make -j"$JOBS"

test -x src/osmo-sgsn
ls -la src/osmo-sgsn
echo "Build OK: $SRC/src/osmo-sgsn"
echo "Run ~/finish-osmo-sgsn-static-ip.sh to install and restart."
