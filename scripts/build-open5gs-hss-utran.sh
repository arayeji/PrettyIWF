#!/usr/bin/env bash
# Build Open5GS HSS with UTRAN-Vector (CK/IK) support for 3G GSUP/IWF attach.
set -euo pipefail

TAG="${OPEN5GS_TAG:-v2.7.6}"
SRC="${OPEN5GS_SRC:-$HOME/open5gs}"
PATCH="${PATCH:-$HOME/IWF/scripts/open5gs-hss-utran-vector.patch}"

echo "==> Open5GS tag: $TAG"
echo "==> Source dir:  $SRC"

if [[ ! -d "$SRC/.git" ]]; then
    git clone --depth 1 --branch "$TAG" https://github.com/open5gs/open5gs.git "$SRC"
fi

cd "$SRC"
git fetch --tags --depth 1 origin "$TAG" 2>/dev/null || true
git checkout -f "$TAG"

if [[ -f "$PATCH" ]]; then
    echo "==> Applying patch: $PATCH"
    git apply --check "$PATCH"
    git apply "$PATCH"
else
    echo "Patch not found: $PATCH" >&2
    exit 1
fi

echo "==> Meson configure"
meson setup build --prefix=/usr -Db_pie=true

echo "==> Build open5gs-hssd only"
ninja -C build src/hss/open5gs-hssd

echo "==> Built: $SRC/build/src/hss/open5gs-hssd"
echo "Install (requires root):"
echo "  sudo systemctl stop open5gs-hssd"
echo "  sudo install -m 0755 build/src/hss/open5gs-hssd /usr/bin/open5gs-hssd"
echo "  sudo systemctl start open5gs-hssd"
