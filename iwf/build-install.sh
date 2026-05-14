#!/usr/bin/env bash
# Build the IWF and install binary + sample config (see Makefile install target).
#
# Usage:
#   ./build-install.sh                 # plain GTP build, install under /usr/local
#   PREFIX=/opt/iwf ./build-install.sh
#   ./build-install.sh MAP_IWF_ENABLED=1    # requires libosmo-* dev packages
#
# On Windows: run from WSL, from this directory:
#   bash ./build-install.sh
#
set -euo pipefail
cd "$(dirname "$0")"
PREFIX="${PREFIX:-/usr/local}"

install_args=(PREFIX="$PREFIX")
[[ -n "${DESTDIR:-}" ]] && install_args+=(DESTDIR="$DESTDIR")

make "$@"
if [[ "$(id -u)" -eq 0 ]]; then
  make install "${install_args[@]}"
else
  sudo make install "${install_args[@]}"
fi

echo "Installed: ${DESTDIR:-}${PREFIX}/sbin/iwf"
echo "Example config: ${DESTDIR:-}/etc/iwf/iwf.conf.example — copy to ${DESTDIR:-}/etc/iwf/iwf.conf or pass -c to iwf."
