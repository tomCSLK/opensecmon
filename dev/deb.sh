#!/usr/bin/env bash
# Builds the Debian package target/debian/opensecmon_<version>-1_amd64.deb from the
# static binary. Extra arguments go to cargo-deb (e.g. --no-build after a release build).
# Needs cargo-deb (cargo install cargo-deb --locked) and the musl target (rustup target add x86_64-unknown-linux-musl).
set -euo pipefail

cd "$(dirname "$0")/.."
command -v cargo-deb >/dev/null || { echo "cargo-deb is missing: cargo install cargo-deb --locked" >&2; exit 1; }
if grep -n /usr/local deploy/*.service deploy/*.sh; then
  echo "error: paths under /usr/local left in the package files above" >&2
  exit 1
fi

# The packages of opensecagent that go along (dev/agent-packages.sh puts them into dist/agent/).
agents=$(find dist/agent -maxdepth 1 -type f -name 'opensecagent*' ! -name '*.sig' -printf '%f\n' | sort)
if [ -n "$agents" ]; then
  echo "opensecagent packages included:"; echo "$agents" | sed 's/^/  /'
else
  echo "no opensecagent packages in dist/agent/ (the computers' pages then only offer the scripts)"
fi

cargo deb --target x86_64-unknown-linux-musl "$@"
