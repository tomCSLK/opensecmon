#!/usr/bin/env bash
# Fetches the signed packages of the opensecagent release named in dist/agent/release.txt and puts them into
# dist/agent/, from where dev/container.sh takes them into the image (and dev/deb.sh into the .deb).
#
#   dev/agent-release.sh                  # download from the GitHub release of tomCSLK/opensecagent
#   AGENT_RELEASE_BASE=URL dev/agent-release.sh   # another base URL (file:// for a test), <base>/<tag>/<file>
#
# Every file must match its SHA-256 in release.txt, then dev/agent-packages.sh checks the signatures against
# keys/opensecagent.allowed_signers. One wrong file stops everything and leaves dist/agent/ as it was. Without a tag
# in release.txt nothing is done (the image then has no packages). Signing happens only at the publisher's: no key here.
set -euo pipefail
cd "$(dirname "$0")/.."

PIN=dist/agent/release.txt
BASE="${AGENT_RELEASE_BASE:-https://github.com/tomCSLK/opensecagent/releases/download}"
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

tag=$(sed -n 's/^tag=\(v[0-9][0-9.]*\)[[:space:]]*$/\1/p' "$PIN")
if [ -z "$tag" ]; then
  echo "no opensecagent release in $PIN: no packages"
  exit 0
fi
# Lines "<64 hex>  <file>"; the names are checked again by dev/agent-packages.sh.
mapfile -t lines < <(grep -E '^[0-9a-f]{64}  opensecagent[A-Za-z0-9_.+-]*$' "$PIN")
[ ${#lines[@]} -gt 0 ] || fail "$PIN names $tag but no files"
[ "$(grep -cvE '^(#.*|tag=.*|[0-9a-f]{64}  opensecagent[A-Za-z0-9_.+-]*|[[:space:]]*)$' "$PIN")" = 0 ] \
  || fail "$PIN has lines that are neither a tag, a checksum nor a comment"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
for line in "${lines[@]}"; do
  file=${line#*  }
  echo "downloading $tag/$file"
  curl --silent --show-error --fail --location --proto '=https,file' --max-time 300 --max-filesize 100000000 \
    -o "$WORK/$file" "$BASE/$tag/$file"
done
(cd "$WORK" && printf '%s\n' "${lines[@]}" | sha256sum --check --strict --quiet) || fail "a file does not match its checksum"
dev/agent-packages.sh "$WORK"
