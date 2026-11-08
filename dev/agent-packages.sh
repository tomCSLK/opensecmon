#!/usr/bin/env bash
# Puts the signed packages of an opensecagent release into dist/agent/, from where dev/deb.sh takes them into the
# package of opensecmon (docs/agent-api.md, "Updates of opensecagent").
#
#   dev/agent-packages.sh <folder with the packages and their .sig files> [allowed_signers file]
#
# Every package (opensecagent_<version>-<rev>_<arch>.deb, opensecagent-<version>-<arch>-setup.exe) needs its
# signature <file>.sig, made with `ssh-keygen -Y sign -n opensecagent`. The signature is checked against the
# publisher key (default ../opensecagent/keys/allowed_signers, identity "opensecagent") before anything is copied;
# one bad file stops everything. Packages already in dist/agent/ are replaced.
set -euo pipefail

cd "$(dirname "$0")/.."
source_dir=${1:?usage: dev/agent-packages.sh <folder> [allowed_signers]}
signers=${2:-../opensecagent/keys/allowed_signers}
[ -f "$signers" ] || { echo "error: no allowed_signers file at $signers" >&2; exit 1; }
command -v ssh-keygen >/dev/null || { echo "error: ssh-keygen is missing" >&2; exit 1; }

shopt -s nullglob
files=("$source_dir"/opensecagent_*.deb "$source_dir"/opensecagent-*-setup.exe)
[ ${#files[@]} -gt 0 ] || { echo "error: no opensecagent packages in $source_dir" >&2; exit 1; }

deb='^opensecagent_[0-9]+(\.[0-9]+){1,3}(-[0-9]+)?_(amd64|arm64)\.deb$'
exe='^opensecagent-[0-9]+(\.[0-9]+){1,3}-(x64|arm64)-setup\.exe$'
for f in "${files[@]}"; do
  name=$(basename "$f")
  if ! [[ $name =~ $deb || $name =~ $exe ]]; then
    echo "error: $name does not have the name opensecmon expects" >&2
    exit 1
  fi
  [ -f "$f.sig" ] || { echo "error: $name has no signature ($name.sig)" >&2; exit 1; }
  if ! ssh-keygen -Y verify -f "$signers" -I opensecagent -n opensecagent -s "$f.sig" <"$f" >/dev/null; then
    echo "error: the signature of $name does not match the publisher key" >&2
    exit 1
  fi
done

find dist/agent -maxdepth 1 -type f -name 'opensecagent*' -delete
for f in "${files[@]}"; do
  install -m 644 "$f" "$f.sig" dist/agent/
  echo "taken: $(basename "$f")"
done
