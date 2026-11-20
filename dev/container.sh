#!/usr/bin/env bash
# Builds the container image of opensecmon for the architecture of this machine and checks it (docs/docker.md).
#
#   dev/container.sh                       # build the static binary, then the image opensecmon:<version>
#   dev/container.sh --binary FILE         # use this binary instead (the release workflow builds it before)
#   dev/container.sh --test                # also run the smoke test against the new image
#   dev/container.sh --test-only IMAGE     # only run the smoke test against IMAGE
#   dev/container.sh --tag NAME            # image name (default opensecmon:<version>)
#
# Uses podman if present, else docker (ENGINE=docker dev/container.sh to choose). The image is built from a prepared
# context in target/container/ (Containerfile, rootfs/, state/) without RUN steps. The signed opensecagent packages in
# dist/agent/ (dev/agent-release.sh or dev/agent-packages.sh) go into the image after their signatures are checked
# again; without them the image has none. Nothing is pushed.
set -euo pipefail

cd "$(dirname "$0")/.."
BINARY=""
TEST=no
BUILD=yes
IMAGE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --binary) BINARY="${2:?--binary needs a file}"; shift 2 ;;
    --test) TEST=yes; shift ;;
    --test-only) TEST=yes; BUILD=no; IMAGE="${2:?--test-only needs an image}"; shift 2 ;;
    --tag) IMAGE="${2:?--tag needs a name}"; shift 2 ;;
    -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

step() { printf '==> %s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

ENGINE="${ENGINE:-$(command -v podman >/dev/null && echo podman || echo docker)}"
command -v "$ENGINE" >/dev/null || fail "neither podman nor docker found"
VERSION=$(cargo metadata --format-version 1 --no-deps | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["packages"][0]["version"])')
IMAGE="${IMAGE:-opensecmon:$VERSION}"
shopt -s nullglob

if [ "$BUILD" = yes ]; then
  case "$(uname -m)" in
    x86_64) TARGET=x86_64-unknown-linux-musl ;;
    aarch64|arm64) TARGET=aarch64-unknown-linux-musl ;;
    *) fail "no musl target for $(uname -m)" ;;
  esac
  if [ -z "$BINARY" ]; then
    step "building the static binary ($TARGET)"
    cargo build --release --locked --target "$TARGET"
    BINARY="target/$TARGET/release/opensecmon"
  fi
  [ "$("$BINARY" --version)" = "opensecmon $VERSION" ] || fail "$BINARY reports $("$BINARY" --version), expected $VERSION"
  file -b "$BINARY" | grep -Eq "statically linked|static-pie linked" || fail "$BINARY is not statically linked"

  step "preparing the build context"
  CONTEXT=target/container
  rm -rf "$CONTEXT"
  mkdir -p "$CONTEXT/rootfs/usr/bin" "$CONTEXT/rootfs/usr/share/doc/opensecmon" "$CONTEXT/rootfs/usr/share/opensecmon/agent" \
           "$CONTEXT/rootfs/tmp" "$CONTEXT/state/etc/opensecmon" "$CONTEXT/state/var/lib/opensecmon"
  install -m 0755 "$BINARY" "$CONTEXT/rootfs/usr/bin/opensecmon"
  install -m 0644 LICENSE THIRD-PARTY-LICENSES.txt "$CONTEXT/rootfs/usr/share/doc/opensecmon/"
  PACKAGES=(dist/agent/opensecagent_*.deb dist/agent/opensecagent-*-setup.exe)
  for f in "${PACKAGES[@]}"; do
    ssh-keygen -Y verify -f keys/opensecagent.allowed_signers -I opensecagent -n opensecagent -s "$f.sig" <"$f" >/dev/null \
      || fail "the signature of $f does not match keys/opensecagent.allowed_signers"
    install -m 0644 "$f" "$f.sig" "$CONTEXT/rootfs/usr/share/opensecmon/agent/"
  done
  echo "    opensecagent packages: ${#PACKAGES[@]}"
  chmod 1777 "$CONTEXT/rootfs/tmp"
  chmod 0700 "$CONTEXT/state/etc/opensecmon" "$CONTEXT/state/var/lib/opensecmon"
  cp Containerfile "$CONTEXT/"

  step "building $IMAGE with $ENGINE"
  FORMAT=()
  # Podman writes OCI images by default, which have no HEALTHCHECK; the Docker format keeps it.
  [ "$(basename "$ENGINE")" = podman ] && FORMAT=(--format docker)
  "$ENGINE" build "${FORMAT[@]}" --file "$CONTEXT/Containerfile" --tag "$IMAGE" \
    --build-arg "VERSION=$VERSION" \
    --build-arg "REVISION=$(git rev-parse HEAD)" \
    --build-arg "CREATED=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "$CONTEXT"
  "$ENGINE" image inspect --format '{{.Size}}' "$IMAGE" | awk '{ printf "    image size: %.1f MB\n", $1 / 1000000 }'
fi

[ "$TEST" = yes ] || exit 0

# Smoke test: start the image as compose.yaml does (read-only, no capabilities) with an allowed host name, wait until
# it is healthy, check that the certificate names that host, create a user, sign in over HTTPS with the certificate
# checked, download the opensecagent packages if the image has some; then restart and check that key and data stayed.
# The sources are not fetched (that would download about 2 GB).
step "smoke test of $IMAGE"
NAME="opensecmon-smoke-$$"
PORT="${SMOKE_PORT:-18444}"
HOST="opensecmon.test"
URL="https://$HOST:$PORT"
WORK=$(mktemp -d)
cleanup() {
  "$ENGINE" rm -f "$NAME" >/dev/null 2>&1 || true
  "$ENGINE" volume rm -f "$NAME-config" "$NAME-data" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

start() {
  "$ENGINE" run -d --name "$NAME" -p "127.0.0.1:$PORT:8444" \
    -v "$NAME-config:/etc/opensecmon" -v "$NAME-data:/var/lib/opensecmon" \
    -e TZ=Europe/Berlin -e OPENSECMON_ALLOWED_HOSTS="$HOST:$PORT" -e OPENSECMON_FETCH_SOURCES=false \
    --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true \
    "$IMAGE" >/dev/null
}

wait_healthy() {
  for _ in $(seq 1 30); do
    if "$ENGINE" exec "$NAME" opensecmon healthcheck >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  "$ENGINE" logs "$NAME" >&2
  fail "the container did not become healthy"
}

# curl that reaches the container under the allowed name and checks its certificate (no -k).
web() { curl -s --resolve "$HOST:$PORT:127.0.0.1" --cacert "$WORK/cert.pem" "$@"; }

start
wait_healthy
echo "    healthy"
# The log goes into a variable first: `grep -q` would end the pipe early and fail it under pipefail.
LOG=$("$ENGINE" logs "$NAME" 2>&1)
grep -q "created a self-signed certificate" <<<"$LOG" || fail "no certificate was created"
grep -q "names=$HOST," <<<"$LOG" || fail "the certificate does not name the allowed host first"
grep -q 'time_zone=Europe/Berlin' <<<"$LOG" || fail "the time zone from TZ is not used"
"$ENGINE" cp "$NAME:/etc/opensecmon/tls-cert.pem" "$WORK/cert.pem"
[ "$(web -o /dev/null -w '%{http_code}' "$URL/healthz")" = 200 ] || fail "the certificate is not valid for $HOST"
[ "$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:$PORT/login")" = 421 ] || fail "a foreign host name was not refused"
echo "    certificate names $HOST, other host names are refused"

PASSWORD="smoke-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
printf '%s\n' "$PASSWORD" | "$ENGINE" exec -i "$NAME" opensecmon user add smoke >/dev/null
USERS=$("$ENGINE" exec "$NAME" opensecmon user list)
grep -q '^smoke ' <<<"$USERS" || fail "user add did not create the user"

login() {
  local jar="$WORK/cookies" page token
  rm -f "$jar"
  page=$(web -c "$jar" "$URL/login")
  token=$(sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' <<<"$page" | head -n1)
  [ -n "$token" ] || fail "no sign-in form"
  web -b "$jar" -c "$jar" -o /dev/null -H "Origin: $URL" --data-urlencode "username=smoke" --data-urlencode "password@-" \
    --data-urlencode "csrf_token=$token" "$URL/login" < <(printf '%s' "$PASSWORD")
  [ "$(web -b "$jar" -o /dev/null -w '%{http_code}' "$URL/")" = 200 ] || fail "sign-in failed"
}
login
echo "    signed in"

PACKAGES_IN_IMAGE=$(grep -o 'agent packages found count=[0-9]*' <<<"$LOG" | grep -o '[0-9]*$' || true)
if [ -n "$PACKAGES_IN_IMAGE" ]; then
  for f in dist/agent/opensecagent_*.deb dist/agent/opensecagent-*-setup.exe; do
    web -b "$WORK/cookies" -o "$WORK/package" "$URL/assets/computers/agent/$(basename "$f")"
    cmp -s "$f" "$WORK/package" || fail "the image offers another $(basename "$f") than dist/agent/"
  done
  echo "    opensecagent packages: $PACKAGES_IN_IMAGE, downloads match dist/agent/"
else
  echo "    opensecagent packages: none"
fi
if grep -q "the port forwarding hides the clients" <<<"$LOG$("$ENGINE" logs "$NAME" 2>&1)"; then
  echo "    note: this engine's port forwarding hides the client addresses (warning in the log, docs/docker.md)"
fi
OUT=$("$ENGINE" exec "$NAME" opensecmon tls generate 2>&1 || true)
grep -q "already exists" <<<"$OUT" || fail "tls generate did not refuse to overwrite the certificate"

"$ENGINE" restart "$NAME" >/dev/null
wait_healthy
login
LOG=$("$ENGINE" logs "$NAME" 2>&1)
[ "$(grep -c "created a new encryption key" <<<"$LOG")" = 1 ] || fail "the key was created again after a restart"
echo "    restart kept key, certificate and data"
step "smoke test passed"
