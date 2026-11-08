#!/bin/sh
# opensecmon-agent.sh – reports the installed packages of a Debian or Ubuntu computer (or one based on them,
# such as Linux Mint or Zorin OS) to opensecmon over its agent API (docs/agent-api.md).
#
#   sudo sh opensecmon-agent.sh enroll <https://server:port> <code> [opensecmon.pem]
#       Enrolls the computer with the one-time code from its page in opensecmon, keeps the token in
#       /etc/opensecmon-agent (readable by root only), installs itself as /usr/local/sbin/opensecmon-agent with
#       a systemd timer that reports every 6 hours, and sends the first report. Pass the certificate when
#       opensecmon runs with its own self-signed certificate (download it from the computer's page).
#   opensecmon-agent report      sends the package list now (as root, or by the timer)
#   opensecmon-agent status      checks the token and the connection
#   opensecmon-agent uninstall   removes the timer, the token and the settings
#
# What is sent: /etc/os-release, the running kernel (uname -r), whether a reboot is pending, whether the sources of
# Ubuntu Pro are set up and, per installed package, its status, name, version, source package and source version
# (dpkg-query), and the installed snaps (snap list) and system-wide Flatpak apps (flatpak list --app: ID, name,
# version, installation). Nothing else: no user names, no files, no network details. Needs curl, gzip and systemd.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

set -eu
umask 077

VERSION=4
DIR=${OPENSECMON_AGENT_DIR:-/etc/opensecmon-agent}
BIN=/usr/local/sbin/opensecmon-agent
UNIT=/etc/systemd/system/opensecmon-agent

die() {
    echo "opensecmon-agent: $*" >&2
    exit 1
}

# The settings: under systemd from the credentials (the service runs without root), otherwise from $DIR.
conf() {
    if [ -n "${CREDENTIALS_DIRECTORY:-}" ] && [ -e "$CREDENTIALS_DIRECTORY/$1" ]; then
        echo "$CREDENTIALS_DIRECTORY/$1"
    else
        echo "$DIR/$1"
    fi
}

# curl with the certificate as the only trust anchor when there is one; HTTPS only, no redirects.
call() {
    pem=$(conf opensecmon.pem)
    if [ -s "$pem" ]; then
        curl --silent --show-error --fail-with-body --proto =https --max-time 300 --cacert "$pem" "$@"
    else
        curl --silent --show-error --fail-with-body --proto =https --max-time 300 "$@"
    fi
}

url() {
    f=$(conf url)
    [ -s "$f" ] || die "not enrolled (no $f); run: opensecmon-agent enroll <url> <code>"
    head -n 1 "$f"
}

header() {
    f=$(conf auth-header)
    [ -s "$f" ] || die "not enrolled (no token); run: opensecmon-agent enroll <url> <code>"
    echo "$f"
}

inventory() {
    cat /etc/os-release
    echo "OPENSECMON_KERNEL=$(uname -r)"
    if [ -e /var/run/reboot-required ]; then echo "OPENSECMON_REBOOT=1"; fi
    for f in /etc/apt/sources.list.d/ubuntu-esm-infra.* /etc/apt/sources.list.d/ubuntu-esm-apps.*; do
        if [ -e "$f" ]; then
            echo "OPENSECMON_PRO=1"
            break
        fi
    done
    echo "---"
    dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\t${source:Package}\t${source:Version}\n' || exit
    if command -v snap >/dev/null 2>&1; then
        echo "--- snap"
        LC_ALL=C snap list --unicode=never --color=never 2>/dev/null || true
    fi
    if command -v flatpak >/dev/null 2>&1; then
        echo "--- flatpak"
        # flatpak needs a cache it can write to, which a user without a home of its own lacks.
        cache=$(mktemp -d 2>/dev/null) || cache=""
        XDG_CACHE_HOME=${cache:-/tmp} LC_ALL=C flatpak list --app --columns=application,name,version,installation 2>/dev/null || true
        if [ -n "$cache" ]; then rm -rf "$cache"; fi
    fi
}

report() {
    command -v dpkg-query >/dev/null || die "dpkg-query is missing: only Debian and Ubuntu are supported"
    u=$(url)
    h=$(header)
    if reply=$(inventory | gzip -c | call -H "@$h" -H 'Content-Type: text/plain; charset=utf-8' \
        -H 'Content-Encoding: gzip' --data-binary @- "$u/api/v1/agent/report"); then
        echo "$reply"
    else
        die "the report failed: $reply"
    fi
}

status() {
    u=$(url)
    h=$(header)
    if reply=$(call -H "@$h" "$u/api/v1/agent/status"); then
        echo "$reply"
    else
        die "the check failed: $reply"
    fi
}

install_timer() {
    self=$(readlink -f "$0")
    [ "$self" = "$BIN" ] || install -m 755 "$self" "$BIN"
    pem=""
    [ -s "$DIR/opensecmon.pem" ] && pem="LoadCredential=opensecmon.pem:$DIR/opensecmon.pem"
    cat >"$UNIT.service" <<EOF
[Unit]
Description=Report the installed packages to opensecmon
Documentation=https://github.com/tomCSLK/opensecmon/blob/main/docs/agent-api.md
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=$BIN report
# Runs without root: the token and the settings come in as credentials, dpkg's database is readable for all.
DynamicUser=yes
LoadCredential=url:$DIR/url
LoadCredential=auth-header:$DIR/auth-header
$pem
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
CapabilityBoundingSet=
EOF
    cat >"$UNIT.timer" <<EOF
[Unit]
Description=Report the installed packages to opensecmon every 6 hours

[Timer]
OnBootSec=10min
OnUnitActiveSec=6h
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now opensecmon-agent.timer >/dev/null
    echo "timer installed: systemctl list-timers opensecmon-agent.timer"
}

enroll() {
    [ $# -ge 2 ] || die "usage: opensecmon-agent enroll <https://server:port> <code> [opensecmon.pem]"
    [ "$(id -u)" = 0 ] || [ -n "${OPENSECMON_AGENT_DIR:-}" ] || die "run as root (sudo)"
    u=${1%/}
    case $u in
        https://*) ;;
        *) die "the address must start with https://" ;;
    esac
    code=$(printf '%s' "$2" | tr -cd 'A-Za-z0-9-')
    host=$({ hostname 2>/dev/null || cat /etc/hostname; } | tr -cd 'A-Za-z0-9.-' | cut -c 1-253)
    mkdir -p "$DIR"
    chmod 700 "$DIR"
    if [ $# -ge 3 ]; then
        grep -q -- '-----BEGIN CERTIFICATE-----' "$3" || die "$3 is not a certificate"
        if grep -q -- 'PRIVATE KEY' "$3"; then die "$3 contains a private key"; fi
        install -m 600 "$3" "$DIR/opensecmon.pem"
    else
        rm -f "$DIR/opensecmon.pem"
    fi
    printf '%s\n' "$u" >"$DIR/url"
    body="{\"schema\":1,\"code\":\"$code\",\"hostname\":\"$host\",\"agent\":{\"name\":\"opensecmon-agent.sh\",\"version\":\"$VERSION\"}}"
    if ! reply=$(call -H 'Content-Type: application/json' --data-binary "$body" "$u/api/v1/agent/enroll"); then
        die "the enrollment failed: $reply"
    fi
    token=$(printf '%s' "$reply" | sed -n 's/.*"token":"\(osm1_[A-Za-z0-9_-]*\)".*/\1/p')
    [ -n "$token" ] || die "the answer holds no token: $reply"
    printf 'Authorization: Bearer %s\n' "$token" >"$DIR/auth-header"
    chmod 600 "$DIR/auth-header" "$DIR/url"
    echo "enrolled as $(printf '%s' "$reply" | sed -n 's/.*"device":"\([^"]*\)".*/\1/p')"
    if [ "$(id -u)" = 0 ] && [ -d /run/systemd/system ]; then
        install_timer
    else
        echo "no timer installed (not root or no systemd): send reports with: opensecmon-agent report"
    fi
    report
}

uninstall() {
    [ "$(id -u)" = 0 ] || die "run as root (sudo)"
    systemctl disable --now opensecmon-agent.timer 2>/dev/null || true
    rm -f "$UNIT.service" "$UNIT.timer"
    systemctl daemon-reload
    rm -rf "$DIR"
    rm -f "$BIN"
    echo "removed; remove or revoke the computer in opensecmon as well"
}

case ${1:-} in
    enroll)
        shift
        enroll "$@"
        ;;
    report) report ;;
    status) status ;;
    uninstall) uninstall ;;
    version) echo "opensecmon-agent.sh $VERSION" ;;
    *) sed -n '2,18s/^# \{0,1\}//p' "$0" >&2; exit 2 ;;
esac
