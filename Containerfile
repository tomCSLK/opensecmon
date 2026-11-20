# Container image of opensecmon (docs/docker.md): the static binary on an empty base, no shell, no package manager.
#
# Built by dev/container.sh (locally) and .github/workflows/container.yml (releases) from a prepared context, not from
# the repository root. There are no RUN steps, so every architecture builds natively without emulation:
#   rootfs/  the binary, LICENSE, THIRD-PARTY-LICENSES.txt, the signed opensecagent packages (if any) and /tmp
#   state/   the empty directories /etc/opensecmon and /var/lib/opensecmon (owned by 10001, the user the server runs as)
FROM scratch

ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown

LABEL org.opencontainers.image.title="opensecmon" \
      org.opencontainers.image.description="Security advisories (CVE, CSAF, KEV, EPSS, distributions) for your own software and devices" \
      org.opencontainers.image.url="https://github.com/tomCSLK/opensecmon" \
      org.opencontainers.image.source="https://github.com/tomCSLK/opensecmon" \
      org.opencontainers.image.documentation="https://github.com/tomCSLK/opensecmon/blob/main/docs/docker.md" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.authors="Thomas Cieslik" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"

COPY rootfs/ /
COPY --chown=10001:10001 state/ /

# All settings as variables (docs/configuration.md); override them in compose.yaml or with `docker run -e`.
# Built-in HTTPS on 8444 (8443 is opennetmon's) with a self-signed certificate that the server creates on the first
# start, like the .deb. A backup is about as large as the database (1.5 GB and more), so only three are kept.
ENV OPENSECMON_LISTEN=0.0.0.0:8444 \
    OPENSECMON_DATABASE_PATH=/var/lib/opensecmon/opensecmon.db \
    OPENSECMON_SECRET_KEY_FILE=/etc/opensecmon/secret.key \
    OPENSECMON_TLS_CERT_FILE=/etc/opensecmon/tls-cert.pem \
    OPENSECMON_TLS_KEY_FILE=/etc/opensecmon/tls-key.pem \
    OPENSECMON_GENERATE_MISSING=true \
    OPENSECMON_BACKUP_DIR=/var/lib/opensecmon/backups \
    OPENSECMON_BACKUP_KEEP=3 \
    OPENSECMON_AGENT_PACKAGES_DIR=/usr/share/opensecmon/agent

USER 10001:10001
EXPOSE 8444
# The key and the certificate live apart from the database and its backups.
VOLUME ["/etc/opensecmon", "/var/lib/opensecmon"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 CMD ["/usr/bin/opensecmon", "healthcheck"]
ENTRYPOINT ["/usr/bin/opensecmon"]
CMD ["serve"]
