# Security policy

## Supported versions

Security fixes go into the next release; only the latest release is supported.

Dependencies are checked against the RustSec advisory database (`cargo deny`, rules in `deny.toml`) on every change and every
week.

## Reporting a vulnerability

Please report vulnerabilities **privately** and not as a public issue:

1. Open the [Security tab](https://github.com/tomCSLK/opensecmon/security) of the repository.
2. Choose **Report a vulnerability** and describe the problem.

Helpful details: the affected version, how to reproduce it, what an attacker can achieve and under which conditions (for example:
signed in or not, in the local network, a crafted feed or CSAF document, a crafted agent report). Do not include data of your own
installation such as host names, tokens or asset lists; reduce an example to what triggers the problem.

opensecmon is maintained in spare time. You will get an answer as soon as possible; once a fix is released, the advisory is
published and you are credited if you want.

## Scope

In scope: the web interface and its sign-in, sessions and CSRF protection; the readers of all sources (CVE list, NVD, KEV, EPSS,
CSAF, OSV, Debian Security Tracker) and of the imports (SSH, CSV, opennetmon); the agent API (`/api/v1/agent/…`); the mails; the
storage of secrets; the Debian package and its systemd units.

Known and documented, not vulnerabilities in themselves:

- Every user is an administrator; there are no roles. Users are managed on the command line only.
- The generated certificate is self-signed. Compare its fingerprint once (see `docs/operations.md`); a reverse proxy or your own
  certificate is optional.
- The agent API accepts enrollments and reports only from the networks in `agent_networks` (private and local addresses by
  default). Each computer has its own token; a revoked token is refused.
- Agent packages are offered for download by opensecmon and are signed by the publisher of
  [opensecagent](https://github.com/tomCSLK/opensecagent) (`dev/agent-packages.sh` checks the signatures when the
  package of opensecmon is built; installing updates in the agent, with its own check, is not implemented yet).
- Texts from the sources (CVE descriptions, advisories) are data: they are escaped in the interface and stripped of control
  characters in mails, but their content is not checked for accuracy.
