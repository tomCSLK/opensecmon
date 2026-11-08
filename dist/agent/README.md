# Packages of opensecagent

The package of opensecmon installs the files of this folder into `/usr/share/opensecmon/agent/`. opensecmon offers
them to the computers for download and as updates (`docs/agent-api.md`, "Updates of opensecagent").

Only the publisher puts files here, with `dev/agent-packages.sh`, which copies the signed packages of a release of
opensecagent and checks their signatures first. The files themselves are not part of the repository.
