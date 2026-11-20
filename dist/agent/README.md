# Packages of opensecagent

The package of opensecmon installs the files of this folder into `/usr/share/opensecmon/agent/`. opensecmon offers
them to the computers for download and as updates (`docs/agent-api.md`, "Updates of opensecagent").

Only the publisher puts files here, with `dev/agent-packages.sh`, which copies the signed packages of a release of
opensecagent and checks their signatures first, or with `dev/agent-release.sh`, which downloads the release named in
`release.txt`, checks the SHA-256 listed there and then the signatures the same way. The publisher key is
`keys/opensecagent.allowed_signers`. The packages themselves are not part of the repository.

The container image takes the packages of `release.txt` (`dev/container.sh`, `.github/workflows/container.yml`).
