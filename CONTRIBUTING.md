# Contributing to opensecmon

Thanks for your interest! opensecmon is a small, self-hosted program; testing it with your own assets and telling us what is
missing or wrong is a valuable contribution.

## Reporting bugs and ideas

- **Bugs:** open an issue. Include the version, how you installed it, your distribution and, for wrong matches, the asset (vendor,
  product, version or package and release) and the CVE or advisory. Leave out host names, addresses and tokens.
- **Ideas:** open an issue and describe what you want to achieve.
- **Security vulnerabilities:** please do **not** open a public issue, see [`SECURITY.md`](SECURITY.md).

For a larger change, open an issue first so we can agree on the approach before you invest the time. Small pull requests are easier
to review than large ones.

## Development

Requirements: a current stable Rust toolchain (edition 2024). How to run a test instance is described in the README under
[Building](README.md#building). Before you open a pull request, all of these must pass:

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny --locked check
```

The tests run without network access; the readers are tested with small, made-up sample documents. CI runs the same checks on
every pull request; `cargo deny` (licenses, sources and RustSec advisories, rules in `deny.toml`) also runs weekly. Install it with
`cargo install cargo-deny --locked`.

Please be gentle with the sources while you develop: use `fetch_sources = false`, fetch by hand, and keep a copy of the database
instead of importing everything again.

## Conventions

- **Language:** code, identifiers, code comments, commit messages, the README and the changelog are English; only the internal
  planning files `PLAN.md` and `CLAUDE.md` and the UI drafts in `docs/entwurf/` are German.
- **UI texts** only through the Fluent catalogs in `locales/<code>/*.ftl`, never as fixed text in Rust or in the templates. Add every
  new message in German (`de`) and English (`en`); texts of the scripts go to `js.ftl`.
- **Interface:** the Content Security Policy is `default-src 'self'`: no inline scripts and no `style` attributes. Additions to the
  CSS go to the end of `static/app.css`.
- **Data from the sources** must never be committed. Test documents are written by hand or reduced so far that nothing of the
  original is left.
- **Database:** every change is a new migration in `migrations/`; released migrations are never changed.
- **Dependencies:** only maintained crates under a license compatible with the AGPL (see `deny.toml`). Give a short reason in the
  commit message. After any change to `Cargo.lock`, run `python3 -I dev/third-party-licenses.py` and commit
  `THIRD-PARTY-LICENSES.txt`.
- Small, self-contained commits; every commit should build and pass the tests.

## Use of AI tools

Large parts of opensecmon were written with the help of an AI assistant (Claude). If you use AI tools for a contribution, say so in
the pull request, review the result yourself and make sure you can explain every change.

## Developer Certificate of Origin (DCO)

opensecmon uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/) instead of a contributor license
agreement. By signing off a commit you certify that you wrote the change, or otherwise have the right to submit it under the
project's license.

Sign off every commit by adding a line with your name and the e-mail address of the commit author:

```
Signed-off-by: Jane Doe <jane@example.org>
```

`git commit -s` adds it for you. To sign off commits you already made: `git commit --amend -s` for the last one, or
`git rebase --signoff main` for all commits of your branch, then force-push the branch. CI checks every commit of a pull request.

## License

opensecmon is licensed under the [GNU Affero General Public License v3.0 or later](LICENSE). Any contribution you submit is
licensed the same way.
