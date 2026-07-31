# Contributing to auth-oidc

Thanks for your interest in improving `auth-oidc`. This document covers how to
build, test, and submit changes.

## Ground rules

- Be respectful and constructive in all project spaces (see
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)).
- By contributing, you agree your contributions are licensed under the project's
  [Apache-2.0](LICENSE) license.
- Security issues go through [SECURITY.md](SECURITY.md), **not** public issues.

## Development setup

`auth-oidc` is a Cargo workspace of two crates — `auth-oidc/` (the
`busbar-auth-oidc` logic library) and `auth-oidc-plugin/` (the
`busbar-auth-oidc-plugin` cdylib). You need a recent stable toolchain
(`rustup` recommended), and — until [busbarAI](https://github.com/GetBusbar/busbarAI)
ships publicly — a sibling checkout of it at `../busbarAI`, since both
crates' `Cargo.toml` point at busbar's crates as local path dependencies.
See the README's [Dependencies](README.md#dependencies) section for the
exact layout. `ci.yml` itself defines no `BUSBAR_REF` — it delegates
entirely to the reusable `GetBusbar/busbar` `plugin-ci.yml` workflow,
which pins its own busbar ref; the `BUSBAR_REF` this repo owns lives in
[`release.yml`](.github/workflows/release.yml) (used to check out the
sibling `busbarAI` for packing/signing) and
[`entra-live-check.yml`](.github/workflows/entra-live-check.yml) (used
for the live Entra check).

```bash
cargo build --release                       # cdylib
cargo test                                   # unit tests + the e2e dlopen/JWKS/JWT test
cargo clippy --all-targets -- -D warnings    # lints must be clean
cargo fmt --all -- --check                   # format before committing
```

## Before you open a pull request

1. **`cargo fmt --all`** — code must be rustfmt-clean.
2. **`cargo clippy --all-targets -- -D warnings`** — no warnings.
3. **`cargo build && cargo test`** — green, including the end-to-end `dlopen`/JWKS/JWT
   test in `auth-oidc-plugin/tests/e2e.rs` (see the README's [Tests](README.md#tests)
   section — it must never be allowed to quietly skip under CI).
4. Add or update tests for any behavior change.
5. Update documentation (`README.md`, doc comments) when you change behavior or config.

## Architecture

This repo is a same-repo, 2-crate Cargo workspace: `auth-oidc/` (the
`busbar-auth-oidc` library — the real OIDC logic) and `auth-oidc-plugin/`
(the `busbar-auth-oidc-plugin` cdylib adapter).

`auth-oidc-plugin/src/lib.rs` is deliberately a thin adapter: it turns the
engine's JSON config into an `OidcModule` and hands the trait object to
[`busbar-plugin-sdk`](https://github.com/GetBusbar/busbarAI/tree/main/crates/plugin-sdk),
which emits the C ABI symbols the loader resolves. The actual OIDC logic (JWKS
fetch/cache, JWT verification, claim policy) lives in `auth-oidc/`, the
`busbar-auth-oidc` library crate this plugin wraps — a same-repo sibling
crate, not the `busbarAI` monorepo — so most substantive OIDC-logic changes
belong in `auth-oidc/`, not `auth-oidc-plugin/`. Changes to the auth/identity
path deserve extra care and review: this plugin decides who busbar trusts.

## Commit & PR conventions

- Keep commits focused; squash noisy WIP commits before opening the PR.
- Write a clear PR description: what changed, why, and how it was verified.
- Reference any related issue.
- Stage files by name; avoid sweeping `git add -A` that pulls in unrelated changes.

## Questions

Open a discussion or issue. We're happy to help you get oriented.
