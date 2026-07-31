# auth-oidc

**This plugin's version: v1.0.0.** (Independently versioned from busbar
itself — see [Versioning](#versioning) below.)

[![CI](https://github.com/GetBusbar/auth-oidc/actions/workflows/ci.yml/badge.svg)](https://github.com/GetBusbar/auth-oidc/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/GetBusbar/auth-oidc)](https://github.com/GetBusbar/auth-oidc/releases)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The first-party, signed `kind: auth` plugin for
[busbar](https://getbusbar.com): verifies a caller's identity by checking
a bearer JWT against an OpenID Connect identity provider's JWKS — real
signature verification (RS256 and ES256 on [`ring`](https://github.com/briansmith/ring),
no `jsonwebtoken`/`rsa`), issuer/audience/expiry/not-before checks, and a
claim-to-role mapping — then hands busbar a `Principal` it can bind to
virtual keys and roles.

It is a `cdylib` that implements busbar's `AuthModule` trait (via
[`busbar-plugin-sdk`](https://github.com/GetBusbar/busbar/tree/main/crates/plugin-sdk))
and is loaded in-process by busbar over the signed hybrid plugin ABI —
`dlopen`'d, not spawned as a separate process.

## Versioning

This plugin is versioned **independently of busbar** — `v1.0.0` here says
nothing about which busbar release it is. Compatibility with busbar is
stated separately: **requires busbar 1.5.0+** (the release that ships the
signed hybrid plugin ABI this crate loads over). Pin both versions
explicitly in production; do not assume they move together.

## What it is for

- **Verifying who's calling**: add `oidc` to `auth.chain` with its
  `settings:` pointed at an IdP (Entra ID, Okta, Auth0, Keycloak, or any
  standards-compliant OIDC provider) — `auth: { chain: [{ oidc: {
  settings: {...} } }] }`. Every request's bearer token is verified
  against the IdP's live JWKS — the plugin never trusts an unsigned
  claim.
- **Mapping claims to busbar identity**: the configured role claim (e.g.
  `groups`) becomes the `Principal`'s roles, which busbar's virtual-key
  and policy layer can then gate on — so an operator's existing IdP
  groups drive busbar access without a second identity system.

## Design

This repo is a same-repo, 2-crate Cargo workspace: `auth-oidc/` (the
`busbar-auth-oidc` library — the real OIDC logic, no plugin ABI) and
`auth-oidc-plugin/` (the `busbar-auth-oidc-plugin` cdylib adapter).

`auth-oidc-plugin/src/lib.rs` (~60 lines) is a thin adapter: it turns the
engine's JSON config into a real `OidcModule` and hands the trait object
to the SDK, which emits the six extern-C symbols the loader resolves
(`busbar_abi`, `busbar_plugin_kind`, `busbar_open`, `busbar_call`,
`busbar_free`, `busbar_close`).
All the actual OIDC logic — JWKS fetch/cache, JWT verification, claim
policy — lives in the `busbar-auth-oidc` library crate (`auth-oidc/`, a
same-repo sibling crate; see [Dependencies](#dependencies) below), so a
custom build can also link that logic statically instead of going
through the plugin ABI.

`jwks_url` in the config is optional: when omitted, it is resolved once
at `open()` via the issuer's OIDC discovery document, so boot fails
loudly if discovery can't find it rather than deferring the failure to
the first request.

## Build

Needs a Rust toolchain ([rustup](https://rustup.rs)), and — interim,
until [busbarAI](https://github.com/GetBusbar/busbar) ships publicly —
a sibling checkout of `busbarAI` at `../busbarAI` (see
[Dependencies](#dependencies) below).

```sh
cargo build --release      # cdylib: target/release/libbusbar_auth_oidc_plugin.{so,dylib}
cargo test                 # unit tests + the end-to-end loader/JWKS/JWT test (see tests/e2e.rs)
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Dependencies

`busbar-auth-oidc` (`auth-oidc/`) is a same-repo crate now — no external
checkout is needed for the OIDC logic itself; `auth-oidc-plugin` depends
on it as a normal workspace path dependency (`../auth-oidc`).

The remaining dependencies still reach into the
[busbarAI](https://github.com/GetBusbar/busbarAI) monorepo: `busbar-api`
(needed by both crates), `busbar-plugin-sdk` (`auth-oidc-plugin` only),
and, as dev-dependencies for the end-to-end test, `busbar-plugin-loader`
and `busbar-plugin-abi` (`auth-oidc-plugin` only) — the core-engine
contracts every plugin depends on the same way. Because busbarAI is not
yet public, both crates' `Cargo.toml` point at these as **local path
dependencies** (`../../busbarAI/crates/...`), which means this repo
expects to be checked out as a sibling of `busbarAI`:

```
some-parent-dir/
├── busbarAI/
└── auth-oidc/          # this repo — the auth-oidc/ + auth-oidc-plugin/ workspace
```

This is an interim measure — once busbarAI ships publicly, these should
become git (pinned rev/tag) or crates.io dependencies instead. Grep both
crates' `Cargo.toml` for the `INTERIM` comments when doing that
migration.

## Pack and sign

Once built, the cdylib is packed and signed like any other busbar plugin
— see
[`docs/plugins.md`](https://github.com/GetBusbar/busbar/blob/main/docs/plugins.md#signing-and-packaging)
in busbarAI for the full reference. In short:

```sh
BUSBAR_SIGN_KEY=<signing key> busbar-plugin-pack pack \
    --lib target/release/libbusbar_auth_oidc_plugin.so \
    --name busbar-auth-oidc-plugin --alias oidc --kind auth \
    --version 1.0.0 --publisher busbar \
    --license Apache-2.0 \
    --out busbar-auth-oidc-plugin-1.0.0-x86_64-linux.tar.gz
```

For local development without a signing key, `busbar-plugin-pack pack
--allow-unsigned` produces a tarball busbar loads only under
`plugins.trust.allow_unsigned: true`.

Drop the resulting tarball into busbar's configured `plugins.dir` and
set:

```yaml
auth:
  chain:
    - oidc:
        settings:
          issuer: "https://login.microsoftonline.com/<tenant-id>/v2.0"
          audience: "<client-id>"
          role_claim: groups
```

— see [`docs/configuration.md`](https://github.com/GetBusbar/busbar/blob/main/docs/configuration.md#auth-plugins)
for the full `auth.chain` config reference.

## Config

| Setting | Required | Default | Notes |
|---|---|---|---|
| `issuer` | yes | — | The IdP's OIDC issuer URL. Checked against the JWT's `iss` claim. |
| `audience` | yes | — | The expected `aud` claim (busbar's registered client/resource identifier at the IdP). |
| `jwks_url` | no | discovered from `issuer` | The IdP's JWKS endpoint. When omitted, resolved once at `open()` via OIDC discovery (`<issuer>/.well-known/openid-configuration`). |
| `role_claim` | no | `groups` | The claim mapped onto the resulting `Principal`'s roles; set `roles` to use Entra app-roles instead. |
| `jwks_min_refetch_secs` | no | `60` | JWKS refetch rate-limit (seconds) — the bound on how often a kid-rotation refetch can occur. |
| `jwks_ttl_secs` | no | `3600` | JWKS cache TTL (seconds). |
| `ca_cert_pem` | no | — | An extra root CA (PEM) to trust for the JWKS/discovery HTTPS fetch, in addition to the system trust store — for a private CA or a test fixture (this is exactly what `tests/e2e.rs` uses to trust its own self-signed local JWKS server). |

Unknown config fields are rejected (`deny_unknown_fields`) — a typo'd or
stray key fails loudly at boot instead of being silently ignored.

## Tests

`cargo test` runs both `auth-oidc-plugin`'s own hermetic unit tests
(`auth-oidc-plugin/src/lib.rs` — covering `open()`'s config-parsing
responsibility: empty/malformed/missing-required-field/unknown-field
config, and the "explicit `jwks_url` skips discovery" and "malformed
issuer fails fast" paths, all without any network I/O) and the
end-to-end test in `auth-oidc-plugin/tests/e2e.rs`. (`auth-oidc/` has
its own unit tests too — `auth-oidc/src/tests.rs` — covering the JWT/JWKS
logic itself; both crates' tests run under a workspace-wide `cargo
test`.)

The end-to-end test is NOT a stub: it stands up a genuine local HTTPS
JWKS server (a real self-signed certificate minted with `rcgen`, served
over a real `rustls` TLS listener on `127.0.0.1`), mints a real
ES256-signed JWT with `ring`, and `dlopen`s the actually-built
`busbar-auth-oidc-plugin` cdylib over `busbar-plugin-loader`'s real
`kind: auth` C ABI seam — the same seam busbar's engine uses. It proves,
entirely offline (no external IdP, no Docker service):

- a genuine JWKS fetch over real TLS, trusted via the plugin's own
  `ca_cert_pem` config field;
- genuine ES256 signature verification (a token signed by the fixture's
  key is accepted and its claims mapped to a `Principal`; a token signed
  by a *different* key with the same `kid` is rejected);
- the full claim → `Principal` mapping (`sub`/`preferred_username`/
  `name`/the configured role claim) survives the round trip across the
  real C ABI, not just in-process Rust calls;
- a load-time config error (empty config, or config missing a required
  field) surfaces back across the ABI as a clean `Err`, never a panic or
  a silently-succeeded load.

Build under `cargo test --workspace`-equivalent (i.e. a normal `cargo
build` first, or just `cargo test`, which builds the cdylib as part of
the test run) so the e2e test finds the library; it self-skips with a
message if the cdylib isn't present locally, but hard-fails under CI
(`CI` env var set) instead of silently skipping — this is the only
over-the-ABI coverage of the `kind: auth` dlopen seam and must never
quietly vanish.

## License

Licensed **Apache-2.0** ([LICENSE](LICENSE)). Contributions welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md). Governed by our
[Code of Conduct](CODE_OF_CONDUCT.md); security issues go through
[SECURITY.md](SECURITY.md), not public issues.
