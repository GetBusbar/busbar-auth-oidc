# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public issues, pull
requests, or discussions.**

Instead, report privately through either channel:

- Email **security@getbusbar.com**, or
- GitHub's [private vulnerability reporting](https://github.com/GetBusbar/busbar-auth-oidc/security/advisories/new)
  (the **Security** tab on this repository).

Please include:

- A description of the issue and its potential impact.
- Steps to reproduce (proof-of-concept if available).
- Affected version / commit.
- Any suggested mitigation.

We aim to **acknowledge your report within 48 hours**, work with you on a fix, and
coordinate disclosure timing. Confirmed vulnerabilities are published as
[GitHub Security Advisories](https://github.com/GetBusbar/busbar-auth-oidc/security/advisories),
through which we request and issue **CVE** identifiers. We credit reporters who wish to be
credited once a fix is released.

## Scope

`auth-oidc` is a `kind: auth` busbar plugin: it is the seam that decides whether a
caller's bearer JWT is trusted, and what `Principal` (identity + roles) busbar binds
to the request as a result. A defect here can translate directly into an
authentication or authorization bypass on every busbar deployment that loads it.
Issues of particular interest include:

- JWT signature verification bypass, algorithm confusion, or acceptance of an
  unsigned/`alg: none` token.
- Issuer / audience / expiry / not-before check bypass.
- JWKS fetch or cache poisoning (including SSRF via a config-controlled `issuer`
  or `jwks_url`, or OIDC discovery-document spoofing).
- Claim-to-role mapping errors that grant a caller roles it should not have.
- A load-time config error surfacing as a silent success instead of a clean `Err`
  across the plugin ABI.
- Anything that lets an untrusted caller reach busbar core with a forged or
  over-privileged `Principal`.

See busbar's own [threat model](https://github.com/GetBusbar/busbar/blob/main/THREAT_MODEL.md)
for the trust boundaries this plugin operates inside.

## Supported versions

This plugin is versioned independently of busbar (see the README's
[Versioning](README.md#versioning) section). Security fixes are applied to the
latest `main` and the most recent tagged release of **this repository**. Pin to a
tag for production use.
