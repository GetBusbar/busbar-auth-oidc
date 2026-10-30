// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **OIDC auth module** for busbar — the first identity-provider auth PLUGIN. Validates an OpenID
//! Connect JWT (ID or access token) a caller presents as its bearer credential and maps it to a
//! [`busbar_contract::auth::Principal`]: verify the signature against the provider's JWKS, check `iss`/`aud`/
//! `exp`/`nbf`, and read the configured role claim (`groups` by default, or `roles` for Entra
//! app-roles) into the principal's ROLES. busbar's own `auth.role_bindings:` config
//! then resolves those roles to governance grants and admin scope — the module asserts identity
//! only, never policy.
//!
//! This crate is the LOGIC and its door ([`door::door`], on the auth kind's memory ABI): a build that
//! links it registers that door, and the dropped-in `cdylib`, the sibling `busbar-auth-oidc-plugin`
//! crate, exports the same door as `busbar_plugin_door`.
//!
//! ## Crypto & dependencies
//!
//! Signature verification runs on `ring` — the crypto backend the whole workspace already uses (via
//! rustls). NO `jsonwebtoken`/`rsa`: that avoids RUSTSEC-2023-0071 (the Marvin RSA-timing advisory)
//! and a second crypto stack. Crypto lives HERE in the plugin crate,
//! never in busbar core.
//!
//! ## Microsoft Entra ID (Azure AD) gotchas — handled here
//!
//! - **issuer** is `https://login.microsoftonline.com/<tenant-id>/v2.0`, **aud** is the app's
//!   client-id. Both are exact-matched.
//! - **group claims are GUIDs**, not names: the operator maps those GUIDs in `auth.role_bindings:`.
//! - **>200 groups overage**: Entra omits the `groups` claim and instead emits `_claim_names` /
//!   `_claim_sources` markers pointing at the Graph API. busbar does NOT call Graph and does NOT
//!   silently degrade: [`OidcVerifier`] REJECTS such a token with a precise error pointing the
//!   operator at **app-roles** (`role_claim: roles`), whose count is bounded.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use busbar_contract::abi::sdk::cred::{Cred, FormBody};
use busbar_contract::auth::{AuthVerdict, BeginLogin, LoginHttpResponse, LoginOutcome, Principal};
use serde::Deserialize;
use serde_json::Value;
use std::borrow::Cow;
use std::time::{Duration, Instant};

#[macro_use]
mod flight;
pub mod cache;
pub mod discovery;
pub mod door;
pub mod fetch;
pub mod jwks;
pub mod jwt;
mod open;
pub mod verdicts;

pub use cache::{JwksCache, KeyError};
pub use discovery::Discovery;
pub use fetch::Fetch;
pub use flight::Step;
pub use open::config;

/// The default role/group claim name — the token claim read into the principal's ROLES when the
/// operator does not set `role_claim`, and the value the Entra >200-groups overage guard keys on.
const DEFAULT_ROLE_CLAIM: &str = "groups";
/// Default JWKS refetch bound (the kid-rotation rate limit) and TTL.
const DEFAULT_MIN_REFETCH_SECS: u64 = 60;
const DEFAULT_TTL_SECS: u64 = 3600;
/// Small clock-skew tolerance applied to `exp`/`nbf` (seconds) — standard practice so a few seconds of
/// clock drift between busbar and the IdP does not spuriously reject a just-issued / near-expiry token.
const CLOCK_SKEW_SECS: i64 = 60;
/// Ceiling on the credential-cache TTL this module suggests via `Principal::ttl_secs`, the TTL its
/// own verdict cache ([`verdicts`]) holds an identity for. This is the default cache TTL, and it
/// must only ever SHORTEN it, never lengthen it: a token derives its TTL from its own remaining
/// `exp`, but a standard access token's `exp` is often itself ~3600s out, and suggesting that as the
/// cache TTL would take the stale-revocation window from 5 minutes to up to an hour. `min`-ing
/// against this bounds the over-cache window while still shortening the TTL for a token that
/// expires sooner than this.
const MAX_CACHE_TTL_SECS: i64 = 300;
/// A host clock reading before this instant means the clock cannot be trusted at all — used to make
/// `now_unix()` fail CLOSED not just on a sub-epoch clock (`SystemTime::now()` returning `Err`), but
/// on the far more realistic broken-clock states: a dead RTC booting a host at the epoch, or an
/// NTP/RTC fault landing the clock in 1970-2000. Both of those return `Ok(small_value)`, never hit the
/// `unwrap_or` fallback, and would otherwise still make `exp` checks pass for virtually any real
/// token — the exact fail-open failure mode this whole guard exists to close. Updated occasionally is
/// fine; it only needs to stay behind "now".
const CLOCK_SANITY_FLOOR_UNIX: i64 = 1_767_225_600; // 2026-01-01T00:00:00Z

/// Why no token can be judged while the host clock reads `i64::MAX` ([`clock_or_fail_closed`]).
const CLOCK_UNREADABLE: &str = "the host clock is unreadable or reads before 2026-01-01 (the clock \
     sanity floor), so no token can be judged; fix the host clock";

/// The operator's `identity-providers:` settings for this module, deserialized from the JSON the engine passes to
/// the plugin's `open`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// The token `iss` to require, EXACT match. For Entra:
    /// `https://login.microsoftonline.com/<tenant-id>/v2.0`.
    pub issuer: String,
    /// The token `aud` to require, EXACT match. For Entra this is the application (client) id.
    pub audience: String,
    /// The JWKS endpoint. Optional: when absent it is derived from the issuer's OIDC discovery
    /// document (`<issuer>/.well-known/openid-configuration` → `jwks_uri`), fetched by the first
    /// op that needs it.
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// Which token claim carries the caller's roles/groups → the principal's GROUPS. Default
    /// `groups`; set `roles` to use Entra app-roles (the bounded-count alternative that sidesteps the
    /// >200-groups overage).
    #[serde(default = "default_role_claim")]
    pub role_claim: String,
    /// JWKS refetch rate-limit (seconds) — the bound on the kid-rotation refetch. Default 60.
    #[serde(default = "default_min_refetch_secs")]
    pub jwks_min_refetch_secs: u64,
    /// JWKS cache TTL (seconds). Default 3600.
    #[serde(default = "default_ttl_secs")]
    pub jwks_ttl_secs: u64,
    /// An ADDITIONAL trusted root CA certificate (PEM), layered on top of the built-in public root
    /// store, for a self-hosted/internal-CA OIDC provider whose JWKS/discovery endpoint doesn't chain
    /// to a public root (e.g. an on-prem Keycloak signed by a corporate CA). Optional; absent means
    /// only the built-in public roots are trusted. Every need names it as its `trust_from`: the
    /// host's connector does the TLS, never this module. Certificate validation is never disabled
    /// by this — it only widens the trusted-root set.
    #[serde(default)]
    pub ca_cert_pem: Option<String>,

    // ── browser-login (auth ABI v2) fields — all ADDITIVE and `#[serde(default)]`, so a verify-only
    // config that predates login still parses unchanged; a login-capable IdP sets what it needs. ──
    /// The OAuth `client_id` presented on the authorize URL and the token exchange. Optional: when
    /// absent it defaults to [`OidcConfig::audience`] (the common confidential-client case where the
    /// app's client-id IS the token audience, e.g. Entra). The confidential-client SECRET is never
    /// here — the host lends it at `open` and it fills the token-exchange hop when it is sent.
    #[serde(default)]
    pub client_id: Option<String>,
    /// Extra OAuth scopes to request on the authorize URL, on top of the always-added `openid`.
    /// Empty by default. Deduplicated against `openid` when the URL is built.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// The IdP `authorization_endpoint` (where the browser is redirected to log in). Optional: when
    /// absent it is discovered from the issuer's openid-configuration (issuer-match guarded). Absent
    /// AND undiscoverable ⇒ browser login is not available and `begin_login` fails closed.
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    /// The IdP `token_endpoint` (where the authorization code is exchanged for tokens). Optional:
    /// discovered from openid-configuration when absent. Absent AND undiscoverable ⇒ `complete_login`
    /// fails closed.
    #[serde(default)]
    pub token_endpoint: Option<String>,
}

fn default_role_claim() -> String {
    DEFAULT_ROLE_CLAIM.to_string()
}
fn default_min_refetch_secs() -> u64 {
    DEFAULT_MIN_REFETCH_SECS
}
fn default_ttl_secs() -> u64 {
    DEFAULT_TTL_SECS
}

/// The pure token VERIFIER: config-derived policy (issuer/audience/role_claim) plus the current time
/// source. Separated from the module + JWKS cache so the whole verify path — signature aside — is unit
/// testable with plain claim maps. Signature verification is [`jwt::verify_signature`].
pub struct OidcVerifier {
    issuer: String,
    audience: String,
    role_claim: String,
    /// Whether this verifier judges a browser-login `id_token` (OIDC Core 1.0 §3.1.3.7's
    /// authorized-party rules against `audience`, the client_id) rather than a bearer access token
    /// (RFC 9068 §4: `aud` contains the resource audience, no `azp` rule).
    id_token: bool,
}

/// The result of validating a token's CLAIMS (post-signature): the resolved principal, or a denial
/// reason. Kept separate from the signature step so tests can exercise claim policy directly.
impl OidcVerifier {
    /// The BEARER verifier: `issuer` exactly, an `aud` containing `audience` (RFC 7519 §4.1.3,
    /// RFC 9068 §4), roles from `role_claim`.
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        role_claim: impl Into<String>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            role_claim: role_claim.into(),
            id_token: false,
        }
    }

    /// The browser-login `id_token` verifier: as [`Self::new`] with the OAuth `client_id` as the
    /// audience, plus OIDC Core 1.0 §3.1.3.7's authorized-party rules against it.
    pub fn for_id_token(
        issuer: impl Into<String>,
        client_id: impl Into<String>,
        role_claim: impl Into<String>,
    ) -> Self {
        Self {
            id_token: true,
            ..Self::new(issuer, client_id, role_claim)
        }
    }

    /// Validate a decoded claims object (signature ALREADY verified) and build the [`Principal`].
    /// Checks `iss`/`aud`/`exp`/`nbf` (with a small skew tolerance), detects the Entra >200-groups
    /// overage marker (REJECT, never call Graph), and reads `role_claim` into the principal's groups.
    /// `now_unix` is the current UNIX time in seconds.
    pub fn validate_claims(&self, claims: &Value, now_unix: i64) -> Result<Principal, String> {
        // `now_unix()`'s broken-clock sentinel: refused outright, so an `exp` that saturates cannot
        // pass it, and the refusal names the clock rather than the token.
        if now_unix == i64::MAX {
            return Err(CLOCK_UNREADABLE.to_string());
        }
        // iss — exact match. A wrong issuer is a different tenant / a token minted elsewhere.
        match claims.get("iss").and_then(Value::as_str) {
            Some(iss) if iss == self.issuer => {}
            Some(other) => {
                return Err(format!(
                    "token issuer '{}' does not match the configured issuer",
                    untrusted(other)
                ))
            }
            None => return Err("token has no 'iss' claim".to_string()),
        }

        // aud — `aud` may be a single string or an array of strings (RFC 7519). The configured
        // audience MUST be present (RFC 7519 §4.1.3). A BEARER needs nothing more (RFC 9068 §4: an
        // access token may name several resource audiences, and its `azp` is the client that asked
        // for it, never the resource). An ID TOKEN follows OIDC Core 1.0 §3.1.3.7 against the
        // client_id: a multi-valued `aud` that also lists audiences the client does not trust is
        // rejected UNLESS `azp` names the client (step 4) — the `.any(trusted)` shortcut would wave
        // through a token minted for the client AND an attacker-controlled app — and an `azp` that
        // is present must name the client whatever the `aud` (step 5).
        let trusted = self.audience.as_str();
        let azp = claims.get("azp").and_then(Value::as_str);
        let aud_ok = match claims.get("aud") {
            Some(Value::String(s)) => s == trusted,
            Some(Value::Array(a)) => {
                let trusted_present = a.iter().any(|v| v.as_str() == Some(trusted));
                let has_untrusted_extra = a.iter().any(|v| v.as_str() != Some(trusted));
                trusted_present && !(self.id_token && has_untrusted_extra && azp != Some(trusted))
            }
            _ => false,
        } && !(self.id_token && claims.get("azp").is_some() && azp != Some(trusted));
        if !aud_ok {
            return Err(
                "token audience does not match the configured audience (or lists an untrusted \
                 additional audience without an azp naming the trusted client)"
                    .to_string(),
            );
        }

        // exp — required, must be in the future (with skew tolerance). A token with no exp is refused
        // (an unbounded credential).
        //
        // `saturating_add`, not `checked_add`/reject: `exp` is IdP-signed and already unbounded above
        // by policy — nothing in this crate imposes a max-lifetime check, so every `exp` below the
        // overflow band (i64::MAX - CLOCK_SKEW_SECS) is already accepted, including
        // effectively-never-expiring values. Rejecting only the top CLOCK_SKEW_SECS values would be
        // an arbitrary cliff with no security benefit, since an IdP that can set `exp` at all can
        // trivially pick a value just below it for the identical effect. This guard exists solely to
        // stop the debug-build overflow panic, not to implement an expiry policy; saturating_add(i64,
        // i64) here can only saturate to i64::MAX, which still compares `>= now_unix` and verifies —
        // consistent with the unbounded-above policy already in effect.
        let exp = match as_numeric_date_floor(claims.get("exp")) {
            Some(exp) if exp.saturating_add(CLOCK_SKEW_SECS) >= now_unix => exp,
            Some(_) => return Err("token has expired".to_string()),
            None => return Err("token has no 'exp' claim".to_string()),
        };

        // nbf — optional; if present, must not be in the future (with skew tolerance). Same
        // saturating rationale as `exp` above, opposite direction: `nbf` at i64::MIN saturates to
        // i64::MIN, which is trivially `<= now_unix` and passes — an out-of-range-low `nbf` was
        // never a meaningful "not yet valid" signal anyway.
        //
        // PRESENT-BUT-UNREADABLE is rejected, not skipped. `as_numeric_date_ceil` returns `None`
        // both for an absent claim and for one that is present but not a JSON number, and treating
        // those alike means a token carrying `"nbf": "2099-01-01T00:00:00Z"` (a string NumericDate,
        // a real shape from non-compliant issuers) has its not-before constraint silently dropped
        // rather than enforced. `exp` already distinguishes the two cases; this makes `nbf` match.
        match claims.get("nbf") {
            // A missing member and an explicit JSON `null` both mean "no not-before constraint".
            // `null` is what a serializer that writes absent optionals verbatim emits, so treating
            // it as a malformed value would reject tokens that are legitimate everywhere else, and
            // it weakens nothing: omitting the claim entirely already yields no constraint.
            None | Some(Value::Null) => {}
            Some(raw) => match as_numeric_date_ceil(Some(raw)) {
                Some(nbf) if nbf.saturating_sub(CLOCK_SKEW_SECS) > now_unix => {
                    return Err("token is not yet valid (nbf in the future)".to_string());
                }
                Some(_) => {}
                None => {
                    return Err(
                        "token has an 'nbf' claim that is not a NumericDate; refusing to ignore a \
                         not-before constraint it cannot evaluate"
                            .to_string(),
                    );
                }
            },
        }

        // ENTRA >200-GROUPS OVERAGE: when a user is in more groups than the token can carry, Entra
        // omits the groups claim and emits `_claim_names` + `_claim_sources` pointing at Graph. We do
        // NOT call Graph and MUST NOT silently proceed with an empty group set (which would strip the
        // user's authorization). Reject with a precise pointer to app-roles — UNLESS the operator is
        // already using a role claim other than `groups` (app-roles don't overflow), in which case the
        // marker is irrelevant.
        if self.role_claim == DEFAULT_ROLE_CLAIM && is_groups_overage(claims) {
            return Err(
                "token carries an Entra groups OVERAGE marker (_claim_names/_claim_sources): the \
                 user is in too many groups to fit the token, so the 'groups' claim was omitted. \
                 busbar does not call the Graph API to expand it. Switch this app to APP-ROLES and \
                 set role_claim: roles (app-role assignments are bounded and ride in the token), or \
                 reduce the user's group count."
                    .to_string(),
            );
        }

        // Roles/groups claim → principal ROLES. A missing/empty claim is NOT an error here (an
        // unmapped principal is denied downstream by the role bindings when default:deny); it
        // yields no groups.
        let groups = extract_string_list(claims.get(&self.role_claim));

        // Subject → stable principal id. ONLY the IMMUTABLE identifier (`oid` — Entra's stable object
        // id — or the generic `sub`, REQUIRED by OIDC Core 1.0 in every ID token) is acceptable here:
        // audit attribution, the per-principal budget bucket, and the idempotency cache all key on
        // `principal.id`, so a MUTABLE claim (`preferred_username`/`upn`/`email` — any of which a
        // rename or a recycled UPN can silently retarget to a different human) must never be allowed
        // to become the identity of record, not even as a fallback. A spec-compliant IdP always sends
        // `sub`; one that omits both `oid` and `sub` is itself non-compliant, and this module fails
        // CLOSED on that rather than quietly downgrading to a spoofable/reassignable identity.
        // An EMPTY (or whitespace-only) `oid`/`sub` is treated exactly like an ABSENT one: it is not a
        // usable identity anchor. Accepting `""` would collapse every such caller onto the single
        // degenerate principal `oidc:` — a shared bucket for audit attribution, budget, and the
        // idempotency cache. Fail closed rather than mint a shared/blank principal.
        let subject = non_empty_claim(claims.get("oid"))
            .or_else(|| non_empty_claim(claims.get("sub")))
            .ok_or(
                "token has no non-empty 'oid' or 'sub' claim (both are absent or blank, so no \
                 IMMUTABLE identifier is available); refusing to derive identity from a mutable claim \
                 like preferred_username/upn/email or from an empty subject — this IdP is not OIDC \
                 Core 1.0 compliant (sub is a REQUIRED, non-empty claim)",
            )?;

        // Display name: informational only (never used as identity), so the mutable claims ARE an
        // acceptable fallback chain here — an Entra ACCESS token commonly omits `name` unless the
        // optional claim is configured, and an audit trail with a bare GUID and no human-readable
        // handle anywhere is worth avoiding when a mutable-but-still-useful one is available.
        let name = claims
            .get("name")
            .and_then(Value::as_str)
            .or_else(|| claims.get("preferred_username").and_then(Value::as_str))
            .or_else(|| claims.get("upn").and_then(Value::as_str))
            .or_else(|| claims.get("email").and_then(Value::as_str))
            .map(str::to_string);

        let mut principal = Principal::from_id(format!("oidc:{subject}"));
        principal.name = name;
        principal.roles = groups;
        // Bound the engine's credential-cache lifetime to the token's OWN remaining validity instead
        // of the engine's blanket default (300s): this module is the only component that knows the
        // real `exp`, and the ABI crosses here, so this is the only place the bound can be set. Without
        // it, a token cached at T with exp=T+10 keeps authenticating from cache until T+300 — a replay
        // window that outlives the token by up to five minutes and never re-enters this module's expiry
        // check. `saturating_sub` + `max(0)`: exp can be within CLOCK_SKEW_SECS in the past and still
        // pass the check above, which must not underflow into a huge u64. Also `min`-ed against
        // MAX_CACHE_TTL_SECS: an un-ceilinged suggestion would, for a standard ~3600s-lived access
        // token, WIDEN the cache window instead of shortening it (the default is 300s). This can
        // only ever shorten the cache lifetime relative to the fixed 300s, never lengthen it.
        principal.ttl_secs = Some(exp.saturating_sub(now_unix).clamp(0, MAX_CACHE_TTL_SECS) as u64);
        Ok(principal)
    }
}

/// The longest far-end or attacker string an error or log line repeats, in characters.
const UNTRUSTED_MAX: usize = 64;

/// A FAR-END string (a JWKS key's `kty`/`crv`, a discovery document's `issuer`) or an ATTACKER one
/// (a token's `alg`, `kid`, `crit`, `iss`) as an error or log line repeats it: escaped (a newline or
/// a terminal escape cannot forge or colour a record) and capped at [`UNTRUSTED_MAX`] characters,
/// then `…`. The one helper every such site uses.
pub fn untrusted(s: &str) -> String {
    let mut shown: String = s
        .chars()
        .take(UNTRUSTED_MAX)
        .flat_map(char::escape_debug)
        .collect();
    if s.chars().nth(UNTRUSTED_MAX).is_some() {
        shown.push('…');
    }
    shown
}

/// Issuer routing: `None` when the (UNVERIFIED) claims `payload` names exactly `issuer` as its
/// `iss`, so the token is this provider's to verify; otherwise the issuer it names instead, as a
/// log may print it (escaped, bounded), `<none>` for a payload with no string `iss` or no JSON
/// object at all. The signature is not checked here: this only decides WHO judges the token.
fn foreign_issuer(payload: &[u8], issuer: &str) -> Option<String> {
    let claims = serde_json::from_slice::<Value>(payload).ok();
    match claims
        .as_ref()
        .and_then(|c| c.get("iss"))
        .and_then(Value::as_str)
    {
        Some(iss) if iss == issuer => None,
        Some(iss) => Some(untrusted(iss)),
        None => Some("<none>".to_string()),
    }
}

/// Detect the Entra groups-overage markers. Present ⇒ the token deliberately omitted the groups claim.
fn is_groups_overage(claims: &Value) -> bool {
    let names_has_groups = claims
        .get("_claim_names")
        .and_then(Value::as_object)
        .is_some_and(|o| o.contains_key("groups"));
    names_has_groups
        || claims.get("_claim_sources").is_some()
            && claims.get("groups").is_none()
            && claims.get("_claim_names").is_some()
}

/// Read a claim as a string ONLY if it is present and not empty/whitespace-only. Used for the
/// identity anchor (`oid`/`sub`), where a blank value is no identity at all and must be treated like
/// an absent claim, not accepted as the degenerate `oidc:` principal.
fn non_empty_claim(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str).filter(|s| !s.trim().is_empty())
}

/// Read an `exp` claim as a JWT NumericDate (RFC 7519 §2), FLOORING any fractional part. `as_i64`
/// alone treats a spec-legal fractional value (e.g. `exp: 1700000000.5`) as ABSENT, so fall back to
/// `as_f64`. Flooring is the conservative direction for `exp`: it never rounds an expiry LATER, so a
/// token never outlives its stated `exp`.
fn as_numeric_date_floor(v: Option<&Value>) -> Option<i64> {
    as_numeric_date(v, f64::floor)
}

/// Read an `nbf` claim as a JWT NumericDate (RFC 7519 §2), CEILING any fractional part. Same
/// `as_i64`→`as_f64` fallback as [`as_numeric_date_floor`], but the OPPOSITE rounding direction:
/// `nbf` is conservative when it never rounds a not-before EARLIER, so a token never becomes valid
/// before its stated `nbf`. (Flooring `nbf` would make a fractional `T.5` not-before admit a token as
/// early as `T`, up to ~1s sooner than intended — the lenient direction, which this avoids.)
fn as_numeric_date_ceil(v: Option<&Value>) -> Option<i64> {
    as_numeric_date(v, f64::ceil)
}

/// Shared NumericDate reader: integer fast path, else `as_f64` rounded via `round` (floor for `exp`,
/// ceil for `nbf` — see the two wrappers above), so a spec-legal fractional NumericDate is honored in
/// the conservative direction for its bound rather than silently dropped as absent.
fn as_numeric_date(v: Option<&Value>, round: impl Fn(f64) -> f64) -> Option<i64> {
    let v = v?;
    v.as_i64().or_else(|| v.as_f64().map(|f| round(f) as i64))
}

/// Read a claim as a list of strings. Accepts a JSON array of strings OR a single string (a
/// space-free scalar role). Anything else yields an empty list.
fn extract_string_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

/// The runtime OIDC auth module: a verifier, the JWKS cache and the issuer's discovery document.
/// Sans-IO: every request it makes goes through the caller's [`Fetch`], and every answer that may
/// need one is a [`Step`] (JWKS fetching is sans-IO single-flight).
pub struct OidcModule {
    verifier: OidcVerifier,
    /// The verifier for the browser-login `id_token`: the same issuer and role claim, but the
    /// audience is the OAuth `client_id` (OIDC Core 1.0 §3.1.3.7 step 3: the id_token's `aud` MUST
    /// contain the client_id). With `client_id` unset it resolves to `audience`, so the two
    /// verifiers are identical.
    login_verifier: OidcVerifier,
    jwks: JwksCache,
    discovery: Discovery,
    /// The identities this module verified for bearer credentials, held for their TTL
    /// ([`verdicts`]).
    verdicts: verdicts::VerdictCache,
    /// The config, retained so the browser-login path can read the client-id, scopes, and the
    /// authorize/token endpoints, and the JWKS url when it is configured.
    cfg: OidcConfig,
    /// The destination refusals already raised as the door's declared diagnostic
    /// ([`Self::first_report`]): each is raised once per module, not once per request.
    reported: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl OidcModule {
    /// Construct from parsed (and [`check_jwks_url`]-checked) config. Nothing is fetched here: the
    /// JWKS, and the discovery document when a URL is not configured, are fetched by the first op
    /// that needs them.
    pub fn new(cfg: &OidcConfig) -> Self {
        Self {
            verifier: OidcVerifier::new(&cfg.issuer, &cfg.audience, &cfg.role_claim),
            login_verifier: OidcVerifier::for_id_token(
                &cfg.issuer,
                resolved_client_id(cfg),
                &cfg.role_claim,
            ),
            jwks: JwksCache::new(
                Duration::from_secs(cfg.jwks_min_refetch_secs),
                Duration::from_secs(cfg.jwks_ttl_secs),
            ),
            discovery: Discovery::new(Duration::from_secs(cfg.jwks_min_refetch_secs)),
            verdicts: verdicts::VerdictCache::default(),
            cfg: cfg.clone(),
            reported: std::sync::Mutex::default(),
        }
    }

    /// Whether the destination refusal `why` is met for the first time by this module: the door
    /// raises it as its declared diagnostic (which the host audits) only then, so a refusal every
    /// request meets is audited once, not per request. A new module (a `refresh` with new
    /// settings) reports afresh.
    pub fn first_report(&self, why: &str) -> bool {
        self.reported
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(why.to_string())
    }

    /// Drop every cached verdict (`refresh`, the admin cache flush): how many there were.
    pub fn flush_verdicts(&self) -> usize {
        self.verdicts.flush()
    }

    /// How often `tick` asks to run: the JWKS refetch bound (`jwks_min_refetch_secs`, 60 s by
    /// default), at least one second.
    pub fn tick_period(&self) -> Duration {
        Duration::from_secs(self.cfg.jwks_min_refetch_secs.max(1))
    }

    /// The tick refreshes ahead of the TTL: the key set is fetched again once it is within one
    /// tick period of its TTL (`jwks_ttl_secs`, 3600 s by default), on the caller's ticket, rate-limited by `jwks_min_refetch_secs` like every fetch, so
    /// the request that finds the set stale is not the one that waits on its refresh. PENDING while
    /// this caller's fetch is in flight (re-enter with the same `io` state); WAIT while another
    /// caller's discovery is.
    ///
    /// # Errors
    /// The JWKS url could not be discovered, or the fetch failed with no key set to keep.
    pub fn refresh_ahead(&self, now: Instant, io: &mut dyn Fetch) -> Step<Result<(), String>> {
        let url = step_ok!(self.jwks_url(now, io));
        self.jwks.refresh_ahead(&url, self.tick_period(), now, io)
    }

    /// Whether the settings name an operator CA (`ca_cert_pem`, non-empty): the module's requests
    /// then go out on the needs that trust it (`fetch::NEEDS`' anchored set), else on the public
    /// set. Read as the host reads a `trust_from` path: an empty value names nothing.
    pub fn anchored(&self) -> bool {
        self.cfg
            .ca_cert_pem
            .as_deref()
            .is_some_and(|p| !p.is_empty())
    }

    /// The JWKS url: the configured `jwks_url`, or the discovery document's `jwks_uri`.
    ///
    /// # Errors
    /// The discovery error, or a document with no `jwks_uri`.
    pub fn jwks_url(&self, now: Instant, io: &mut dyn Fetch) -> Step<Result<Cow<'_, str>, String>> {
        let url = step_ok!(self.endpoint(self.cfg.jwks_url.as_ref(), "jwks_uri", now, io));
        Step::Ready(url.ok_or_else(|| {
            "OIDC discovery document has no 'jwks_uri'; set jwks_url explicitly".to_string()
        }))
    }

    /// The host's `ready` (after `open`, before any listener binds; boot awaits it): boot-time
    /// discovery, the JWKS url from the issuer's discovery document, a failure refusing boot (an
    /// explicit `jwks_url` skips it), then the key set's best-effort warm-up.
    /// Single-flight with every op that needs the same document or keys.
    ///
    /// # Errors
    /// The discovery error, or a document with no `jwks_uri`.
    pub fn ready(&self, now: Instant, io: &mut dyn Fetch) -> Step<Result<(), String>> {
        let url = step_ok!(self.jwks_url(now, io));
        // The key set's warm-up: fetched once at boot so the first verdicts are answered on the
        // spot. A boot never fails on it: a failed warm-up is left to the first verify, which
        // fetches again.
        match self.jwks.warm(&url, now, io) {
            Step::Pending => Step::Pending,
            Step::Ready(_) | Step::Wait => Step::Ready(Ok(())),
        }
    }

    /// The login endpoint `configured`, else the discovery document's `field` (the SAME
    /// issuer-match–guarded document [`Self::jwks_url`] reads); `None` when the document omits it
    /// too (that half of browser login is then unavailable and fails closed).
    fn endpoint<'a>(
        &'a self,
        configured: Option<&'a String>,
        field: &str,
        now: Instant,
        io: &mut dyn Fetch,
    ) -> Step<Result<Option<Cow<'a, str>>, String>> {
        if let Some(url) = configured {
            return Step::Ready(Ok(Some(Cow::Borrowed(url))));
        }
        let doc = step_ok!(self.discovery.document(&self.cfg, now, io));
        let Some(url) = doc.get(field).and_then(Value::as_str) else {
            return Step::Ready(Ok(None));
        };
        // A key set, a token exchange or an authorize URL the DOCUMENT names, on any host, is taken
        // over https only (plain http only to loopback); WHERE a fetched one goes is the
        // destination guard's (the needs' classes). The authorize URL is a browser redirect, never
        // fetched, but the browser is never sent to it in plaintext.
        if let Some(setting) = discovered_setting(field) {
            if let Err(why) = discovered_secure(field, setting, url) {
                io.refused(&why);
                return Step::Ready(Err(why));
            }
        }
        Step::Ready(Ok(Some(Cow::Owned(url.to_string()))))
    }

    /// The IdP `authorization_endpoint`: configured, or discovered.
    pub fn authorization_endpoint(
        &self,
        now: Instant,
        io: &mut dyn Fetch,
    ) -> Step<Result<Option<String>, String>> {
        let configured = self.cfg.authorization_endpoint.as_ref();
        let url = step_ok!(self.endpoint(configured, "authorization_endpoint", now, io));
        Step::Ready(Ok(url.map(Cow::into_owned)))
    }

    /// The IdP `token_endpoint`: configured, or discovered.
    pub fn token_endpoint(
        &self,
        now: Instant,
        io: &mut dyn Fetch,
    ) -> Step<Result<Option<String>, String>> {
        let configured = self.cfg.token_endpoint.as_ref();
        let url = step_ok!(self.endpoint(configured, "token_endpoint", now, io));
        Step::Ready(Ok(url.map(Cow::into_owned)))
    }

    /// Verify a login token-endpoint response into an identity. Parses the token endpoint's JSON,
    /// extracts the `id_token`, and REUSES the full verify path (JWKS signature +
    /// [`OidcVerifier::validate_claims`] for iss/aud/exp/nbf) to produce a [`Principal`]. The `aud`
    /// checked is the OAuth `client_id`, not the bearer `audience` (OIDC Core 1.0 §3.1.3.7 step 3).
    /// A missing/malformed body, a missing `id_token`, or any signature/claim failure is a
    /// fail-closed `Reject`. An `id_token` whose key set cannot be had — fetched, or its URL
    /// discovered — is an OUTAGE (OWNER-SIGNED 2026-10-30: an IdP outage is never a 401): the
    /// error, which the door answers `LOGIN_OUTAGE`, with a warn naming why.
    ///
    /// The OIDC `nonce` is minted by the CORE at begin and lent again on the callback; the door
    /// binds the token response to it ([`nonce_binds`]) before this verifies the id_token, and
    /// [`Self::begin_login`] refuses a login the host lends no nonce.
    ///
    /// # Errors
    /// The identity provider could not answer: its token endpoint answered 5xx or 429, or the
    /// id_token's key set cannot be had. That is an outage (the host answers 503, retryable), never
    /// a declined login. Every other failure is a `Reject`.
    pub fn identity_from_token_response(
        &self,
        resp: &LoginHttpResponse,
        now_unix: i64,
        now_mono: Instant,
        io: &mut dyn Fetch,
    ) -> Step<Result<LoginOutcome, String>> {
        // A non-2xx token-endpoint response never carries a usable id_token. OWNER-SIGNED
        // 2026-10-30: only an RFC 6749 §5.2 credential error answers 401 — a 400 or 401 carrying a
        // §5.2 JSON `error` is a declined login, logged with the allow-listed code (the client's own
        // misconfiguration at warn, the user's code at info). Any other non-2xx — 5xx, 429, a
        // redirect, 403, 404, 408, a 4xx with no §5.2 body — is the IdP not answering the
        // exchange: an outage, logged with its status (the operator's to see: warn).
        if !(200..300).contains(&resp.status) {
            if let (400 | 401, Some(code)) = (resp.status, oauth_error(&resp.body)) {
                if matches!(code, "invalid_client" | "unauthorized_client") {
                    tracing::warn!(
                        module = "oidc",
                        status = resp.status,
                        error = code,
                        "OIDC token endpoint refused this client (check client_id and the client secret); login declined"
                    );
                } else {
                    tracing::info!(
                        module = "oidc",
                        status = resp.status,
                        error = code,
                        "OIDC token endpoint refused the login's code; login declined"
                    );
                }
                return Step::Ready(Ok(LoginOutcome::Reject));
            }
            tracing::warn!(
                module = "oidc",
                status = resp.status,
                "OIDC token endpoint is unavailable; login refused as an outage"
            );
            return Step::Ready(Err(format!(
                "the identity provider is unavailable: its token endpoint answered HTTP {}",
                resp.status
            )));
        }
        let body = match TokenResponse::parse(&resp.body) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(module = "oidc", error = %e, "OIDC token endpoint response is not JSON; login declined");
                return Step::Ready(Ok(LoginOutcome::Reject));
            }
        };
        let Some(id_token) = body.id_token.as_deref().map(String::as_str) else {
            tracing::warn!(
                module = "oidc",
                "OIDC token endpoint response carries no id_token; login declined"
            );
            return Step::Ready(Ok(LoginOutcome::Reject));
        };
        // The key set cannot be had (fetched, or its URL discovered): an outage, logged by
        // `verify_with`, answered as the error.
        let verdict = step_ok!(self.verify_with(
            &self.login_verifier,
            id_token,
            now_unix,
            now_mono,
            io
        ));
        Step::Ready(Ok(match verdict {
            AuthVerdict::Identify(p) => LoginOutcome::Identify(p),
            // A non-JWT / bad-sig / bad-claim id_token in a login callback is a hard failure —
            // unlike the verify chain, there is no "next module" to defer a `Pass` to. Enumerated
            // (not `_`) so a future `AuthVerdict` variant is a compile error here.
            AuthVerdict::Reject => LoginOutcome::Reject,
            AuthVerdict::Pass => {
                tracing::warn!(
                    module = "oidc",
                    "the IdP's id_token is not a JWT naming this provider's issuer; login declined"
                );
                LoginOutcome::Reject
            }
        }))
    }

    /// The full verification of one presented bearer credential → an [`AuthVerdict`]: none
    /// presented, one that is not a JWT, or a JWT whose (unverified) `iss` is not this provider's
    /// issuer, is not ours (`Pass`, to the next auth in the chain); a JWT naming this provider's
    /// issuer is verified in full, and any failure of the token is a `Reject`. An identity is cached for its TTL
    /// and answered from the cache until it expires or a `refresh` drops it; a REJECT or a PASS is
    /// never cached.
    ///
    /// # Errors
    /// The key set cannot be had: the JWKS url could not be discovered, or the key set could not be
    /// fetched (an IdP outage, never a `Reject`).
    pub fn verify(
        &self,
        token: Option<&str>,
        now_unix: i64,
        now_mono: Instant,
        io: &mut dyn Fetch,
    ) -> Step<Result<AuthVerdict, String>> {
        if let Some(hit) = token.and_then(|t| self.cached(t, now_unix)) {
            let mut principal = Principal::clone(&hit.principal);
            principal.ttl_secs = hit.ttl_secs;
            return Step::Ready(Ok(AuthVerdict::Identify(principal)));
        }
        self.judge(token, now_unix, now_mono, io)
    }

    /// The credential cache: the identity a bearer this module identified within its TTL
    /// verified as, and the TTL it has left, answered with no decode, parse or signature check and
    /// no request.
    pub fn cached(&self, token: &str, now_unix: i64) -> Option<verdicts::Hit> {
        self.verdicts.get(token, now_unix)
    }

    /// [`Self::verify`] past its cache: the credential judged, an identity cached.
    ///
    /// # Errors
    /// As [`Self::verify`].
    pub fn judge(
        &self,
        token: Option<&str>,
        now_unix: i64,
        now_mono: Instant,
        io: &mut dyn Fetch,
    ) -> Step<Result<AuthVerdict, String>> {
        let Some(token) = token else {
            tracing::debug!(
                module = "oidc",
                "no bearer presented: nothing for this provider; passed to the next auth"
            );
            return Step::Ready(Ok(AuthVerdict::Pass));
        };
        let generation = self.verdicts.generation();
        let verdict = step!(self.verify_with(&self.verifier, token, now_unix, now_mono, io));
        if let Ok(AuthVerdict::Identify(principal)) = &verdict {
            self.verdicts.put(token, principal, now_unix, generation);
        }
        Step::Ready(verdict)
    }

    /// [`Self::verify`] against an explicit claim `verifier`: the bearer path passes the
    /// `audience` verifier, the browser-login path the `client_id` one.
    fn verify_with(
        &self,
        verifier: &OidcVerifier,
        token: &str,
        now_unix: i64,
        now_mono: Instant,
        io: &mut dyn Fetch,
    ) -> Step<Result<AuthVerdict, String>> {
        // Not shaped as a compact JWS (three segments, a base64url payload) ⇒ not our credential
        // shape. `Pass` so a later chain module (or the mode default) can handle it — a random
        // opaque bearer is not an OIDC failure.
        let Some(payload) = jwt::payload(token) else {
            tracing::debug!(
                module = "oidc",
                "bearer is not a JWT: not this provider's credential; passed to the next auth"
            );
            return Step::Ready(Ok(AuthVerdict::Pass));
        };
        // ISSUER ROUTING (multi-issuer resource servers): the token's UNVERIFIED `iss` routes it,
        // read from the payload BEFORE the header is decoded.
        // One naming another issuer, or none, is not this provider's credential: `Pass`, so a
        // second identity provider later in the chain can judge it, and the chain's end refuses a
        // token no provider claims. Nothing is fetched for it. One naming THIS issuer is this
        // provider's alone and is verified in full below; any failure is a `Reject` that stops the
        // chain, never a fall-through. The unverified claim only ever narrows: it selects which
        // provider judges, never what that provider accepts.
        if let Some(other) = foreign_issuer(&payload, &verifier.issuer) {
            tracing::info!(
                module = "oidc",
                token_issuer = %other,
                "OIDC token names an issuer that is not this provider's issuer: not this \
                 provider's credential; passed to the next auth"
            );
            return Step::Ready(Ok(AuthVerdict::Pass));
        }
        // Ours, and the host's clock cannot be read (`clock_or_fail_closed`'s sentinel): no token
        // can be judged, and that is the host's fault, not the caller's — a FAILURE (the login's
        // outage), never a reject.
        if now_unix == i64::MAX {
            tracing::warn!(module = "oidc", "the host clock is unreadable; the token cannot be judged");
            return Step::Ready(Err(CLOCK_UNREADABLE.to_string()));
        }
        // Ours: a header that does not decode is this provider's to refuse.
        let parts = match jwt::split(token) {
            Ok(p) => p,
            Err(e) => {
                tracing::info!(module = "oidc", reason = "malformed", error = %e, "OIDC token naming this provider's issuer is malformed; rejected");
                return Step::Ready(Ok(AuthVerdict::Reject));
            }
        };
        let kid = parts.header.kid.as_deref().unwrap_or_default();
        // The key set's URL could not be discovered: the key set cannot be had, an OUTAGE.
        let url = match step!(self.jwks_url(now_mono, io)) {
            Ok(url) => url,
            Err(e) => {
                tracing::warn!(module = "oidc", error = %e, "OIDC key set is unavailable; the token cannot be judged");
                return Step::Ready(Err(e));
            }
        };

        // Verify the signature against the JWKS key for this kid (fetching / rotation-refetching as
        // needed). No key that verifies is a REJECT — a presented-but-invalid credential; a key set
        // that cannot be had is an OUTAGE (OWNER-SIGNED 2026-10-30: never a 401).
        let alg = Some(parts.header.alg.as_str());
        let signed = step!(self.jwks.with_key_for(&url, kid, alg, now_mono, io, |key| {
            jwt::verify_signature(&parts, key)
        }));
        match signed {
            Ok(()) => {}
            Err(KeyError::Unavailable(e)) => {
                tracing::warn!(module = "oidc", error = %e, "OIDC key set is unavailable; the token cannot be judged");
                return Step::Ready(Err(e));
            }
            Err(KeyError::Mismatch(e)) => {
                tracing::info!(module = "oidc", reason = "signature", error = %e, "OIDC token rejected: no key in the key set verifies it");
                return Step::Ready(Ok(AuthVerdict::Reject));
            }
        }

        let claims = match jwt::claims(&parts) {
            Ok(c) => c,
            Err(e) => {
                tracing::info!(module = "oidc", reason = "malformed", error = %e, "OIDC token rejected: its claims are malformed");
                return Step::Ready(Ok(AuthVerdict::Reject));
            }
        };

        Step::Ready(Ok(match verifier.validate_claims(&claims, now_unix) {
            Ok(principal) => AuthVerdict::Identify(principal),
            Err(e) => {
                tracing::info!(module = "oidc", reason = "claims", error = %e, "OIDC token rejected: its claims do not validate");
                AuthVerdict::Reject
            }
        }))
    }

    /// Start browser login: the CORE has already minted PKCE `state`/`code_challenge` and the
    /// `nonce`; answer the IdP authorize URL to redirect to. Fails closed (`Reject`) when no
    /// `authorization_endpoint` is configured or discovered — this module is verify-only then.
    ///
    /// # Errors
    /// The host lent no nonce (absent or empty: the login's id_token could never bind to it, so
    /// `complete_login` would refuse it), logged; or the endpoint had to be discovered, and
    /// discovery failed.
    pub fn begin_login(
        &self,
        req: &BeginLogin,
        now: Instant,
        io: &mut dyn Fetch,
    ) -> Step<Result<LoginOutcome, String>> {
        let Some(nonce) = req.nonce.as_deref().filter(|n| !n.is_empty()) else {
            tracing::warn!(
                module = "oidc",
                "begin_login carries no nonce; browser login refused"
            );
            return Step::Ready(Err(
                "oidc: begin_login carries no nonce, so the login's id_token could never be bound \
                 to it; browser login refused"
                    .to_string(),
            ));
        };
        let Some(endpoint) = step_ok!(self.authorization_endpoint(now, io)) else {
            tracing::info!(
                module = "oidc",
                "no authorization_endpoint is configured and the discovery document names none; \
                 browser login refused"
            );
            return Step::Ready(Ok(LoginOutcome::Reject));
        };
        // Fold the operator's request-time extra scopes into the configured set;
        // `build_authorize_url` dedups against the always-added `openid`.
        let mut cfg = self.cfg.clone();
        cfg.authorization_endpoint = Some(endpoint);
        cfg.scopes.extend(req.scopes.iter().cloned());
        Step::Ready(Ok(LoginOutcome::Authorize(build_authorize_url(
            &cfg,
            &req.redirect_uri,
            &req.state,
            &req.code_challenge,
            Some(nonce),
        ))))
    }

    /// The callback's token request: its `code`, `redirect_uri` and `code_verifier`, and the lent
    /// client `secret` (if any), as the form [`token_form`] builds. `None` (fail closed) for a
    /// callback lacking any of the three, or with no `token_endpoint` configured or discovered.
    ///
    /// # Errors
    /// The endpoint had to be discovered, and discovery failed.
    pub fn token_exchange(
        &self,
        code: Option<&str>,
        redirect_uri: Option<&str>,
        code_verifier: Option<&str>,
        secret: Option<&Cred>,
        now: Instant,
        io: &mut dyn Fetch,
    ) -> Step<Result<Option<TokenRequest>, String>> {
        let (Some(code), Some(redirect_uri), Some(code_verifier)) =
            (code, redirect_uri, code_verifier)
        else {
            let absent: Vec<&str> = [
                ("code", code.is_none()),
                ("redirect_uri", redirect_uri.is_none()),
                ("code_verifier", code_verifier.is_none()),
            ]
            .into_iter()
            .filter_map(|(name, missing)| missing.then_some(name))
            .collect();
            // The user's callback, not the operator's config: an end-user decline (info).
            tracing::info!(module = "oidc", absent = %absent.join(", "), "OIDC callback lacks fields the token exchange needs; login declined");
            return Step::Ready(Ok(None));
        };
        let Some(url) = step_ok!(self.token_endpoint(now, io)) else {
            tracing::warn!(module = "oidc", "no token_endpoint is configured and the discovery document names none; login declined");
            return Step::Ready(Ok(None));
        };
        let form = token_form(&self.cfg, &url, code, redirect_uri, code_verifier, secret);
        Step::Ready(Ok(Some(TokenRequest { url, form })))
    }
}

/// The callback's token request: the token endpoint and the form it is sent. The form's values
/// (the code, the code_verifier) are wiped when it drops, and the client secret is sealed in it:
/// the SDK writes it into the request body and nowhere else.
#[derive(Debug)]
pub struct TokenRequest {
    /// The token endpoint.
    pub url: String,
    /// The `application/x-www-form-urlencoded` body.
    pub form: FormBody,
}

/// THE TOKEN ENDPOINT'S ANSWER (RFC 6749 §5.1, OIDC Core §3.1.3.3), typed: the issued tokens are
/// held in wiped holders, so no plain copy of one outlives its use; every other member is ignored.
/// No `Debug`: it holds credentials.
#[derive(Deserialize)]
pub(crate) struct TokenResponse {
    /// The OIDC identity token, the one member the login reads.
    #[serde(default, deserialize_with = "wiped")]
    pub(crate) id_token: Option<zeroize::Zeroizing<String>>,
    /// The access token: never read, but parsed into a wiped holder rather than left to a scratch
    /// buffer.
    #[serde(default, deserialize_with = "wiped")]
    #[allow(dead_code)]
    access_token: Option<zeroize::Zeroizing<String>>,
    /// The refresh token: as `access_token`.
    #[serde(default, deserialize_with = "wiped")]
    #[allow(dead_code)]
    refresh_token: Option<zeroize::Zeroizing<String>>,
}

impl TokenResponse {
    /// `body` parsed; the error never echoes it.
    pub(crate) fn parse(body: &str) -> Result<Self, String> {
        serde_json::from_str(body)
            .map_err(busbar_contract::abi::sdk::auth_kit::json_error("token response"))
    }
}

/// A token member deserialized straight into a wiped holder.
fn wiped<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<zeroize::Zeroizing<String>>, D::Error> {
    Ok(Option::<String>::deserialize(d)?.map(zeroize::Zeroizing::new))
}

/// The nonce binding: `true` when the token endpoint's `body`
/// carries no `id_token`, or carries one whose (unverified) payload names `nonce` as its `nonce`
/// claim, compared in constant time. An `id_token` with no readable `nonce` claim does not bind.
/// The signature, issuer and audience are checked afterwards, by the verifier.
pub(crate) fn nonce_binds(body: &str, nonce: &str) -> bool {
    use base64::Engine as _;
    let Some(id_token) = TokenResponse::parse(body).ok().and_then(|r| r.id_token) else {
        return true;
    };
    let claimed = id_token
        .split('.')
        .nth(1)
        .and_then(|p| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(p)
                .ok()
        })
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|c| c.get("nonce").and_then(Value::as_str).map(str::to_string));
    claimed.is_some_and(|c| busbar_contract::constant_time_eq(&c, nonce))
}

/// The RFC 6749 §5.2 error codes a token endpoint answers a refused exchange with.
const OAUTH_ERRORS: &[&str] = &[
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
];

/// The RFC 6749 §5.2 error a token-endpoint `body` carries, as a log may print it: the allow-listed
/// code, `(unlisted)` for any other string (an extension code is never echoed); `None` when the
/// body is not a JSON object with a string `error` (no §5.2 body at all).
fn oauth_error(body: &str) -> Option<&'static str> {
    #[derive(Deserialize)]
    struct ErrorBody {
        error: String,
    }
    let code = serde_json::from_str::<ErrorBody>(body).ok()?.error;
    Some(
        OAUTH_ERRORS
            .iter()
            .find(|c| **c == code)
            .copied()
            .unwrap_or("(unlisted)"),
    )
}

/// The OAuth `client_id` to present: the explicit `client_id`, else the `audience` (the common
/// confidential-client case where the app's client-id IS the token audience).
fn resolved_client_id(cfg: &OidcConfig) -> String {
    cfg.client_id
        .clone()
        .unwrap_or_else(|| cfg.audience.clone())
}

/// The space-delimited `scope` value: always `openid` first, then the configured scopes, deduped.
fn scope_value(cfg: &OidcConfig) -> String {
    let mut scopes = vec!["openid".to_string()];
    for s in &cfg.scopes {
        if !scopes.iter().any(|x| x == s) {
            scopes.push(s.clone());
        }
    }
    scopes.join(" ")
}

/// Percent-encode `s` for use as a URL QUERY-component value (RFC 3986 unreserved set kept literal,
/// everything else `%`-escaped). Used only for the authorize URL; the token request's form is
/// encoded by the SDK ([`token_form`]).
fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Build the OAuth **authorization-code** authorize URL: `response_type=code`, `client_id`,
/// `redirect_uri`, `scope` (`openid` + configured), `state`, PKCE `code_challenge` +
/// `code_challenge_method=S256`, and `nonce` when present. Structurally cannot contain a
/// `client_secret` — the begin path is public and the secret is the CORE's alone.
pub fn build_authorize_url(
    cfg: &OidcConfig,
    redirect_uri: &str,
    state: &str,
    code_challenge: &str,
    nonce: Option<&str>,
) -> String {
    let endpoint = cfg.authorization_endpoint.as_deref().unwrap_or_default();
    let client_id = resolved_client_id(cfg);
    let scope = scope_value(cfg);
    // RFC 6749 §3.1: an authorization endpoint MAY carry a query component (e.g. Azure AD B2C's
    // `?p=<policy>`), which MUST be retained when adding parameters, so join with `&` then.
    let sep = if endpoint.contains('?') { '&' } else { '?' };
    let mut url = format!(
        "{endpoint}{sep}response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        pct(&client_id),
        pct(redirect_uri),
        pct(&scope),
        pct(state),
        pct(code_challenge),
    );
    if let Some(nonce) = nonce {
        url.push_str(&format!("&nonce={}", pct(nonce)));
    }
    url
}

/// THE TOKEN REQUEST'S FORM (`url`'s authorization-code grant): `grant_type=authorization_code`,
/// `code`, `redirect_uri`, `code_verifier`, `client_id`, then the lent client `secret` sealed as
/// `client_secret`. With no secret lent the field is left out rather than sent empty (a public
/// client sends none). The secret goes out only on a secured connection when `url` is https.
pub fn token_form(
    cfg: &OidcConfig,
    url: &str,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
    secret: Option<&Cred>,
) -> FormBody {
    let form = FormBody::new()
        .public("grant_type", "authorization_code")
        .public("code", code)
        .public("redirect_uri", redirect_uri)
        .public("code_verifier", code_verifier)
        .public("client_id", &resolved_client_id(cfg));
    match secret {
        Some(secret) => form.sealed("client_secret", &secret.clone().secure_for(url)),
        None => form,
    }
}

/// Current UNIX time in seconds. Fails CLOSED on a clock this module cannot trust: `validate_claims`'s
/// `exp` check is `exp + skew >= now_unix`, so a `now_unix` that reads too LOW makes every token
/// appear unexpired (fail OPEN) — the exact failure this guards against. Two cases, both mapped to
/// `i64::MAX` (which `validate_claims` refuses outright, naming the clock):
///   - `SystemTime::now()` returns `Err` (host clock strictly before the UNIX epoch) — rare.
///   - The clock IS readable but below [`CLOCK_SANITY_FLOOR_UNIX`] — the realistic broken-clock case
///     (a dead RTC booting a host at the epoch, or an NTP/RTC fault landing in 1970-2000), which
///     `duration_since` reports as `Ok(small_value)` and would otherwise sail straight through.
#[cfg(test)]
pub(crate) fn now_unix() -> i64 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(i64::MAX);
    clock_or_fail_closed(t)
}

/// The fail-closed mapping every clock reading takes (the request's timestamp, the host's
/// `clock.now`, the tests' `now_unix`): a reading at or above
/// [`CLOCK_SANITY_FLOOR_UNIX`] passes through, anything below becomes `i64::MAX`. Pure, so the mapping
/// is testable (`now_unix` reads the real host clock).
pub(crate) fn clock_or_fail_closed(t: i64) -> i64 {
    if t >= CLOCK_SANITY_FLOOR_UNIX {
        t
    } else {
        i64::MAX
    }
}

/// The setting an operator configures to name a discovered endpoint's URL themselves: the discovery
/// fields whose URL the module FETCHES (`jwks_uri`, `token_endpoint`) or sends the browser to
/// (`authorization_endpoint`), and so holds to https ([`discovered_secure`]). `None` for any other
/// field.
fn discovered_setting(field: &str) -> Option<&'static str> {
    match field {
        "jwks_uri" => Some("jwks_url"),
        "token_endpoint" => Some("token_endpoint"),
        "authorization_endpoint" => Some("authorization_endpoint"),
        _ => None,
    }
}

/// A DISCOVERED ENDPOINT'S SCHEME (OIDC Discovery 1.0 §3, RFC 9700 §4): a `field` URL the issuer's
/// discovery document names is taken on ANY host (the discovery spec ties the document's `issuer`,
/// not its endpoints: Google serves its keys from `www.googleapis.com`), but only over https (plain
/// http only to a loopback host). WHERE it may go is the destination guard's: the needs it goes out
/// on refuse a private, loopback, link-local or metadata address unless
/// `advanced.allow_destinations` names it ([`fetch::DOCUMENT_CLASS`], [`fetch::TOKEN_CLASS`]).
///
/// # Errors
/// The refusal ([`fetch::refusal`]): the URL's host and the rule, never its path or query.
pub fn discovered_secure(field: &str, setting: &str, url: &str) -> Result<(), String> {
    let Ok(parsed) = url::Url::parse(url) else {
        return Err(fetch::refusal(
            "?",
            &format!("cannot be read: the discovery document's {field} is not a URL"),
        ));
    };
    if parsed.scheme() == "https" || (parsed.scheme() == "http" && is_loopback_host(&parsed)) {
        return Ok(());
    }
    Err(fetch::refusal(
        parsed.host_str().unwrap_or("?"),
        &format!(
            "is named over {}: a {field} the discovery document names must be https (plain http \
             only to loopback); set {setting} to name another URL",
            parsed.scheme().escape_debug()
        ),
    ))
}

/// The configured `jwks_url`, checked. Absent is fine (discovery names it), and so is `https`.
///
/// PLAIN HTTP ONLY FOR LOOPBACK (identity-providers.md; RFC 8414 / OIDC Discovery: key material
/// over TLS): to a LOOPBACK host ([`is_loopback_host`]: 127.0.0.0/8, `::1`, `localhost`,
/// `*.localhost`), the local identity-provider rig, it OPENS with the warning this returns, which
/// `open` logs (the key set is fetched only over https, [`fetch::plaintext_allowed`], so every
/// token is rejected until the URL is https). To any other host it is REFUSED at `open` (so at
/// `--validate` and boot), naming the field, the host and the rule: a key set over plain http could
/// be substituted in transit. Any other scheme, or no URL at all, is refused at `open`, naming the
/// field.
///
/// # Errors
/// The URL does not parse, is neither https nor http, or is plain http to a host that is not
/// loopback.
pub fn check_jwks_url(cfg: &OidcConfig) -> Result<Option<String>, String> {
    const ONLY: &str = "it must be an https URL (plain http only to a loopback host)";
    let Some(url) = &cfg.jwks_url else {
        return Ok(None);
    };
    let parsed = url::Url::parse(url)
        .map_err(|e| format!("settings.jwks_url: is not a valid URL ({e}); {ONLY}"))?;
    match parsed.scheme() {
        "https" => Ok(None),
        "http" if is_loopback_host(&parsed) => Ok(Some(
            "jwks_url is plain http to a loopback host; it loads, but the JWKS is only ever \
             fetched over https, so every OIDC token will be rejected until jwks_url is an https \
             URL"
            .to_string(),
        )),
        "http" => Err(format!(
            "settings.jwks_url: is plain http to the host '{}', which is not loopback: signing keys over \
             plain http can be substituted in transit, so it is refused; use https (plain http \
             only to a loopback host)",
            parsed.host_str().unwrap_or("?").escape_debug()
        )),
        other => Err(format!(
            "settings.jwks_url: must be an https URL (got scheme '{}'); {ONLY}",
            other.escape_debug()
        )),
    }
}

/// Whether the parsed URL's host is loopback: an IPv4 literal in 127.0.0.0/8, the IPv6 literal
/// `::1`, or the `localhost` name or a name under it (RFC 6761 reserves both to loopback), a
/// trailing dot and case ignored. It reads the parsed host only, so a userinfo
/// (`http://127.0.0.1@evil.example/`) or a lookalike name (`127.0.0.1.evil.example`) is not loopback,
/// and no DNS lookup is made.
fn is_loopback_host(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(v4)) => v4.is_loopback(),
        Some(url::Host::Ipv6(v6)) => v6.is_loopback(),
        Some(url::Host::Domain(name)) => {
            let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
            name == "localhost" || name.ends_with(".localhost")
        }
        None => false,
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "tests/script.rs"]
mod script;

#[cfg(test)]
#[path = "tests/destination_tests.rs"]
mod destination_tests;
