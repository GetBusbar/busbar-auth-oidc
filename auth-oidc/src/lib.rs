// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **OIDC auth module** for busbar — the first identity-provider auth PLUGIN. Validates an OpenID
//! Connect JWT (ID or access token) a caller presents as its bearer credential and maps it to a
//! [`busbar_api::Principal`]: verify the signature against the provider's JWKS, check `iss`/`aud`/
//! `exp`/`nbf`, and read the configured role claim (`groups` by default, or `roles` for Entra
//! app-roles) into the principal's ROLES. busbar's own `group_map:` / `auth.modules.oidc:` config
//! then resolves those roles to governance grants and admin scope — the module asserts identity
//! only, never policy.
//!
//! This crate is the reusable LOGIC (usable statically). The dynamic `cdylib` that exports the auth C
//! ABI is the sibling `busbar-auth-oidc-plugin` crate.
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
//! - **group claims are GUIDs**, not names — the operator maps those GUIDs in `group_map:`.
//! - **>200 groups overage**: Entra omits the `groups` claim and instead emits `_claim_names` /
//!   `_claim_sources` markers pointing at the Graph API. busbar does NOT call Graph and does NOT
//!   silently degrade: [`OidcVerifier`] REJECTS such a token with a precise error pointing the
//!   operator at **app-roles** (`role_claim: roles`), whose count is bounded.

use busbar_api::{
    AuthModule, AuthOutcome, BeginLogin, CompleteLogin, LoginHop, LoginHttpResponse, LoginModule,
    LoginOutcome, Principal,
};
use serde::Deserialize;
use serde_json::Value;
use std::time::{Duration, Instant};

pub mod cache;
pub mod jwks;
pub mod jwt;
mod reqwest_fetcher;

pub use cache::{JwksCache, JwksFetcher};
pub use reqwest_fetcher::ReqwestFetcher;

/// The default role/group claim name — the token claim read into the principal's ROLES when the
/// operator does not set `role_claim`, and the value the Entra >200-groups overage guard keys on.
const DEFAULT_ROLE_CLAIM: &str = "groups";
/// Default JWKS refetch bound (the kid-rotation rate limit) and TTL.
const DEFAULT_MIN_REFETCH_SECS: u64 = 60;
const DEFAULT_TTL_SECS: u64 = 3600;
/// Small clock-skew tolerance applied to `exp`/`nbf` (seconds) — standard practice so a few seconds of
/// clock drift between busbar and the IdP does not spuriously reject a just-issued / near-expiry token.
const CLOCK_SKEW_SECS: i64 = 60;
/// Ceiling on the credential-cache TTL this module suggests via `Principal::ttl_secs`. Mirrors the
/// engine's own `DEFAULT_IDENTIFY_TTL_SECS` (`auth_cache.rs`) — deliberately NOT the engine's higher
/// `MAX_IDENTIFY_TTL_SECS` (3600s), which exists to bound a module that gives no opinion at all. This
/// value must only ever SHORTEN that engine default, never lengthen it: a token derives its TTL from
/// its own remaining `exp`, but a standard access token's `exp` is often itself ~3600s out, and
/// suggesting that as the cache TTL would take the stale-revocation window from "5 minutes today" to
/// "up to an hour" — trading a small over-cache bug for a much larger one. `min`-ing against this
/// keeps the module's whole reason for existing (bound the over-cache window) while still shortening
/// the TTL for a token that expires sooner than this.
const MAX_CACHE_TTL_SECS: i64 = 300;
/// A host clock reading before this instant means the clock cannot be trusted at all — used to make
/// `now_unix()` fail CLOSED not just on a sub-epoch clock (`SystemTime::now()` returning `Err`), but
/// on the far more realistic broken-clock states: a dead RTC booting a host at the epoch, or an
/// NTP/RTC fault landing the clock in 1970-2000. Both of those return `Ok(small_value)`, never hit the
/// `unwrap_or` fallback, and would otherwise still make `exp` checks pass for virtually any real
/// token — the exact fail-open failure mode this whole guard exists to close. Updated occasionally is
/// fine; it only needs to stay behind "now".
const CLOCK_SANITY_FLOOR_UNIX: i64 = 1_767_225_600; // 2026-01-01T00:00:00Z

/// The operator's `auth.modules.oidc.config` settings, deserialized from the JSON the engine passes to
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
    /// document (`<issuer>/.well-known/openid-configuration` → `jwks_uri`) at construction.
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
    /// the fetcher trusts only the built-in public roots, as before. Certificate validation is never
    /// disabled by this — it only widens the trusted-root set.
    #[serde(default)]
    pub ca_cert_pem: Option<String>,

    // ── browser-login (auth ABI v2) fields — all ADDITIVE and `#[serde(default)]`, so a verify-only
    // config that predates login still parses unchanged; a login-capable IdP sets what it needs. ──
    /// The OAuth `client_id` presented on the authorize URL and the token exchange. Optional: when
    /// absent it defaults to [`OidcConfig::audience`] (the common confidential-client case where the
    /// app's client-id IS the token audience, e.g. Entra). The confidential-client SECRET is never
    /// here — the CORE holds it and injects it into the token-exchange hop.
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
}

/// The result of validating a token's CLAIMS (post-signature): the resolved principal, or a denial
/// reason. Kept separate from the signature step so tests can exercise claim policy directly.
impl OidcVerifier {
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        role_claim: impl Into<String>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            role_claim: role_claim.into(),
        }
    }

    /// Validate a decoded claims object (signature ALREADY verified) and build the [`Principal`].
    /// Checks `iss`/`aud`/`exp`/`nbf` (with a small skew tolerance), detects the Entra >200-groups
    /// overage marker (REJECT, never call Graph), and reads `role_claim` into the principal's groups.
    /// `now_unix` is the current UNIX time in seconds.
    pub fn validate_claims(&self, claims: &Value, now_unix: i64) -> Result<Principal, String> {
        // iss — exact match. A wrong issuer is a different tenant / a token minted elsewhere.
        match claims.get("iss").and_then(Value::as_str) {
            Some(iss) if iss == self.issuer => {}
            Some(other) => {
                return Err(format!(
                    "token issuer '{other}' does not match the configured issuer"
                ))
            }
            None => return Err("token has no 'iss' claim".to_string()),
        }

        // aud — `aud` may be a single string or an array of strings (RFC 7519). The configured
        // audience MUST be present. For the MULTI-VALUED array form, OIDC Core 1.0 §3.1.3.7 is
        // stricter than "any match": a token that also lists audiences the client does not trust MUST
        // be rejected UNLESS an `azp` (authorized party) claim is present and equals the trusted
        // client — the `.any(trusted)` shortcut would otherwise wave through a token minted for the
        // trusted client AND some attacker-controlled app. A single-string `aud`, or an array whose
        // only value is the trusted audience, needs no `azp`.
        let trusted = self.audience.as_str();
        let aud_ok = match claims.get("aud") {
            Some(Value::String(s)) => s == trusted,
            Some(Value::Array(a)) => {
                let trusted_present = a.iter().any(|v| v.as_str() == Some(trusted));
                let has_untrusted_extra = a.iter().any(|v| v.as_str() != Some(trusted));
                if !trusted_present {
                    false
                } else if has_untrusted_extra {
                    // Multiple audiences, at least one untrusted: require azp == the trusted client.
                    claims.get("azp").and_then(Value::as_str) == Some(trusted)
                } else {
                    true
                }
            }
            _ => false,
        };
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
        // overflow band (i64::MAX - CLOCK_SKEW_SECS) is already accepted today, including
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
        if let Some(nbf) = as_numeric_date_ceil(claims.get("nbf")) {
            if nbf.saturating_sub(CLOCK_SKEW_SECS) > now_unix {
                return Err("token is not yet valid (nbf in the future)".to_string());
            }
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

        // Roles/groups claim → principal ROLES (1.5.0: the field was renamed groups->roles). A missing/empty claim is NOT an error here (an unmapped
        // principal is denied downstream by group_map when default:deny); it just yields no groups.
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
        // token, WIDEN the engine's cache window instead of shortening it (its own default is 300s) —
        // trading a small over-cache bug for a much larger one. This can only ever shorten the cache
        // lifetime relative to today's fixed 300s, never lengthen it.
        principal.ttl_secs = Some(exp.saturating_sub(now_unix).clamp(0, MAX_CACHE_TTL_SECS) as u64);
        Ok(principal)
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

/// The runtime OIDC auth module: a verifier + a JWKS cache. Implements [`busbar_api::AuthModule`].
pub struct OidcModule {
    verifier: OidcVerifier,
    jwks: JwksCache,
    /// The resolved config, retained so the browser-login path ([`LoginModule`]) can read the
    /// client-id, scopes, and the authorize/token endpoints. The verify-only path uses none of it.
    cfg: OidcConfig,
}

impl OidcModule {
    /// Construct from parsed config + an already-resolved JWKS url + a fetcher. The plugin's `open`
    /// resolves the JWKS url (explicit or via discovery) and supplies a real HTTPS fetcher; tests
    /// supply a fixture fetcher.
    pub fn new(cfg: &OidcConfig, jwks_url: String, fetcher: Box<dyn JwksFetcher>) -> Self {
        let jwks = JwksCache::new(
            jwks_url,
            fetcher,
            Duration::from_secs(cfg.jwks_min_refetch_secs),
            Duration::from_secs(cfg.jwks_ttl_secs),
        );
        Self {
            verifier: OidcVerifier::new(&cfg.issuer, &cfg.audience, &cfg.role_claim),
            jwks,
            cfg: cfg.clone(),
        }
    }

    /// Verify a login token-endpoint response into an identity. Parses the token endpoint's JSON,
    /// extracts the `id_token`, and REUSES the full verify path ([`Self::verify`] — JWKS signature +
    /// [`OidcVerifier::validate_claims`] for iss/aud/exp/nbf) to produce a [`Principal`]. A missing/
    /// malformed body, a missing `id_token`, or any signature/claim failure is a fail-closed
    /// `Reject`. `now_unix`/`now_mono` are injected so this is unit-testable with a fixture JWKS, the
    /// same as [`Self::verify`].
    ///
    /// NOTE (committed ABI): OIDC `nonce` is minted by the CORE at begin and is NOT carried back on
    /// [`CompleteLogin`], so nonce binding is the core's to enforce; this reuses the existing
    /// signature+claims path (iss/aud/exp) that the verify module already trusts.
    pub fn identity_from_token_response(
        &self,
        resp: &LoginHttpResponse,
        now_unix: i64,
        now_mono: Instant,
    ) -> LoginOutcome {
        // A non-2xx token-endpoint response (e.g. invalid_grant) never carries a usable id_token.
        if !(200..300).contains(&resp.status) {
            return LoginOutcome::Reject;
        }
        let body: Value = match serde_json::from_str(&resp.body) {
            Ok(v) => v,
            Err(_) => return LoginOutcome::Reject,
        };
        let id_token = match body.get("id_token").and_then(Value::as_str) {
            Some(t) => t,
            None => return LoginOutcome::Reject,
        };
        match self.verify(id_token, now_unix, now_mono) {
            AuthOutcome::Identify(p) => LoginOutcome::Identify(p),
            // A non-JWT / bad-sig / bad-claim id_token in a login callback is a hard failure — unlike
            // the verify chain, there is no "next module" to defer a `Pass` to. Enumerated (not `_`)
            // so a future `AuthOutcome` variant is a compile error here, forcing a deliberate mapping.
            AuthOutcome::Reject | AuthOutcome::Pass => LoginOutcome::Reject,
        }
    }

    /// The full verification of one presented bearer token → an [`AuthOutcome`]. Split from
    /// `authenticate` so it can be driven with an injected `now` in tests.
    fn verify(&self, token: &str, now_unix: i64, now_mono: Instant) -> AuthOutcome {
        let parts = match jwt::split(token) {
            Ok(p) => p,
            // Not a well-formed JWT ⇒ not our credential shape. `Pass` so a later chain module (or
            // the mode default) can handle it — a random opaque bearer is not an OIDC failure.
            Err(_) => return AuthOutcome::Pass,
        };
        let kid = parts.header.kid.clone().unwrap_or_default();

        // Verify the signature against the JWKS key for this kid (fetching / rotation-refetching as
        // needed). A signature or key error is a REJECT — a presented-but-invalid credential.
        if let Err(e) = self
            .jwks
            .with_key(&kid, now_mono, |key| jwt::verify_signature(&parts, key))
        {
            tracing::warn!(module = "oidc", error = %e, "OIDC token signature verification failed");
            return AuthOutcome::Reject;
        }

        let claims = match jwt::claims(&parts) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(module = "oidc", error = %e, "OIDC token claims are malformed");
                return AuthOutcome::Reject;
            }
        };

        match self.verifier.validate_claims(&claims, now_unix) {
            Ok(principal) => AuthOutcome::Identify(principal),
            Err(e) => {
                tracing::warn!(module = "oidc", error = %e, "OIDC token claim validation failed");
                AuthOutcome::Reject
            }
        }
    }
}

impl AuthModule for OidcModule {
    fn name(&self) -> &'static str {
        "oidc"
    }

    fn authenticate(&self, candidate: Option<&str>) -> AuthOutcome {
        let Some(token) = candidate else {
            // No credential presented ⇒ not ours; defer.
            return AuthOutcome::Pass;
        };
        self.verify(token, now_unix(), Instant::now())
    }

    /// OIDC does real I/O (JWKS fetch) and its verdicts are safe to cache for the token's short life,
    /// so the engine's credential cache is worth using.
    fn cacheable(&self) -> bool {
        true
    }
}

impl LoginModule for OidcModule {
    /// Start browser login: the CORE has already minted PKCE `state`/`code_challenge` and the
    /// `nonce`; return the IdP authorize URL to redirect to. Fails closed (`Reject`) when no
    /// `authorization_endpoint` is configured or was discovered — this module is verify-only then.
    fn begin_login(&self, req: &BeginLogin) -> LoginOutcome {
        if self.cfg.authorization_endpoint.is_none() {
            return LoginOutcome::Reject;
        }
        // Fold the operator's request-time extra scopes into the configured set; `build_authorize_url`
        // dedups against the always-added `openid`.
        let mut cfg = self.cfg.clone();
        cfg.scopes.extend(req.scopes.iter().cloned());
        let url = build_authorize_url(
            &cfg,
            &req.redirect_uri,
            &req.state,
            &req.code_challenge,
            req.nonce.as_deref(),
        );
        LoginOutcome::Authorize(url)
    }

    /// Handle the callback. With a token response fed back in, verify it → `Identify`. Otherwise
    /// describe the token-exchange hop for the CORE to run (the core injects `client_secret`). A
    /// callback lacking both a token response and a usable `code`+`redirect_uri`+`code_verifier`
    /// triple, or with no `token_endpoint`, fails closed.
    fn complete_login(&self, req: &CompleteLogin) -> LoginOutcome {
        if let Some(resp) = &req.token_response {
            return self.identity_from_token_response(resp, now_unix(), Instant::now());
        }
        let (Some(code), Some(redirect_uri), Some(code_verifier)) = (
            req.code.as_deref(),
            req.redirect_uri.as_deref(),
            req.code_verifier.as_deref(),
        ) else {
            return LoginOutcome::Reject;
        };
        if self.cfg.token_endpoint.is_none() {
            return LoginOutcome::Reject;
        }
        LoginOutcome::Exchange(build_token_exchange(
            &self.cfg,
            code,
            redirect_uri,
            code_verifier,
        ))
    }
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
/// everything else `%`-escaped). Used only for the authorize URL; the token-exchange form is encoded
/// by the CORE, so its values stay raw.
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
    let mut url = format!(
        "{endpoint}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
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

/// Build the token-exchange hop the CORE executes: `POST` to the token endpoint with
/// `grant_type=authorization_code`, `code`, `redirect_uri`, `code_verifier`, and `client_id`. The
/// `client_secret` is written as an EMPTY placeholder keyed by `secret_form_field`, so the module
/// writes the KEY and the CORE injects the VALUE — the plugin never holds the secret.
pub fn build_token_exchange(
    cfg: &OidcConfig,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> LoginHop {
    LoginHop {
        method: "POST".to_string(),
        url: cfg.token_endpoint.clone().unwrap_or_default(),
        form: vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("redirect_uri".to_string(), redirect_uri.to_string()),
            ("code_verifier".to_string(), code_verifier.to_string()),
            ("client_id".to_string(), resolved_client_id(cfg)),
            // Placeholder ONLY — the CORE overwrites this value with the real confidential-client
            // secret. The plugin writes the key, never the value.
            ("client_secret".to_string(), String::new()),
        ],
        secret_form_field: Some("client_secret".to_string()),
        // This module has no extra hop headers to add (e.g. no userinfo Authorization header on the
        // token-exchange hop); the core's own headers (Content-Type, etc.) are added on its side.
        headers: Vec::new(),
    }
}

/// Current UNIX time in seconds. Fails CLOSED on a clock this module cannot trust: `validate_claims`'s
/// `exp` check is `exp + skew >= now_unix`, so a `now_unix` that reads too LOW makes every token
/// appear unexpired (fail OPEN) — the exact failure this guards against. Two cases, both mapped to
/// `i64::MAX` (which fails `exp`/`nbf` checks for any realistic token):
///   - `SystemTime::now()` returns `Err` (host clock strictly before the UNIX epoch) — rare.
///   - The clock IS readable but below [`CLOCK_SANITY_FLOOR_UNIX`] — the realistic broken-clock case
///     (a dead RTC booting a host at the epoch, or an NTP/RTC fault landing in 1970-2000), which
///     `duration_since` reports as `Ok(small_value)` and would otherwise sail straight through.
fn now_unix() -> i64 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(i64::MAX);
    if is_clock_sane(t) {
        t
    } else {
        i64::MAX
    }
}

/// Whether a UNIX timestamp reading is within the range this module considers a trustworthy clock
/// (see [`CLOCK_SANITY_FLOOR_UNIX`]). Pulled out of [`now_unix`] as a pure, parameterized function
/// purely for testability: `now_unix` itself reads the real host clock and cannot be driven with an
/// injected boundary value from a test.
fn is_clock_sane(t: i64) -> bool {
    t >= CLOCK_SANITY_FLOOR_UNIX
}

/// Resolve the JWKS url from config: the explicit `jwks_url`, or discovered from the issuer's OIDC
/// discovery document. `fetcher` performs the discovery GET when needed.
pub fn resolve_jwks_url(cfg: &OidcConfig, fetcher: &dyn JwksFetcher) -> Result<String, String> {
    if let Some(url) = &cfg.jwks_url {
        return Ok(url.clone());
    }
    let doc = fetch_discovery_doc(cfg, fetcher)?;
    doc.get("jwks_uri")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            "OIDC discovery document has no 'jwks_uri'; set jwks_url explicitly".to_string()
        })
}

/// Resolve the browser-login endpoints `(authorization_endpoint, token_endpoint)` from config: the
/// explicit config fields win; whatever is absent is discovered from the issuer's
/// openid-configuration (SAME issuer-match–guarded document `resolve_jwks_url` uses). When BOTH are
/// already set explicitly, no fetch happens at all. An endpoint the document also omits stays `None`
/// (that half of browser login is then unavailable and its `LoginModule` method fails closed).
pub fn resolve_login_endpoints(
    cfg: &OidcConfig,
    fetcher: &dyn JwksFetcher,
) -> Result<(Option<String>, Option<String>), String> {
    if cfg.authorization_endpoint.is_some() && cfg.token_endpoint.is_some() {
        return Ok((
            cfg.authorization_endpoint.clone(),
            cfg.token_endpoint.clone(),
        ));
    }
    let doc = fetch_discovery_doc(cfg, fetcher)?;
    let field = |name: &str| doc.get(name).and_then(Value::as_str).map(str::to_string);
    let authorization_endpoint = cfg
        .authorization_endpoint
        .clone()
        .or_else(|| field("authorization_endpoint"));
    let token_endpoint = cfg
        .token_endpoint
        .clone()
        .or_else(|| field("token_endpoint"));
    Ok((authorization_endpoint, token_endpoint))
}

/// Fetch and validate the issuer's OIDC discovery document (`<issuer>/.well-known/openid-configuration`).
///
/// RFC 8414 §3.3 / OIDC Discovery 1.0 §4.3: the document's own `issuer` MUST equal the issuer it was
/// requested from. Without this check, one poisoned discovery response at `open()` repoints
/// `jwks_uri` (and the login endpoints) — and therefore every future signature verification — at an
/// attacker-controlled key set for the process lifetime. Callers that already have their URLs
/// explicitly configured bypass discovery entirely and are unaffected.
fn fetch_discovery_doc(cfg: &OidcConfig, fetcher: &dyn JwksFetcher) -> Result<Value, String> {
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        cfg.issuer.trim_end_matches('/')
    );
    let body = fetcher.fetch(&discovery_url).map_err(|e| {
        format!("OIDC discovery fetch failed ({discovery_url}): {e}; set jwks_url explicitly")
    })?;
    let doc: Value = serde_json::from_str(&body)
        .map_err(|e| format!("OIDC discovery document is not JSON: {e}"))?;
    match doc.get("issuer").and_then(Value::as_str) {
        Some(doc_issuer) if doc_issuer == cfg.issuer => {}
        Some(other) => {
            return Err(format!(
                "OIDC discovery document's issuer '{other}' does not match the configured issuer \
                 '{}' ({discovery_url}); refusing to trust its jwks_uri",
                cfg.issuer
            ))
        }
        None => {
            return Err(format!(
                "OIDC discovery document has no 'issuer' ({discovery_url}); refusing to trust its \
                 jwks_uri"
            ))
        }
    }
    Ok(doc)
}

#[cfg(test)]
mod tests;
