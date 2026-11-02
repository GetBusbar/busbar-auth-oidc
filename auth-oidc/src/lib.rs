// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **OIDC auth module** for busbar — the first identity-provider auth PLUGIN. Validates an OpenID

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

const DEFAULT_ROLE_CLAIM: &str = "groups";
/// Default JWKS refetch bound (the kid-rotation rate limit) and JWKS TTL (not the verdict

const DEFAULT_MIN_REFETCH_SECS: u64 = 60;
const DEFAULT_JWKS_TTL_SECS: u64 = 3600;
/// Small clock-skew tolerance applied to `exp`/`nbf` (seconds) — standard practice so a few seconds of

const CLOCK_SKEW_SECS: i64 = 60;
/// Ceiling on the credential-cache TTL this module suggests via `Principal::ttl_secs`, the TTL its

const MAX_CACHE_TTL_SECS: i64 = 300;
/// A host clock reading before this instant means the clock cannot be trusted at all — used to make

const CLOCK_SANITY_FLOOR_UNIX: i64 = 1_767_225_600;

/// Why no token can be judged while the host clock reads `i64::MAX` ([`clock_or_fail_closed`]).
const CLOCK_UNREADABLE: &str =
    "the host clock is unreadable or reads before 2026-01-01 (the clock \
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
    /// Which token claim carries the caller's roles/groups → the principal's ROLES. Default
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
    DEFAULT_JWKS_TTL_SECS
}

/// The pure token VERIFIER: config-derived policy (issuer/audience/role_claim) plus the current time

pub struct OidcVerifier {
    issuer: String,
    audience: String,
    role_claim: String,
    /// Whether this verifier judges a browser-login `id_token` (OIDC Core 1.0 §3.1.3.7's
    id_token: bool,
}

/// The result of validating a token's CLAIMS (post-signature): the resolved principal, or a denial

impl OidcVerifier {
    /// The BEARER verifier: `issuer` exactly, an `aud` containing `audience` (RFC 7519 §4.1.3,

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

    pub fn validate_claims(&self, claims: &Value, now_unix: i64) -> Result<Principal, String> {
        if now_unix == i64::MAX {
            return Err(CLOCK_UNREADABLE.to_string());
        }

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

        let trusted = self.audience.as_str();
        let azp = claims.get("azp").and_then(Value::as_str);
        let aud_ok = match claims.get("aud") {
            Some(Value::String(s)) => s == trusted,
            Some(Value::Array(a)) => {
                let strings_only = a.iter().all(Value::is_string);
                let trusted_present = a.iter().any(|v| v.as_str() == Some(trusted));
                let has_untrusted_extra = a.iter().any(|v| v.as_str() != Some(trusted));
                strings_only
                    && trusted_present
                    && !(self.id_token && has_untrusted_extra && azp != Some(trusted))
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

        let exp = match as_numeric_date_floor(claims.get("exp")) {
            Some(exp) if exp.saturating_add(CLOCK_SKEW_SECS) >= now_unix => exp,
            Some(_) => return Err("token has expired".to_string()),
            None if claims.get("exp").is_none() => {
                return Err("token has no 'exp' claim".to_string())
            }
            None => return Err("token has an 'exp' claim that is not a NumericDate".to_string()),
        };

        match claims.get("nbf") {
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

        let groups = extract_string_list(claims.get(&self.role_claim));

        let subject = non_empty_claim(claims.get("oid"))
            .or_else(|| non_empty_claim(claims.get("sub")))
            .ok_or(
                "token has no non-empty 'oid' or 'sub' claim (both are absent or blank, so no \
                 IMMUTABLE identifier is available); refusing to derive identity from a mutable claim \
                 like preferred_username/upn/email or from an empty subject — this IdP is not OIDC \
                 Core 1.0 compliant (sub is a REQUIRED, non-empty claim)",
            )?;

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

        principal.ttl_secs = Some(exp.saturating_sub(now_unix).clamp(0, MAX_CACHE_TTL_SECS) as u64);
        Ok(principal)
    }
}

/// The longest far-end or attacker string an error or log line repeats, in characters.
const UNTRUSTED_MAX: usize = 64;

/// A FAR-END string (a JWKS key's `kty`/`crv`, a discovery document's `issuer`) or an ATTACKER one

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

fn non_empty_claim(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str).filter(|s| !s.trim().is_empty())
}

/// Read an `exp` claim as a JWT NumericDate (RFC 7519 §2), FLOORING any fractional part. `as_i64`

fn as_numeric_date_floor(v: Option<&Value>) -> Option<i64> {
    as_numeric_date(v, f64::floor)
}

/// Read an `nbf` claim as a JWT NumericDate (RFC 7519 §2), CEILING any fractional part. Same

fn as_numeric_date_ceil(v: Option<&Value>) -> Option<i64> {
    as_numeric_date(v, f64::ceil)
}

/// Shared NumericDate reader: integer fast path, else `as_f64` rounded via `round` (floor for `exp`,

fn as_numeric_date(v: Option<&Value>, round: impl Fn(f64) -> f64) -> Option<i64> {
    let v = v?;
    v.as_i64().or_else(|| v.as_f64().map(|f| round(f) as i64))
}

/// Read a claim as a list of strings. Accepts a JSON array of strings OR a single string (one

fn extract_string_list(v: Option<&Value>) -> Vec<String> {
    if v.is_some_and(|value| match value {
        Value::String(_) => false,
        Value::Array(values) => values.iter().any(|value| !value.is_string()),
        _ => true,
    }) {
        tracing::warn!(
            module = "oidc",
            "OIDC role claim contains unreadable values; only string roles are used"
        );
    }
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

pub struct OidcModule {
    verifier: OidcVerifier,
    /// The verifier for the browser-login `id_token`: the same issuer and role claim, but the
    login_verifier: OidcVerifier,
    jwks: JwksCache,
    discovery: Discovery,
    /// The identities this module verified for bearer credentials, held for their TTL
    verdicts: verdicts::VerdictCache,
    /// The config, retained so the browser-login path can read the client-id, scopes, and the
    cfg: OidcConfig,
    /// The destination refusals already raised as the door's declared diagnostic
    reported: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl OidcModule {
    /// Construct from parsed (and [`check_jwks_url`]-checked) config. Nothing is fetched here: the

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

    pub fn first_report(&self, why: &str) -> bool {
        self.reported
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(why.to_string())
    }

    /// Have the issuer's discovery document asked for again at its next use (`refresh`), the one

    pub fn rediscover(&self) {
        self.discovery.expire();
    }

    /// Drop every cached verdict (`refresh`, the admin cache flush): how many there were.
    pub fn flush_verdicts(&self) -> usize {
        self.verdicts.flush()
    }

    /// How often `tick` asks to run: the JWKS refetch bound (`jwks_min_refetch_secs`, 60 s by

    pub fn tick_period(&self) -> Duration {
        Duration::from_secs(self.cfg.jwks_min_refetch_secs.max(1))
    }

    /// The tick refreshes ahead of the TTL: the key set is fetched again once it is within one

    pub fn refresh_ahead(&self, now: Instant, io: &mut dyn Fetch) -> Step<Result<(), String>> {
        let url = match self.jwks_url(now, io) {
            Step::Ready(Err(error)) => {
                tracing::warn!(module = "oidc", error = %error, "OIDC refresh cannot resolve its key endpoint");
                return Step::Ready(Err(error));
            }
            Step::Ready(Ok(url)) => url,
            Step::Pending => return Step::Pending,
            Step::Wait => return Step::Wait,
        };
        self.jwks.refresh_ahead(&url, self.tick_period(), now, io)
    }

    /// Whether the settings name an operator CA (`ca_cert_pem`, non-empty): the module's requests

    pub fn anchored(&self) -> bool {
        self.cfg
            .ca_cert_pem
            .as_deref()
            .is_some_and(|p| !p.is_empty())
    }

    /// The JWKS url: the configured `jwks_url`, or the discovery document's `jwks_uri`.

    pub fn jwks_url(&self, now: Instant, io: &mut dyn Fetch) -> Step<Result<Cow<'_, str>, String>> {
        let url = step_ok!(self.endpoint(self.cfg.jwks_url.as_ref(), "jwks_uri", now, io));
        Step::Ready(url.ok_or_else(|| {
            "OIDC discovery document has no 'jwks_uri'; set jwks_url explicitly".to_string()
        }))
    }

    /// The host's `ready` (after `open`, before any listener binds; boot awaits it): boot-time

    pub fn ready(&self, now: Instant, io: &mut dyn Fetch) -> Step<Result<(), String>> {
        let url = step_ok!(self.jwks_url(now, io));

        match self.jwks.warm(&url, now, io) {
            Step::Pending => Step::Pending,
            Step::Ready(_) | Step::Wait => Step::Ready(Ok(())),
        }
    }

    /// The login endpoint `configured`, else the discovery document's `field` (the SAME

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
        let Some(value) = doc.get(field) else {
            return Step::Ready(Ok(None));
        };
        let Some(url) = value.as_str() else {
            return Step::Ready(Err(format!(
                "OIDC discovery document's {field} must be a URL string"
            )));
        };

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

    pub fn identity_from_token_response(
        &self,
        resp: &LoginHttpResponse,
        now_unix: i64,
        now_mono: Instant,
        io: &mut dyn Fetch,
    ) -> Step<Result<LoginOutcome, String>> {
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
                tracing::warn!(module = "oidc", error = %e, "OIDC token endpoint response is not JSON; login unavailable");
                return Step::Ready(Err(e));
            }
        };
        let Some(id_token) = body.id_token.as_deref().map(String::as_str) else {
            tracing::warn!(
                module = "oidc",
                "OIDC token endpoint response carries no id_token; login unavailable"
            );
            return Step::Ready(Err(
                "OIDC token endpoint response carries no id_token".to_string()
            ));
        };

        let verdict =
            step_ok!(self.verify_with(&self.login_verifier, id_token, now_unix, now_mono, io));
        Step::Ready(Ok(match verdict {
            AuthVerdict::Identify(p) => LoginOutcome::Identify(p),

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

    pub fn cached(&self, token: &str, now_unix: i64) -> Option<verdicts::Hit> {
        self.verdicts.get(token, now_unix)
    }

    /// [`Self::verify`] past its cache: the credential judged, an identity cached.

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

    fn verify_with(
        &self,
        verifier: &OidcVerifier,
        token: &str,
        now_unix: i64,
        now_mono: Instant,
        io: &mut dyn Fetch,
    ) -> Step<Result<AuthVerdict, String>> {
        let Some(payload) = jwt::payload(token) else {
            tracing::debug!(
                module = "oidc",
                "bearer is not a JWT: not this provider's credential; passed to the next auth"
            );
            return Step::Ready(Ok(AuthVerdict::Pass));
        };

        if let Some(other) = foreign_issuer(&payload, &verifier.issuer) {
            tracing::debug!(
                module = "oidc",
                token_issuer = %other,
                "OIDC token names an issuer that is not this provider's issuer: not this \
                 provider's credential; passed to the next auth"
            );
            return Step::Ready(Ok(AuthVerdict::Pass));
        }

        if now_unix == i64::MAX {
            tracing::warn!(
                module = "oidc",
                "the host clock is unreadable; the token cannot be judged"
            );
            return Step::Ready(Err(CLOCK_UNREADABLE.to_string()));
        }

        let parts = match jwt::split(token) {
            Ok(p) => p,
            Err(e) => {
                tracing::info!(module = "oidc", reason = "malformed", error = %e, "OIDC token naming this provider's issuer is malformed; rejected");
                return Step::Ready(Ok(AuthVerdict::Reject));
            }
        };
        let kid = parts.header.kid.as_deref().unwrap_or_default();

        let url = match step!(self.jwks_url(now_mono, io)) {
            Ok(url) => url,
            Err(e) => {
                tracing::warn!(module = "oidc", error = %e, "OIDC key set is unavailable; the token cannot be judged");
                return Step::Ready(Err(e));
            }
        };

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
            tracing::warn!(
                module = "oidc",
                "no authorization_endpoint is configured and the discovery document names none; \
                 browser login refused"
            );
            return Step::Ready(Ok(LoginOutcome::Reject));
        };

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

            tracing::info!(module = "oidc", absent = %absent.join(", "), "OIDC callback lacks fields the token exchange needs; login declined");
            return Step::Ready(Ok(None));
        };
        let Some(url) = step_ok!(self.token_endpoint(now, io)) else {
            tracing::warn!(module = "oidc", "no token_endpoint is configured and the discovery document names none; login unavailable");
            return Step::Ready(Err(
                "no token_endpoint is configured and the discovery document names none".to_string(),
            ));
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
        serde_json::from_str(body).map_err(busbar_contract::abi::sdk::auth_kit::json_error(
            "token response",
        ))
    }
}

/// A token member deserialized straight into a wiped holder.
fn wiped<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<zeroize::Zeroizing<String>>, D::Error> {
    Ok(Option::<String>::deserialize(d)?.map(zeroize::Zeroizing::new))
}

/// The nonce binding: `true` when the token endpoint's `body`

pub(crate) fn nonce_binds(body: &str, nonce: &str) -> bool {
    if nonce.is_empty() {
        return false;
    }
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

/// TESTS' current UNIX time in seconds (production reads the request's timestamp and the host's
/// `clock.now`, through [`clock_or_fail_closed`]). Fails CLOSED on a clock it cannot trust: `validate_claims`'s
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

pub(crate) fn clock_or_fail_closed(t: i64) -> i64 {
    if t >= CLOCK_SANITY_FLOOR_UNIX {
        t
    } else {
        i64::MAX
    }
}

/// The setting an operator configures to name a discovered endpoint's URL themselves: the discovery

fn discovered_setting(field: &str) -> Option<&'static str> {
    match field {
        "jwks_uri" => Some("jwks_url"),
        "token_endpoint" => Some("token_endpoint"),
        "authorization_endpoint" => Some("authorization_endpoint"),
        _ => None,
    }
}

/// A DISCOVERED ENDPOINT'S SCHEME (OIDC Discovery 1.0 §3, RFC 9700 §4): a `field` URL the issuer's

pub fn discovered_secure(field: &str, setting: &str, url: &str) -> Result<(), String> {
    let Ok(parsed) = url::Url::parse(url) else {
        return Err(fetch::refusal(
            "?",
            &format!("cannot be read: the discovery document's {field} is not a URL"),
        ));
    };
    if url.chars().any(char::is_control)
        || (field == "authorization_endpoint" && parsed.fragment().is_some())
    {
        return Err(fetch::refusal(
            parsed.host_str().unwrap_or("?"),
            &format!("names an invalid {field}: control characters and authorization fragments are not allowed"),
        ));
    }
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
             fetched over https, so OIDC verification is unavailable until jwks_url is an https \
             URL"
            .to_string(),
        )),
        "http" => Err(
            "settings.jwks_url: is plain http to a host that is not loopback: signing keys over \
             plain http can be substituted in transit, so it is refused; use https (plain http \
             only to a loopback host)"
                .to_string(),
        ),
        _ => Err(format!("settings.jwks_url: must be an https URL; {ONLY}")),
    }
}

/// Whether the parsed URL's host is loopback: an IPv4 literal in 127.0.0.0/8, the IPv6 literal

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
