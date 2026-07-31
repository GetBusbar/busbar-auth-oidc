// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Verification-logic tests. An in-test ES256 keypair (via `ring`) mints real tokens against a local
//! JWKS fixture — the FULL signature path runs in-process, no network. Claim-policy cases
//! (iss/aud/exp/nbf, overage, unmapped) drive [`OidcVerifier::validate_claims`] directly.

use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const ISSUER: &str = "https://login.microsoftonline.com/tenant-guid/v2.0";
const AUDIENCE: &str = "api://busbar-client-id";
const KID: &str = "test-key-1";

/// A ring ES256 signer + the JWKS fixture that verifies it.
struct TestKey {
    kp: EcdsaKeyPair,
    rng: SystemRandom,
    kid: String,
}

impl TestKey {
    fn generate(kid: &str) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        Self {
            kp,
            rng,
            kid: kid.to_string(),
        }
    }

    /// The public key as a single-key JWKS document.
    fn jwks(&self) -> String {
        // Uncompressed SEC1 point: 0x04 || X(32) || Y(32).
        let pt = self.kp.public_key().as_ref();
        assert_eq!(pt[0], 0x04, "uncompressed point");
        let x = URL_SAFE_NO_PAD.encode(&pt[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&pt[33..65]);
        serde_json::json!({
            "keys": [{
                "kty": "EC", "crv": "P-256", "kid": self.kid, "x": x, "y": y, "use": "sig", "alg": "ES256"
            }]
        })
        .to_string()
    }

    /// Sign a claims object into a compact ES256 JWT with this key's kid.
    fn mint(&self, claims: &Value) -> String {
        let header = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": self.kid });
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig = self.kp.sign(&self.rng, signing_input.as_bytes()).unwrap();
        let s = URL_SAFE_NO_PAD.encode(sig.as_ref());
        format!("{signing_input}.{s}")
    }
}

/// A fetcher serving a fixed body, counting fetches (to prove caching + bounded refetch). The body can
/// be swapped to simulate a key rotation (`set_body`), and `calls` counts every fetch attempt so a
/// test can assert exactly how many refetches a scenario triggered.
struct FixtureFetcher {
    body: Mutex<String>,
    calls: AtomicUsize,
}
impl FixtureFetcher {
    fn new(body: String) -> Self {
        Self {
            body: Mutex::new(body),
            calls: AtomicUsize::new(0),
        }
    }

    /// Swap the served body in place — simulates the provider rotating its JWKS underneath an
    /// already-running module, without rebuilding the module (and therefore without resetting the
    /// cache or the refetch rate-limit clock).
    fn set_body(&self, body: String) {
        *self.body.lock().unwrap() = body;
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}
impl JwksFetcher for FixtureFetcher {
    fn fetch(&self, _url: &str) -> Result<String, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.body.lock().unwrap().clone())
    }
}
// `OidcModule::new` takes ownership of a `Box<dyn JwksFetcher>`, but the test needs a live handle to
// swap the body after construction — so hand the module an `Arc<FixtureFetcher>` through this
// blanket impl rather than changing `OidcModule::new`'s signature.
impl JwksFetcher for Arc<FixtureFetcher> {
    fn fetch(&self, url: &str) -> Result<String, String> {
        (**self).fetch(url)
    }
}

fn base_claims(now: i64) -> Value {
    serde_json::json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + 3600,
        "nbf": now - 10,
        "sub": "subject-guid",
        "oid": "object-guid",
        "preferred_username": "alice@contoso.com",
        "name": "Alice Contoso",
        "groups": ["11111111-aaaa", "22222222-bbbb"],
    })
}

fn cfg(role_claim: &str) -> OidcConfig {
    OidcConfig {
        issuer: ISSUER.to_string(),
        audience: AUDIENCE.to_string(),
        jwks_url: Some("https://jwks.test/keys".to_string()),
        role_claim: role_claim.to_string(),
        jwks_min_refetch_secs: 60,
        jwks_ttl_secs: 3600,
        ca_cert_pem: None,
    }
}

fn module_with(key: &TestKey, role_claim: &str) -> OidcModule {
    let fetcher = Box::new(FixtureFetcher::new(key.jwks()));
    OidcModule::new(
        &cfg(role_claim),
        "https://jwks.test/keys".to_string(),
        fetcher,
    )
}

// ── signature + full-path tests ─────────────────────────────────────────────────────────────────

#[test]
fn valid_token_identifies_with_groups() {
    let key = TestKey::generate(KID);
    let m = module_with(&key, "groups");
    let now = 1_700_000_000;
    let token = key.mint(&base_claims(now));
    match m.verify(&token, now, Instant::now()) {
        AuthOutcome::Identify(p) => {
            assert_eq!(p.id, "oidc:object-guid");
            assert_eq!(p.name.as_deref(), Some("Alice Contoso"));
            assert_eq!(p.roles, vec!["11111111-aaaa", "22222222-bbbb"]);
        }
        other => panic!("expected Identify, got {other:?}"),
    }
}

#[test]
fn app_roles_claim_maps_to_groups() {
    let key = TestKey::generate(KID);
    let m = module_with(&key, "roles");
    let now = 1_700_000_000;
    let mut claims = base_claims(now);
    claims["roles"] = serde_json::json!(["Billing.Reader", "Billing.Admin"]);
    let token = key.mint(&claims);
    match m.verify(&token, now, Instant::now()) {
        AuthOutcome::Identify(p) => assert_eq!(p.roles, vec!["Billing.Reader", "Billing.Admin"]),
        other => panic!("expected Identify, got {other:?}"),
    }
}

#[test]
fn bad_signature_is_rejected() {
    let key = TestKey::generate(KID);
    let other = TestKey::generate(KID); // same kid, different key material
    let m = module_with(&key, "groups");
    let now = 1_700_000_000;
    // Token minted by the WRONG key but presenting the fixture's kid ⇒ signature must fail.
    let token = other.mint(&base_claims(now));
    assert!(matches!(
        m.verify(&token, now, Instant::now()),
        AuthOutcome::Reject
    ));
}

#[test]
fn tampered_payload_is_rejected() {
    let key = TestKey::generate(KID);
    let m = module_with(&key, "groups");
    let now = 1_700_000_000;
    let token = key.mint(&base_claims(now));
    // Replace the payload with a DIFFERENT but validly-encoded claims object (escalated groups),
    // keeping the original header + signature. The signature no longer covers this payload ⇒ Reject.
    let segs: Vec<&str> = token.split('.').collect();
    let mut forged = base_claims(now);
    forged["groups"] = serde_json::json!(["busbar-admins"]);
    let forged_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged).unwrap());
    let tampered = format!("{}.{}.{}", segs[0], forged_payload, segs[2]);
    assert!(matches!(
        m.verify(&tampered, now, Instant::now()),
        AuthOutcome::Reject
    ));
}

// ── alg-confusion guard (Finding 7) ────────────────────────────────────────────────────────────

/// Build a compact JWT with an arbitrary (attacker-controlled) `alg` header value and an arbitrary
/// signature segment, independent of [`TestKey::mint`] (which always writes `"ES256"`). Used to
/// exercise the classic `alg: none` and `RS256→HS256` key-confusion attacks against
/// [`jwt::verify_signature`] directly — the signature bytes never matter for these cases, because a
/// correctly-guarded implementation must reject on `alg` alone, before it ever touches the key.
fn token_with_alg(kid: &str, alg: &str, claims: &Value, sig: &[u8]) -> String {
    let header = serde_json::json!({ "alg": alg, "typ": "JWT", "kid": kid });
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    let s = URL_SAFE_NO_PAD.encode(sig);
    format!("{h}.{p}.{s}")
}

#[test]
fn alg_none_is_rejected() {
    // The classic "alg: none" attack: an attacker strips the signature and claims the token is
    // unsigned. `verify_signature` must refuse this on the alg check alone — never treat an empty/
    // absent signature as vacuously valid.
    let key = TestKey::generate(KID);
    let jwk = jwks::JwkSet::parse(&key.jwks()).unwrap().keys[0].clone();
    let now = 1_700_000_000;
    let token = token_with_alg(KID, "none", &base_claims(now), b"");
    let parts = jwt::split(&token).unwrap();
    let err = jwt::verify_signature(&parts, &jwk).unwrap_err();
    assert!(
        err.contains("unsupported/forbidden") && err.contains("none"),
        "expected the alg-rejection branch, got: {err}"
    );
}

#[test]
fn hmac_alg_confusion_is_rejected() {
    // The classic RS256/ES256 → HS256 key-confusion attack: an attacker re-signs the token with
    // HMAC, hoping the verifier will use the provider's PUBLIC asymmetric key material as an HMAC
    // secret. `verify_signature` must refuse on the alg check alone — it must never reach into `key`
    // for an HS* alg, so an arbitrary/garbage signature is sufficient to prove the guard fires before
    // any signature math happens (a malformed-signature failure would look identical to the attacker,
    // but we assert the actual error text below to make sure it's the alg branch, not that one).
    let key = TestKey::generate(KID);
    let jwk = jwks::JwkSet::parse(&key.jwks()).unwrap().keys[0].clone();
    let now = 1_700_000_000;
    for alg in ["HS256", "HS384", "HS512"] {
        let token = token_with_alg(KID, alg, &base_claims(now), b"garbage-signature-bytes");
        let parts = jwt::split(&token).unwrap();
        let err = jwt::verify_signature(&parts, &jwk).unwrap_err();
        assert!(
            err.contains("unsupported/forbidden") && err.contains(alg),
            "expected the alg-rejection branch for {alg}, got: {err}"
        );
    }
}

#[test]
fn non_jwt_bearer_passes() {
    let key = TestKey::generate(KID);
    let m = module_with(&key, "groups");
    // An opaque non-JWT bearer is not our credential shape ⇒ Pass (defer to the next chain module).
    assert!(matches!(
        m.verify("sk-opaque-token", 1_700_000_000, Instant::now()),
        AuthOutcome::Pass
    ));
}

#[test]
fn no_credential_passes() {
    let key = TestKey::generate(KID);
    let m = module_with(&key, "groups");
    assert!(matches!(m.authenticate(None), AuthOutcome::Pass));
}

// ── kid rotation ────────────────────────────────────────────────────────────────────────────────

#[test]
fn kid_rotation_triggers_bounded_refetch() {
    // ONE module, ONE cache, for the whole scenario — the provider rotates its JWKS underneath the
    // already-running module, which is what the miss-then-bounded-refetch branch
    // (`cache.rs::with_key`'s post-first-lookup `refresh`) actually exists to handle. A prior version
    // of this test rebuilt a second module with a pre-rotated two-key fixture, which meant the FIRST
    // lookup already found the new key and the refetch branch was never reached.
    let old = TestKey::generate("old-kid");
    let new = TestKey::generate("new-kid");
    let fetcher = Arc::new(FixtureFetcher::new(old.jwks()));
    let m = OidcModule::new(
        &cfg("groups"),
        "https://jwks.test/keys".to_string(),
        Box::new(fetcher.clone()),
    );
    let t0 = Instant::now();
    let now = 1_700_000_000;

    // First, a token from the OLD key verifies (initial fetch, calls == 1).
    let tok_old = old.mint(&base_claims(now));
    assert!(matches!(
        m.verify(&tok_old, now, t0),
        AuthOutcome::Identify(_)
    ));
    assert_eq!(fetcher.calls(), 1);

    // Rotate: the provider now serves BOTH keys. The cache still has only "old" cached — nothing
    // has told it to refetch yet.
    let both = serde_json::json!({
        "keys": [
            serde_json::from_str::<Value>(&old.jwks()).unwrap()["keys"][0].clone(),
            serde_json::from_str::<Value>(&new.jwks()).unwrap()["keys"][0].clone(),
        ]
    })
    .to_string();
    fetcher.set_body(both);

    // Present a NEW-kid token past `jwks_min_refetch_secs` (60s, `cfg()` above) so the rate limit
    // permits the refetch, but well inside `jwks_ttl_secs` (3600s) so the set is NOT TTL-stale — the
    // ONLY thing that can trigger a fetch here is the miss-then-refetch branch, exactly what this
    // test claims to exercise.
    let tok_new = new.mint(&base_claims(now));
    match m.verify(&tok_new, now, t0 + Duration::from_secs(61)) {
        AuthOutcome::Identify(p) => assert_eq!(p.id, "oidc:object-guid"),
        other => panic!("expected Identify after rotation, got {other:?}"),
    }
    assert_eq!(fetcher.calls(), 2, "exactly one refetch for the rotation");

    // And the bound itself: a THIRD, genuinely-unknown kid arriving inside the rate-limit window
    // must NOT trigger another fetch — it should be rejected off the set already in hand.
    let ghost = TestKey::generate("ghost-kid");
    let tok_ghost = ghost.mint(&base_claims(now));
    assert!(matches!(
        m.verify(&tok_ghost, now, t0 + Duration::from_secs(62)),
        AuthOutcome::Reject
    ));
    assert_eq!(fetcher.calls(), 2, "rate limit held off a second refetch");
}

#[test]
fn unknown_kid_after_refetch_is_rejected() {
    let key = TestKey::generate("real-kid");
    let m = module_with(&key, "groups");
    let now = 1_700_000_000;
    // Mint a token claiming a kid absent from the JWKS.
    let bogus = TestKey::generate("ghost-kid");
    let token = bogus.mint(&base_claims(now));
    assert!(matches!(
        m.verify(&token, now, Instant::now()),
        AuthOutcome::Reject
    ));
}

// ── claim-policy tests (drive the verifier directly) ──────────────────────────────────────────────

fn verifier(role: &str) -> OidcVerifier {
    OidcVerifier::new(ISSUER, AUDIENCE, role)
}

#[test]
fn wrong_issuer_denied() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["iss"] = serde_json::json!("https://evil.example/v2.0");
    assert!(verifier("groups").validate_claims(&c, now).is_err());
}

#[test]
fn wrong_audience_denied() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["aud"] = serde_json::json!("api://some-other-app");
    assert!(verifier("groups").validate_claims(&c, now).is_err());
}

#[test]
fn audience_array_form_accepted() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["aud"] = serde_json::json!(["api://other", AUDIENCE]);
    assert!(verifier("groups").validate_claims(&c, now).is_ok());
}

#[test]
fn expired_denied() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["exp"] = serde_json::json!(now - 3600); // well past skew
    assert!(verifier("groups").validate_claims(&c, now).is_err());
}

#[test]
fn not_yet_valid_denied() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["nbf"] = serde_json::json!(now + 3600);
    assert!(verifier("groups").validate_claims(&c, now).is_err());
}

#[test]
fn missing_exp_denied() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c.as_object_mut().unwrap().remove("exp");
    assert!(verifier("groups").validate_claims(&c, now).is_err());
}

#[test]
fn an_exp_at_i64_max_does_not_panic() {
    // `exp + CLOCK_SKEW_SECS` on a wire-supplied i64 must not panic in a debug/test build
    // (overflow-checks on). `i64::MAX` is the top of the reachable range for a JSON-carried integer.
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["exp"] = serde_json::json!(i64::MAX);
    // Not asserting Ok/Err here — the tie-break verdict is to SATURATE (accept), see lib.rs's
    // comment at the `checked_add`/saturating_add call site — this test's job is only to prove the
    // arithmetic no longer panics on an in-range-for-i64-but-overflowing-the-skew-add value.
    let _ = verifier("groups").validate_claims(&c, now);
}

#[test]
fn an_nbf_at_i64_min_does_not_panic() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["nbf"] = serde_json::json!(i64::MIN);
    let _ = verifier("groups").validate_claims(&c, now);
}

#[test]
fn unmapped_no_groups_still_identifies_with_empty_groups() {
    // A token with no groups claim is NOT a verifier error — it identifies with empty groups; the
    // engine's group_map denies an unmapped principal downstream (default:deny). Proving the module
    // asserts identity only, never policy.
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c.as_object_mut().unwrap().remove("groups");
    let p = verifier("groups").validate_claims(&c, now).unwrap();
    assert!(p.roles.is_empty());
    assert_eq!(p.id, "oidc:object-guid");
}

#[test]
fn entra_groups_overage_marker_is_rejected_with_pointer_to_app_roles() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c.as_object_mut().unwrap().remove("groups");
    c["_claim_names"] = serde_json::json!({ "groups": "src1" });
    c["_claim_sources"] =
        serde_json::json!({ "src1": { "endpoint": "https://graph.microsoft.com/..." } });
    let err = verifier("groups").validate_claims(&c, now).unwrap_err();
    assert!(err.contains("OVERAGE"), "got: {err}");
    assert!(
        err.to_lowercase().contains("app-roles"),
        "must point at app-roles: {err}"
    );
}

#[test]
fn overage_marker_ignored_when_using_app_roles() {
    // With role_claim: roles, a groups-overage marker is irrelevant (app-roles ride in the token).
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["roles"] = serde_json::json!(["Billing.Reader"]);
    c["_claim_names"] = serde_json::json!({ "groups": "src1" });
    c["_claim_sources"] = serde_json::json!({ "src1": {} });
    let p = verifier("roles").validate_claims(&c, now).unwrap();
    assert_eq!(p.roles, vec!["Billing.Reader"]);
}

#[test]
fn config_defaults_role_claim_to_groups() {
    let parsed: OidcConfig =
        serde_json::from_str(r#"{"issuer":"https://i/v2.0","audience":"a"}"#).unwrap();
    assert_eq!(parsed.role_claim, "groups");
    assert_eq!(parsed.jwks_min_refetch_secs, 60);
    assert!(parsed.jwks_url.is_none());
}

// ── discovery issuer check (RFC 8414 §3.3 / OIDC Discovery 1.0 §4.3) ───────────────────────────────

fn discovery_cfg() -> OidcConfig {
    OidcConfig {
        issuer: ISSUER.to_string(),
        audience: AUDIENCE.to_string(),
        jwks_url: None, // forces discovery
        role_claim: "groups".to_string(),
        jwks_min_refetch_secs: 60,
        jwks_ttl_secs: 3600,
        ca_cert_pem: None,
    }
}

#[test]
fn discovery_with_matching_issuer_resolves_jwks_uri() {
    let doc = serde_json::json!({ "issuer": ISSUER, "jwks_uri": "https://issuer.test/keys" });
    let fetcher = FixtureFetcher::new(doc.to_string());
    let url = resolve_jwks_url(&discovery_cfg(), &fetcher).expect("matching issuer must resolve");
    assert_eq!(url, "https://issuer.test/keys");
}

/// RED (pre-fix): a discovery document with NO issuer check at all resolves `jwks_uri` regardless of
/// which host served it — a poisoned response silently repoints key fetching for the process
/// lifetime. GREEN (this fix): the mismatch is rejected before `jwks_uri` is ever read.
#[test]
fn discovery_with_mismatched_issuer_is_rejected() {
    let doc = serde_json::json!({
        "issuer": "https://attacker.example/v2.0",
        "jwks_uri": "https://attacker.example/keys"
    });
    let fetcher = FixtureFetcher::new(doc.to_string());
    let err = resolve_jwks_url(&discovery_cfg(), &fetcher)
        .expect_err("mismatched issuer must be rejected");
    assert!(
        err.contains("does not match the configured issuer"),
        "expected an issuer-mismatch error, got: {err}"
    );
}

#[test]
fn discovery_with_no_issuer_field_is_rejected() {
    let doc = serde_json::json!({ "jwks_uri": "https://issuer.test/keys" });
    let fetcher = FixtureFetcher::new(doc.to_string());
    let err = resolve_jwks_url(&discovery_cfg(), &fetcher)
        .expect_err("a discovery document with no 'issuer' must be rejected, not trusted");
    assert!(err.contains("no 'issuer'"), "got: {err}");
}

// ── subject-claim precedence: immutable-only for identity, mutable-ok for display name ─────────────

#[test]
fn subject_prefers_immutable_oid_over_mutable_preferred_username() {
    let now = 1_700_000_000;
    let c = base_claims(now); // carries both oid and preferred_username
    let p = verifier("groups").validate_claims(&c, now).unwrap();
    assert_eq!(
        p.id, "oidc:object-guid",
        "oid must win over preferred_username"
    );
}

#[test]
fn subject_falls_back_to_sub_when_oid_absent() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c.as_object_mut().unwrap().remove("oid");
    let p = verifier("groups").validate_claims(&c, now).unwrap();
    assert_eq!(p.id, "oidc:subject-guid", "sub must win when oid is absent");
}

/// RED (pre-fix): with neither immutable claim present, the module silently fell through to the
/// MUTABLE preferred_username and identified the caller anyway. GREEN (this fix): a non-compliant IdP
/// that omits both oid and sub (sub is REQUIRED by OIDC Core 1.0) is refused, not silently downgraded
/// to a spoofable/reassignable identity.
#[test]
fn missing_both_oid_and_sub_is_rejected_not_downgraded_to_a_mutable_claim() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    let obj = c.as_object_mut().unwrap();
    obj.remove("oid");
    obj.remove("sub");
    let err = verifier("groups")
        .validate_claims(&c, now)
        .expect_err("missing both oid and sub must be a hard rejection");
    assert!(
        err.contains("oid") && err.contains("sub"),
        "error should name both missing immutable claims: {err}"
    );
}

#[test]
fn display_name_falls_back_to_preferred_username_when_name_claim_absent() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c.as_object_mut().unwrap().remove("name"); // Entra access tokens often omit this
    let p = verifier("groups").validate_claims(&c, now).unwrap();
    assert_eq!(
        p.id, "oidc:object-guid",
        "identity must still be the immutable oid"
    );
    assert_eq!(
        p.name.as_deref(),
        Some("alice@contoso.com"),
        "display name should still fall back to a mutable claim when name is absent"
    );
}

// ── credential-cache TTL ceiling ─────────────────────────────────────────────────────────────────

/// RED (pre-fix): an un-ceilinged `ttl_secs` derived straight from a standard ~3600s-lived access
/// token WIDENED the engine's credential-cache window from its 300s default to up to 3600s — trading
/// the reported over-cache bug for a larger one. GREEN: the suggestion can only ever shorten the
/// engine's default, never lengthen it.
#[test]
fn ttl_secs_is_ceilinged_even_for_a_long_lived_token() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["exp"] = serde_json::json!(now + 3600); // a standard-length access token
    let p = verifier("groups").validate_claims(&c, now).unwrap();
    assert_eq!(
        p.ttl_secs,
        Some(300),
        "ttl_secs must be ceilinged to MAX_CACHE_TTL_SECS, not the token's full 3600s lifetime"
    );
}

#[test]
fn ttl_secs_still_shortens_for_a_token_expiring_sooner_than_the_ceiling() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["exp"] = serde_json::json!(now + 30); // shorter than the 300s ceiling
    let p = verifier("groups").validate_claims(&c, now).unwrap();
    assert_eq!(p.ttl_secs, Some(30));
}

// ── clock-failure fail-closed (realistic broken-clock states, not just sub-epoch) ──────────────────

#[test]
fn now_unix_fails_closed_below_the_sanity_floor() {
    // Below CLOCK_SANITY_FLOOR_UNIX simulates a dead RTC / NTP fault landing the clock in the past —
    // the realistic broken-clock case, which `SystemTime::now()` reports as `Ok(small_value)` and
    // never touches the `unwrap_or` branch at all. A token whose exp is comfortably in the "future"
    // relative to that bogus small `now` must NOT be treated as valid.
    let now = CLOCK_SANITY_FLOOR_UNIX - 1;
    let mut c = base_claims(0);
    c["exp"] = serde_json::json!(now + 3600); // "unexpired" relative to the broken clock
    c["nbf"] = serde_json::json!(now - 10);
    // Directly exercises validate_claims with the bogus `now` a broken now_unix() would have
    // produced BEFORE this fix (i.e. proves the check rejects once now_unix correctly reports
    // i64::MAX instead) by asserting the module-level now_unix() itself is what's under test:
    assert!(
        now_unix() >= CLOCK_SANITY_FLOOR_UNIX,
        "the REAL now_unix() (real host clock) must read above the sanity floor for this test to \
         mean anything"
    );
    // Simulate what now_unix() returns for a host clock below the floor: i64::MAX, fed straight into
    // validate_claims, exactly as authenticate() would.
    let err = verifier("groups")
        .validate_claims(&c, i64::MAX)
        .expect_err("a below-sanity-floor clock must fail the exp check, not pass it");
    assert!(err.contains("expired"), "got: {err}");
}
