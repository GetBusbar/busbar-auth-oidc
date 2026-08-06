// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Verification-logic tests. An in-test ES256 keypair (via `ring`) mints real tokens against a local
//! JWKS fixture — the FULL signature path runs in-process, no network. Claim-policy cases
//! (iss/aud/exp/nbf, overage, unmapped) drive [`OidcVerifier::validate_claims`] directly.

use super::*;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, KeyPair, RsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING, RSA_PKCS1_SHA256,
};
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
        client_id: None,
        scopes: Vec::new(),
        authorization_endpoint: None,
        token_endpoint: None,
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

// ── RS256 real-signature coverage ────────────────────────────────────────────────────────────────
//
// RS256 is the DOCUMENTED DEFAULT for the IdPs busbar targets (Entra/Google/Okta), yet the rest of
// this suite signs ES256 only. `ring` cannot GENERATE RSA keys, so these tests carry two fixed
// 2048-bit RSA keypairs (PKCS#8, minted offline with OpenSSL) and their public `n` — real key
// material driving the genuine `RSA_PKCS1_2048_8192_SHA256` verify path in-process, no network.

/// A fixed 2048-bit RSA test keypair (PKCS#8 DER, base64) and its public modulus `n` (base64url).
const RSA_PKCS8_B64: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDfiEloqx6vE5RaE/nwH9GrY9jdPiyJX5jElECQhH/8UoTGbDtjZ7WGPlp3mIieJ/iyjBtBtW/Z7csJxEMfrAP7Dew9sXv76RTVE2zZXqwxFt9xPtva7WlKqhZbt+NEQNR5Yo1dsaOaCJiLTd8iuRoJACqfuQpWrcSkpvf25oA+cdY/p+MyzVKMSCkYMX4YdIp1ie914N2i98SuymZBnv2oJHD93AGU4xLW7gUuDyn6HNywbcSXqRM8G8i8ouClkeaMpFEzewAJyTuBSCOalq0fZFYWUsCIR87wUkE+u6arHqxn+MhiOHn8JvU31ETUsAF6tth7bmaHXvdEaIf4/INfAgMBAAECggEAXclHy5OobxqO7vBcuIQRK5DcB4+zjfu/FBODt17weASDUuFMVZvIzMdSm8Uy5PCuZvNj6EDg6hXcT3+6DgrVLLuduBDEjWAw7mmVDOqs4nfPTitqgUOFHt+YO+k+gH+W5ksUNxB2LQWYQzJsAZyaMNaSC6vOi6mizNaFSWFSw1+lH1QQDriBwwUC9Q+gjD9DSbYlXrRNso3VfAr/FfenfDN1IB6F2IKaGwzPIVyDA4tHn54yzm4FA6HHY3/hRZFtzwnPXGdYcEduc38FXBG9NYzkX9H2NSYgJrsXJRpa27SjCWOi/jt9MgUUcBzqafjJdfVDUmlN8GvoEyJ2c9QhCQKBgQDxXYfiZjlEgjtFCbnyExc6nppl0Vrg8OL1BczNdgV6rRSoIDbUGoKvP8arwDtgZ4rTYEz/0F9wh8Sc7EmTbt3XJBOFt7xt1ldrWGA2HKYj5TzJqs3V87Fb4XNCFk234rjHxIzPe5wNQhk7VYH5X2y/UURyW9WOTr910JbijzY6UwKBgQDtFfPhAdOvV10UOfCSmrgP0tNuAJp3MKWx10trOQFQq5TxrQpZ1ME+4kl84VwX2fUmdF+4O14fe1PM+oCjke+V43susJwkz4n+danUpHbB25wCZBrwarUt52mgFzN5liy43w5Ypa2IX4A+1wQFEL1Y3yLcLblVaE0zIEidUeqpRQKBgEfxBuWWbo9a+euUAJaE1jGkwISEqD/PzPYXann7KZrtJ/EM2QrTdAxkSAU9YPVVJ23lkE3Xf/r8nL/hNfT54KmVmTQMFd/vOVNHnjXCyEp+s2WwwXV6E209f6s9FqEutMDmdsoJH/RbtUWYMQtxQ+qqgGpNsROfqTWmnLKe2Rz9AoGBAIXILm7Ybg/yN1azfxnq7lQXfjEDbCY3sDgTKb6eUyynNYvOPhoEoOsQG7G5JRNcbSY+4sh9z5XqLJZtAGvMbKpiy97Dz8hByDdrQ+L2zwCDIJyEymLBg+0cOREaJnTElgXX8Ct7idl7Mk3DXMRS9tWQTAZ8UqlsCqv/2pnTYJwVAoGATZFcTxzL2lSurJ1oi5VrpuxSdY9PrQsYAiZOJ+AqdiPk6jDgRWG2adEo+Ze9wlsn29NsFeoNVYoXv9lQHQWEP8v9z0AXfecM1yP+JPWYzvjlHQzZ1aNgI5ewWi2pB0G9LGm2iHDchQG72TjiRF+VFdIXFzBJmsXxW6vOncVIHdI=";
const RSA_N_B64URL: &str = "34hJaKserxOUWhP58B_Rq2PY3T4siV-YxJRAkIR__FKExmw7Y2e1hj5ad5iInif4sowbQbVv2e3LCcRDH6wD-w3sPbF7--kU1RNs2V6sMRbfcT7b2u1pSqoWW7fjREDUeWKNXbGjmgiYi03fIrkaCQAqn7kKVq3EpKb39uaAPnHWP6fjMs1SjEgpGDF-GHSKdYnvdeDdovfErspmQZ79qCRw_dwBlOMS1u4FLg8p-hzcsG3El6kTPBvIvKLgpZHmjKRRM3sACck7gUgjmpatH2RWFlLAiEfO8FJBPrumqx6sZ_jIYjh5_Cb1N9RE1LABerbYe25mh173RGiH-PyDXw";

/// A SECOND, unrelated RSA keypair — used to prove a signature made by the wrong key is rejected.
const RSA2_PKCS8_B64: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDHtV4BMlSKdJMOkqYcSTPbr7oZGiiFf1SzIk8or7EZ0B1jBARQt2SezW6lMrja/ARH5ERcCa5Yh9Nfzq0BSzK6rMfoEIQyIpkaDp6Khd1nsys7CRuQ/5TympIIwrQ63JYd6UhmXqNdVkaFwzOmcAGR4/UILPxpNOWLC35zuaMVAo2EKWvRxt0A6eyZeVfnWv9JcmJy2kXKySxo84e4O+2/mLOLighMuuQzj40JdJw8iQ+7sCvroNaXEPNiNPyTNmGt459zfxjDQBNdH3UU33ud46xW2HTu92S0tV2KXqtoUx+bP5RhBHKVOfuTn0QVKUxyUkBwai02oU6Yg9uBjt/lAgMBAAECggEANwSxVDUQc2BwTxh5qNtF7ST5aQb62OReakdudXAJo2nhXrDxm2ca0mEYNWzG3pWFfGTXrF+CZ6NryT5ADVYxMJp/LGC4erNraHFUnicI+xOyOj5lGMpAt6F7z+wMCRdSSAVHy+QQr5sgLKO9bAH5fL7Hd6wlEbrf7jGJccpXsmaYC7Azeo2tJnnpxXX0JoP6ytQrbIe9aEVtdoFiJuD+u23YLL0GhTDqzJDIgekftjUZOXPGjxrv+AE6O+q7u484yecviMAKpYfty2mf2tb1cz4OZDsQvxUm0UoZ8Le5tPS9dUxTAlqzF908sRrHx6urmxf6zA3yPohOdU6L1U/0NQKBgQDlFSV+0gzAlw5G1ip40xNxoLGISRgZHrceeSmRhTL4Ya35KvNkqHIEBlLbSjZzOPEF2kdzrQblvVno5jPLz+vnRklRBuMLRacKswLSel//tmqtg9+MMRKVWxMScRgmDXYe3dSaAvnw73ilipBc0Cb6ghQnMR+EBYy/nunl4eg/cwKBgQDfLKPySohchz/88ZPmWKmYmAXUNlU15wdaZ4gpjTXwf1tUCjjQVJ8VYh26AOV2XpGCmyNxAu3zIlKF+wUJtcPQ8293N8VWBZC0yp49nWSjpRDQZfj+moE0YfjosyKrr1z5yq2g7nFsucHIK7DJFymMlfFrsnEuRKAM9cJEoWXdRwKBgQCtgEqZtrT52G5zsBkS0arUUISlV9bsj5rZdaLKGDv2auS85o7ZGcrgyXlPpPGAawwBBsU/Ezk6HyNNhayNHLjqvQ0iVTj4fJR7QgFNMGos3hgFuu9A2pncjNHxEb7ccy2XSyOOUdrDZFvX5Q5ZfT1IVeS1mjroXtuu9cjo1yRziQKBgD9fe8anp4Uu2trG9sqoTrCIKs+SBixiSFJBqAa0lKaQY6y/olZ2UR5PWEWjT4WHYSaHS08iF9O84VYua8XQGaTSG8rsyVqeBfNwvfKdKSDXFKk467XQxfPMBlR92dCK4YoFJbzXONo4/XAMCA1ySFgllAKTD1SmJBTKDLpUYoqtAoGAFp9+Eg5Be4SJpAOmnRgHe2FckHmU8G/QQ4zPQL0KziI0YiVw7f7k7GFajapGFNbsVcFtTuQMyRbzmnxD7xJ/0mwEcmnEBLbJp21angie6I//9wNrmN/fkbhkinD7azUGIKulsyAzlXg5pmpnjZK/EJtzdZ6LrM2RwULrbEK+Ht8=";
const RSA2_N_B64URL: &str = "x7VeATJUinSTDpKmHEkz26-6GRoohX9UsyJPKK-xGdAdYwQEULdkns1upTK42vwER-REXAmuWIfTX86tAUsyuqzH6BCEMiKZGg6eioXdZ7MrOwkbkP-U8pqSCMK0OtyWHelIZl6jXVZGhcMzpnABkeP1CCz8aTTliwt-c7mjFQKNhClr0cbdAOnsmXlX51r_SXJictpFysksaPOHuDvtv5izi4oITLrkM4-NCXScPIkPu7Ar66DWlxDzYjT8kzZhreOfc38Yw0ATXR91FN97neOsVth07vdktLVdil6raFMfmz-UYQRylTn7k59EFSlMclJAcGotNqFOmIPbgY7f5Q";

/// A ring RS256 signer wrapping one of the fixed keypairs, plus the JWKS fixture (`n`/`e`) that
/// verifies it — the RSA analogue of [`TestKey`].
struct RsaTestKey {
    kp: RsaKeyPair,
    rng: SystemRandom,
    kid: String,
    n_b64url: String,
}

impl RsaTestKey {
    fn from_pkcs8(pkcs8_b64: &str, n_b64url: &str, kid: &str) -> Self {
        let der = STANDARD.decode(pkcs8_b64).unwrap();
        let kp = RsaKeyPair::from_pkcs8(&der).unwrap();
        Self {
            kp,
            rng: SystemRandom::new(),
            kid: kid.to_string(),
            n_b64url: n_b64url.to_string(),
        }
    }

    /// The default fixture keypair.
    fn generate(kid: &str) -> Self {
        Self::from_pkcs8(RSA_PKCS8_B64, RSA_N_B64URL, kid)
    }

    /// The public key as a single-key RSA JWKS document (`e` = 65537 = `AQAB`).
    fn jwks(&self) -> String {
        serde_json::json!({
            "keys": [{
                "kty": "RSA", "kid": self.kid, "n": self.n_b64url, "e": "AQAB",
                "use": "sig", "alg": "RS256"
            }]
        })
        .to_string()
    }

    /// Sign a claims object into a compact RS256 JWT with this key's kid.
    fn mint(&self, claims: &Value) -> String {
        let header = serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": self.kid });
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let signing_input = format!("{h}.{p}");
        let mut sig = vec![0u8; self.kp.public().modulus_len()];
        self.kp
            .sign(
                &RSA_PKCS1_SHA256,
                &self.rng,
                signing_input.as_bytes(),
                &mut sig,
            )
            .unwrap();
        let s = URL_SAFE_NO_PAD.encode(&sig);
        format!("{signing_input}.{s}")
    }
}

fn rsa_module(key: &RsaTestKey, role_claim: &str) -> OidcModule {
    OidcModule::new(
        &cfg(role_claim),
        "https://jwks.test/keys".to_string(),
        Box::new(FixtureFetcher::new(key.jwks())),
    )
}

#[test]
fn valid_rs256_token_identifies() {
    let key = RsaTestKey::generate(KID);
    let m = rsa_module(&key, "groups");
    let now = 1_700_000_000;
    let token = key.mint(&base_claims(now));
    match m.verify(&token, now, Instant::now()) {
        AuthOutcome::Identify(p) => {
            assert_eq!(p.id, "oidc:object-guid");
            assert_eq!(p.roles, vec!["11111111-aaaa", "22222222-bbbb"]);
        }
        other => panic!("expected Identify for a valid RS256 token, got {other:?}"),
    }
}

#[test]
fn bad_rs256_signature_is_rejected() {
    // Token signed by RSA key #2 but presented against key #1's JWKS (same kid) ⇒ signature fails.
    let served = RsaTestKey::generate(KID); // JWKS carries key #1's modulus
    let wrong = RsaTestKey::from_pkcs8(RSA2_PKCS8_B64, RSA2_N_B64URL, KID); // signs with key #2
    let m = rsa_module(&served, "groups");
    let now = 1_700_000_000;
    let token = wrong.mint(&base_claims(now));
    assert!(
        matches!(m.verify(&token, now, Instant::now()), AuthOutcome::Reject),
        "an RS256 token signed by the wrong RSA key must be rejected"
    );
}

#[test]
fn tampered_rs256_payload_is_rejected() {
    let key = RsaTestKey::generate(KID);
    let m = rsa_module(&key, "groups");
    let now = 1_700_000_000;
    let token = key.mint(&base_claims(now));
    // Swap the payload for an escalated-groups claims object, keeping the valid RS256 header +
    // signature. The signature no longer covers this payload ⇒ Reject.
    let segs: Vec<&str> = token.split('.').collect();
    let mut forged = base_claims(now);
    forged["groups"] = serde_json::json!(["busbar-admins"]);
    let forged_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged).unwrap());
    let tampered = format!("{}.{}.{}", segs[0], forged_payload, segs[2]);
    assert!(
        matches!(
            m.verify(&tampered, now, Instant::now()),
            AuthOutcome::Reject
        ),
        "a tampered payload under a valid RS256 header must be rejected"
    );
}

/// The RSA-keyed variant of the alg-confusion guard: against a real RSA JWKS key, both `alg: none`
/// and the RS256→HS256 key-confusion (re-signing with HMAC, hoping the public modulus is used as an
/// HMAC secret) must be refused on the `alg` check alone, before any signature math.
#[test]
fn alg_confusion_against_an_rsa_key_is_rejected() {
    let key = RsaTestKey::generate(KID);
    let jwk = jwks::JwkSet::parse(&key.jwks()).unwrap().keys[0].clone();
    let now = 1_700_000_000;
    for alg in ["none", "HS256", "HS384", "HS512"] {
        let token = token_with_alg(KID, alg, &base_claims(now), b"garbage-signature-bytes");
        let parts = jwt::split(&token).unwrap();
        let err = jwt::verify_signature(&parts, &jwk).unwrap_err();
        assert!(
            err.contains("unsupported/forbidden") && err.contains(alg),
            "expected the alg-rejection branch for {alg} against an RSA key, got: {err}"
        );
    }
}

// ── alg-confusion guard ────────────────────────────────────────────────────────────────────────

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

/// RFC 7515 §4.1.11: a token whose header marks a critical extension the verifier does not implement
/// MUST be rejected. This verifier implements none, so any non-empty `crit` is a rejection — and the
/// check fires on the header alone, before signature math (the signature bytes here are arbitrary).
///
/// Without `crit` inspection the header is ignored and the token falls through to normal signature
/// processing. As implemented it is rejected with a message naming the critical extension.
#[test]
fn a_token_naming_an_unimplemented_critical_extension_is_rejected() {
    let key = TestKey::generate(KID);
    let jwk = jwks::JwkSet::parse(&key.jwks()).unwrap().keys[0].clone();
    let now = 1_700_000_000;
    let header =
        serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": KID, "crit": ["b64", "my-ext"] });
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&base_claims(now)).unwrap());
    let s = URL_SAFE_NO_PAD.encode(b"arbitrary-sig");
    let token = format!("{h}.{p}.{s}");
    let parts = jwt::split(&token).unwrap();
    let err = jwt::verify_signature(&parts, &jwk).unwrap_err();
    assert!(
        err.contains("critical"),
        "expected a crit-rejection naming the unimplemented extension, got: {err}"
    );
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
    // (`cache.rs::with_key`'s post-first-lookup `refresh`) actually exists to handle. Rebuilding a
    // second module with a pre-rotated two-key fixture instead would leave the FIRST lookup finding
    // the new key, and the refetch branch would never be reached.
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

/// A token with NO `iss` claim at all must be rejected. Every fixture in this file carries an
/// issuer, and `wrong_issuer_denied` only mutates it to a wrong VALUE, so the absent-claim arm had
/// no coverage: changing it from a rejection to `{}` would accept a token that names no issuer
/// whatsoever, and nothing here would go red.
#[test]
fn a_token_with_no_iss_claim_is_denied() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c.as_object_mut().unwrap().remove("iss");
    let err = verifier("groups")
        .validate_claims(&c, now)
        .expect_err("a token carrying no issuer must be rejected, not accepted");
    assert!(err.contains("iss"), "{err}");
}

/// A token with NO `aud` claim, or an `aud` that is neither a string nor an array, must be
/// rejected. The catch-all arm that does this had no test: flipping it to accept would admit a
/// token with no audience at all, which is the confused-deputy shape this check exists to stop.
#[test]
fn a_token_with_no_aud_or_a_malformed_aud_is_denied() {
    let now = 1_700_000_000;

    let mut absent = base_claims(now);
    absent.as_object_mut().unwrap().remove("aud");
    assert!(
        verifier("groups").validate_claims(&absent, now).is_err(),
        "a token carrying no audience must be rejected"
    );

    for malformed in [
        serde_json::json!(42),
        serde_json::json!(true),
        serde_json::json!({ "aud": AUDIENCE }),
        serde_json::json!(null),
    ] {
        let mut c = base_claims(now);
        c["aud"] = malformed.clone();
        assert!(
            verifier("groups").validate_claims(&c, now).is_err(),
            "an aud that is not a string or an array of strings must be rejected, got {malformed}"
        );
    }
}

/// An `nbf` that is PRESENT but not a NumericDate must be rejected rather than silently skipped.
/// Both an absent claim and an unreadable one used to produce `None` from the same helper, so a
/// string NumericDate (a real shape from non-compliant issuers) dropped the not-before constraint
/// entirely while the token still verified.
#[test]
fn a_present_but_unreadable_nbf_is_denied_rather_than_ignored() {
    let now = 1_700_000_000;
    for malformed in [
        serde_json::json!("2099-01-01T00:00:00Z"),
        serde_json::json!(true),
        serde_json::json!([now + 3600]),
        serde_json::json!(null),
    ] {
        let mut c = base_claims(now);
        c["nbf"] = malformed.clone();
        let err = verifier("groups")
            .validate_claims(&c, now)
            .expect_err(&format!(
                "an unreadable nbf must be rejected, got {malformed}"
            ));
        assert!(err.contains("nbf"), "{err}");
    }

    // An ABSENT nbf is still fine: it is an optional claim.
    let mut absent = base_claims(now);
    absent.as_object_mut().unwrap().remove("nbf");
    assert!(verifier("groups").validate_claims(&absent, now).is_ok());
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
    // A single-valued `aud` array containing exactly the trusted audience is accepted with no `azp`
    // required (there is no untrusted extra audience to authorize).
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["aud"] = serde_json::json!([AUDIENCE]);
    assert!(verifier("groups").validate_claims(&c, now).is_ok());
}

// ── multi-valued aud + azp (OIDC Core 1.0 §3.1.3.7) ────────────────────────────────────────────────

/// A multi-valued `aud` that lists an audience the client does NOT trust is accepted ONLY when an
/// `azp` claim names the trusted client. This is the spec's authorized-party gate.
#[test]
fn multivalued_aud_with_untrusted_extra_is_accepted_when_azp_names_the_trusted_client() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["aud"] = serde_json::json!([AUDIENCE, "api://some-other-app"]);
    c["azp"] = serde_json::json!(AUDIENCE);
    assert!(
        verifier("groups").validate_claims(&c, now).is_ok(),
        "a multi-aud token whose azp is the trusted client must be accepted"
    );
}

/// Under a bare `.any(trusted)` check, a token minted for the trusted client AND an
/// attacker-controlled app sails through on the mere presence of the trusted audience. As
/// implemented, an untrusted extra audience with NO `azp` is rejected.
#[test]
fn multivalued_aud_with_untrusted_extra_and_no_azp_is_rejected() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["aud"] = serde_json::json!([AUDIENCE, "api://attacker-app"]);
    // no azp
    let err = verifier("groups")
        .validate_claims(&c, now)
        .expect_err("a multi-aud token with an untrusted extra and no azp must be rejected");
    assert!(err.contains("audience"), "got: {err}");
}

/// The `azp` must equal the TRUSTED client, not merely be present: an `azp` naming the attacker app
/// must not authorize the extra audience.
#[test]
fn multivalued_aud_with_wrong_azp_is_rejected() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["aud"] = serde_json::json!([AUDIENCE, "api://attacker-app"]);
    c["azp"] = serde_json::json!("api://attacker-app");
    assert!(
        verifier("groups").validate_claims(&c, now).is_err(),
        "an azp that is not the trusted client must not authorize the untrusted extra audience"
    );
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

/// RFC 7519 §2: a NumericDate MAY be fractional. Under an `as_i64`-only read, a fractional `exp` is
/// read as ABSENT and the token is denied for "no exp claim". As implemented the fractional seconds
/// are accepted (floored), so a future fractional `exp` verifies.
#[test]
fn fractional_exp_is_accepted_not_treated_as_absent() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["exp"] = serde_json::json!((now + 3600) as f64 + 0.5); // spec-legal fractional NumericDate
    assert!(
        verifier("groups").validate_claims(&c, now).is_ok(),
        "a fractional but future exp must be accepted, not treated as a missing exp"
    );
}

/// A fractional `exp` in the PAST is still expired (floor keeps it conservative).
///
/// Asserts the SPECIFIC failure, not just `is_err()`: the exp must have been PARSED and found in the
/// past ("expired"), not silently treated as absent. RED against an `as_i64`-only revert: there a
/// fractional exp reads as ABSENT and the error is "no 'exp' claim" — a different reason that a bare
/// `is_err()` could not tell apart, so it would pass with OR without the fractional-parse fix.
#[test]
fn fractional_exp_in_the_past_is_expired() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["exp"] = serde_json::json!((now - 3600) as f64 + 0.5);
    let err = verifier("groups")
        .validate_claims(&c, now)
        .expect_err("a fractional past exp must be rejected");
    assert!(
        err.contains("expired"),
        "the fractional exp must be parsed and rejected as EXPIRED, not treated as a missing exp; \
         got: {err}"
    );
}

/// A fractional `nbf` that sits BETWEEN its floor and its ceil, with `now` below both, must be treated
/// as NOT-YET-valid. `nbf` is ceiled (conservative — a not-before never rounds earlier); flooring it
/// would admit the token up to ~1s early. Constructed so ONLY the ceil-vs-floor choice decides the
/// verdict, with the 60s CLOCK_SKEW factored out: with `nbf = (now + 60) + 0.5`,
///   ceil ⇒ nbf=now+61, and `(now+61) - 60 = now+1 > now` ⇒ REJECT (correct, this crate);
///   floor ⇒ nbf=now+60, and `(now+60) - 60 = now  > now` is false ⇒ ADMIT (the old lenient bug).
/// RED against a floored `nbf`: the token would verify.
#[test]
fn fractional_nbf_between_floor_and_ceil_is_not_yet_valid() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["nbf"] = serde_json::json!((now + 60) as f64 + 0.5);
    assert!(
        verifier("groups").validate_claims(&c, now).is_err(),
        "a fractional nbf between its floor and ceil must be ceiled (not-yet-valid), not floored in"
    );
}

/// A fractional `nbf` is likewise honored rather than ignored (floored).
#[test]
fn fractional_nbf_in_the_future_is_not_yet_valid() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["nbf"] = serde_json::json!((now + 3600) as f64 + 0.5);
    assert!(
        verifier("groups").validate_claims(&c, now).is_err(),
        "a fractional future nbf must still reject, not be ignored as absent"
    );
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
        client_id: None,
        scopes: Vec::new(),
        authorization_endpoint: None,
        token_endpoint: None,
    }
}

#[test]
fn discovery_with_matching_issuer_resolves_jwks_uri() {
    let doc = serde_json::json!({ "issuer": ISSUER, "jwks_uri": "https://issuer.test/keys" });
    let fetcher = FixtureFetcher::new(doc.to_string());
    let url = resolve_jwks_url(&discovery_cfg(), &fetcher).expect("matching issuer must resolve");
    assert_eq!(url, "https://issuer.test/keys");
}

/// Without an issuer check, a discovery document resolves `jwks_uri` regardless of which host served
/// it — a poisoned response silently repoints key fetching for the process lifetime. As implemented,
/// the mismatch is rejected before `jwks_uri` is ever read.
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

/// Falling through to the MUTABLE preferred_username when neither immutable claim is present would
/// identify the caller anyway. As implemented, a non-compliant IdP that omits both oid and sub (sub
/// is REQUIRED by OIDC Core 1.0) is refused, not silently downgraded to a spoofable/reassignable
/// identity.
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

/// Under a bare `.and_then(Value::as_str)`, an empty-string `sub` (with `oid` absent) is accepted
/// and yields the degenerate shared principal `oidc:`. As implemented, an empty/whitespace subject is
/// treated like an absent one and rejected — the identity anchor must be non-empty.
#[test]
fn empty_string_subject_is_rejected_not_accepted_as_a_blank_identity() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    let obj = c.as_object_mut().unwrap();
    obj.remove("oid");
    obj.insert("sub".to_string(), serde_json::json!("")); // empty subject
    let err = verifier("groups")
        .validate_claims(&c, now)
        .expect_err("an empty-string sub must be rejected, not accepted as the 'oidc:' principal");
    assert!(err.contains("sub"), "got: {err}");
}

/// The same guard for a whitespace-only `oid` (Entra's immutable id): still no usable anchor.
#[test]
fn whitespace_only_oid_is_not_a_usable_identity_anchor() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["oid"] = serde_json::json!("   ");
    c.as_object_mut().unwrap().remove("sub");
    assert!(
        verifier("groups").validate_claims(&c, now).is_err(),
        "a whitespace-only oid with no sub must be rejected"
    );
}

/// A whitespace-only `oid` must FALL THROUGH to a valid `sub`, not abort identity derivation — the
/// blank immutable claim is skipped exactly like an absent one.
#[test]
fn blank_oid_falls_through_to_a_valid_sub() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["oid"] = serde_json::json!(""); // blank oid; sub stays "subject-guid"
    let p = verifier("groups")
        .validate_claims(&c, now)
        .expect("a blank oid must fall through to the valid sub");
    assert_eq!(p.id, "oidc:subject-guid");
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

/// An un-ceilinged `ttl_secs` derived straight from a standard ~3600s-lived access token would WIDEN
/// the engine's credential-cache window from its 300s default to up to 3600s — a worse problem than
/// the over-caching it is meant to address. As implemented, the suggestion can only ever shorten the
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

/// Boundary-tests the pure comparison [`is_clock_sane`] was extracted from `now_unix` for (see its
/// doc comment): `now_unix` itself reads the real host clock and cannot be driven with an injected
/// value, so the floor comparison is only directly testable once pulled out.
#[test]
fn is_clock_sane_boundary() {
    assert!(
        !is_clock_sane(CLOCK_SANITY_FLOOR_UNIX - 1),
        "one second below the floor must be considered insane"
    );
    assert!(
        is_clock_sane(CLOCK_SANITY_FLOOR_UNIX),
        "exactly at the floor must be considered sane (the floor itself is a trustworthy reading)"
    );
    assert!(
        is_clock_sane(CLOCK_SANITY_FLOOR_UNIX + 1),
        "above the floor must be considered sane"
    );
}

// ── config defaults (deserialization) ──────────────────────────────────────────────────────────

#[test]
fn config_defaults_jwks_ttl_secs_to_3600() {
    let parsed: OidcConfig =
        serde_json::from_str(r#"{"issuer":"https://i/v2.0","audience":"a"}"#).unwrap();
    assert_eq!(
        parsed.jwks_ttl_secs, 3600,
        "jwks_ttl_secs must default to DEFAULT_TTL_SECS when the operator does not set it"
    );
}

// ── audience array rejection ───────────────────────────────────────────────────────────────────

#[test]
fn audience_array_form_without_configured_audience_is_denied() {
    // `audience_array_form_accepted` above proves the array form is accepted when the configured
    // audience IS one of the entries; this proves the mirror case — an array present but NOT
    // containing it must still be denied, not vacuously accepted just because `aud` was an array.
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["aud"] = serde_json::json!(["api://other-1", "api://other-2"]);
    let err = verifier("groups")
        .validate_claims(&c, now)
        .expect_err("an aud array that never contains the configured audience must be denied");
    assert!(err.contains("audience"), "got: {err}");
}

// ── nbf skew boundary ───────────────────────────────────────────────────────────────────────────

#[test]
fn nbf_exactly_at_the_skew_boundary_is_accepted() {
    // `nbf.saturating_sub(CLOCK_SKEW_SECS) > now_unix` rejects; at exact equality the token must
    // still be accepted (the skew tolerance is inclusive of its own boundary).
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["nbf"] = serde_json::json!(now + CLOCK_SKEW_SECS);
    assert!(
        verifier("groups").validate_claims(&c, now).is_ok(),
        "nbf exactly CLOCK_SKEW_SECS in the future must still be accepted (skew is inclusive)"
    );
}

// ── Entra groups-overage marker: full boolean truth table ─────────────────────────────────────────

#[test]
fn overage_names_marker_alone_is_overage_even_without_claim_sources() {
    // A = true (_claim_names carries "groups"), B = false (no _claim_sources at all, and the
    // "groups" claim is itself present) — isolates the `||`: real code must still reject via A
    // alone. `A && B` (the `||`→`&&` mutant) would wrongly accept here since B is false.
    let now = 1_700_000_000;
    let mut c = base_claims(now); // still carries "groups"
    c["_claim_names"] = serde_json::json!({ "groups": "src1" });
    let err = verifier("groups")
        .validate_claims(&c, now)
        .expect_err("the _claim_names marker alone must trigger the overage rejection");
    assert!(err.contains("OVERAGE"), "got: {err}");
}

#[test]
fn overage_claim_names_present_but_without_groups_key_and_no_claim_sources_is_not_overage() {
    // A = false (_claim_names present but does NOT carry a "groups" entry), B1 (_claim_sources
    // present) = false, B2 (groups claim absent) = true, B3 (_claim_names present) = true.
    // Isolates the first `&&` inside B: real code is `B1 && B2 && B3` = false (B1 is false), so this
    // must NOT be treated as overage. The `&&`→`||` mutant at that spot would evaluate
    // `B1 || (B2 && B3)` = true, wrongly rejecting.
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c.as_object_mut().unwrap().remove("groups");
    c["_claim_names"] = serde_json::json!({ "unrelated_claim": "src1" });
    let p = verifier("groups")
        .validate_claims(&c, now)
        .expect("no _claim_sources and no groups-in-_claim_names must not be treated as overage");
    assert!(p.roles.is_empty());
}

#[test]
fn overage_claim_sources_present_but_groups_claim_present_is_not_overage() {
    // A = false, B1 (_claim_sources present) = true, B2 (groups claim absent) = FALSE (groups IS
    // present), B3 (_claim_names present) = true. Isolates the second `&&` inside B: real code is
    // `B1 && B2 && B3` = false (B2 is false), so a token that has a real groups list must verify
    // normally. The `&&`→`||` mutant at that spot would evaluate `B1 && (B2 || B3)` = true, wrongly
    // rejecting a token that actually carries its groups.
    let now = 1_700_000_000;
    let mut c = base_claims(now); // carries "groups"
    c["_claim_sources"] = serde_json::json!({ "src1": {} });
    c["_claim_names"] = serde_json::json!({ "unrelated_claim": "src1" });
    let p = verifier("groups")
        .validate_claims(&c, now)
        .expect("a token that actually carries its groups claim must not be treated as overage");
    assert_eq!(p.roles, vec!["11111111-aaaa", "22222222-bbbb"]);
}

// ── extract_string_list: scalar-string form ────────────────────────────────────────────────────

#[test]
fn role_claim_as_a_single_scalar_string_is_accepted() {
    // extract_string_list accepts a bare string (not just a JSON array) as a single-role claim.
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["groups"] = serde_json::json!("single-role");
    let p = verifier("groups").validate_claims(&c, now).unwrap();
    assert_eq!(p.roles, vec!["single-role"]);
}

// ── AuthModule trivia: name/cacheable ──────────────────────────────────────────────────────────

#[test]
fn module_name_and_cacheable() {
    let key = TestKey::generate(KID);
    let m = module_with(&key, "groups");
    assert_eq!(m.name(), "oidc");
    assert!(
        m.cacheable(),
        "OIDC does real I/O and its verdicts are worth caching"
    );
}

// ── browser-login primitives (auth ABI v2, 1.5.2 token-exchange) ─────────────────────────────────

/// The authorize URL is an OAuth authorization-code request carrying PKCE + state + nonce, and
/// STRUCTURALLY never a client_secret (the begin path is public).
#[test]
fn build_authorize_url_has_pkce_state_no_secret() {
    let mut c = cfg("groups");
    c.authorization_endpoint = Some("https://idp.test/authorize".to_string());
    c.scopes = vec!["email".to_string(), "profile".to_string()];
    let url = build_authorize_url(
        &c,
        "https://busbar.test/auth/token",
        "state-xyz",
        "challenge-abc",
        Some("nonce-123"),
    );
    assert!(
        url.starts_with("https://idp.test/authorize?"),
        "URL must target the authorization endpoint: {url}"
    );
    assert!(url.contains("response_type=code"), "{url}");
    assert!(url.contains("code_challenge=challenge-abc"), "{url}");
    assert!(url.contains("code_challenge_method=S256"), "{url}");
    assert!(url.contains("state=state-xyz"), "{url}");
    assert!(url.contains("nonce=nonce-123"), "{url}");
    // redirect_uri is percent-encoded as a query value.
    assert!(
        url.contains("redirect_uri=https%3A%2F%2Fbusbar.test%2Fauth%2Ftoken"),
        "redirect_uri must be percent-encoded: {url}"
    );
    // scope is `openid` + the configured scopes, space (%20) delimited.
    assert!(url.contains("scope=openid%20email%20profile"), "{url}");
    // client_id defaults to the audience when not explicitly configured.
    assert!(
        url.contains(&format!("client_id={}", pct(AUDIENCE))),
        "client_id must default to the audience: {url}"
    );
    // The confidential-client secret must NEVER appear on the begin path.
    assert!(
        !url.contains("client_secret") && !url.contains("secret"),
        "authorize URL must not carry a secret: {url}"
    );
}

/// The token-exchange hop is an authorization-code POST that NAMES the secret form field for the
/// core to fill — it carries the key, never a secret value.
#[test]
fn build_token_exchange_marks_secret_field() {
    let mut c = cfg("groups");
    c.token_endpoint = Some("https://idp.test/token".to_string());
    let hop = build_token_exchange(
        &c,
        "auth-code-1",
        "https://busbar.test/auth/token",
        "verifier-1",
    );
    assert_eq!(hop.method, "POST");
    assert_eq!(hop.url, "https://idp.test/token");
    // The core injects the secret VALUE into this named field; the module only wrote the KEY.
    assert_eq!(hop.secret_form_field.as_deref(), Some("client_secret"));

    let form: std::collections::HashMap<&str, &str> = hop
        .form
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    assert_eq!(form.get("grant_type").copied(), Some("authorization_code"));
    assert_eq!(form.get("code").copied(), Some("auth-code-1"));
    assert_eq!(form.get("code_verifier").copied(), Some("verifier-1"));
    assert_eq!(
        form.get("redirect_uri").copied(),
        Some("https://busbar.test/auth/token")
    );
    assert_eq!(form.get("client_id").copied(), Some(AUDIENCE));
    // The secret field is present as a KEY with an EMPTY placeholder value — never a real secret.
    assert_eq!(
        form.get("client_secret").copied(),
        Some(""),
        "client_secret must be an empty placeholder the core overwrites, not a value the plugin set"
    );
}

/// A good token-endpoint response verifies its id_token to an `oidc:<sub>` identity with groups; a
/// bad-audience id_token is a fail-closed Reject.
#[test]
fn identity_from_token_response_verifies_id_token() {
    let key = TestKey::generate(KID);
    let m = module_with(&key, "groups");
    let now = 1_700_000_000;

    let id_token = key.mint(&base_claims(now));
    let body = serde_json::json!({
        "token_type": "Bearer",
        "access_token": "opaque-access",
        "id_token": id_token,
    })
    .to_string();
    let resp = LoginHttpResponse { status: 200, body };
    match m.identity_from_token_response(&resp, now, Instant::now()) {
        LoginOutcome::Identify(p) => {
            assert_eq!(p.id, "oidc:object-guid");
            assert_eq!(p.roles, vec!["11111111-aaaa", "22222222-bbbb"]);
        }
        other => panic!("expected Identify, got {other:?}"),
    }

    // Bad audience id_token ⇒ Reject (reuses the verify signature+claims path).
    let mut bad = base_claims(now);
    bad["aud"] = serde_json::json!("api://some-other-app");
    let bad_body = serde_json::json!({ "id_token": key.mint(&bad) }).to_string();
    let bad_resp = LoginHttpResponse {
        status: 200,
        body: bad_body,
    };
    assert!(
        matches!(
            m.identity_from_token_response(&bad_resp, now, Instant::now()),
            LoginOutcome::Reject
        ),
        "a bad-audience id_token must be rejected"
    );

    // A response missing the id_token entirely ⇒ Reject.
    let no_id = LoginHttpResponse {
        status: 200,
        body: serde_json::json!({ "access_token": "opaque" }).to_string(),
    };
    assert!(matches!(
        m.identity_from_token_response(&no_id, now, Instant::now()),
        LoginOutcome::Reject
    ));
}

/// Discovery resolves BOTH login endpoints from the issuer's openid-configuration (issuer-match
/// guarded, the same document `resolve_jwks_url` reads).
#[test]
fn discovery_populates_authorization_and_token_endpoints() {
    let doc = serde_json::json!({
        "issuer": ISSUER,
        "jwks_uri": "https://issuer.test/keys",
        "authorization_endpoint": "https://issuer.test/authorize",
        "token_endpoint": "https://issuer.test/token",
    });
    let fetcher = FixtureFetcher::new(doc.to_string());
    let (auth_ep, tok_ep) = resolve_login_endpoints(&discovery_cfg(), &fetcher)
        .expect("discovery must resolve the login endpoints");
    assert_eq!(auth_ep.as_deref(), Some("https://issuer.test/authorize"));
    assert_eq!(tok_ep.as_deref(), Some("https://issuer.test/token"));

    // A poisoned discovery doc (issuer mismatch) is refused for login endpoints too.
    let evil = serde_json::json!({
        "issuer": "https://attacker.example/v2.0",
        "authorization_endpoint": "https://attacker.example/authorize",
        "token_endpoint": "https://attacker.example/token",
    });
    let evil_fetcher = FixtureFetcher::new(evil.to_string());
    assert!(resolve_login_endpoints(&discovery_cfg(), &evil_fetcher).is_err());
}

/// ADDITIVE-CONFIG regression: a verify-only config that predates the login fields still parses (all
/// login fields default to absent/empty), and a login-capable config parses the new fields.
#[test]
fn open_still_succeeds_with_and_without_login_fields() {
    let without: OidcConfig =
        serde_json::from_str(r#"{"issuer":"https://i/v2.0","audience":"a"}"#).unwrap();
    assert!(without.client_id.is_none());
    assert!(without.scopes.is_empty());
    assert!(without.authorization_endpoint.is_none());
    assert!(without.token_endpoint.is_none());

    let with: OidcConfig = serde_json::from_str(
        r#"{
            "issuer":"https://i/v2.0","audience":"a",
            "client_id":"cid","scopes":["email","profile"],
            "authorization_endpoint":"https://i/authorize","token_endpoint":"https://i/token"
        }"#,
    )
    .unwrap();
    assert_eq!(with.client_id.as_deref(), Some("cid"));
    assert_eq!(
        with.scopes,
        vec!["email".to_string(), "profile".to_string()]
    );
    assert_eq!(
        with.authorization_endpoint.as_deref(),
        Some("https://i/authorize")
    );
    assert_eq!(with.token_endpoint.as_deref(), Some("https://i/token"));
}

// ── LoginModule trait wiring ─────────────────────────────────────────────────────────────────────

/// begin_login → Authorize URL, complete_login(code) → Exchange hop, complete_login(token_response)
/// → Identify: the whole core-driven flow the module drives.
#[test]
fn begin_and_complete_login_drive_the_full_flow() {
    let key = TestKey::generate(KID);
    let now = 1_700_000_000;
    let mut c = cfg("groups");
    c.authorization_endpoint = Some("https://idp.test/authorize".to_string());
    c.token_endpoint = Some("https://idp.test/token".to_string());
    let m = OidcModule::new(
        &c,
        "https://jwks.test/keys".to_string(),
        Box::new(FixtureFetcher::new(key.jwks())),
    );

    let begin = BeginLogin {
        redirect_uri: "https://busbar.test/auth/token".to_string(),
        state: "st".to_string(),
        code_challenge: "ch".to_string(),
        nonce: Some("nc".to_string()),
        scopes: vec!["offline_access".to_string()],
    };
    match m.begin_login(&begin) {
        LoginOutcome::Authorize(url) => {
            assert!(url.starts_with("https://idp.test/authorize?"), "{url}");
            // request-time scope folded in alongside openid + none configured
            assert!(url.contains("scope=openid%20offline_access"), "{url}");
        }
        other => panic!("expected Authorize, got {other:?}"),
    }

    // complete_login with a code ⇒ an Exchange hop the core runs.
    let cl = CompleteLogin {
        code: Some("the-code".to_string()),
        redirect_uri: Some("https://busbar.test/auth/token".to_string()),
        code_verifier: Some("the-verifier".to_string()),
        ..Default::default()
    };
    match m.complete_login(&cl) {
        LoginOutcome::Exchange(hop) => {
            assert_eq!(hop.url, "https://idp.test/token");
            assert_eq!(hop.secret_form_field.as_deref(), Some("client_secret"));
        }
        other => panic!("expected Exchange, got {other:?}"),
    }

    // complete_login with the token_response fed back ⇒ Identify.
    let body = serde_json::json!({ "id_token": key.mint(&base_claims(now)) }).to_string();
    let cl2 = CompleteLogin {
        token_response: Some(LoginHttpResponse { status: 200, body }),
        ..Default::default()
    };
    // Uses the real clock inside complete_login; base_claims exp is 'now'+3600 relative to the fixed
    // `now`, well in the past of the real clock, so drive identity_from_token_response directly for a
    // deterministic time instead — the code path is identical.
    match m.identity_from_token_response(cl2.token_response.as_ref().unwrap(), now, Instant::now())
    {
        LoginOutcome::Identify(p) => assert_eq!(p.id, "oidc:object-guid"),
        other => panic!("expected Identify, got {other:?}"),
    }
}

/// `complete_login`'s `token_response` arm, driven through `complete_login` ITSELF rather than
/// through the inner helper.
///
/// The round-trip test above reaches this behaviour via `identity_from_token_response` because the
/// helper takes an injectable clock and `complete_login` does not. That left the arm in
/// `complete_login` executed by no test at all: replacing its whole body with an unconditional
/// `LoginOutcome::Identify(...)` (that is, handing out an identity for ANY token-endpoint response,
/// with no signature and no claim check) kept the entire suite green. The e2e tests do not cover it
/// either, since they drive `authenticate`, not the login flow.
///
/// Mints against the REAL clock so `complete_login`'s internal `now_unix()` accepts it, and pairs
/// the positive case with a wrong-key negative so the test cannot pass on an unconditional accept.
#[test]
fn complete_login_verifies_the_token_response_and_rejects_a_forged_one() {
    let key = TestKey::generate(KID);
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut c = cfg("groups");
    c.authorization_endpoint = Some("https://idp.test/authorize".to_string());
    c.token_endpoint = Some("https://idp.test/token".to_string());
    let m = OidcModule::new(
        &c,
        "https://jwks.test/keys".to_string(),
        Box::new(FixtureFetcher::new(key.jwks())),
    );

    let good = serde_json::json!({ "id_token": key.mint(&base_claims(real_now)) }).to_string();
    match m.complete_login(&CompleteLogin {
        token_response: Some(LoginHttpResponse {
            status: 200,
            body: good,
        }),
        ..Default::default()
    }) {
        LoginOutcome::Identify(p) => assert_eq!(p.id, "oidc:object-guid"),
        other => panic!("a validly signed id_token must Identify, got {other:?}"),
    }

    // Same claims, DIFFERENT signing key, same kid. Only a real signature check rejects this, so
    // this is the half that fails if the arm ever stops verifying.
    let forged = TestKey::generate(KID);
    let bad = serde_json::json!({ "id_token": forged.mint(&base_claims(real_now)) }).to_string();
    match m.complete_login(&CompleteLogin {
        token_response: Some(LoginHttpResponse {
            status: 200,
            body: bad,
        }),
        ..Default::default()
    }) {
        LoginOutcome::Reject => {}
        other => panic!("an id_token signed by the wrong key must Reject, got {other:?}"),
    }

    // A non-2xx token-endpoint response must be refused before its body is ever parsed: an
    // `invalid_grant` error body carrying an attacker-supplied `id_token` field is otherwise
    // verified as though the exchange had succeeded. Every existing fixture used status 200.
    let error_body =
        serde_json::json!({ "error": "invalid_grant", "id_token": key.mint(&base_claims(real_now)) })
            .to_string();
    match m.complete_login(&CompleteLogin {
        token_response: Some(LoginHttpResponse {
            status: 400,
            body: error_body,
        }),
        ..Default::default()
    }) {
        LoginOutcome::Reject => {}
        other => panic!("a non-2xx token-endpoint response must Reject, got {other:?}"),
    }
}

/// Fail-closed: a module with no login endpoints (a verify-only deployment) rejects both login
/// steps rather than emitting a malformed authorize URL or exchange.
#[test]
fn login_fails_closed_without_endpoints() {
    let key = TestKey::generate(KID);
    let m = module_with(&key, "groups"); // cfg() leaves both endpoints None
    let begin = BeginLogin {
        redirect_uri: "https://busbar.test/auth/token".to_string(),
        state: "st".to_string(),
        code_challenge: "ch".to_string(),
        nonce: None,
        scopes: Vec::new(),
    };
    assert!(matches!(m.begin_login(&begin), LoginOutcome::Reject));

    let cl = CompleteLogin {
        code: Some("c".to_string()),
        redirect_uri: Some("r".to_string()),
        code_verifier: Some("v".to_string()),
        ..Default::default()
    };
    assert!(matches!(m.complete_login(&cl), LoginOutcome::Reject));

    // No code and no token_response is also a hard reject.
    assert!(matches!(
        m.complete_login(&CompleteLogin::default()),
        LoginOutcome::Reject
    ));
}
