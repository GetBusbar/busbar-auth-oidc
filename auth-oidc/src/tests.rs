// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Verification-logic tests. An in-test ES256 keypair (via `ring`) mints real tokens against a local

use super::*;
use crate::script::{ready, Idp, ME};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use busbar_contract::auth::CompleteLogin;
use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, KeyPair, RsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING, RSA_PKCS1_SHA256,
};
use std::sync::Arc;

/// The tests' current UNIX time in seconds, through the production mapping every clock reading
/// takes ([`clock_or_fail_closed`]): a reading before the epoch, or below the sanity floor, is
/// `i64::MAX`, which no token is judged against. Production reads the request's timestamp and the
/// host's `clock.now` instead.
pub(crate) fn now_unix() -> i64 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(i64::MAX);
    clock_or_fail_closed(t)
}

pub(crate) const ISSUER: &str = "https://login.microsoftonline.com/tenant-guid/v2.0";
pub(crate) const AUDIENCE: &str = "api://busbar-client-id";
const KID: &str = "test-key-1";

/// A ring ES256 signer + the JWKS fixture that verifies it.
pub(crate) struct TestKey {
    kp: EcdsaKeyPair,
    rng: SystemRandom,
    kid: String,
}

impl TestKey {
    pub(crate) fn generate(kid: &str) -> Self {
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
    pub(crate) fn jwks(&self) -> String {
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
    pub(crate) fn mint(&self, claims: &Value) -> String {
        let header = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": self.kid });
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig = self.kp.sign(&self.rng, signing_input.as_bytes()).unwrap();
        let s = URL_SAFE_NO_PAD.encode(sig.as_ref());
        format!("{signing_input}.{s}")
    }
}

/// The scripted IdP serving the JWKS (`crate::script`): a fixed body, swappable to simulate a key
type FixtureFetcher = Idp;

/// A module over a scripted IdP whose requests answer at once: the module's sans-IO answers, as
struct Module {
    m: OidcModule,
    idp: Arc<Idp>,
}

impl Module {
    fn new(c: &OidcConfig, idp: impl Into<Arc<Idp>>) -> Self {
        Self {
            m: OidcModule::new(c),
            idp: idp.into(),
        }
    }

    fn verify(&self, token: &str, now: i64, mono: Instant) -> AuthVerdict {
        ready(
            self.m
                .verify(Some(token), now, mono, &mut self.idp.at_once(Some(ME))),
        )
        .expect("the JWKS url is configured")
    }

    fn authenticate(&self, token: Option<&str>) -> AuthVerdict {
        let mut io = self.idp.at_once(Some(ME));
        ready(self.m.verify(token, now_unix(), Instant::now(), &mut io)).expect("no discovery")
    }

    fn begin_login(&self, req: &BeginLogin) -> LoginOutcome {
        let mut io = self.idp.at_once(Some(ME));
        ready(self.m.begin_login(req, Instant::now(), &mut io)).expect("no discovery")
    }

    /// 1.5.5's `complete_login`: a token response verified into an identity, else the callback's
    fn complete_login(&self, req: &CompleteLogin) -> LoginOutcome {
        let mut io = self.idp.at_once(Some(ME));
        if let Some(resp) = &req.token_response {
            return ready(self.m.identity_from_token_response(
                resp,
                now_unix(),
                Instant::now(),
                &mut io,
            ))
            .expect("no discovery");
        }
        match ready(self.m.token_exchange(
            req.code.as_deref(),
            req.redirect_uri.as_deref(),
            req.code_verifier.as_deref(),
            None,
            Instant::now(),
            &mut io,
        ))
        .expect("no discovery")
        {
            Some(request) => LoginOutcome::Exchange(busbar_contract::auth::LoginHop {
                method: "POST".to_string(),
                url: request.url.clone(),
                form: crate::script::wire(&request.form),
                secret_form_field: None,
                headers: Vec::new(),
            }),
            None => LoginOutcome::Reject,
        }
    }

    fn identity_from_token_response(
        &self,
        resp: &LoginHttpResponse,
        now: i64,
        mono: Instant,
    ) -> LoginOutcome {
        let mut io = self.idp.at_once(Some(ME));
        ready(
            self.m
                .identity_from_token_response(resp, now, mono, &mut io),
        )
        .expect("no discovery")
    }
}

/// The validated explicit JWKS URL, else the discovered URL.
fn resolve_jwks_url(c: &OidcConfig, idp: &Idp) -> Result<String, String> {
    check_jwks_url(c)?;
    ready(OidcModule::new(c).jwks_url(Instant::now(), &mut idp.at_once(Some(ME))))
        .map(std::borrow::Cow::into_owned)
}

/// 1.5.5's `resolve_login_endpoints`: explicit ones win, the others discovered.
fn resolve_login_endpoints(
    c: &OidcConfig,
    idp: &Idp,
) -> Result<(Option<String>, Option<String>), String> {
    let (m, now) = (OidcModule::new(c), Instant::now());
    let authorize = ready(m.authorization_endpoint(now, &mut idp.at_once(Some(ME))))?;
    let token = ready(m.token_endpoint(now, &mut idp.at_once(Some(ME))))?;
    Ok((authorize, token))
}

pub(crate) fn base_claims(now: i64) -> Value {
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

fn module_with(key: &TestKey, role_claim: &str) -> Module {
    Module::new(&cfg(role_claim), FixtureFetcher::new(key.jwks()))
}

#[test]
fn valid_token_identifies_with_groups() {
    let key = TestKey::generate(KID);
    let m = module_with(&key, "groups");
    let now = 1_700_000_000;
    let token = key.mint(&base_claims(now));
    match m.verify(&token, now, Instant::now()) {
        AuthVerdict::Identify(p) => {
            assert_eq!(p.id, "oidc-v2:aHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL3RlbmFudC1ndWlkL3YyLjA:object-guid");
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
        AuthVerdict::Identify(p) => assert_eq!(p.roles, vec!["Billing.Reader", "Billing.Admin"]),
        other => panic!("expected Identify, got {other:?}"),
    }
}

/// A provider can withdraw every signing key with a successful empty JWKS. Neither a request
/// refresh nor the proactive refresh may continue authenticating freshly minted old-key tokens.
#[test]
fn an_authoritative_empty_jwks_rejects_fresh_tokens_signed_by_a_withdrawn_key() {
    let key = TestKey::generate(KID);
    let now = 1_800_000_000;
    for proactive in [false, true] {
        let mut config = cfg("groups");
        config.jwks_ttl_secs = 60;
        let idp = Arc::new(Idp::new(key.jwks()));
        let module = Module::new(&config, idp.clone());
        let t0 = Instant::now();
        let original = key.mint(&base_claims(now));
        assert!(matches!(
            module.verify(&original, now, t0),
            AuthVerdict::Identify(_)
        ));
        idp.set_body(r#"{"keys":[]}"#.to_string());
        let refreshed = t0 + Duration::from_secs(61);
        if proactive {
            ready(
                module
                    .m
                    .refresh_ahead(refreshed, &mut idp.at_once(Some(ME))),
            )
            .expect("empty JWKS is a successful refresh");
        }
        let mut claims = base_claims(now + 61);
        claims["oid"] = serde_json::json!("new-credential-after-withdrawal");
        let fresh = key.mint(&claims);
        assert!(
            matches!(
                module.verify(&fresh, now + 61, refreshed),
                AuthVerdict::Reject
            ),
            "a fresh token cannot use a withdrawn key (proactive={proactive})"
        );
        assert_eq!(idp.calls(), 2, "one successful refresh; no fetch storm");

        // A subsequent real outage must not resurrect the removed key set.
        idp.set_answer(Err("provider unreachable".to_string()));
        let mut io = idp.at_once(Some(ME));
        assert!(
            ready(module.m.verify(
                Some(&fresh),
                now + 122,
                t0 + Duration::from_secs(122),
                &mut io
            ))
            .is_err(),
            "an outage has no old key to restore"
        );

        // Publishing a valid replacement key set restores service normally.
        idp.set_body(key.jwks());
        assert!(matches!(
            module.verify(&fresh, now + 183, t0 + Duration::from_secs(183)),
            AuthVerdict::Identify(_)
        ));
    }
}

#[test]
fn bad_signature_is_rejected() {
    let key = TestKey::generate(KID);
    let other = TestKey::generate(KID);
    let m = module_with(&key, "groups");
    let now = 1_700_000_000;

    let token = other.mint(&base_claims(now));
    assert!(matches!(
        m.verify(&token, now, Instant::now()),
        AuthVerdict::Reject
    ));
}

#[test]
fn tampered_payload_is_rejected() {
    let key = TestKey::generate(KID);
    let m = module_with(&key, "groups");
    let now = 1_700_000_000;
    let token = key.mint(&base_claims(now));

    let segs: Vec<&str> = token.split('.').collect();
    let mut forged = base_claims(now);
    forged["groups"] = serde_json::json!(["busbar-admins"]);
    let forged_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged).unwrap());
    let tampered = format!("{}.{}.{}", segs[0], forged_payload, segs[2]);
    assert!(matches!(
        m.verify(&tampered, now, Instant::now()),
        AuthVerdict::Reject
    ));
}

/// A fixed 2048-bit RSA test keypair (PKCS#8 DER, base64) and its public modulus `n` (base64url).
const RSA_PKCS8_B64: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDfiEloqx6vE5RaE/nwH9GrY9jdPiyJX5jElECQhH/8UoTGbDtjZ7WGPlp3mIieJ/iyjBtBtW/Z7csJxEMfrAP7Dew9sXv76RTVE2zZXqwxFt9xPtva7WlKqhZbt+NEQNR5Yo1dsaOaCJiLTd8iuRoJACqfuQpWrcSkpvf25oA+cdY/p+MyzVKMSCkYMX4YdIp1ie914N2i98SuymZBnv2oJHD93AGU4xLW7gUuDyn6HNywbcSXqRM8G8i8ouClkeaMpFEzewAJyTuBSCOalq0fZFYWUsCIR87wUkE+u6arHqxn+MhiOHn8JvU31ETUsAF6tth7bmaHXvdEaIf4/INfAgMBAAECggEAXclHy5OobxqO7vBcuIQRK5DcB4+zjfu/FBODt17weASDUuFMVZvIzMdSm8Uy5PCuZvNj6EDg6hXcT3+6DgrVLLuduBDEjWAw7mmVDOqs4nfPTitqgUOFHt+YO+k+gH+W5ksUNxB2LQWYQzJsAZyaMNaSC6vOi6mizNaFSWFSw1+lH1QQDriBwwUC9Q+gjD9DSbYlXrRNso3VfAr/FfenfDN1IB6F2IKaGwzPIVyDA4tHn54yzm4FA6HHY3/hRZFtzwnPXGdYcEduc38FXBG9NYzkX9H2NSYgJrsXJRpa27SjCWOi/jt9MgUUcBzqafjJdfVDUmlN8GvoEyJ2c9QhCQKBgQDxXYfiZjlEgjtFCbnyExc6nppl0Vrg8OL1BczNdgV6rRSoIDbUGoKvP8arwDtgZ4rTYEz/0F9wh8Sc7EmTbt3XJBOFt7xt1ldrWGA2HKYj5TzJqs3V87Fb4XNCFk234rjHxIzPe5wNQhk7VYH5X2y/UURyW9WOTr910JbijzY6UwKBgQDtFfPhAdOvV10UOfCSmrgP0tNuAJp3MKWx10trOQFQq5TxrQpZ1ME+4kl84VwX2fUmdF+4O14fe1PM+oCjke+V43susJwkz4n+danUpHbB25wCZBrwarUt52mgFzN5liy43w5Ypa2IX4A+1wQFEL1Y3yLcLblVaE0zIEidUeqpRQKBgEfxBuWWbo9a+euUAJaE1jGkwISEqD/PzPYXann7KZrtJ/EM2QrTdAxkSAU9YPVVJ23lkE3Xf/r8nL/hNfT54KmVmTQMFd/vOVNHnjXCyEp+s2WwwXV6E209f6s9FqEutMDmdsoJH/RbtUWYMQtxQ+qqgGpNsROfqTWmnLKe2Rz9AoGBAIXILm7Ybg/yN1azfxnq7lQXfjEDbCY3sDgTKb6eUyynNYvOPhoEoOsQG7G5JRNcbSY+4sh9z5XqLJZtAGvMbKpiy97Dz8hByDdrQ+L2zwCDIJyEymLBg+0cOREaJnTElgXX8Ct7idl7Mk3DXMRS9tWQTAZ8UqlsCqv/2pnTYJwVAoGATZFcTxzL2lSurJ1oi5VrpuxSdY9PrQsYAiZOJ+AqdiPk6jDgRWG2adEo+Ze9wlsn29NsFeoNVYoXv9lQHQWEP8v9z0AXfecM1yP+JPWYzvjlHQzZ1aNgI5ewWi2pB0G9LGm2iHDchQG72TjiRF+VFdIXFzBJmsXxW6vOncVIHdI=";
const RSA_N_B64URL: &str = "34hJaKserxOUWhP58B_Rq2PY3T4siV-YxJRAkIR__FKExmw7Y2e1hj5ad5iInif4sowbQbVv2e3LCcRDH6wD-w3sPbF7--kU1RNs2V6sMRbfcT7b2u1pSqoWW7fjREDUeWKNXbGjmgiYi03fIrkaCQAqn7kKVq3EpKb39uaAPnHWP6fjMs1SjEgpGDF-GHSKdYnvdeDdovfErspmQZ79qCRw_dwBlOMS1u4FLg8p-hzcsG3El6kTPBvIvKLgpZHmjKRRM3sACck7gUgjmpatH2RWFlLAiEfO8FJBPrumqx6sZ_jIYjh5_Cb1N9RE1LABerbYe25mh173RGiH-PyDXw";

/// A SECOND, unrelated RSA keypair — used to prove a signature made by the wrong key is rejected.
const RSA2_PKCS8_B64: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDHtV4BMlSKdJMOkqYcSTPbr7oZGiiFf1SzIk8or7EZ0B1jBARQt2SezW6lMrja/ARH5ERcCa5Yh9Nfzq0BSzK6rMfoEIQyIpkaDp6Khd1nsys7CRuQ/5TympIIwrQ63JYd6UhmXqNdVkaFwzOmcAGR4/UILPxpNOWLC35zuaMVAo2EKWvRxt0A6eyZeVfnWv9JcmJy2kXKySxo84e4O+2/mLOLighMuuQzj40JdJw8iQ+7sCvroNaXEPNiNPyTNmGt459zfxjDQBNdH3UU33ud46xW2HTu92S0tV2KXqtoUx+bP5RhBHKVOfuTn0QVKUxyUkBwai02oU6Yg9uBjt/lAgMBAAECggEANwSxVDUQc2BwTxh5qNtF7ST5aQb62OReakdudXAJo2nhXrDxm2ca0mEYNWzG3pWFfGTXrF+CZ6NryT5ADVYxMJp/LGC4erNraHFUnicI+xOyOj5lGMpAt6F7z+wMCRdSSAVHy+QQr5sgLKO9bAH5fL7Hd6wlEbrf7jGJccpXsmaYC7Azeo2tJnnpxXX0JoP6ytQrbIe9aEVtdoFiJuD+u23YLL0GhTDqzJDIgekftjUZOXPGjxrv+AE6O+q7u484yecviMAKpYfty2mf2tb1cz4OZDsQvxUm0UoZ8Le5tPS9dUxTAlqzF908sRrHx6urmxf6zA3yPohOdU6L1U/0NQKBgQDlFSV+0gzAlw5G1ip40xNxoLGISRgZHrceeSmRhTL4Ya35KvNkqHIEBlLbSjZzOPEF2kdzrQblvVno5jPLz+vnRklRBuMLRacKswLSel//tmqtg9+MMRKVWxMScRgmDXYe3dSaAvnw73ilipBc0Cb6ghQnMR+EBYy/nunl4eg/cwKBgQDfLKPySohchz/88ZPmWKmYmAXUNlU15wdaZ4gpjTXwf1tUCjjQVJ8VYh26AOV2XpGCmyNxAu3zIlKF+wUJtcPQ8293N8VWBZC0yp49nWSjpRDQZfj+moE0YfjosyKrr1z5yq2g7nFsucHIK7DJFymMlfFrsnEuRKAM9cJEoWXdRwKBgQCtgEqZtrT52G5zsBkS0arUUISlV9bsj5rZdaLKGDv2auS85o7ZGcrgyXlPpPGAawwBBsU/Ezk6HyNNhayNHLjqvQ0iVTj4fJR7QgFNMGos3hgFuu9A2pncjNHxEb7ccy2XSyOOUdrDZFvX5Q5ZfT1IVeS1mjroXtuu9cjo1yRziQKBgD9fe8anp4Uu2trG9sqoTrCIKs+SBixiSFJBqAa0lKaQY6y/olZ2UR5PWEWjT4WHYSaHS08iF9O84VYua8XQGaTSG8rsyVqeBfNwvfKdKSDXFKk467XQxfPMBlR92dCK4YoFJbzXONo4/XAMCA1ySFgllAKTD1SmJBTKDLpUYoqtAoGAFp9+Eg5Be4SJpAOmnRgHe2FckHmU8G/QQ4zPQL0KziI0YiVw7f7k7GFajapGFNbsVcFtTuQMyRbzmnxD7xJ/0mwEcmnEBLbJp21angie6I//9wNrmN/fkbhkinD7azUGIKulsyAzlXg5pmpnjZK/EJtzdZ6LrM2RwULrbEK+Ht8=";
const RSA2_N_B64URL: &str = "x7VeATJUinSTDpKmHEkz26-6GRoohX9UsyJPKK-xGdAdYwQEULdkns1upTK42vwER-REXAmuWIfTX86tAUsyuqzH6BCEMiKZGg6eioXdZ7MrOwkbkP-U8pqSCMK0OtyWHelIZl6jXVZGhcMzpnABkeP1CCz8aTTliwt-c7mjFQKNhClr0cbdAOnsmXlX51r_SXJictpFysksaPOHuDvtv5izi4oITLrkM4-NCXScPIkPu7Ar66DWlxDzYjT8kzZhreOfc38Yw0ATXR91FN97neOsVth07vdktLVdil6raFMfmz-UYQRylTn7k59EFSlMclJAcGotNqFOmIPbgY7f5Q";

/// A ring RS256 signer wrapping one of the fixed keypairs, plus the JWKS fixture (`n`/`e`) that
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

fn rsa_module(key: &RsaTestKey, role_claim: &str) -> Module {
    Module::new(&cfg(role_claim), FixtureFetcher::new(key.jwks()))
}

#[test]
fn valid_rs256_token_identifies() {
    let key = RsaTestKey::generate(KID);
    let m = rsa_module(&key, "groups");
    let now = 1_700_000_000;
    let token = key.mint(&base_claims(now));
    match m.verify(&token, now, Instant::now()) {
        AuthVerdict::Identify(p) => {
            assert_eq!(p.id, "oidc-v2:aHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL3RlbmFudC1ndWlkL3YyLjA:object-guid");
            assert_eq!(p.roles, vec!["11111111-aaaa", "22222222-bbbb"]);
        }
        other => panic!("expected Identify for a valid RS256 token, got {other:?}"),
    }
}

#[test]
fn bad_rs256_signature_is_rejected() {
    let served = RsaTestKey::generate(KID);
    let wrong = RsaTestKey::from_pkcs8(RSA2_PKCS8_B64, RSA2_N_B64URL, KID);
    let m = rsa_module(&served, "groups");
    let now = 1_700_000_000;
    let token = wrong.mint(&base_claims(now));
    assert!(
        matches!(m.verify(&token, now, Instant::now()), AuthVerdict::Reject),
        "an RS256 token signed by the wrong RSA key must be rejected"
    );
}

#[test]
fn tampered_rs256_payload_is_rejected() {
    let key = RsaTestKey::generate(KID);
    let m = rsa_module(&key, "groups");
    let now = 1_700_000_000;
    let token = key.mint(&base_claims(now));

    let segs: Vec<&str> = token.split('.').collect();
    let mut forged = base_claims(now);
    forged["groups"] = serde_json::json!(["busbar-admins"]);
    let forged_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged).unwrap());
    let tampered = format!("{}.{}.{}", segs[0], forged_payload, segs[2]);
    assert!(
        matches!(
            m.verify(&tampered, now, Instant::now()),
            AuthVerdict::Reject
        ),
        "a tampered payload under a valid RS256 header must be rejected"
    );
}

/// The RSA-keyed variant of the alg-confusion guard: against a real RSA JWKS key, both `alg: none`
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

/// Build a compact JWT with an arbitrary (attacker-controlled) `alg` header value and an arbitrary
fn token_with_alg(kid: &str, alg: &str, claims: &Value, sig: &[u8]) -> String {
    let header = serde_json::json!({ "alg": alg, "typ": "JWT", "kid": kid });
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    let s = URL_SAFE_NO_PAD.encode(sig);
    format!("{h}.{p}.{s}")
}

/// RFC 7515 §4.1.11: a token whose header marks a critical extension the verifier does not implement
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

    assert!(matches!(
        m.verify("sk-opaque-token", 1_700_000_000, Instant::now()),
        AuthVerdict::Pass
    ));
}

/// Malformed-but-dotted bearers are not this module's credential shape either (OIDC-21): too few
#[test]
fn malformed_but_dotted_bearers_pass() {
    let key = TestKey::generate(KID);
    let m = module_with(&key, "groups");
    let header = serde_json::json!({ "alg": "RSA-OAEP", "enc": "A256GCM", "kid": KID });
    let jwe_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let jwe = format!("{jwe_header}.AAAA.AAAA.AAAA.AAAA");
    for bearer in ["a.b", "a.b.c.d", jwe.as_str(), "!!.x.y"] {
        assert!(
            matches!(
                m.verify(bearer, 1_700_000_000, Instant::now()),
                AuthVerdict::Pass
            ),
            "{bearer:?} is not a compact JWS and must Pass"
        );
    }
}

#[test]
fn a_token_naming_this_issuer_with_a_malformed_header_is_rejected_not_passed() {
    let key = TestKey::generate(KID);
    let m = module_with(&key, "groups");
    let now = 1_700_000_000;
    let payload = |iss: &str| {
        let mut c = base_claims(now);
        c["iss"] = serde_json::json!(iss);
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&c).unwrap())
    };
    let mistyped = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","kid":12345}"#);
    let not_json = URL_SAFE_NO_PAD.encode(b"not json");
    for header in ["!!not-base64!!", not_json.as_str(), mistyped.as_str()] {
        let ours = format!("{header}.{}.c2ln", payload(ISSUER));
        assert!(
            matches!(m.verify(&ours, now, Instant::now()), AuthVerdict::Reject),
            "{header:?}: a token naming this issuer is ours to refuse"
        );
        let theirs = format!("{header}.{}.c2ln", payload("https://other.example"));
        assert!(
            matches!(m.verify(&theirs, now, Instant::now()), AuthVerdict::Pass),
            "{header:?}: a token naming another issuer passes"
        );
    }
}

#[test]
fn no_credential_passes() {
    let key = TestKey::generate(KID);
    let m = module_with(&key, "groups");
    assert!(matches!(m.authenticate(None), AuthVerdict::Pass));
}

#[test]
fn kid_rotation_triggers_bounded_refetch() {
    let old = TestKey::generate("old-kid");
    let new = TestKey::generate("new-kid");
    let fetcher = Arc::new(FixtureFetcher::new(old.jwks()));
    let m = Module::new(&cfg("groups"), fetcher.clone());
    let t0 = Instant::now();
    let now = 1_700_000_000;

    let tok_old = old.mint(&base_claims(now));
    assert!(matches!(
        m.verify(&tok_old, now, t0),
        AuthVerdict::Identify(_)
    ));
    assert_eq!(fetcher.calls(), 1);

    let both = serde_json::json!({
        "keys": [
            serde_json::from_str::<Value>(&old.jwks()).unwrap()["keys"][0].clone(),
            serde_json::from_str::<Value>(&new.jwks()).unwrap()["keys"][0].clone(),
        ]
    })
    .to_string();
    fetcher.set_body(both);

    let tok_new = new.mint(&base_claims(now));
    match m.verify(&tok_new, now, t0 + Duration::from_secs(61)) {
        AuthVerdict::Identify(p) => assert_eq!(p.id, "oidc-v2:aHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL3RlbmFudC1ndWlkL3YyLjA:object-guid"),
        other => panic!("expected Identify after rotation, got {other:?}"),
    }
    assert_eq!(fetcher.calls(), 2, "exactly one refetch for the rotation");

    let ghost = TestKey::generate("ghost-kid");
    let tok_ghost = ghost.mint(&base_claims(now));
    assert!(matches!(
        m.verify(&tok_ghost, now, t0 + Duration::from_secs(62)),
        AuthVerdict::Reject
    ));
    assert_eq!(fetcher.calls(), 2, "rate limit held off a second refetch");
}

/// 1.5.5's CREDENTIAL CACHE, now the module's own (v1.5.5 `crates/busbar/src/auth_cache.rs`; OIDC
#[test]
fn a_verified_identity_is_answered_from_the_verdict_cache_for_its_ttl() {
    let key = TestKey::generate(KID);
    let fetcher = Arc::new(FixtureFetcher::new(key.jwks()));
    let m = Module::new(&cfg("groups"), fetcher.clone());
    let t0 = Instant::now();
    let now = 1_700_000_000;
    let token = key.mint(&base_claims(now));
    assert!(matches!(
        m.verify(&token, now, t0),
        AuthVerdict::Identify(_)
    ));
    assert_eq!(fetcher.calls(), 1);

    fetcher.set_body(TestKey::generate("another-kid").jwks());
    match m.verify(&token, now + 299, t0 + Duration::from_secs(3601)) {
        AuthVerdict::Identify(p) => assert_eq!(p.id, "oidc-v2:aHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL3RlbmFudC1ndWlkL3YyLjA:object-guid"),
        other => panic!("expected the cached identity, got {other:?}"),
    }
    assert_eq!(fetcher.calls(), 1, "answered from the cache: no fetch");

    assert!(matches!(
        m.verify(&token, now + 300, t0 + Duration::from_secs(3602)),
        AuthVerdict::Reject
    ));
    assert_eq!(
        fetcher.calls(),
        2,
        "past its TTL the module judges it again"
    );

    assert!(matches!(
        m.verify(&token, now + 301, t0 + Duration::from_secs(3603)),
        AuthVerdict::Reject
    ));
}

#[test]
fn a_jwk_whose_alg_or_key_ops_forbid_it_does_not_verify() {
    let key = TestKey::generate(KID);
    let now = 1_700_000_000;
    let token = key.mint(&base_claims(now));
    let with = |member: &str, value: Value| {
        let mut set: Value = serde_json::from_str(&key.jwks()).unwrap();
        set["keys"][0][member] = value;
        Module::new(&cfg("groups"), FixtureFetcher::new(set.to_string()))
    };
    for (member, value) in [
        ("alg", serde_json::json!("ES384")),
        ("key_ops", serde_json::json!(["encrypt"])),
        ("key_ops", serde_json::json!([])),
    ] {
        assert!(
            matches!(
                with(member, value.clone()).verify(&token, now, Instant::now()),
                AuthVerdict::Reject
            ),
            "{member}: {value} must not verify an ES256 signature"
        );
    }
    for (member, value) in [
        ("alg", serde_json::json!("ES256")),
        ("key_ops", serde_json::json!(["verify"])),
    ] {
        assert!(
            matches!(
                with(member, value.clone()).verify(&token, now, Instant::now()),
                AuthVerdict::Identify(_)
            ),
            "{member}: {value} verifies"
        );
    }
}

#[test]
fn a_token_with_no_kid_uses_the_one_usable_key_for_its_alg() {
    let key = TestKey::generate("k1");
    let now = 1_700_000_000;
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&base_claims(now)).unwrap());
    let input = format!("{header}.{payload}");
    let sig = key.kp.sign(&key.rng, input.as_bytes()).unwrap();
    let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()));
    let ec = || serde_json::from_str::<Value>(&key.jwks()).unwrap()["keys"][0].clone();
    let rsa = serde_json::from_str::<Value>(&RsaTestKey::generate("r1").jwks()).unwrap()["keys"][0]
        .clone();
    let set = |keys: Vec<Value>| serde_json::json!({ "keys": keys }).to_string();

    for (what, keys) in [
        ("one EC key", vec![ec()]),
        ("one EC key beside an RSA key", vec![rsa.clone(), ec()]),
    ] {
        let m = Module::new(&cfg("groups"), FixtureFetcher::new(set(keys)));
        assert!(
            matches!(
                m.verify(&token, now, Instant::now()),
                AuthVerdict::Identify(_)
            ),
            "{what}: the one usable key verifies a kid-less token"
        );
    }
    let mut other =
        serde_json::from_str::<Value>(&TestKey::generate("k2").jwks()).unwrap()["keys"][0].clone();
    other["kid"] = serde_json::json!("k2");
    let m = Module::new(&cfg("groups"), FixtureFetcher::new(set(vec![ec(), other])));
    assert!(
        matches!(m.verify(&token, now, Instant::now()), AuthVerdict::Reject),
        "two usable EC keys: ambiguous"
    );
}

#[test]
fn a_cache_hit_answers_the_remaining_ttl() {
    let key = TestKey::generate(KID);
    let m = module_with(&key, "groups");
    let now = 1_700_000_000;
    let token = key.mint(&base_claims(now));
    let ttl = |at: i64| match m.verify(&token, at, Instant::now()) {
        AuthVerdict::Identify(p) => p.ttl_secs,
        other => panic!("expected Identify, got {other:?}"),
    };
    assert_eq!(ttl(now), Some(300));
    assert_eq!(ttl(now + 100), Some(200), "the hit answers what is left");
    assert_eq!(
        m.m.cached(&token, now + 299).map(|h| h.ttl_secs),
        Some(Some(1))
    );
}

#[test]
fn a_rejected_token_is_logged_at_info_with_a_reason() {
    let key = TestKey::generate(KID);
    let m = module_with(&key, "groups");
    let now = 1_700_000_000;
    let mut expired = base_claims(now);
    expired["exp"] = serde_json::json!(now - 3600);
    let forged = TestKey::generate(KID).mint(&base_claims(now));
    for (what, token, reason) in [
        ("expired", key.mint(&expired), "reason=\"claims\""),
        ("forged", forged, "reason=\"signature\""),
    ] {
        let (warn, all) = (
            crate::tests::diagnostics::WarnCapture::default(),
            crate::tests::diagnostics::WarnCapture::capturing_debug(),
        );
        for cap in [&warn, &all] {
            let verdict = tracing::subscriber::with_default(cap.subscriber(), || {
                m.verify(&token, now, Instant::now())
            });
            assert!(matches!(verdict, AuthVerdict::Reject), "{what}");
        }
        assert!(
            warn.messages().is_empty(),
            "{what}: not at warn: {:?}",
            warn.messages()
        );
        assert_eq!(
            all.count(reason),
            1,
            "{what}: once, with its reason: {:?}",
            all.messages()
        );
    }
}

#[test]
fn an_unreadable_host_clock_is_a_failure_not_a_bad_credential() {
    let key = TestKey::generate(KID);
    let m = module_with(&key, "groups");
    let token = key.mint(&base_claims(now_unix()));
    let cap = crate::tests::diagnostics::WarnCapture::default();
    let (bearer, login) = tracing::subscriber::with_default(cap.subscriber(), || {
        let bearer = ready(m.m.verify(
            Some(&token),
            i64::MAX,
            Instant::now(),
            &mut m.idp.at_once(Some(ME)),
        ));
        let resp = LoginHttpResponse {
            status: 200,
            body: serde_json::json!({ "id_token": token }).to_string(),
        };
        let login = ready(m.m.identity_from_token_response(
            &resp,
            i64::MAX,
            Instant::now(),
            &mut m.idp.at_once(Some(ME)),
        ));
        (bearer, login)
    });
    for (what, answered) in [("bearer", bearer.map(|_| ())), ("login", login.map(|_| ()))] {
        match answered {
            Err(e) => assert!(e.contains("clock"), "{what}: {e}"),
            Ok(()) => panic!("{what}: an unreadable clock is a failure, not a verdict"),
        }
    }
    assert!(cap.contains("clock"), "warned: {:?}", cap.messages());
}

/// A kid absent from the key set is rejected, and the bounded rotation refetch it triggers is
#[test]
fn an_unknown_kid_is_rejected_with_its_refetch_rate_limited() {
    let key = TestKey::generate("real-kid");
    let m = module_with(&key, "groups");
    let now = 1_700_000_000;

    let bogus = TestKey::generate("ghost-kid");
    let token = bogus.mint(&base_claims(now));
    assert!(matches!(
        m.verify(&token, now, Instant::now()),
        AuthVerdict::Reject
    ));
    assert_eq!(
        m.idp.calls(),
        1,
        "the initial fetch only: the refetch is rate-limited"
    );
}

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
        serde_json::json!([AUDIENCE, 42]),
        serde_json::json!([AUDIENCE, null]),
        serde_json::json!([AUDIENCE, { "aud": AUDIENCE }]),
        serde_json::json!([AUDIENCE, [AUDIENCE]]),
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
#[test]
fn a_present_but_unreadable_nbf_is_denied_rather_than_ignored() {
    let now = 1_700_000_000;
    for malformed in [
        serde_json::json!("2099-01-01T00:00:00Z"),
        serde_json::json!(true),
        serde_json::json!([now + 3600]),
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

    let mut absent = base_claims(now);
    absent.as_object_mut().unwrap().remove("nbf");
    assert!(verifier("groups").validate_claims(&absent, now).is_ok());
    let mut null_nbf = base_claims(now);
    null_nbf["nbf"] = serde_json::json!(null);
    assert!(
        verifier("groups").validate_claims(&null_nbf, now).is_ok(),
        "an explicit null nbf means absent, not malformed"
    );
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
    c["aud"] = serde_json::json!([AUDIENCE]);
    assert!(verifier("groups").validate_claims(&c, now).is_ok());
}

#[test]
fn a_bearer_aud_must_contain_the_audience_and_needs_no_azp() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["aud"] = serde_json::json!([AUDIENCE, "account"]);
    assert!(
        verifier("groups").validate_claims(&c, now).is_ok(),
        "a multi-audience access token containing the audience, no azp"
    );
    c["azp"] = serde_json::json!("web-frontend");
    assert!(
        verifier("groups").validate_claims(&c, now).is_ok(),
        "a multi-audience access token whose azp is the requesting client"
    );
    c["aud"] = serde_json::json!(["api://some-other-app", "account"]);
    let err = verifier("groups")
        .validate_claims(&c, now)
        .expect_err("an aud not containing the audience");
    assert!(err.contains("audience"), "got: {err}");
}

#[test]
fn an_id_token_aud_follows_the_oidc_azp_rules_against_the_client_id() {
    let key = TestKey::generate(KID);
    let mut c = cfg("groups");
    c.audience = "api://x".to_string();
    c.client_id = Some("cid".to_string());
    let m = Module::new(&c, FixtureFetcher::new(key.jwks()));
    let now = 1_700_000_000;
    let login = |aud: Value, azp: Option<&str>| {
        let mut claims = base_claims(now);
        claims["aud"] = aud;
        if let Some(azp) = azp {
            claims["azp"] = serde_json::json!(azp);
        }
        let resp = LoginHttpResponse {
            status: 200,
            body: serde_json::json!({ "id_token": key.mint(&claims) }).to_string(),
        };
        m.identity_from_token_response(&resp, now, Instant::now())
    };
    let multi = || serde_json::json!(["cid", "api://attacker-app"]);
    assert!(matches!(
        login(multi(), Some("cid")),
        LoginOutcome::Identify(_)
    ));
    assert!(matches!(login(multi(), None), LoginOutcome::Reject));
    assert!(matches!(
        login(multi(), Some("api://attacker-app")),
        LoginOutcome::Reject
    ));
    assert!(matches!(
        login(serde_json::json!("cid"), Some("cid")),
        LoginOutcome::Identify(_)
    ));
    assert!(
        matches!(
            login(serde_json::json!("cid"), Some("someone-else")),
            LoginOutcome::Reject
        ),
        "an azp present with a single aud must name the client (§3.1.3.7 step 5)"
    );
    for extra in [
        serde_json::json!(42),
        serde_json::json!(null),
        serde_json::json!({ "aud": "cid" }),
        serde_json::json!(["cid"]),
    ] {
        assert!(
            matches!(
                login(serde_json::json!(["cid", extra]), Some("cid")),
                LoginOutcome::Reject
            ),
            "a matching azp cannot make a mixed-type audience array valid"
        );
    }
}

#[test]
fn expired_denied() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["exp"] = serde_json::json!(now - 3600);
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
#[test]
fn fractional_exp_is_accepted_not_treated_as_absent() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["exp"] = serde_json::json!((now + 3600) as f64 + 0.5);
    assert!(
        verifier("groups").validate_claims(&c, now).is_ok(),
        "a fractional but future exp must be accepted, not treated as a missing exp"
    );
}

/// A fractional `exp` in the PAST is still expired (floor keeps it conservative).
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
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["exp"] = serde_json::json!(i64::MAX);

    let p = verifier("groups")
        .validate_claims(&c, now)
        .expect("exp at i64::MAX saturates and is accepted");
    assert_eq!(p.ttl_secs, Some(300), "ttl is still ceilinged");
}

#[test]
fn an_nbf_at_i64_min_does_not_panic() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["nbf"] = serde_json::json!(i64::MIN);

    assert!(
        verifier("groups").validate_claims(&c, now).is_ok(),
        "nbf at i64::MIN saturates and is accepted"
    );
}

/// The `exp` clock-skew window at its exact boundary, and the ttl clamp at 0 (OIDC-15): an `exp`
#[test]
fn exp_at_the_skew_boundary_verifies_with_ttl_zero_and_one_past_is_expired() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["exp"] = serde_json::json!(now - CLOCK_SKEW_SECS);
    let p = verifier("groups")
        .validate_claims(&c, now)
        .expect("exp within the skew window verifies");
    assert_eq!(
        p.ttl_secs,
        Some(0),
        "a just-expired-within-skew token is not cached"
    );

    c["exp"] = serde_json::json!(now - CLOCK_SKEW_SECS - 1);
    let err = verifier("groups")
        .validate_claims(&c, now)
        .expect_err("exp one second past the skew window is expired");
    assert!(err.contains("expired"), "got: {err}");
}

#[test]
fn unmapped_no_groups_still_identifies_with_empty_groups() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c.as_object_mut().unwrap().remove("groups");
    let p = verifier("groups").validate_claims(&c, now).unwrap();
    assert!(p.roles.is_empty());
    assert_eq!(
        p.id,
        "oidc-v2:aHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL3RlbmFudC1ndWlkL3YyLjA:object-guid"
    );
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

fn discovery_cfg() -> OidcConfig {
    OidcConfig {
        issuer: ISSUER.to_string(),
        audience: AUDIENCE.to_string(),
        jwks_url: None,
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
    let doc = serde_json::json!({
        "issuer": ISSUER,
        "jwks_uri": "https://login.microsoftonline.com/tenant-guid/discovery/v2.0/keys"
    });
    let fetcher = FixtureFetcher::new(doc.to_string());
    let url = resolve_jwks_url(&discovery_cfg(), &fetcher).expect("matching issuer must resolve");
    assert_eq!(
        url,
        "https://login.microsoftonline.com/tenant-guid/discovery/v2.0/keys"
    );
}

/// Without an issuer check, a discovery document resolves `jwks_uri` regardless of which host served
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

#[test]
fn subject_prefers_immutable_oid_over_mutable_preferred_username() {
    let now = 1_700_000_000;
    let c = base_claims(now);
    let p = verifier("groups").validate_claims(&c, now).unwrap();
    assert_eq!(
        p.id,
        "oidc-v2:aHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL3RlbmFudC1ndWlkL3YyLjA:object-guid",
        "oid must win over preferred_username"
    );
}

#[test]
fn subject_falls_back_to_sub_when_oid_absent() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c.as_object_mut().unwrap().remove("oid");
    let p = verifier("groups").validate_claims(&c, now).unwrap();
    assert_eq!(
        p.id,
        "oidc-v2:aHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL3RlbmFudC1ndWlkL3YyLjA:subject-guid",
        "sub must win when oid is absent"
    );
}

/// Falling through to the MUTABLE preferred_username when neither immutable claim is present would
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
#[test]
fn empty_string_subject_is_rejected_not_accepted_as_a_blank_identity() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    let obj = c.as_object_mut().unwrap();
    obj.remove("oid");
    obj.insert("sub".to_string(), serde_json::json!(""));
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
#[test]
fn blank_oid_falls_through_to_a_valid_sub() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["oid"] = serde_json::json!("");
    let p = verifier("groups")
        .validate_claims(&c, now)
        .expect("a blank oid must fall through to the valid sub");
    assert_eq!(
        p.id,
        "oidc-v2:aHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL3RlbmFudC1ndWlkL3YyLjA:subject-guid"
    );
}

#[test]
fn display_name_falls_back_to_preferred_username_when_name_claim_absent() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c.as_object_mut().unwrap().remove("name");
    let p = verifier("groups").validate_claims(&c, now).unwrap();
    assert_eq!(
        p.id,
        "oidc-v2:aHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL3RlbmFudC1ndWlkL3YyLjA:object-guid",
        "identity must still be the immutable oid"
    );
    assert_eq!(
        p.name.as_deref(),
        Some("alice@contoso.com"),
        "display name should still fall back to a mutable claim when name is absent"
    );
}

/// An un-ceilinged `ttl_secs` derived straight from a standard ~3600s-lived access token would WIDEN
#[test]
fn ttl_secs_is_ceilinged_even_for_a_long_lived_token() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["exp"] = serde_json::json!(now + 3600);
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
    c["exp"] = serde_json::json!(now + 30);
    let p = verifier("groups").validate_claims(&c, now).unwrap();
    assert_eq!(p.ttl_secs, Some(30));
}

/// The fail-closed MAPPING `now_unix` applies (OIDC-13): below the floor the reading becomes
#[test]
fn clock_or_fail_closed_maps_an_insane_reading_to_i64_max() {
    assert_eq!(clock_or_fail_closed(CLOCK_SANITY_FLOOR_UNIX - 1), i64::MAX);
    assert_eq!(clock_or_fail_closed(0), i64::MAX);
    assert_eq!(clock_or_fail_closed(i64::MIN), i64::MAX);
    assert_eq!(
        clock_or_fail_closed(CLOCK_SANITY_FLOOR_UNIX),
        CLOCK_SANITY_FLOOR_UNIX
    );
    assert_eq!(clock_or_fail_closed(1_800_000_000), 1_800_000_000);
}

#[test]
fn config_defaults_jwks_ttl_secs_to_3600() {
    let parsed: OidcConfig =
        serde_json::from_str(r#"{"issuer":"https://i/v2.0","audience":"a"}"#).unwrap();
    assert_eq!(
        parsed.jwks_ttl_secs, 3600,
        "jwks_ttl_secs must default to DEFAULT_TTL_SECS when the operator does not set it"
    );
}

#[test]
fn audience_array_form_without_configured_audience_is_denied() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["aud"] = serde_json::json!(["api://other-1", "api://other-2"]);
    let err = verifier("groups")
        .validate_claims(&c, now)
        .expect_err("an aud array that never contains the configured audience must be denied");
    assert!(err.contains("audience"), "got: {err}");
}

#[test]
fn nbf_exactly_at_the_skew_boundary_is_accepted() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["nbf"] = serde_json::json!(now + CLOCK_SKEW_SECS);
    assert!(
        verifier("groups").validate_claims(&c, now).is_ok(),
        "nbf exactly CLOCK_SKEW_SECS in the future must still be accepted (skew is inclusive)"
    );
}

#[test]
fn overage_names_marker_alone_is_overage_even_without_claim_sources() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["_claim_names"] = serde_json::json!({ "groups": "src1" });
    let err = verifier("groups")
        .validate_claims(&c, now)
        .expect_err("the _claim_names marker alone must trigger the overage rejection");
    assert!(err.contains("OVERAGE"), "got: {err}");
}

#[test]
fn overage_claim_names_present_but_without_groups_key_and_no_claim_sources_is_not_overage() {
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
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["_claim_sources"] = serde_json::json!({ "src1": {} });
    c["_claim_names"] = serde_json::json!({ "unrelated_claim": "src1" });
    let p = verifier("groups")
        .validate_claims(&c, now)
        .expect("a token that actually carries its groups claim must not be treated as overage");
    assert_eq!(p.roles, vec!["11111111-aaaa", "22222222-bbbb"]);
}

#[test]
fn role_claim_as_a_single_scalar_string_is_accepted() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["groups"] = serde_json::json!("single-role");
    let p = verifier("groups").validate_claims(&c, now).unwrap();
    assert_eq!(p.roles, vec!["single-role"]);
}

/// The authorize URL is an OAuth authorization-code request carrying PKCE + state + nonce, and
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

    assert!(
        url.contains("redirect_uri=https%3A%2F%2Fbusbar.test%2Fauth%2Ftoken"),
        "redirect_uri must be percent-encoded: {url}"
    );

    assert!(url.contains("scope=openid%20email%20profile"), "{url}");

    assert!(
        url.contains(&format!("client_id={}", pct(AUDIENCE))),
        "client_id must default to the audience: {url}"
    );

    assert!(
        !url.contains("client_secret") && !url.contains("secret"),
        "authorize URL must not carry a secret: {url}"
    );
}

/// The authorize URL's query encoding (OIDC-16): query delimiters in a value are escaped (never
#[test]
fn build_authorize_url_escapes_delimiters_dedups_openid_and_omits_an_absent_nonce() {
    let mut c = cfg("groups");
    c.authorization_endpoint = Some("https://idp.test/authorize".to_string());
    c.scopes = vec!["openid".to_string(), "email".to_string()];
    let url = build_authorize_url(&c, "https://busbar.test/cb", "a&b=c#d+e%", "ch", None);
    assert!(
        url.contains("&state=a%26b%3Dc%23d%2Be%25&"),
        "every query delimiter in a value must be percent-encoded: {url}"
    );
    assert!(
        url.contains("&scope=openid%20email&"),
        "a configured openid must not be repeated: {url}"
    );
    assert!(
        !url.contains("nonce="),
        "an absent nonce adds no parameter: {url}"
    );
    assert!(url.ends_with("&code_challenge_method=S256"), "{url}");
}

/// The login's own scopes are requested beside the configured ones, deduped against them, and every
/// entry goes out as given, but a blank one (configured or the login's own) is left out: a
/// scope-token is never empty (RFC 6749 §3.3).
#[test]
fn the_authorize_url_dedups_the_login_s_own_scopes_and_drops_blank_entries() {
    let mut c = cfg("groups");
    c.scopes = vec!["email".to_string(), " ".to_string()];
    let extra = [
        "email".to_string(),
        String::new(),
        "profile".to_string(),
        "\t".to_string(),
        "openid".to_string(),
    ];
    let url = authorize_url(
        &c,
        "https://idp.test/authorize",
        &extra,
        "https://busbar.test/cb",
        "st",
        "ch",
        Some("n"),
    );
    assert!(
        url.contains("&scope=openid%20email%20profile&"),
        "openid first, each scope once, blank entries left out: {url}"
    );
    assert!(url.starts_with("https://idp.test/authorize?response_type=code&"));
}

#[test]
fn build_authorize_url_keeps_an_existing_endpoint_query() {
    let mut c = cfg("groups");
    c.authorization_endpoint = Some("https://idp/authorize?p=b2c_1".to_string());
    let url = build_authorize_url(&c, "https://busbar.test/cb", "st", "ch", None);
    assert!(
        url.starts_with("https://idp/authorize?p=b2c_1&response_type=code&"),
        "the endpoint's own query must be kept and joined with '&': {url}"
    );
    assert_eq!(url.matches('?').count(), 1, "exactly one '?': {url}");
}

/// The token request is an authorization-code grant: its pairs in order, and the lent client
#[test]
fn the_token_form_is_an_authorization_code_grant_with_the_secret_sealed() {
    let url = "https://idp.test/token";
    let public = token_form(
        &cfg("groups"),
        url,
        "auth-code-1",
        "https://busbar.test/auth/token",
        "verifier-1",
        None,
    );
    let pairs = vec![
        ("grant_type", "authorization_code"),
        ("code", "auth-code-1"),
        ("redirect_uri", "https://busbar.test/auth/token"),
        ("code_verifier", "verifier-1"),
        ("client_id", AUDIENCE),
    ];
    let owned = |p: &[(&str, &str)]| -> Vec<(String, String)> {
        p.iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    };
    assert_eq!(crate::script::wire(&public), owned(&pairs));

    let secret = busbar_contract::abi::sdk::test_support::chip::cred("s3cret");
    let confidential = token_form(
        &cfg("groups"),
        url,
        "auth-code-1",
        "https://busbar.test/auth/token",
        "verifier-1",
        Some(&secret),
    );
    let mut with_secret = pairs.clone();
    with_secret.push(("client_secret", "s3cret"));
    assert_eq!(crate::script::wire(&confidential), owned(&with_secret));
    assert!(
        !format!("{confidential:?}").contains("s3cret"),
        "the form's Debug names keys only"
    );
}

/// A good token-endpoint response verifies its id_token to an `oidc:<sub>` identity with groups; a
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
            assert_eq!(p.id, "oidc-v2:aHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL3RlbmFudC1ndWlkL3YyLjA:object-guid");
            assert_eq!(p.roles, vec!["11111111-aaaa", "22222222-bbbb"]);
        }
        other => panic!("expected Identify, got {other:?}"),
    }

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

    let no_id = LoginHttpResponse {
        status: 200,
        body: serde_json::json!({ "access_token": "opaque" }).to_string(),
    };
    assert!(ready(m.m.identity_from_token_response(
        &no_id,
        now,
        Instant::now(),
        &mut m.idp.at_once(Some(ME)),
    ))
    .is_err());
}

#[test]
fn a_key_set_that_cannot_be_had_at_login_is_an_outage_not_a_decline() {
    let key = TestKey::generate(KID);
    let now = now_unix();
    let response = LoginHttpResponse {
        status: 200,
        body: serde_json::json!({ "id_token": key.mint(&base_claims(now)) }).to_string(),
    };
    let mut discovered = cfg("groups");
    discovered.jwks_url = None;
    for (c, cause) in [
        (cfg("groups"), "jwks unreachable"),
        (discovered, "issuer unreachable"),
    ] {
        let m = OidcModule::new(&c);
        let down = Idp::answering(Err(cause.to_string()));
        let cap = crate::tests::diagnostics::WarnCapture::default();
        let outcome = tracing::subscriber::with_default(cap.subscriber(), || {
            ready(m.identity_from_token_response(
                &response,
                now,
                Instant::now(),
                &mut down.at_once(Some(ME)),
            ))
        });
        match outcome {
            Err(e) => assert!(e.contains(cause), "{cause}: the error names why: {e}"),
            other => panic!("{cause}: an outage, never a declined login: {other:?}"),
        }
        assert!(
            cap.contains(cause),
            "{cause}: a warn names why: {:?}",
            cap.messages()
        );
    }
}

#[test]
fn a_key_set_that_cannot_be_had_fails_a_bearer_verify_and_a_mismatch_rejects_it() {
    let key = TestKey::generate(KID);
    let now = 1_700_000_000;
    let token = key.mint(&base_claims(now));
    let verify = |m: &OidcModule, idp: &Idp, token: &str, at: Instant| {
        ready(m.verify(Some(token), now, at, &mut idp.at_once(Some(ME))))
    };
    let t0 = Instant::now();

    let m = OidcModule::new(&cfg("groups"));
    let down = Idp::answering(Err("jwks unreachable".to_string()));
    for at in [t0, t0 + Duration::from_secs(1)] {
        match verify(&m, &down, &token, at) {
            Err(e) => assert!(!e.is_empty()),
            other => panic!("a key set that cannot be had is an outage: {other:?}"),
        }
    }

    let idp = Idp::new(key.jwks());
    let m = OidcModule::new(&cfg("groups"));
    assert!(matches!(
        verify(&m, &idp, &token, t0),
        Ok(AuthVerdict::Identify(_))
    ));
    idp.set_answer(Err("jwks unreachable".to_string()));
    let rotated = TestKey::generate("rotated-kid").mint(&base_claims(now));
    match verify(&m, &idp, &rotated, t0 + Duration::from_secs(61)) {
        Err(e) => assert!(!e.is_empty()),
        other => panic!("a failed rotation refetch is an outage: {other:?}"),
    }

    let idp = Idp::new(key.jwks());
    let m = OidcModule::new(&cfg("groups"));
    let ghost = TestKey::generate("ghost-kid").mint(&base_claims(now));
    assert!(matches!(
        verify(&m, &idp, &ghost, t0),
        Ok(AuthVerdict::Reject)
    ));
    let forged = TestKey::generate(KID).mint(&base_claims(now));
    assert!(matches!(
        verify(&m, &idp, &forged, t0),
        Ok(AuthVerdict::Reject)
    ));
}

#[test]
fn login_id_token_audience_is_the_client_id_not_the_bearer_audience() {
    let key = TestKey::generate(KID);
    let mut c = cfg("groups");
    c.audience = "api://x".to_string();
    c.client_id = Some("cid".to_string());
    let m = Module::new(&c, FixtureFetcher::new(key.jwks()));
    let now = 1_700_000_000;
    let response_for = |aud: &str| {
        let mut claims = base_claims(now);
        claims["aud"] = serde_json::json!(aud);
        LoginHttpResponse {
            status: 200,
            body: serde_json::json!({ "id_token": key.mint(&claims) }).to_string(),
        }
    };

    match m.identity_from_token_response(&response_for("cid"), now, Instant::now()) {
        LoginOutcome::Identify(p) => assert_eq!(p.id, "oidc-v2:aHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL3RlbmFudC1ndWlkL3YyLjA:object-guid"),
        other => panic!("an id_token whose aud is the client_id must Identify, got {other:?}"),
    }
    assert!(
        matches!(
            m.identity_from_token_response(&response_for("api://x"), now, Instant::now()),
            LoginOutcome::Reject
        ),
        "an id_token whose aud is only the bearer audience, not the client_id, must Reject"
    );

    let mut bearer = base_claims(now);
    bearer["aud"] = serde_json::json!("api://x");
    assert!(matches!(
        m.verify(&key.mint(&bearer), now, Instant::now()),
        AuthVerdict::Identify(_)
    ));
    bearer["aud"] = serde_json::json!("cid");
    assert!(matches!(
        m.verify(&key.mint(&bearer), now, Instant::now()),
        AuthVerdict::Reject
    ));
}

/// Discovery resolves BOTH login endpoints from the issuer's openid-configuration (issuer-match
#[test]
fn discovery_populates_authorization_and_token_endpoints() {
    let doc = serde_json::json!({
        "issuer": ISSUER,
        "jwks_uri": "https://login.microsoftonline.com/keys",
        "authorization_endpoint": "https://login.microsoftonline.com/authorize",
        "token_endpoint": "https://login.microsoftonline.com/token",
    });
    let fetcher = FixtureFetcher::new(doc.to_string());
    let (auth_ep, tok_ep) = resolve_login_endpoints(&discovery_cfg(), &fetcher)
        .expect("discovery must resolve the login endpoints");
    assert_eq!(
        auth_ep.as_deref(),
        Some("https://login.microsoftonline.com/authorize")
    );
    assert_eq!(
        tok_ep.as_deref(),
        Some("https://login.microsoftonline.com/token")
    );

    let evil = serde_json::json!({
        "issuer": "https://attacker.example/v2.0",
        "authorization_endpoint": "https://attacker.example/authorize",
        "token_endpoint": "https://attacker.example/token",
    });
    let evil_fetcher = FixtureFetcher::new(evil.to_string());
    assert!(resolve_login_endpoints(&discovery_cfg(), &evil_fetcher).is_err());
}

/// Explicit login endpoints win over discovered ones, and when BOTH are explicit no discovery
#[test]
fn explicit_login_endpoints_win_and_both_explicit_skip_discovery() {
    let doc = serde_json::json!({
        "issuer": ISSUER,
        "authorization_endpoint": "https://login.microsoftonline.com/discovered/authorize",
        "token_endpoint": "https://login.microsoftonline.com/discovered/token",
    });

    let fetcher = FixtureFetcher::new(doc.to_string());
    let mut c = discovery_cfg();
    c.authorization_endpoint = Some("https://explicit.test/authorize".to_string());
    let (auth_ep, tok_ep) = resolve_login_endpoints(&c, &fetcher).expect("resolves");
    assert_eq!(auth_ep.as_deref(), Some("https://explicit.test/authorize"));
    assert_eq!(
        tok_ep.as_deref(),
        Some("https://login.microsoftonline.com/discovered/token")
    );
    assert_eq!(fetcher.calls(), 1);

    let fetcher = FixtureFetcher::new(doc.to_string());
    c.token_endpoint = Some("https://explicit.test/token".to_string());
    let (auth_ep, tok_ep) = resolve_login_endpoints(&c, &fetcher).expect("resolves");
    assert_eq!(auth_ep.as_deref(), Some("https://explicit.test/authorize"));
    assert_eq!(tok_ep.as_deref(), Some("https://explicit.test/token"));
    assert_eq!(fetcher.calls(), 0, "both explicit must not fetch discovery");
}

/// ADDITIVE-CONFIG regression: a verify-only config that predates the login fields still parses (all
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

/// begin_login → Authorize URL, complete_login(code) → Exchange hop, complete_login(token_response)
#[test]
fn begin_and_complete_login_drive_the_full_flow() {
    let key = TestKey::generate(KID);
    let now = 1_700_000_000;
    let mut c = cfg("groups");
    c.authorization_endpoint = Some("https://idp.test/authorize".to_string());
    c.token_endpoint = Some("https://idp.test/token".to_string());
    let m = Module::new(&c, FixtureFetcher::new(key.jwks()));

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

            assert!(url.contains("scope=openid%20offline_access"), "{url}");
        }
        other => panic!("expected Authorize, got {other:?}"),
    }

    let cl = CompleteLogin {
        code: Some("the-code".to_string()),
        redirect_uri: Some("https://busbar.test/auth/token".to_string()),
        code_verifier: Some("the-verifier".to_string()),
        ..Default::default()
    };
    match m.complete_login(&cl) {
        LoginOutcome::Exchange(hop) => {
            assert_eq!(hop.url, "https://idp.test/token");
            assert!(
                hop.form.iter().all(|(k, _)| k != "client_secret"),
                "no secret lent: none sent"
            );
        }
        other => panic!("expected Exchange, got {other:?}"),
    }

    let body = serde_json::json!({ "id_token": key.mint(&base_claims(now)) }).to_string();
    let cl2 = CompleteLogin {
        token_response: Some(LoginHttpResponse { status: 200, body }),
        ..Default::default()
    };

    match m.identity_from_token_response(cl2.token_response.as_ref().unwrap(), now, Instant::now())
    {
        LoginOutcome::Identify(p) => assert_eq!(p.id, "oidc-v2:aHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL3RlbmFudC1ndWlkL3YyLjA:object-guid"),
        other => panic!("expected Identify, got {other:?}"),
    }
}

/// The module's token-response verification ([`OidcModule::identity_from_token_response`], which
#[test]
fn the_module_verifies_a_token_response_and_rejects_a_forged_one() {
    let key = TestKey::generate(KID);
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut c = cfg("groups");
    c.authorization_endpoint = Some("https://idp.test/authorize".to_string());
    c.token_endpoint = Some("https://idp.test/token".to_string());
    let m = Module::new(&c, FixtureFetcher::new(key.jwks()));

    let good = serde_json::json!({ "id_token": key.mint(&base_claims(real_now)) }).to_string();
    match m.complete_login(&CompleteLogin {
        token_response: Some(LoginHttpResponse {
            status: 200,
            body: good,
        }),
        ..Default::default()
    }) {
        LoginOutcome::Identify(p) => assert_eq!(p.id, "oidc-v2:aHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL3RlbmFudC1ndWlkL3YyLjA:object-guid"),
        other => panic!("a validly signed id_token must Identify, got {other:?}"),
    }

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

#[test]
fn an_idp_5xx_or_429_at_the_token_endpoint_is_an_outage_not_a_decline() {
    let key = TestKey::generate(KID);
    let m = Module::new(&cfg("groups"), FixtureFetcher::new(key.jwks()));
    let answered = |status: u16| {
        ready(m.m.identity_from_token_response(
            &LoginHttpResponse {
                status,
                // Even a credential-error body is an outage at 5xx/429; at 400 it declines.
                body: r#"{"error":"invalid_grant"}"#.to_string(),
            },
            0,
            Instant::now(),
            &mut m.idp.at_once(Some(ME)),
        ))
    };
    for status in [500, 502, 503, 429] {
        let Err(cause) = answered(status) else {
            panic!("{status} was not an outage");
        };
        assert!(cause.contains(&status.to_string()), "{cause}");
    }
    assert!(matches!(answered(400), Ok(LoginOutcome::Reject)));
}

#[test]
fn only_an_rfc_6749_credential_error_at_the_token_endpoint_is_a_decline() {
    let m = OidcModule::new(&cfg("groups"));
    let idp = Idp::new(String::new());
    let answered = |status: u16, body: &str| {
        let response = LoginHttpResponse {
            status,
            body: body.to_string(),
        };
        let (warn, all) = (
            crate::tests::diagnostics::WarnCapture::default(),
            crate::tests::diagnostics::WarnCapture::capturing_debug(),
        );
        let mut outcome = None;
        for cap in [&warn, &all] {
            outcome = Some(tracing::subscriber::with_default(cap.subscriber(), || {
                ready(m.identity_from_token_response(
                    &response,
                    1_700_000_000,
                    Instant::now(),
                    &mut idp.at_once(Some(ME)),
                ))
            }));
        }
        (outcome.expect("answered"), warn, all)
    };
    for (status, code, at_warn) in [
        (400, "invalid_grant", false),
        (400, "invalid_request", false),
        (401, "invalid_client", true),
        (400, "unauthorized_client", true),
    ] {
        let (outcome, warn, all) = answered(status, &format!(r#"{{"error":"{code}"}}"#));
        assert!(
            matches!(outcome, Ok(LoginOutcome::Reject)),
            "{status} {code}: declined, got {outcome:?}"
        );
        assert!(all.contains(code), "{code} is logged: {:?}", all.messages());
        assert_eq!(
            warn.contains(code),
            at_warn,
            "{code}: {:?}",
            warn.messages()
        );
    }
    for code in ["SECRET-made-up", "temporarily_unavailable", "server_error"] {
        let (outcome, _, all) = answered(400, &format!(r#"{{"error":"{code}"}}"#));
        assert!(
            matches!(&outcome, Err(cause) if cause.contains("400")),
            "{code}: not an RFC 6749 §5.2 credential error, so an outage: {outcome:?}"
        );
        assert!(
            !all.contains("SECRET"),
            "an unlisted code is not echoed: {:?}",
            all.messages()
        );
    }
    for (status, body) in [
        (302, ""),
        (403, r#"{"error":"invalid_grant"}"#),
        (404, "{}"),
        (408, ""),
        (400, "<html>bad gateway</html>"),
        (401, "{}"),
        (400, r#"{"error":42}"#),
    ] {
        let (outcome, warn, _) = answered(status, body);
        let Err(cause) = outcome else {
            panic!("{status} {body:?} is not a credential error: an outage, got {outcome:?}");
        };
        assert!(cause.contains(&status.to_string()), "{cause}");
        assert!(
            warn.contains(&status.to_string()),
            "{status}: logged at warn: {:?}",
            warn.messages()
        );
    }
}

#[test]
fn a_begin_login_with_no_nonce_is_refused_and_logged() {
    let mut c = cfg("groups");
    c.authorization_endpoint = Some("https://idp.test/authorize".to_string());
    let m = OidcModule::new(&c);
    let idp = Idp::new(String::new());
    for nonce in [None, Some(String::new())] {
        let begin = BeginLogin {
            redirect_uri: "https://busbar.test/auth/token".to_string(),
            state: "st".to_string(),
            code_challenge: "ch".to_string(),
            nonce: nonce.clone(),
            scopes: Vec::new(),
        };
        let cap = crate::tests::diagnostics::WarnCapture::default();
        let begun = tracing::subscriber::with_default(cap.subscriber(), || {
            ready(m.begin_login(&begin, Instant::now(), &mut idp.at_once(Some(ME))))
        });
        match begun {
            Err(e) => assert!(e.contains("nonce"), "{nonce:?}: {e}"),
            other => panic!("{nonce:?}: a login with no nonce is refused, got {other:?}"),
        }
        assert!(
            cap.contains("nonce"),
            "{nonce:?}: logged: {:?}",
            cap.messages()
        );
    }
}

/// Fail-closed: a module with no login endpoints configured whose issuer's discovery document names
#[test]
fn login_fails_closed_without_endpoints() {
    let doc = serde_json::json!({ "issuer": ISSUER, "jwks_uri": "https://jwks.test/keys" });
    let m = Module::new(&cfg("groups"), FixtureFetcher::new(doc.to_string()));
    let begin = BeginLogin {
        redirect_uri: "https://busbar.test/auth/token".to_string(),
        state: "st".to_string(),
        code_challenge: "ch".to_string(),
        nonce: Some("nc".to_string()),
        scopes: Vec::new(),
    };
    assert!(matches!(m.begin_login(&begin), LoginOutcome::Reject));

    let cl = CompleteLogin {
        code: Some("c".to_string()),
        redirect_uri: Some("r".to_string()),
        code_verifier: Some("v".to_string()),
        ..Default::default()
    };
    assert!(
        ready(m.m.token_exchange(
            cl.code.as_deref(),
            cl.redirect_uri.as_deref(),
            cl.code_verifier.as_deref(),
            None,
            Instant::now(),
            &mut m.idp.at_once(Some(ME)),
        ))
        .is_err(),
        "missing endpoint is unavailable, not a bad credential"
    );

    assert!(matches!(
        m.complete_login(&CompleteLogin::default()),
        LoginOutcome::Reject
    ));
}

#[test]
fn far_end_and_attacker_strings_are_escaped_and_capped_in_errors() {
    let hostile = format!("{}\n\u{1b}[31m", "A".repeat(300));
    let check = |what: &str, err: &str| {
        assert!(
            !err.contains('\n') && !err.contains('\u{1b}'),
            "{what}: not escaped: {err:?}"
        );
        assert!(
            !err.contains(&"A".repeat(65)),
            "{what}: not capped: {} chars",
            err.len()
        );
        assert!(
            err.contains(&format!("{}…", "A".repeat(64))),
            "{what}: named up to the cap: {err:?}"
        );
    };
    let key = TestKey::generate(KID);
    let now = 1_700_000_000;

    let c = crate::cache::JwksCache::new(Duration::from_secs(60), Duration::from_secs(3600));
    let idp = FixtureFetcher::new(key.jwks());
    let err = ready(c.with_key(
        "https://jwks.test/keys",
        &hostile,
        Instant::now(),
        &mut idp.at_once(Some(ME)),
        |_| Ok(()),
    ))
    .expect_err("an unknown kid");
    check("kid", err.message());

    let jwk = jwks::JwkSet::parse(&key.jwks()).unwrap().keys[0].clone();
    let token = token_with_alg(KID, &hostile, &base_claims(now), b"sig");
    let parts = jwt::split(&token).unwrap();
    check("alg", &jwt::verify_signature(&parts, &jwk).unwrap_err());

    let parts_with = |alg: &str, crit: Option<Vec<String>>| jwt::Parts {
        header: jwt::Header {
            alg: alg.to_string(),
            kid: None,
            crit,
        },
        payload: Vec::new(),
        signature: Vec::new(),
        signing_input: "h.p",
    };
    check(
        "crit",
        &jwt::verify_signature(&parts_with("ES256", Some(vec![hostile.clone()])), &jwk)
            .unwrap_err(),
    );
    let mut odd = jwk.clone();
    odd.kty = hostile.clone();
    odd.alg = None;
    check(
        "kty",
        &jwt::verify_signature(&parts_with("RS256", None), &odd).unwrap_err(),
    );
    match odd.material() {
        jwks::KeyMaterial::Unusable(e) => check("kty (material)", e),
        _ => panic!("an unknown kty is unusable"),
    }
    let mut curve = jwk.clone();
    curve.crv = Some(hostile.clone());
    check(
        "crv",
        &jwt::verify_signature(&parts_with("ES256", None), &curve).unwrap_err(),
    );

    let doc = serde_json::json!({ "issuer": hostile }).to_string();
    let err = discovery::check_document(
        &discovery_cfg(),
        "https://login.microsoftonline.com/x",
        Ok(doc),
    )
    .unwrap_err();
    check("discovery issuer", &err);
}

/// `kid` and `alg` come from the UNSIGNED header of an untrusted bearer, and the errors that carry
#[test]
fn untrusted_kid_and_alg_are_escaped_in_error_text() {
    let key = TestKey::generate(KID);
    let c = crate::cache::JwksCache::new(Duration::from_secs(60), Duration::from_secs(3600));
    let idp = FixtureFetcher::new(key.jwks());
    let err = ready(c.with_key(
        "https://jwks.test/keys",
        "a\nb\u{1b}[31m",
        Instant::now(),
        &mut idp.at_once(Some(ME)),
        |_| Ok(()),
    ))
    .expect_err("an unknown kid must not verify");
    assert!(
        !err.message().contains('\n') && !err.message().contains('\u{1b}'),
        "the unknown-kid error must escape the header's kid: {err:?}"
    );
    assert!(
        err.message().contains("a\\nb"),
        "the kid is still named, escaped: {err:?}"
    );

    let jwk = jwks::JwkSet::parse(&key.jwks()).unwrap().keys[0].clone();
    let token = token_with_alg(KID, "HS\n\u{1b}[31m", &base_claims(1_700_000_000), b"sig");
    let parts = jwt::split(&token).unwrap();
    let err = jwt::verify_signature(&parts, &jwk).unwrap_err();
    assert!(
        !err.contains('\n') && !err.contains('\u{1b}'),
        "the forbidden-alg error must escape the header's alg: {err:?}"
    );
    assert!(err.contains("unsupported/forbidden"), "{err}");
}

/// The discovery document's `issuer` is untrusted remote input, and the mismatch error carrying it
#[test]
fn a_hostile_discovery_issuer_is_escaped_in_the_mismatch_error() {
    let doc = serde_json::json!({ "issuer": "x\n\u{1b}]0;pwn\u{7}", "jwks_uri": "https://x" });
    let fetcher = FixtureFetcher::new(doc.to_string());
    for err in [
        resolve_login_endpoints(&discovery_cfg(), &fetcher).expect_err("mismatched issuer"),
        resolve_jwks_url(&discovery_cfg(), &fetcher).expect_err("mismatched issuer"),
    ] {
        assert!(
            err.contains("does not match the configured issuer"),
            "expected the issuer-mismatch error, got: {err:?}"
        );
        assert!(
            !err.contains('\n') && !err.contains('\u{1b}') && !err.contains('\u{7}'),
            "the remote issuer must be escaped in the error: {err:?}"
        );
    }
}

/// An explicit non-HTTPS JWKS URL is refused before fetching.
#[test]
fn an_explicit_non_https_jwks_url_is_refused_at_resolve_time() {
    let fetcher = FixtureFetcher::new(String::new());
    for bad in [
        "not a url",
        "ftp://idp.invalid/k",
        "http://idp.invalid/k",
        "http://127.0.0.1:8080/k",
    ] {
        let mut c = cfg("groups");
        c.jwks_url = Some(bad.to_string());
        let err = resolve_jwks_url(&c, &fetcher)
            .expect_err("a non-https jwks_url must be refused at boot");
        assert!(
            err.contains("jwks_url"),
            "the error must name jwks_url: {err}"
        );
        assert!(
            err.contains("https"),
            "the error must say https is required: {err}"
        );
    }
    let mut c = cfg("groups");
    c.jwks_url = Some("https://idp.invalid/keys".to_string());
    assert_eq!(
        resolve_jwks_url(&c, &fetcher).as_deref(),
        Ok("https://idp.invalid/keys")
    );
    assert_eq!(
        fetcher.calls(),
        0,
        "an explicit jwks_url never triggers discovery"
    );
}

/// One malformed JWK entry (here: no `kty`; there: a numeric `kid`) must not fail the parse of the
#[test]
fn one_malformed_jwk_is_skipped_not_fatal_to_the_whole_set() {
    let key = TestKey::generate("a");
    let key_set: Value = serde_json::from_str(&key.jwks()).unwrap();
    let good = key_set["keys"][0].clone();
    let body = serde_json::json!({ "keys": [{ "kid": "bad" }, { "kty": "EC", "kid": 7 }, good] });
    let body = body.to_string();
    let set = jwks::JwkSet::parse(&body).expect("one bad entry must not fail the whole JWKS");
    assert_eq!(set.find_all("a").count(), 1, "the valid key must survive");
    assert_eq!(set.keys.len(), 1, "the unusable entries are skipped");

    let m = Module::new(&cfg("groups"), FixtureFetcher::new(body));
    let now = 1_700_000_000;
    assert!(matches!(
        m.verify(&key.mint(&base_claims(now)), now, Instant::now()),
        AuthVerdict::Identify(_)
    ));

    let err = jwks::JwkSet::parse(r#"{"keys":[{"kid":"bad"}]}"#)
        .expect_err("a set with no usable key is still an error");
    assert!(err.contains("no keys"), "got: {err}");
}

/// THE NONCE BINDING (1.5.5's core check, now the plugin's): a token answer with no `id_token` binds
#[test]
fn an_id_token_binds_only_to_the_logins_nonce() {
    let token = |claims: serde_json::Value| {
        let part = |v: &serde_json::Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap());
        format!(
            "{}.{}.sig",
            part(&serde_json::json!({ "alg": "ES256" })),
            part(&claims)
        )
    };
    let body = |t: String| serde_json::json!({ "id_token": t }).to_string();
    assert!(nonce_binds(r#"{"error":"invalid_grant"}"#, "n-1"));
    assert!(nonce_binds("not json", "n-1"));
    assert!(nonce_binds(
        &body(token(serde_json::json!({ "nonce": "n-1" }))),
        "n-1"
    ));
    assert!(!nonce_binds(
        &body(token(serde_json::json!({ "nonce": "n-2" }))),
        "n-1"
    ));
    assert!(!nonce_binds(
        &body(token(serde_json::json!({ "sub": "x" }))),
        "n-1"
    ));
    assert!(!nonce_binds(&body("garbage".to_string()), "n-1"));
}

#[test]
fn the_token_response_holds_its_tokens_in_wiped_holders() {
    let r = TokenResponse::parse(
        r#"{"id_token":"a.b.c","access_token":"at","refresh_token":"rt","token_type":"Bearer","expires_in":3600,"x":{"y":[1]}}"#,
    )
    .expect("a token response parses, unknown members ignored");
    let held: &zeroize::Zeroizing<String> = r.id_token.as_ref().expect("an id_token");
    assert_eq!(held.as_str(), "a.b.c");
    let err = TokenResponse::parse("not json SECRET")
        .err()
        .expect("refused");
    assert!(!err.contains("SECRET"), "{err}");
}

#[test]
fn a_logged_idp_url_drops_its_userinfo() {
    let key = TestKey::generate(KID);
    let cap = crate::tests::diagnostics::WarnCapture::default();
    tracing::subscriber::with_default(cap.subscriber(), || {
        let c = crate::cache::JwksCache::new(Duration::from_secs(1), Duration::from_secs(1));
        let url = "https://jwks-user:SECRETPW@jwks.test/keys";
        let idp = Idp::answering(Err("down".to_string()));
        let t0 = Instant::now();
        let _ = ready(c.with_key(url, KID, t0, &mut idp.at_once(Some(ME)), |_| Ok(())));
        idp.set_body(key.jwks());
        let later = t0 + Duration::from_secs(2);
        let _ = ready(c.with_key(url, KID, later, &mut idp.at_once(Some(ME)), |_| Ok(())));
        idp.set_answer(Err("down".to_string()));
        let _ = ready(c.with_key(
            url,
            KID,
            later + Duration::from_secs(2),
            &mut idp.at_once(Some(ME)),
            |_| Ok(()),
        ));

        let mut d = discovery_cfg();
        d.issuer = "https://issuer-user:SECRETPW@login.example/v2.0".to_string();
        let m = OidcModule::new(&d);
        let _ = ready(m.jwks_url(Instant::now(), &mut idp.at_once(Some(ME))));
    });
    let logged = cap.messages().join("\n");
    assert!(logged.contains("JWKS fetch failed"), "{logged}");
    assert!(logged.contains("serving the previous key set"), "{logged}");
    assert!(logged.contains("OIDC discovery failed"), "{logged}");
    assert!(
        !logged.contains("SECRETPW"),
        "a URL's userinfo is logged: {logged}"
    );
}

#[test]
fn skipped_jwks_entries_are_counted_in_one_warn() {
    let key = TestKey::generate(KID);
    let good = serde_json::from_str::<Value>(&key.jwks()).unwrap()["keys"][0].clone();
    let body = serde_json::json!({
        "keys": [good, {"kid": "no-kty-SECRET"}, {"kty": 7}],
    })
    .to_string();
    let cap = crate::tests::diagnostics::WarnCapture::default();
    let set = tracing::subscriber::with_default(cap.subscriber(), || jwks::JwkSet::parse(&body))
        .expect("the usable key parses");
    assert_eq!(set.keys.len(), 1);
    assert_eq!(cap.messages().len(), 1, "one warn: {:?}", cap.messages());
    assert!(cap.contains("skipped=2"), "{:?}", cap.messages());
    assert!(!cap.contains("SECRET"), "{:?}", cap.messages());

    let quiet = crate::tests::diagnostics::WarnCapture::default();
    tracing::subscriber::with_default(quiet.subscriber(), || jwks::JwkSet::parse(&key.jwks()))
        .expect("parses");
    assert!(quiet.messages().is_empty(), "{:?}", quiet.messages());
}

/// Every refusal of the browser login's token response is explained in the plugin's log, by status
#[test]
fn a_refused_token_response_is_logged_with_its_reason() {
    let m = OidcModule::new(&cfg("groups"));
    let idp = Idp::new(String::new());
    let now = 1_700_000_000;
    for (status, body, reason) in [
        (400, r#"{"error":"invalid_grant"}"#, "status=400"),
        (200, "not-json-SECRETBODY", "not JSON"),
        (200, r#"{"access_token":"x"}"#, "carries no id_token"),
    ] {
        let response = LoginHttpResponse {
            status,
            body: body.to_string(),
        };
        let cap = crate::tests::diagnostics::WarnCapture::capturing_debug();
        let outcome = tracing::subscriber::with_default(cap.subscriber(), || {
            ready(m.identity_from_token_response(
                &response,
                now,
                Instant::now(),
                &mut idp.at_once(Some(ME)),
            ))
        });
        assert_eq!(matches!(outcome, Ok(LoginOutcome::Reject)), status == 400);
        assert_eq!(outcome.is_err(), status == 200);
        let logged = cap.messages().join("\n");
        assert!(logged.contains(reason), "{reason}: not logged: {logged:?}");
        assert!(
            !logged.contains("SECRETBODY"),
            "the body leaked: {logged:?}"
        );
    }
}

/// A callback that cannot be exchanged says why in the plugin's log.
#[test]
fn a_refused_token_exchange_is_logged_with_its_reason() {
    let mut c = cfg("groups");
    c.token_endpoint = Some("https://idp.test/token".to_string());
    let idp = Idp::new(String::new());
    let run = |m: &OidcModule, code: Option<&str>| {
        let cap = crate::tests::diagnostics::WarnCapture::capturing_debug();
        let out = tracing::subscriber::with_default(cap.subscriber(), || {
            ready(m.token_exchange(
                code,
                Some("https://busbar.test/cb"),
                None,
                None,
                Instant::now(),
                &mut idp.at_once(Some(ME)),
            ))
        });
        assert!(matches!(out, Ok(None)));
        cap.messages().join("\n")
    };
    let logged = run(&OidcModule::new(&c), None);
    assert!(
        logged.contains("code") && logged.contains("code_verifier"),
        "absent fields are named: {logged:?}"
    );
    let mut none = cfg("groups");
    none.jwks_url = None;
    none.token_endpoint = None;
    idp.set_body(serde_json::json!({ "issuer": ISSUER }).to_string());
    let mut io = idp.at_once(Some(ME));
    let cap = crate::tests::diagnostics::WarnCapture::default();
    let out = tracing::subscriber::with_default(cap.subscriber(), || {
        ready(OidcModule::new(&none).token_exchange(
            Some("c"),
            Some("r"),
            Some("v"),
            None,
            Instant::now(),
            &mut io,
        ))
    });
    assert!(out.is_err());
    assert!(
        cap.contains("names none"),
        "no endpoint is explained: {:?}",
        cap.messages()
    );
}

/// The host clock's sentinel is refused outright, even by a token whose `exp` saturates, and the
#[test]
fn the_clock_sentinel_is_refused_even_for_an_exp_at_i64_max() {
    let mut c = base_claims(0);
    c["exp"] = serde_json::json!(i64::MAX);
    let err = verifier("groups")
        .validate_claims(&c, i64::MAX)
        .expect_err("a broken clock must never verify a token");
    assert!(err.contains("host clock"), "names the clock: {err}");
}

/// The constant-time fold zips, so it truncates to the shorter side: only the length check stops a
#[test]
fn an_id_token_nonce_of_a_different_length_does_not_bind() {
    let token = |nonce: &str| {
        let part = |v: &serde_json::Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap());
        format!(
            "{}.{}.sig",
            part(&serde_json::json!({ "alg": "ES256" })),
            part(&serde_json::json!({ "nonce": nonce }))
        )
    };
    let body = |nonce: &str| serde_json::json!({ "id_token": token(nonce) }).to_string();

    assert!(!nonce_binds(&body("n-1"), "n-1-and-more"));

    assert!(!nonce_binds(&body("n-1-and-more"), "n-1"));

    assert!(!nonce_binds(&body(""), "n-1"));

    assert!(nonce_binds(&body("n-1"), "n-1"));
}

/// END-USER DECLINES LOG AT INFO, operator-actionable conditions at WARN (the fleet's levels, as
#[test]
fn an_end_user_decline_logs_at_info_and_an_idp_failure_at_warn() {
    let mut c = cfg("groups");
    c.token_endpoint = Some("https://idp.test/token".to_string());
    let m = OidcModule::new(&c);
    let idp = Idp::new(String::new());
    let refused = |status: u16| {
        let response = LoginHttpResponse {
            status,
            body: r#"{"error":"invalid_grant"}"#.to_string(),
        };
        let (warn, all) = (
            crate::tests::diagnostics::WarnCapture::default(),
            crate::tests::diagnostics::WarnCapture::capturing_debug(),
        );
        for cap in [&warn, &all] {
            let _ = tracing::subscriber::with_default(cap.subscriber(), || {
                ready(m.identity_from_token_response(
                    &response,
                    1_700_000_000,
                    Instant::now(),
                    &mut idp.at_once(Some(ME)),
                ))
            });
        }
        let said = "OIDC token endpoint";
        (warn.contains(said), all.contains(said))
    };
    assert_eq!(refused(400), (false, true), "a 4xx is the user's: info");
    assert_eq!(refused(503), (true, true), "a 5xx is the IdP's: warn");

    let (warn, all) = (
        crate::tests::diagnostics::WarnCapture::default(),
        crate::tests::diagnostics::WarnCapture::capturing_debug(),
    );
    for cap in [&warn, &all] {
        tracing::subscriber::with_default(cap.subscriber(), || {
            ready(m.token_exchange(
                None,
                Some("https://busbar.test/cb"),
                Some("v"),
                None,
                Instant::now(),
                &mut idp.at_once(Some(ME)),
            ))
        })
        .expect("no discovery");
    }
    assert!(
        !warn.contains("lacks fields"),
        "a bare callback is the user's: info"
    );
    assert!(all.contains("lacks fields"), "and it is still recorded");
}

const ISSUER_B: &str = "https://idp-b.example/realms/b";
const AUDIENCE_B: &str = "busbar-b";

/// How a chain of modules ended: admitted by position `i`, denied by position `i`'s Reject, or
/// denied at the chain's end with no position claiming the token.
#[derive(Debug, PartialEq)]
enum Walked {
    Admitted(usize, String),
    Refused(usize),
    Unclaimed,
}

/// The kernel's chain walk over `modules`, each judging `token` in turn.
fn chain(modules: &[&Module], token: &str, now: i64) -> Walked {
    for (i, m) in modules.iter().enumerate() {
        match m.verify(token, now, Instant::now()) {
            AuthVerdict::Identify(p) => return Walked::Admitted(i, p.id),
            AuthVerdict::Reject => return Walked::Refused(i),
            AuthVerdict::Pass => {}
        }
    }
    Walked::Unclaimed
}

/// Provider A (the Entra fixture issuer) and provider B (a second issuer, its own key and
fn two_providers() -> (TestKey, Module, TestKey, Module) {
    let key_a = TestKey::generate("kid-a");
    let key_b = TestKey::generate("kid-b");
    let a = Module::new(&cfg("groups"), FixtureFetcher::new(key_a.jwks()));
    let mut cfg_b = cfg("groups");
    cfg_b.issuer = ISSUER_B.to_string();
    cfg_b.audience = AUDIENCE_B.to_string();
    cfg_b.jwks_url = Some("https://idp-b.example/keys".to_string());
    let b = Module::new(&cfg_b, FixtureFetcher::new(key_b.jwks()));
    (key_a, a, key_b, b)
}

fn claims_of(issuer: &str, audience: &str, now: i64) -> Value {
    let mut c = base_claims(now);
    c["iss"] = serde_json::json!(issuer);
    c["aud"] = serde_json::json!(audience);
    c
}

/// A token provider B minted passes provider A (another issuer's: not A's credential, and A
#[test]
fn a_token_of_the_second_provider_passes_the_first_and_is_admitted_by_the_second() {
    let (key_a, a, key_b, b) = two_providers();
    let now = 1_700_000_000;
    let token = key_b.mint(&claims_of(ISSUER_B, AUDIENCE_B, now));
    let cap = crate::tests::diagnostics::WarnCapture::capturing_debug();
    let walked =
        tracing::subscriber::with_default(cap.subscriber(), || chain(&[&a, &b], &token, now));
    assert_eq!(
        walked,
        Walked::Admitted(
            1,
            "oidc-v2:aHR0cHM6Ly9pZHAtYi5leGFtcGxlL3JlYWxtcy9i:object-guid".to_string()
        )
    );
    assert_eq!(
        a.idp.calls(),
        0,
        "A judges another issuer's token without fetching its keys"
    );
    assert!(
        cap.contains("not this provider's issuer"),
        "A's pass is logged, not silent"
    );

    let token_a = key_a.mint(&base_claims(now));
    assert_eq!(
        chain(&[&b, &a], &token_a, now),
        Walked::Admitted(1, "oidc-v2:aHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL3RlbmFudC1ndWlkL3YyLjA:object-guid".to_string())
    );
}

/// A token CLAIMING provider A's issuer but not signed by A's key is A's to judge: A refuses it
#[test]
fn a_token_claiming_the_first_providers_issuer_with_a_bad_signature_is_refused_by_it_and_never_reaches_the_second(
) {
    let (key_a, a, key_b, b) = two_providers();
    let now = 1_700_000_000;

    let forged = {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"JWT","kid":"kid-a"}"#);
        let payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims_of(ISSUER, AUDIENCE, now)).unwrap());
        let input = format!("{header}.{payload}");
        let sig = key_b.kp.sign(&key_b.rng, input.as_bytes()).unwrap();
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
    };
    let cap = crate::tests::diagnostics::WarnCapture::capturing_debug();
    let walked =
        tracing::subscriber::with_default(cap.subscriber(), || chain(&[&a, &b], &forged, now));
    assert_eq!(walked, Walked::Refused(0));
    assert_eq!(b.idp.calls(), 0, "B never judged it");
    assert!(
        cap.contains("OIDC token rejected") && cap.contains("JWT signature verification failed"),
        "A's refusal names the signature: {:?}",
        cap.messages()
    );

    for c in [
        claims_of(ISSUER, AUDIENCE_B, now),
        claims_of(ISSUER, AUDIENCE, now - 7200),
    ] {
        assert_eq!(chain(&[&a, &b], &key_a.mint(&c), now), Walked::Refused(0));
    }
}

/// A token naming an issuer neither provider is passes both, and the chain's end refuses it.
#[test]
fn a_token_of_an_unknown_issuer_is_refused_at_the_chains_end() {
    let (_, a, key_b, b) = two_providers();
    let now = 1_700_000_000;
    let stranger = TestKey::generate("kid-c");
    for token in [
        stranger.mint(&claims_of("https://idp-c.example", AUDIENCE, now)),
        key_b.mint(&claims_of("https://idp-c.example", AUDIENCE_B, now)),
        {
            let mut c = base_claims(now);
            c.as_object_mut().unwrap().remove("iss");
            stranger.mint(&c)
        },
    ] {
        assert_eq!(chain(&[&a, &b], &token, now), Walked::Unclaimed);
    }
    assert_eq!(
        a.idp.calls() + b.idp.calls(),
        0,
        "no keys fetched for a stranger"
    );
}

#[test]
fn a_begin_login_with_no_authorize_endpoint_is_logged() {
    let mut none = cfg("groups");
    none.authorization_endpoint = None;
    let idp = Idp::new(serde_json::json!({ "issuer": ISSUER }).to_string());
    let begin = BeginLogin {
        redirect_uri: "https://busbar.test/auth/token".to_string(),
        state: "st".to_string(),
        code_challenge: "ch".to_string(),
        nonce: Some("nc".to_string()),
        scopes: Vec::new(),
    };
    let cap = crate::tests::diagnostics::WarnCapture::default();
    let out = tracing::subscriber::with_default(cap.subscriber(), || {
        ready(OidcModule::new(&none).begin_login(
            &begin,
            Instant::now(),
            &mut idp.at_once(Some(ME)),
        ))
    });
    assert!(matches!(out, Ok(LoginOutcome::Reject)));
    let logged = cap.messages().join("\n");
    assert!(
        logged.contains("authorization_endpoint") && logged.contains("module=\"oidc\""),
        "the refusal is explained: {logged:?}"
    );
}

#[test]
fn malformed_role_values_are_reported_without_changing_valid_roles_or_echoing_claims() {
    let cap = crate::tests::diagnostics::WarnCapture::default();
    let value = serde_json::json!(["admin", {"SecretRoleClaim":true}, 7]);
    let roles =
        tracing::subscriber::with_default(cap.subscriber(), || extract_string_list(Some(&value)));
    assert_eq!(roles, vec!["admin"]);
    assert!(cap.contains("role claim"));
    assert!(!cap.contains("SecretRoleClaim"));
}

#[test]
fn an_unreadable_idp_document_is_refused_without_echoing_it() {
    let Err(err) = crate::jwks::JwkSet::parse(r#"{"keys":"Zq7distinctiveValue"}"#) else {
        panic!("refused");
    };
    assert!(err.starts_with("invalid JWKS document: "), "{err}");
    assert!(!err.contains("Zq7distinctiveValue"), "echoed: {err}");
    assert!(err.contains("line 1"), "where is kept: {err}");

    let err = crate::discovery::check_document(
        &cfg("groups"),
        "https://idp.test/.well-known/openid-configuration",
        Ok(r#"{"issuer": Zq7distinctiveValue}"#.to_string()),
    )
    .expect_err("refused");
    assert!(
        err.starts_with("OIDC discovery document is not JSON: "),
        "{err}"
    );
    assert!(!err.contains("Zq7distinctiveValue"), "echoed: {err}");
    assert!(err.contains("withheld"), "{err}");
}

#[path = "tests/diagnostics.rs"]
pub(crate) mod diagnostics;

#[test]
fn verified_issuer_namespaces_equal_subjects_and_survives_key_rotation() {
    let now = 1_700_000_000;
    for use_oid in [false, true] {
        let key_a = TestKey::generate("issuer-a");
        let key_b = TestKey::generate("issuer-b");
        let key_rotated = TestKey::generate("issuer-a-rotated");
        let config_a = cfg("groups");
        let mut config_b = cfg("groups");
        config_b.issuer = "https://second-issuer.example/tenant".into();
        let a = Module::new(&config_a, FixtureFetcher::new(key_a.jwks()));
        let b = Module::new(&config_b, FixtureFetcher::new(key_b.jwks()));
        let rotated = Module::new(&config_a, FixtureFetcher::new(key_rotated.jwks()));
        let mut claims_a = base_claims(now);
        if !use_oid {
            claims_a.as_object_mut().unwrap().remove("oid");
        }
        let mut claims_b = claims_a.clone();
        claims_b["iss"] = serde_json::json!(config_b.issuer);
        let token_a = key_a.mint(&claims_a);
        let token_b = key_b.mint(&claims_b);
        // The first provider passes a foreign issuer so both providers can coexist.
        assert!(matches!(
            a.verify(&token_b, now, Instant::now()),
            AuthVerdict::Pass
        ));
        assert!(matches!(
            b.verify(&token_a, now, Instant::now()),
            AuthVerdict::Pass
        ));
        let identify =
            |module: &Module, token: &str| match module.verify(token, now, Instant::now()) {
                AuthVerdict::Identify(p) => p.id,
                other => panic!("the actual signature and issuer must verify: {other:?}"),
            };
        let actor_a = identify(&a, &token_a);
        let actor_b = identify(&b, &token_b);
        assert_ne!(
            actor_a, actor_b,
            "equal subjects from independent issuers are different actors"
        );
        assert!(
            !actor_a.contains('/'),
            "issuer qualification must remain a safe self-serve subject"
        );
        assert!(!actor_a.chars().any(char::is_control));
        assert!(actor_a.starts_with("oidc-v2:"));
        assert!(
            !actor_a.starts_with("oidc:"),
            "no old oidc:subject actor can alias a new actor"
        );
        assert_eq!(actor_a, identify(&a, &token_a), "cached identity is stable");
        claims_a["name"] = serde_json::json!("renamed connector");
        claims_a["exp"] = serde_json::json!(now + 300);
        assert_eq!(
            actor_a,
            identify(&rotated, &key_rotated.mint(&claims_a)),
            "issuer key and token rotation preserve actor identity"
        );
    }
}

#[test]
fn issuer_subject_framing_cannot_alias_at_a_delimiter() {
    let now = 1_700_000_000;
    let actor = |issuer: &str, subject: &str| {
        let mut claims = base_claims(now);
        claims.as_object_mut().unwrap().remove("oid");
        claims["iss"] = serde_json::json!(issuer);
        claims["sub"] = serde_json::json!(subject);
        OidcVerifier::new(issuer, AUDIENCE, "groups")
            .validate_claims(&claims, now)
            .unwrap()
            .id
    };
    assert_ne!(
        actor("https://issuer.example/realm", "other:connector"),
        actor("https://issuer.example/realm:other", "connector")
    );
}
