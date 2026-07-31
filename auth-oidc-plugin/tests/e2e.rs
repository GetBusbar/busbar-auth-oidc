// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! End-to-end coverage of the `busbar-auth-oidc-plugin` cdylib loaded over the REAL loader `kind:auth`
//! seam (`busbar_plugin_loader::auth::load_auth_from_bytes`) — the exact seam busbar's engine uses.
//! This is not a stub: it stands up a genuine local HTTPS JWKS fixture (a real self-signed cert minted
//! with `rcgen`, served over a real `rustls` TLS listener), mints a real ES256-signed JWT with `ring`,
//! and `dlopen`s the actually-built plugin cdylib to verify it end to end — a genuine JWKS fetch, a
//! genuine signature verification, and a genuine claim-to-`Principal` mapping across the real C ABI.
//!
//! Ported from `busbarAI`'s `crates/plugin-loader/src/lib.rs`
//! (`load_and_exercise_auth_oidc_plugin_success` /
//! `load_and_exercise_auth_oidc_plugin_bad_config_fails_over_abi`), the only over-the-ABI coverage of
//! the `kind: auth` dlopen seam, now hosted here as this plugin's own end-to-end test suite.

use busbar_plugin_abi::kind as abi_kind;
use busbar_plugin_loader::{auth::load_auth_from_bytes, plugin_library_filename};

/// Locate the built `busbar_auth_oidc_plugin` cdylib in the target dir (mirrors the loader's own
/// `auth_oidc_plugin_path` test helper). Under CI, a missing cdylib is a hard failure — this is the
/// only over-the-ABI coverage of the `kind: auth` dlopen seam and must never silently skip there.
fn plugin_path() -> Option<std::path::PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = plugin_library_filename("busbar_auth_oidc_plugin");
        let candidate = profile_dir.join(&name);
        candidate.exists().then_some(candidate)
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "the auth-oidc plugin cdylib is not built under CI: `cargo test --workspace` must \
             build busbar_auth_oidc_plugin. Refusing to silently skip the only over-the-ABI \
             coverage of the kind:auth dlopen seam."
        );
    }
    candidate
}

/// Install ring as the process-default rustls `CryptoProvider`, once. Idempotent: an already-installed
/// error means some other test (or the plugin's own reqwest/rustls stack under the SAME test binary)
/// already installed one; since everything here is ring, that's fine.
fn install_ring_provider_once() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// A minimal real HTTPS server: one self-signed cert, one background thread, one fixed response body
/// served to every request on every path (the test controls exactly what URL it configures, so
/// path-routing logic would be pure overhead). No framework — just `rustls` over a blocking
/// `TcpStream`, which is all `busbar_auth_oidc::ReqwestFetcher`'s blocking client needs to complete a
/// real TLS handshake, request, and response. Returns `(https url to the served body, the server's
/// cert PEM to trust via the plugin's optional `ca_cert_pem` config)`.
fn spawn_https_fixture(body: String) -> (String, String) {
    install_ring_provider_once();

    let cert_key = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
        .expect("generate self-signed cert");
    let cert_pem = cert_key.cert.pem();
    let cert_der = cert_key.cert.der().clone();
    use rustls::pki_types::pem::PemObject;
    let key_der = rustls::pki_types::PrivateKeyDer::from_pem_slice(
        cert_key.signing_key.serialize_pem().as_bytes(),
    )
    .expect("parse generated private key");

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("build TLS server config");
    let server_config = std::sync::Arc::new(server_config);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral test port");
    let port = listener.local_addr().expect("local_addr").port();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let Ok(conn) = rustls::ServerConnection::new(server_config.clone()) else {
                continue;
            };
            let mut tls = rustls::StreamOwned::new(conn, stream);
            let mut buf = [0u8; 4096];
            // Drive the handshake + read whatever of the request arrives; the response below doesn't
            // depend on the request content (fixed body, any path), so a short/partial read is fine —
            // we only need enough I/O to complete the handshake.
            let _ = std::io::Read::read(&mut tls, &mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = std::io::Write::write_all(&mut tls, response.as_bytes());
            let _ = std::io::Write::write_all(&mut tls, body.as_bytes());
            let _ = std::io::Write::flush(&mut tls);
        }
    });

    (format!("https://127.0.0.1:{port}/jwks"), cert_pem)
}

/// A ring ES256 signer, mirroring `busbar-auth-oidc`'s own test fixture
/// (`crates/auth-oidc/src/tests.rs::TestKey`) so this test mints and verifies REAL tokens rather than
/// stubbing the crypto.
struct TestKey {
    kp: ring::signature::EcdsaKeyPair,
    rng: ring::rand::SystemRandom,
    kid: &'static str,
}
impl TestKey {
    fn generate(kid: &'static str) -> Self {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let kp = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        Self { kp, rng, kid }
    }

    fn jwks(&self) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use ring::signature::KeyPair;
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

    fn mint(&self, claims: &serde_json::Value) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let header = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": self.kid });
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig = self.kp.sign(&self.rng, signing_input.as_bytes()).unwrap();
        let s = URL_SAFE_NO_PAD.encode(sig.as_ref());
        format!("{signing_input}.{s}")
    }
}

/// End-to-end SUCCESS: dlopen the real auth-oidc-plugin cdylib, `open()` it against a config pointing
/// at a real local HTTPS JWKS fixture (trusted via `ca_cert_pem`), then `authenticate()` a real
/// ES256-signed JWT over the C ABI and confirm the identity + mapped groups come back correctly
/// through `DynAuth`/`AuthOutcome::Identify`.
#[test]
fn load_and_exercise_auth_oidc_plugin_success() {
    let Some(path) = plugin_path() else {
        eprintln!("skip: auth-oidc plugin cdylib not built (run under --workspace)");
        return;
    };

    let key = TestKey::generate("test-kid-1");
    let (jwks_url, cert_pem) = spawn_https_fixture(key.jwks());

    const ISSUER: &str = "https://oidc-test.invalid/v2.0";
    const AUDIENCE: &str = "api://busbar-client";

    let cfg = serde_json::json!({
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "jwks_url": jwks_url,
        "ca_cert_pem": cert_pem,
    })
    .to_string();

    let bytes = std::fs::read(&path).expect("read auth-oidc plugin cdylib");
    let module = load_auth_from_bytes(&bytes, &cfg, "auth-oidc", abi_kind::AUTH)
        .expect("load auth-oidc plugin over the ABI (real JWKS fetch at open/first-use time)");

    assert_eq!(module.name(), "oidc");
    assert!(module.cacheable());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = serde_json::json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + 3600,
        "nbf": now - 10,
        "sub": "subject-guid",
        "preferred_username": "alice@contoso.example",
        "name": "Alice Example",
        "groups": ["11111111-aaaa", "22222222-bbbb"],
    });
    let token = key.mint(&claims);

    match module.authenticate(Some(&token)) {
        busbar_api::AuthOutcome::Identify(p) => {
            // No `oid` claim in this fixture, so the IMMUTABLE `sub` is the identity of record —
            // `preferred_username` is display-only now, never identity (see lib.rs's subject-claim
            // precedence: oid/sub only, mutable claims are name-fallback, never id-fallback).
            assert_eq!(p.id, "oidc:subject-guid");
            assert_eq!(p.name.as_deref(), Some("Alice Example"));
            assert_eq!(p.roles, vec!["11111111-aaaa", "22222222-bbbb"]);
        }
        other => panic!(
            "expected the real JWKS fetch + real signature verification to identify the caller, \
             got {other:?}"
        ),
    }

    // A token signed by a DIFFERENT key (same kid) must fail closed over the real ABI too — not just
    // in `busbar-auth-oidc`'s own in-process tests.
    let forged_key = TestKey::generate("test-kid-1");
    let forged_token = forged_key.mint(&claims);
    assert!(
        matches!(
            module.authenticate(Some(&forged_token)),
            busbar_api::AuthOutcome::Reject
        ),
        "a token signed by the wrong key must be rejected across the real ABI"
    );
}

/// End-to-end FAILURE: a plugin `open()` error (malformed config) must surface back across the C ABI
/// as a clean `Err`, not a panic or a silently-succeeded load.
#[test]
fn load_and_exercise_auth_oidc_plugin_bad_config_fails_over_abi() {
    let Some(path) = plugin_path() else {
        eprintln!("skip: auth-oidc plugin cdylib not built (run under --workspace)");
        return;
    };
    let bytes = std::fs::read(&path).expect("read auth-oidc plugin cdylib");

    let err = load_auth_from_bytes(&bytes, "", "auth-oidc", abi_kind::AUTH)
        .err()
        .expect("empty config must fail to load, not silently succeed");
    assert!(
        err.contains("config"),
        "the plugin's own error message should survive the ABI crossing intact: {err}"
    );

    let err = load_auth_from_bytes(
        &bytes,
        r#"{"issuer": "https://idp.example/v2.0"}"#, // missing required `audience`
        "auth-oidc",
        abi_kind::AUTH,
    )
    .err()
    .expect("config missing a required field must fail to load");
    assert!(err.contains("invalid oidc plugin config"), "got: {err}");
}
