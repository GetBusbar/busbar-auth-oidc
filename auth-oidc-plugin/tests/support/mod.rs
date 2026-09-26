// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared by this crate's integration tests (`e2e.rs`, `conformance.rs`): a REAL local HTTPS JWKS
//! fixture (a self-signed cert minted with `rcgen`, served over a `rustls` listener) and a `ring`
//! ES256 signer that mints REAL tokens against it. No stubbed crypto, no stubbed fetch.
#![allow(dead_code)]

/// Install ring as the process-default rustls `CryptoProvider`, once. Idempotent: an already-installed
/// error means some other test (or the plugin's own reqwest/rustls stack under the SAME test binary)
/// already installed one; since everything here is ring, that's fine.
pub fn install_ring_provider_once() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// A minimal real HTTPS server: one self-signed cert, one background thread, one fixed response body
/// served to every request on every path (the test controls exactly what URL it configures, so
/// path-routing logic would be pure overhead). No framework — just `rustls` over a blocking
/// `TcpStream`, which is all `busbar_auth_oidc::ReqwestFetcher`'s blocking client needs to complete a
/// real TLS handshake, request, and response. Returns `(https url to the served body, the server's
/// cert PEM to trust via the plugin's optional `ca_cert_pem` config)`.
pub fn spawn_https_fixture(body: String) -> (String, String) {
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
pub struct TestKey {
    kp: ring::signature::EcdsaKeyPair,
    rng: ring::rand::SystemRandom,
    kid: &'static str,
}
impl TestKey {
    pub fn generate(kid: &'static str) -> Self {
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

    pub fn jwks(&self) -> String {
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

    pub fn mint(&self, claims: &serde_json::Value) -> String {
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
