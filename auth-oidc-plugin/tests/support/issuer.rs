// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **A LOCAL OIDC ISSUER FOR TESTS** (test-side only: never in a shipped crate).
//!
//! A host that loads this module — busbar's own auth-chain and stdio-serve tests, this repo's
//! conformance tests — needs a real issuer to point it at: an ES256 key whose JWKS the host's
//! connector can reach over a certificate-verified connection (the module never dials: its needs
//! do), and genuinely signed tokens to present. [`Issuer::start`] provides exactly that on the
//! loopback interface: a self-signed certificate (trusted through the module's `ca_cert_pem`
//! setting, the needs' `trust_from`, so nothing is disabled), one background thread answering every
//! request with the JWKS, and [`Issuer::sign`] signing tokens with the matching key. A
//! test that plays the IdP as a connection table itself serves [`Issuer::jwks`] and signs with
//! [`Issuer::sign`]. This server is a TEST'S: it lives in the plugin crate's tests, so its TLS stack is
//! never in a shipped closure.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_FIXED_SIGNING};
use std::io::Write as _;
use std::sync::Arc;

/// One whole HTTP request off `stream`: the head, then as many body bytes as it states.
fn read_request(stream: &mut impl std::io::Read) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while let Ok(n) = stream.read(&mut chunk) {
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf);
        if let Some(end) = text.find("\r\n\r\n") {
            let length = text[..end]
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            if buf.len() >= end + 4 + length {
                break;
            }
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// A running local issuer: its identity, its signing key, and where its JWKS is served.
pub struct Issuer {
    issuer: String,
    kid: String,
    key: EcdsaKeyPair,
    rng: ring::rand::SystemRandom,
    jwks_url: String,
    jwks: String,
    cert_pem: String,
}

impl Issuer {
    /// Start an issuer named `issuer` (the `iss` its tokens carry), signing under key id `kid`, with
    /// its JWKS served on a fresh loopback port for the life of the process.
    pub fn start(issuer: &str, kid: &str) -> Issuer {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("generate an ES256 key");
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .expect("load the ES256 key");
        let point = key.public_key().as_ref();
        let jwks = serde_json::json!({ "keys": [{
            "kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "alg": "ES256",
            "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
        }]})
        .to_string();

        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
            .expect("mint a self-signed certificate");
        let cert_pem = cert.cert.pem();
        let chain = vec![cert.cert.der().clone()];
        let private = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
        );
        let config = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(chain, private)
            .expect("server certificate"),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
        let jwks_url = format!(
            "https://{}/jwks",
            listener.local_addr().expect("local addr")
        );
        let served = jwks.clone();
        std::thread::spawn(move || {
            for socket in listener.incoming() {
                let (Ok(socket), Ok(session)) =
                    (socket, rustls::ServerConnection::new(config.clone()))
                else {
                    continue;
                };
                let mut stream = rustls::StreamOwned::new(session, socket);
                let _ = read_request(&mut stream);
                let (status, body) = (200, &served);
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.flush();
            }
        });
        Issuer {
            issuer: issuer.to_string(),
            kid: kid.to_string(),
            key,
            rng,
            jwks_url,
            jwks,
            cert_pem,
        }
    }

    /// Where the JWKS is served (`https://127.0.0.1:<port>/jwks`).
    pub fn jwks_url(&self) -> &str {
        &self.jwks_url
    }

    /// The JWKS document this issuer serves: its one ES256 key.
    pub fn jwks(&self) -> &str {
        &self.jwks
    }

    /// The PEM certificate the JWKS endpoint presents — the module's `ca_cert_pem`.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// `claims`, signed by this issuer as a compact JWS.
    pub fn sign(&self, claims: &serde_json::Value) -> String {
        let head = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": self.kid });
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&head).expect("encode the header")),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("encode the claims")),
        );
        let signature = self
            .key
            .sign(&self.rng, input.as_bytes())
            .expect("sign the token");
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
    }
}
