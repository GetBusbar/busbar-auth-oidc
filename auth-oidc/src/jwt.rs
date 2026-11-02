// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! JWT parsing + **signature verification** over `ring` (the workspace's single, already-vendored

use crate::jwks::{Jwk, KeyMaterial};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use serde_json::Value;

/// The two JWS algorithms this verifier accepts — the ones OIDC IdPs actually sign ID/access tokens
const ALG_RS256: &str = "RS256";
const ALG_ES256: &str = "ES256";

/// The decoded JWT header — the fields that select verification.
#[derive(Debug, Deserialize)]
pub struct Header {
    /// Signature algorithm. Only `RS256` and `ES256` are accepted; `none` (unsigned) and HMAC
    /// (`HS*` — a symmetric key we must never accept from a JWKS) are REJECTED, closing the classic
    /// "alg: none" and "RS256→HS256 key-confusion" JWT attacks.
    pub alg: String,
    /// Key id selecting which JWKS key signed this token. Absent ⇒ the key set's single usable
    /// signing key for `alg`, if there is exactly one ([`crate::jwks::JwkSet::select`]).
    #[serde(default)]
    pub kid: Option<String>,
    /// RFC 7515 §4.1.11 `crit`: header parameters the producer marks as critical — a verifier that
    /// does not understand every one of them MUST reject the token. This verifier implements NO
    /// critical extensions, so a non-empty `crit` is always a rejection (see [`verify_signature`]).
    #[serde(default)]
    pub crit: Option<Vec<String>>,
}

/// The three base64url segments of a compact JWS, plus the signing input (`header.payload`) the
pub struct Parts<'a> {
    /// The decoded JOSE header.
    pub header: Header,
    /// The raw decoded payload bytes (the claims JSON) — decoded once here, deserialized by the caller.
    pub payload: Vec<u8>,
    /// The decoded signature bytes.
    pub signature: Vec<u8>,
    /// `header_b64 + "." + payload_b64` — exactly the bytes the signature is computed over. Borrowed
    pub signing_input: &'a str,
}

/// The decoded PAYLOAD of what reads as a compact JWS (exactly three dot-separated segments, the
pub fn payload(token: &str) -> Option<Vec<u8>> {
    let mut it = token.split('.');
    match (it.next(), it.next(), it.next(), it.next()) {
        (Some(_), Some(p), Some(_), None) => URL_SAFE_NO_PAD.decode(p).ok(),
        _ => None,
    }
}

/// Split and base64url-decode a compact JWT (`header.payload.signature`), decoding the header enough
pub fn split(token: &str) -> Result<Parts<'_>, String> {
    let mut it = token.split('.');
    let (h, p, s) = match (it.next(), it.next(), it.next(), it.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err("malformed JWT: expected three dot-separated segments".to_string()),
    };
    let header_bytes = URL_SAFE_NO_PAD
        .decode(h)
        .map_err(|_| "malformed JWT: header is not base64url".to_string())?;
    let header: Header = serde_json::from_slice(&header_bytes).map_err(
        busbar_contract::abi::sdk::auth_kit::json_error("malformed JWT header"),
    )?;
    let payload = URL_SAFE_NO_PAD
        .decode(p)
        .map_err(|_| "malformed JWT: payload is not base64url".to_string())?;
    let signature = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| "malformed JWT: signature is not base64url".to_string())?;

    let last_dot = token.rfind('.').expect("token has at least two dots here");
    let signing_input = &token[..last_dot];
    Ok(Parts {
        header,
        payload,
        signature,
        signing_input,
    })
}

/// Verify the JWS signature of `parts` against the JWKS key `key`, enforcing that the token's `alg`
pub fn verify_signature(parts: &Parts, key: &Jwk) -> Result<(), String> {
    if let Some(crit) = &parts.header.crit {
        if !crit.is_empty() {
            let named: Vec<String> = crit.iter().map(|c| crate::untrusted(c)).collect();
            return Err(format!(
                "JWT header names critical extension(s) [{}] (RFC 7515 §4.1.11) that this \
                 verifier does not implement; refusing to process the token",
                named.join(", ")
            ));
        }
    }

    if key.key_use.as_deref() == Some("enc") {
        return Err(
            "JWKS key has \"use\": \"enc\" (encryption-only) and must not verify signatures"
                .to_string(),
        );
    }
    let alg = parts.header.alg.as_str();

    let accepted = alg == ALG_RS256 || alg == ALG_ES256;
    if let Some(key_alg) = key.alg.as_deref().filter(|_| accepted) {
        if key_alg != alg {
            return Err(format!(
                "JWKS key is for alg {} but the token is signed {} (RFC 7517 §4.4); it must not \
                 verify this token",
                crate::untrusted(key_alg),
                crate::untrusted(alg)
            ));
        }
    }

    if accepted
        && key
            .key_ops
            .as_ref()
            .is_some_and(|ops| !ops.iter().any(|op| op == "verify"))
    {
        return Err(
            "JWKS key's key_ops does not name \"verify\" (RFC 7517 §4.3); it must not verify \
             signatures"
                .to_string(),
        );
    }
    if alg == ALG_RS256 {
        if key.kty != "RSA" {
            return Err(format!(
                "token alg {ALG_RS256} but JWKS key kty is {} (alg/key-type mismatch)",
                crate::untrusted(&key.kty)
            ));
        }

        let (n, e) = match key.material() {
            KeyMaterial::Rsa { n, e } => (n, e),
            KeyMaterial::Unusable(msg) => return Err(msg.clone()),
            KeyMaterial::Ec { .. } => {
                return Err("JWKS key material does not match its kty".to_string());
            }
        };
        let pubkey = ring::signature::RsaPublicKeyComponents { n, e };
        pubkey
            .verify(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                parts.signing_input.as_bytes(),
                &parts.signature,
            )
            .map_err(|_| "JWT signature verification failed".to_string())
    } else if alg == ALG_ES256 {
        if key.kty != "EC" {
            return Err(format!(
                "token alg {ALG_ES256} but JWKS key kty is {} (alg/key-type mismatch)",
                crate::untrusted(&key.kty)
            ));
        }
        if key.crv.as_deref() != Some("P-256") {
            return Err(format!(
                "{ALG_ES256} requires curve P-256, JWKS key has crv {}",
                key.crv
                    .as_deref()
                    .map_or("(none)".to_string(), crate::untrusted)
            ));
        }

        let point = match key.material() {
            KeyMaterial::Ec { point } => point,
            KeyMaterial::Unusable(msg) => return Err(msg.clone()),
            KeyMaterial::Rsa { .. } => {
                return Err("JWKS key material does not match its kty".to_string());
            }
        };
        let pubkey = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_FIXED,
            point,
        );
        pubkey
            .verify(parts.signing_input.as_bytes(), &parts.signature)
            .map_err(|_| "JWT signature verification failed".to_string())
    } else {
        Err(format!(
            "unsupported/forbidden JWT alg '{}': only {ALG_RS256} and {ALG_ES256} are accepted",
            crate::untrusted(alg)
        ))
    }
}

/// Deserialize the token's claims payload as a JSON object.
pub fn claims(parts: &Parts) -> Result<Value, String> {
    serde_json::from_slice(&parts.payload).map_err(busbar_contract::abi::sdk::auth_kit::json_error(
        "malformed JWT claims",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A JWT header field of the wrong type is refused WITHOUT echoing its value: the header comes
    #[test]
    fn a_mistyped_header_field_is_refused_without_echoing_it() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","kid":12345678}"#);
        let body = URL_SAFE_NO_PAD.encode(b"{}");
        let Err(err) = split(&format!("{header}.{body}.c2ln")) else {
            panic!("a mistyped kid is refused");
        };
        assert!(err.starts_with("malformed JWT header"), "got: {err}");
        assert!(!err.contains("12345678"), "the value is echoed: {err}");
    }

    /// RFC 7517 §4.2: a JWK explicitly marked `"use": "enc"` (encryption-only — e.g. published
    #[test]
    fn verify_signature_rejects_an_encryption_only_key() {
        let key = Jwk {
            kty: "EC".to_string(),
            kid: None,
            n: None,
            e: None,
            crv: Some("P-256".to_string()),
            x: None,
            y: None,
            key_use: Some("enc".to_string()),
            alg: None,
            key_ops: None,
            decoded: std::sync::OnceLock::new(),
        };
        let parts = Parts {
            header: Header {
                alg: "ES256".to_string(),
                kid: None,
                crit: None,
            },
            payload: Vec::new(),
            signature: Vec::new(),
            signing_input: "header.payload",
        };

        let err = verify_signature(&parts, &key).unwrap_err();
        assert!(
            err.contains("enc"),
            "expected a use-policy rejection mentioning 'enc', got: {err}"
        );
        assert!(
            !err.contains("coordinate"),
            "rejection must come from the use-policy check, not from missing key material: {err}"
        );
    }

    /// The RS256/RSA-kty guard, mirroring `verify_signature_permits_a_signing_key_to_reach_key_material_checks`
    #[test]
    fn verify_signature_permits_a_matching_rsa_key_to_reach_key_material_checks() {
        let key = Jwk {
            kty: "RSA".to_string(),
            kid: None,
            n: None,
            e: None,
            crv: None,
            x: None,
            y: None,
            key_use: Some("sig".to_string()),
            alg: None,
            key_ops: None,
            decoded: std::sync::OnceLock::new(),
        };
        let parts = Parts {
            header: Header {
                alg: "RS256".to_string(),
                kid: None,
                crit: None,
            },
            payload: Vec::new(),
            signature: Vec::new(),
            signing_input: "header.payload",
        };

        let err = verify_signature(&parts, &key).unwrap_err();
        assert!(
            err.contains("RSA modulus"),
            "an RS256 token against a real RSA key must reach key-material validation, not be \
             rejected by the kty check: {err}"
        );
        assert!(
            !err.contains("alg/key-type mismatch"),
            "must not be rejected as an alg/kty mismatch when the kty genuinely is RSA: {err}"
        );
    }

    /// A `"use": "sig"` key (the ordinary case) passes the use-policy check — it reaches (and fails
    #[test]
    fn verify_signature_permits_a_signing_key_to_reach_key_material_checks() {
        let key = Jwk {
            kty: "EC".to_string(),
            kid: None,
            n: None,
            e: None,
            crv: Some("P-256".to_string()),
            x: None,
            y: None,
            key_use: Some("sig".to_string()),
            alg: None,
            key_ops: None,
            decoded: std::sync::OnceLock::new(),
        };
        let parts = Parts {
            header: Header {
                alg: "ES256".to_string(),
                kid: None,
                crit: None,
            },
            payload: Vec::new(),
            signature: Vec::new(),
            signing_input: "header.payload",
        };

        let err = verify_signature(&parts, &key).unwrap_err();
        assert!(
            err.contains("coordinate"),
            "a sig-use key must reach key-material validation, not be blocked by the use check: {err}"
        );
    }
}
