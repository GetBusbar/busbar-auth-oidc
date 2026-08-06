// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! JWT parsing + **signature verification** over `ring` (the workspace's single, already-vendored
//! crypto backend — no `jsonwebtoken`/`rsa`, so no new crypto dependency and no RUSTSEC-2023-0071
//! surface). Supports the two algorithms OIDC identity providers actually sign ID/access tokens with:
//! `RS256` (RSA-PKCS1-SHA256 — Entra, Google, Okta default) and `ES256` (ECDSA-P256-SHA256).
//!
//! This module is PURE: it verifies a token against an already-fetched key and returns the decoded
//! claims, or a precise error. iss/aud/exp/nbf policy and JWKS fetching live in [`crate`].

use crate::jwks::{Jwk, KeyMaterial};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use serde_json::Value;

/// The two JWS algorithms this verifier accepts — the ones OIDC IdPs actually sign ID/access tokens
/// with. Named once here so the match arms and the error text can't drift apart.
const ALG_RS256: &str = "RS256";
const ALG_ES256: &str = "ES256";

/// The decoded JWT header — the fields that select verification.
#[derive(Debug, Deserialize)]
pub struct Header {
    /// Signature algorithm. Only `RS256` and `ES256` are accepted; `none` (unsigned) and HMAC
    /// (`HS*` — a symmetric key we must never accept from a JWKS) are REJECTED, closing the classic
    /// "alg: none" and "RS256→HS256 key-confusion" JWT attacks.
    pub alg: String,
    /// Key id selecting which JWKS key signed this token. Absent ⇒ the empty id (matches a keyless
    /// JWKS key only).
    #[serde(default)]
    pub kid: Option<String>,
    /// RFC 7515 §4.1.11 `crit`: header parameters the producer marks as critical — a verifier that
    /// does not understand every one of them MUST reject the token. This verifier implements NO
    /// critical extensions, so a non-empty `crit` is always a rejection (see [`verify_signature`]).
    #[serde(default)]
    pub crit: Option<Vec<String>>,
}

/// The three base64url segments of a compact JWS, plus the signing input (`header.payload`) the
/// signature covers. Produced by [`split`], consumed by [`verify_signature`].
pub struct Parts<'a> {
    pub header: Header,
    /// The raw decoded payload bytes (the claims JSON) — decoded once here, deserialized by the caller.
    pub payload: Vec<u8>,
    /// The decoded signature bytes.
    pub signature: Vec<u8>,
    /// `header_b64 + "." + payload_b64` — exactly the bytes the signature is computed over. Borrowed
    /// from the original token string.
    pub signing_input: &'a str,
}

/// Split and base64url-decode a compact JWT (`header.payload.signature`), decoding the header enough
/// to select verification. Does NOT verify — that is [`verify_signature`]. Rejects a token that isn't
/// exactly three segments (a classic malformed-input guard).
pub fn split(token: &str) -> Result<Parts<'_>, String> {
    let mut it = token.split('.');
    let (h, p, s) = match (it.next(), it.next(), it.next(), it.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err("malformed JWT: expected three dot-separated segments".to_string()),
    };
    let header_bytes = URL_SAFE_NO_PAD
        .decode(h)
        .map_err(|_| "malformed JWT: header is not base64url".to_string())?;
    let header: Header =
        serde_json::from_slice(&header_bytes).map_err(|e| format!("malformed JWT header: {e}"))?;
    let payload = URL_SAFE_NO_PAD
        .decode(p)
        .map_err(|_| "malformed JWT: payload is not base64url".to_string())?;
    let signature = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| "malformed JWT: signature is not base64url".to_string())?;
    // The signing input is the original header + "." + payload substring (pre-decode bytes), i.e. the
    // token up to the last '.'. Slice it from the source so we sign the EXACT transmitted bytes.
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
/// matches the key type (RS256↔RSA, ES256↔EC) — the alg-confusion guard. Returns `Ok(())` on a valid
/// signature, a precise `Err` otherwise. Uses `ring`'s constant-time verifiers.
pub fn verify_signature(parts: &Parts, key: &Jwk) -> Result<(), String> {
    // RFC 7515 §4.1.11 `crit`: a producer can mark header parameters as critical, and a verifier that
    // does not implement EVERY named extension MUST reject the token rather than silently ignore it.
    // This verifier implements no critical extensions, so any non-empty `crit` is a rejection —
    // checked before signature math, since an unimplemented critical param changes how the token must
    // be processed.
    if let Some(crit) = &parts.header.crit {
        if !crit.is_empty() {
            return Err(format!(
                "JWT header names critical extension(s) {crit:?} (RFC 7515 §4.1.11) that this \
                 verifier does not implement; refusing to process the token"
            ));
        }
    }
    // RFC 7517 §4.2 `use`: a key explicitly marked encryption-only must not verify signatures.
    if key.key_use.as_deref() == Some("enc") {
        return Err(
            "JWKS key has \"use\": \"enc\" (encryption-only) and must not verify signatures"
                .to_string(),
        );
    }
    let alg = parts.header.alg.as_str();
    if alg == ALG_RS256 {
        if key.kty != "RSA" {
            return Err(format!(
                "token alg {ALG_RS256} but JWKS key kty is {} (alg/key-type mismatch)",
                key.kty
            ));
        }
        // Key material is base64url-decoded ONCE and memoised on the key (see `Jwk::material`), so
        // this hot path never re-decodes `n`/`e` per request.
        let (n, e) = match key.material() {
            KeyMaterial::Rsa { n, e } => (n, e),
            KeyMaterial::Unusable(msg) => return Err(msg.clone()),
            KeyMaterial::Ec { .. } => {
                // Unreachable: kty == "RSA" is checked above, so the memoised material is Rsa/Unusable.
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
                key.kty
            ));
        }
        if key.crv.as_deref() != Some("P-256") {
            return Err(format!(
                "{ALG_ES256} requires curve P-256, JWKS key has crv {:?}",
                key.crv
            ));
        }
        // Point decoded ONCE and memoised (see `Jwk::material`) — no per-request re-decode/alloc.
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
        // `none` (unsigned), `HS*` (HMAC — accepting a symmetric alg against an asymmetric JWKS key is
        // the RS256→HS256 key-confusion attack), and any other alg are REFUSED.
        Err(format!(
            "unsupported/forbidden JWT alg '{alg}': only {ALG_RS256} and {ALG_ES256} are accepted"
        ))
    }
}

/// Deserialize the token's claims payload as a JSON object.
pub fn claims(parts: &Parts) -> Result<Value, String> {
    serde_json::from_slice(&parts.payload).map_err(|e| format!("malformed JWT claims: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7517 §4.2: a JWK explicitly marked `"use": "enc"` (encryption-only — e.g. published
    /// alongside a signing key on the same JWKS endpoint for key-agreement) must never verify a
    /// signature, no matter how otherwise-valid its key material is.
    ///
    /// The key material here (`x`/`y`: `None`) is deliberately incomplete — proving the `use` check
    /// runs BEFORE any key-material parsing, not as a side effect of the material being unusable. If
    /// the rejection came from missing coordinates instead, this would pass for the wrong reason; the
    /// assertion on the error text guards against that.
    ///
    /// Without a `use` check this falls through to "JWKS key missing EC coordinate x" — a
    /// key-material error, not a use-policy rejection — or, with valid material, verifies the
    /// signature outright. As implemented it is rejected specifically for `use: enc`, before key
    /// material is ever inspected.
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
    /// below for the RSA branch: a token whose `alg` is `RS256` against a JWKS key whose `kty` really
    /// is `"RSA"` must PASS the kty check and reach key-material parsing (and fail there, on missing
    /// `n`/`e`) — proving the guard is `key.kty != "RSA"`, not its inverse. A `!=`→`==` mutation would
    /// instead reject every genuinely-matching RS256/RSA pair with the kty-mismatch error, which this
    /// test's error-text assertion distinguishes from the key-material error.
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
    /// at) key-material parsing, not the use-policy rejection.
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
