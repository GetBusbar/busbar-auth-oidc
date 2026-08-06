// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! JWKS (JSON Web Key Set) model + verifying-key extraction. Pure data + `ring` key material; no I/O
//! (the fetch/cache lives in [`crate::cache`]). A JWKS is the provider's set of PUBLIC signing keys,
//! each tagged by `kid`; a JWT's header `kid` selects which one verified it.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use std::sync::OnceLock;

/// The base64url-decoded, verify-ready key material for one [`Jwk`], decoded ONCE (at first use, then
/// memoised on the owning `Jwk`) so the hot per-request verify path never re-decodes `n`/`e` (RSA) or
/// `x`/`y` (EC). A fresh JWKS refresh builds fresh `Jwk`s with empty caches, so this is effectively
/// "decode once per JWKS refresh". `Unusable` carries the precise error a per-request decode would
/// raise, so a malformed key still fails with an exact message at verify time — and one odd key in a
/// set never poisons the parse of the whole set.
#[derive(Debug, Clone)]
pub enum KeyMaterial {
    /// RSA modulus + exponent (decoded from `n`/`e`).
    Rsa { n: Vec<u8>, e: Vec<u8> },
    /// EC public point in uncompressed SEC1 form `0x04 || X || Y` (decoded from `x`/`y`).
    Ec { point: Vec<u8> },
    /// The key material was absent or not base64url; the deferred error is surfaced at verify time.
    Unusable(String),
}

impl KeyMaterial {
    /// Decode a key's material from its base64url fields, selected by `kty`. Never fails — a decode
    /// problem becomes [`KeyMaterial::Unusable`] so it surfaces at verify time with an exact message.
    fn from_jwk(jwk: &Jwk) -> Self {
        match jwk.kty.as_str() {
            "RSA" => {
                let n = match b64(jwk.n.as_deref(), "RSA modulus n") {
                    Ok(v) => v,
                    Err(e) => return Self::Unusable(e),
                };
                let e = match b64(jwk.e.as_deref(), "RSA exponent e") {
                    Ok(v) => v,
                    Err(err) => return Self::Unusable(err),
                };
                Self::Rsa { n, e }
            }
            "EC" => {
                let x = match b64(jwk.x.as_deref(), "EC coordinate x") {
                    Ok(v) => v,
                    Err(e) => return Self::Unusable(e),
                };
                let y = match b64(jwk.y.as_deref(), "EC coordinate y") {
                    Ok(v) => v,
                    Err(e) => return Self::Unusable(e),
                };
                // ring wants the uncompressed SEC1 point: 0x04 || X || Y.
                let mut point = Vec::with_capacity(1 + x.len() + y.len());
                point.push(0x04);
                point.extend_from_slice(&x);
                point.extend_from_slice(&y);
                Self::Ec { point }
            }
            other => Self::Unusable(format!("JWKS key has unsupported kty {other}")),
        }
    }
}

/// base64url-decode a required JWK field, with a naming error on absence/format.
fn b64(field: Option<&str>, what: &str) -> Result<Vec<u8>, String> {
    let s = field.ok_or_else(|| format!("JWKS key missing {what}"))?;
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| format!("JWKS key {what} is not base64url"))
}

/// One JSON Web Key, the subset busbar's supported algorithms need. Unknown fields are ignored
/// (`use`, `alg`, `x5c`, …) — a JWKS carries more than we consume.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    /// Key type: `RSA` or `EC`. Selects which of the field groups below is populated.
    pub kty: String,
    /// Key id — matched against a JWT header's `kid`. Optional in the spec; a keyless key can only
    /// match a keyless JWT header (rare), so we treat `None` as the empty id.
    #[serde(default)]
    pub kid: Option<String>,
    /// RSA modulus (base64url, no padding). Present when `kty == "RSA"`.
    #[serde(default)]
    pub n: Option<String>,
    /// RSA public exponent (base64url). Present when `kty == "RSA"`.
    #[serde(default)]
    pub e: Option<String>,
    /// EC curve name (`P-256` for ES256). Present when `kty == "EC"`.
    #[serde(default)]
    pub crv: Option<String>,
    /// EC public-point X coordinate (base64url). Present when `kty == "EC"`.
    #[serde(default)]
    pub x: Option<String>,
    /// EC public-point Y coordinate (base64url). Present when `kty == "EC"`.
    #[serde(default)]
    pub y: Option<String>,
    /// Public key use (RFC 7517 §4.2): `"sig"` for signature verification, `"enc"` for encryption.
    /// `use` is a Rust keyword, hence the field rename. A key explicitly marked encryption-only must
    /// never be accepted for signature verification — enforced in [`crate::jwt::verify_signature`].
    #[serde(rename = "use", default)]
    pub key_use: Option<String>,
    /// Memoised base64url-decoded key material — decoded once on first verify and reused for every
    /// later request against this same cached key (see [`KeyMaterial`]). Not part of the JWKS wire
    /// form; skipped in deserialization and rebuilt per JWKS refresh.
    #[serde(skip)]
    pub(crate) decoded: OnceLock<KeyMaterial>,
}

impl Jwk {
    /// The decoded, verify-ready key material for this key — decoded once, then memoised, so the hot
    /// per-request verify path never re-decodes the base64url fields.
    pub fn material(&self) -> &KeyMaterial {
        self.decoded.get_or_init(|| KeyMaterial::from_jwk(self))
    }
}

/// A parsed JWKS: the provider's current set of signing keys.
#[derive(Debug, Clone, Deserialize)]
pub struct JwkSet {
    /// The keys. Deserialized from the top-level `keys` array of a JWKS document.
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    /// Parse a JWKS document (the body of a `jwks_uri` GET).
    ///
    /// A document that parses but carries ZERO keys is an ERROR, not an empty success. An identity
    /// provider that can sign tokens always publishes at least one key, so `{"keys":[]}` is a
    /// provider blip, a maintenance proxy, or a blackholing load balancer answering 200 with a
    /// well-formed nothing. Returning it as `Ok` would let the caller install it over a working key
    /// set and reset the freshness clocks, which converts a transient upstream hiccup into a total
    /// auth outage that lasts at least a full refetch interval and persists for as long as the
    /// empty body does. The caller's error path already preserves the previous keys; this makes the
    /// degenerate document take that path instead of the success path.
    pub fn parse(body: &str) -> Result<Self, String> {
        let set: Self =
            serde_json::from_str(body).map_err(|e| format!("invalid JWKS document: {e}"))?;
        if set.keys.is_empty() {
            return Err(
                "JWKS document contains no keys; refusing to replace the cached key set with an \
                 empty one"
                    .to_string(),
            );
        }
        Ok(set)
    }

    /// Find ALL keys whose `kid` matches `kid`. A JWT header names the `kid` that signed it; selecting
    /// by `kid` (not "try every key in the set") is what makes a KEY-ROTATION refetch meaningful — a
    /// token signed by a freshly-rotated key misses here, triggering a bounded refetch upstream.
    ///
    /// More than one key can share a `kid`: RFC 7517 §4.5 permits distinct keys with the same `kid`
    /// when `kty` differs (e.g. an RSA key and an EC key coexisting under one `kid` during an
    /// algorithm migration, or briefly during rotation by provider convention). The caller must try
    /// every match, not just the first.
    pub fn find_all<'a>(&'a self, kid: &'a str) -> impl Iterator<Item = &'a Jwk> {
        self.keys
            .iter()
            .filter(move |k| k.kid.as_deref() == Some(kid) || (kid.is_empty() && k.kid.is_none()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(body: &str) -> JwkSet {
        JwkSet::parse(body).unwrap()
    }

    /// A well-formed JWKS carrying zero keys must be an ERROR. It parses cleanly, so without this
    /// it reaches the cache's success arm and REPLACES a working key set, resetting the freshness
    /// anchors with it. Every subsequent verification then misses, and the rate limiter holds the
    /// next refetch off, so one 200-with-an-empty-body from a provider or a proxy in front of it
    /// takes the whole deployment's authentication down until the body stops being empty.
    #[test]
    fn an_empty_key_set_is_an_error_not_an_empty_success() {
        let err = JwkSet::parse(r#"{"keys":[]}"#)
            .expect_err("a JWKS with no keys must not parse as a successful empty set");
        assert!(
            err.contains("no keys"),
            "the error should say the document carried no keys: {err}"
        );
        // A document that is merely missing the member is the same case.
        assert!(JwkSet::parse(r#"{}"#).is_err());
        // And a real one-key document still parses.
        assert!(JwkSet::parse(
            r#"{"keys":[{"kty":"EC","kid":"a","crv":"P-256","x":"AAAA","y":"BBBB"}]}"#
        )
        .is_ok());
    }

    #[test]
    fn find_all_matches_by_kid() {
        let s = set(r#"{"keys":[
                {"kty":"EC","kid":"a","crv":"P-256","x":"AAAA","y":"BBBB"},
                {"kty":"EC","kid":"b","crv":"P-256","x":"CCCC","y":"DDDD"}
            ]}"#);
        let found: Vec<_> = s.find_all("a").collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kid.as_deref(), Some("a"));
    }

    /// A non-empty queried `kid` that matches NO key must never fall through to a keyless
    /// (`kid: None`) key in the set — that is only a valid match when the QUERIED kid is itself
    /// empty. Directly exercises the `kid.is_empty() && k.kid.is_none()` fallback clause: an
    /// `&&`→`||` mutation there would wrongly match the keyless key here even though the queried kid
    /// is non-empty and absent from the set.
    #[test]
    fn find_all_does_not_fall_back_to_a_keyless_key_for_a_nonempty_unmatched_kid() {
        let s = set(r#"{"keys":[
                {"kty":"EC","kid":"real-kid","crv":"P-256","x":"AAAA","y":"BBBB"},
                {"kty":"EC","crv":"P-256","x":"CCCC","y":"DDDD"}
            ]}"#);
        let found: Vec<_> = s.find_all("no-such-kid").collect();
        assert!(
            found.is_empty(),
            "a nonempty unmatched kid must not match the keyless key in the set, got {} matches",
            found.len()
        );
    }

    /// The mirror case: an EMPTY queried kid (a keyless JWT header) DOES match a keyless key.
    #[test]
    fn find_all_matches_a_keyless_key_for_an_empty_queried_kid() {
        let s = set(r#"{"keys":[
                {"kty":"EC","kid":"real-kid","crv":"P-256","x":"AAAA","y":"BBBB"},
                {"kty":"EC","crv":"P-256","x":"CCCC","y":"DDDD"}
            ]}"#);
        let found: Vec<_> = s.find_all("").collect();
        assert_eq!(found.len(), 1);
        assert!(found[0].kid.is_none());
    }
}
