// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! JWKS (JSON Web Key Set) model + verifying-key extraction. Pure data + `ring` key material; no I/O
//! (the fetch/cache lives in [`crate::cache`]). A JWKS is the provider's set of PUBLIC signing keys,
//! each tagged by `kid`; a JWT's header `kid` selects which one verified it.

use serde::Deserialize;

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
}

/// A parsed JWKS: the provider's current set of signing keys.
#[derive(Debug, Clone, Deserialize)]
pub struct JwkSet {
    /// The keys. Deserialized from the top-level `keys` array of a JWKS document.
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    /// Parse a JWKS document (the body of a `jwks_uri` GET).
    pub fn parse(body: &str) -> Result<Self, String> {
        serde_json::from_str(body).map_err(|e| format!("invalid JWKS document: {e}"))
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
