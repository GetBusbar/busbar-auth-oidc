// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! JWKS (JSON Web Key Set) model + verifying-key extraction. Pure data + `ring` key material; no I/O
//! (the fetch/cache lives in [`crate::cache`]). A JWKS is the provider's set of PUBLIC signing
//! keys, each tagged by `kid`; a JWT's header `kid` selects which one verified it.

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
    Rsa {
        /// The modulus, big-endian.
        n: Vec<u8>,
        /// The public exponent, big-endian.
        e: Vec<u8>,
    },
    /// EC public point in uncompressed SEC1 form `0x04 || X || Y` (decoded from `x`/`y`).
    Ec {
        /// `0x04 || X || Y`.
        point: Vec<u8>,
    },
    /// The key material was absent or not base64url; the deferred error is surfaced at verify time.
    Unusable(String),
}

impl KeyMaterial {
    /// Decode a key's material from its base64url fields, selected by `kty`. Never fails — a decode
    /// problem becomes [`KeyMaterial::Unusable`] so it surfaces at verify time with an exact
    /// message.
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

                let mut point = Vec::with_capacity(1 + x.len() + y.len());
                point.push(0x04);
                point.extend_from_slice(&x);
                point.extend_from_slice(&y);
                Self::Ec { point }
            }
            other => Self::Unusable(format!(
                "JWKS key has unsupported kty {}",
                crate::untrusted(other)
            )),
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
/// (`x5c`, …) — a JWKS carries more than we consume.
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
    /// The algorithm the key is for (RFC 7517 §4.4): when present, the key verifies only a token
    /// signed with exactly it ([`crate::jwt::verify_signature`]).
    #[serde(default)]
    pub alg: Option<String>,
    /// The operations the key is for (RFC 7517 §4.3): when present, the key verifies a signature
    /// only if it names `verify` ([`crate::jwt::verify_signature`]).
    #[serde(default)]
    pub key_ops: Option<Vec<String>>,
    /// Memoised base64url-decoded key material — decoded once on first verify and reused for every
    /// later request against this same cached key (see [`KeyMaterial`]). Not part of the JWKS wire
    /// form; skipped in deserialization and rebuilt per JWKS refresh.
    #[serde(skip)]
    pub(crate) decoded: OnceLock<KeyMaterial>,
}

impl Jwk {
    /// Whether this key may verify a token signed with `alg`: the key type `alg` needs (`RS256`:
    /// RSA, `ES256`: EC), an `alg` absent or equal to it, not encryption-only, and `key_ops` absent
    /// or naming `verify`.
    pub fn signs(&self, alg: &str) -> bool {
        let shape_fits = match alg {
            crate::jwt::ALG_RS256 => self.kty == "RSA",
            crate::jwt::ALG_ES256 => self.kty == "EC" && self.crv.as_deref() == Some("P-256"),
            _ => false,
        };
        shape_fits
            && self.alg.as_deref().is_none_or(|a| a == alg)
            && self.key_use.as_deref() != Some("enc")
            && self
                .key_ops
                .as_ref()
                .is_none_or(|ops| ops.iter().any(|op| op == "verify"))
    }

    /// The decoded, verify-ready key material for this key — decoded once, then memoised, so the hot
    /// per-request verify path never re-decodes the base64url fields.
    pub fn material(&self) -> &KeyMaterial {
        self.decoded.get_or_init(|| KeyMaterial::from_jwk(self))
    }
}

/// A parsed JWKS: the provider's current set of signing keys.
#[derive(Debug, Clone)]
pub struct JwkSet {
    /// The keys, from the top-level `keys` array of a JWKS document. An entry that is not a usable
    /// [`Jwk`] (not a JSON object, no `kty`, a non-string member, …) is SKIPPED rather than
    /// failing the whole document: RFC 7517 §5 says a JWK Set consumer SHOULD ignore keys it
    /// cannot use, and one odd entry must not take every other key (and so every token) down with
    /// it. How many were skipped is said once per document, at warn ([`JwkSet::parse`]).
    pub keys: Vec<Jwk>,
}

/// A JWKS document as it arrives: its `keys` array, each entry not yet read as a [`Jwk`]. The
/// document must be a JSON object, and the array must be present and be an array.
#[derive(Deserialize)]
struct RawSet {
    keys: Vec<serde_json::Value>,
}

impl JwkSet {
    /// Parse a JWKS document (the body of a `jwks_uri` GET). Entries that are not usable JWKs are
    /// skipped (see [`JwkSet::keys`]), one warn naming how many. A document that parses but carries
    /// no keys is authoritative: the provider may have withdrawn every signing key. A nonempty
    /// document whose entries are all malformed is still an error.
    pub fn parse(body: &str) -> Result<Self, String> {
        if !crate::is_json_object(body.as_bytes()) {
            return Err("invalid JWKS document: it is not a JSON object (RFC 7517 §5)".to_string());
        }
        let raw: RawSet = serde_json::from_str(body).map_err(
            busbar_contract::abi::sdk::auth_kit::json_error("invalid JWKS document"),
        )?;
        let entries = raw.keys.len();
        let set = Self {
            keys: raw
                .keys
                .into_iter()
                .filter(serde_json::Value::is_object)
                .filter_map(|v| serde_json::from_value::<Jwk>(v).ok())
                .collect(),
        };
        let skipped = entries - set.keys.len();
        if skipped > 0 {
            tracing::warn!(
                module = "oidc",
                skipped,
                "JWKS document carries entries that are not usable keys; they are skipped"
            );
        }
        if set.keys.is_empty() && entries > 0 {
            return Err(format!(
                "JWKS document contains no keys this verifier can use (all {entries} entries were \
                 skipped); refusing to replace the cached key set with an empty one"
            ));
        }
        Ok(set)
    }

    /// The keys a token naming `kid`, signed with `alg`, is tried against: every key whose `kid`
    /// matches ([`Self::find_all`]); for a token naming no kid with its `alg` known, the set's
    /// single usable signing key for that alg if there is exactly one, else none. `alg` `None`
    /// selects by `kid` alone.
    pub fn select<'a>(&'a self, kid: &'a str, alg: Option<&str>) -> Vec<&'a Jwk> {
        match alg {
            Some(alg) if kid.is_empty() => {
                let usable: Vec<&Jwk> = self.keys.iter().filter(|k| k.signs(alg)).collect();
                if usable.len() == 1 {
                    usable
                } else {
                    Vec::new()
                }
            }
            _ => self.find_all(kid).collect(),
        }
    }

    /// Find ALL keys whose `kid` matches `kid`. A JWT header names the `kid` that signed it; selecting
    /// by `kid` (not "try every key in the set") is what makes a key-rotation refetch meaningful.
    /// More than one key can share a `kid` (RFC 7517 §4.5), so the caller must try every match.
    pub fn find_all<'a>(&'a self, kid: &'a str) -> impl Iterator<Item = &'a Jwk> {
        self.keys
            .iter()
            .filter(move |k| k.kid.as_deref() == Some(kid) || (kid.is_empty() && k.kid.is_none()))
    }
}

#[cfg(test)]
#[path = "tests/jwks_tests.rs"]
mod tests;
