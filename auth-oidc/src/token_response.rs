// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TOKEN ENDPOINT'S ANSWER (RFC 6749 §5.1, OIDC Core §3.1.3.3), read without a plain copy of
//! any issued token.
//!
//! The shared SDK validates the complete object and decodes selected strings into guarded
//! holders, keeping provider-specific token selection here.

use zeroize::Zeroizing;

/// The token endpoint's answer, typed: the issued tokens are held in wiped holders, so no plain
/// copy of one outlives its use; every other member is ignored. No `Debug`: it holds credentials.
pub(crate) struct TokenResponse {
    /// The OIDC identity token, the one member the login reads.
    pub(crate) id_token: Option<Zeroizing<String>>,
    /// The access token: never read, but parsed into a wiped holder rather than left to a scratch
    /// buffer.
    #[allow(dead_code)]
    access_token: Option<Zeroizing<String>>,
    /// The refresh token: as `access_token`.
    #[allow(dead_code)]
    refresh_token: Option<Zeroizing<String>>,
}

/// The members read, in the order of [`TokenResponse`]'s fields.
const MEMBERS: [&str; 3] = ["id_token", "access_token", "refresh_token"];

impl TokenResponse {
    /// `body` parsed; the error never echoes it.
    ///
    /// A member read is a string, `null` or absent (`null` and absent are both `None`); any other
    /// type, or the member named twice, is refused. A body that is not one JSON object is refused.
    pub(crate) fn parse(body: &str) -> Result<Self, String> {
        let [id_token, access_token, refresh_token] =
            busbar_contract::abi::sdk::cred::json_text_members(body.as_bytes(), MEMBERS)
                .map_err(|error| format!("token response: {error}"))?;
        Ok(Self {
            id_token,
            access_token,
            refresh_token,
        })
    }
}

#[cfg(test)]
#[path = "tests/token_response_tests.rs"]
mod tests;
