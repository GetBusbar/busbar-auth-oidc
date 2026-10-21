// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BEARER ON THIS MODULE'S OWN LINES. Where the host lends `verify` no candidate credential
//! (THE DESIGN §6, "Auth points and guest lists": no kernel step names an inbound credential line;
//! the line's style names them), the module reads its bearer off the field lines its Statement
//! names ([`LINES`]), by the extraction the chain used to lend it byte for byte: 1.5.5's
//! `extract_client_token`, carried on as `carried_credential` over the default inbound style.
//!
//! * the lines, in order: `authorization`, then `x-api-key`, then `x-goog-api-key`; the first that
//!   presents a token wins;
//! * a line's value is read only when every byte is visible ASCII or a tab (the `http` crate's
//!   `HeaderValue::to_str`), else that line presents nothing;
//! * only the first line of a name is read (`HeaderMap::get`);
//! * `authorization` is read in the Bearer scheme ([`bearer`]): another scheme (Basic, DPoP, a
//!   SigV4 signature) presents nothing there;
//! * `x-api-key` and `x-goog-api-key` are taken raw, a blank value presenting nothing, so a blank
//!   line never masks a token on a later one.

/// The Bearer line (RFC 6750 s2.1).
pub const AUTHORIZATION: &str = "authorization";
/// The Anthropic SDK's key line.
pub const X_API_KEY: &str = "x-api-key";
/// The Gemini SDK's key line.
pub const X_GOOG_API_KEY: &str = "x-goog-api-key";

/// The lines this module's bearer sits on, in the order they are read: the Statement's carrier
/// marks, and the lines `verify` names for the transport to strip whatever its verdict.
pub const LINES: [&str; 3] = [AUTHORIZATION, X_API_KEY, X_GOOG_API_KEY];

/// The Bearer auth-scheme, matched ASCII case-insensitively.
const BEARER: &str = "bearer";

/// The token of an `authorization` value in the Bearer scheme: split on the FIRST space (so a
/// multibyte character in the scheme position cannot split a character), the scheme matched ASCII
/// case-insensitively, nothing trimmed (a second space stays in the token), an empty token none.
#[must_use]
pub fn bearer(value: &str) -> Option<&str> {
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case(BEARER) && !token.is_empty()).then_some(token)
}

/// A field value as text: every byte visible ASCII (`0x20..=0x7e`) or a tab, else none.
fn field_text(value: &[u8]) -> Option<&str> {
    value
        .iter()
        .all(|&b| (0x20..0x7f).contains(&b) || b == b'\t')
        .then(|| std::str::from_utf8(value).ok())
        .flatten()
}

/// The bearer the field lines carry, `line` answering a line's value by name (the first line of
/// that name, ASCII case-insensitive; `None` = absent): the first of [`LINES`], in order, that
/// presents one.
pub fn carried<'a>(line: impl Fn(&str) -> Option<&'a [u8]>) -> Option<&'a str> {
    LINES.iter().find_map(|&name| {
        let value = field_text(line(name)?)?;
        if name == AUTHORIZATION {
            bearer(value)
        } else {
            Some(value).filter(|t| !t.is_empty())
        }
    })
}

#[cfg(test)]
#[path = "tests/carried_tests.rs"]
mod tests;
