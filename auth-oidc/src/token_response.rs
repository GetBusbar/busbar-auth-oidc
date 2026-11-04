// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TOKEN ENDPOINT'S ANSWER (RFC 6749 §5.1, OIDC Core §3.1.3.3), read without a plain copy of
//! any issued token.
//!
//! A serde-derived reader unescapes a JSON string that carries an escape into the decoder's scratch
//! buffer, which is freed unwiped. So the body is read in two passes instead. First, serde_json
//! checks the grammar while ignoring every value; that copies no string. Then a small walker over
//! the checked bytes decodes `id_token`, `access_token` and `refresh_token` straight into wiped
//! holders, each sized up front so it never reallocates. Every other member is skipped unread.

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
        serde_json::from_str::<serde::de::IgnoredAny>(body).map_err(
            busbar_contract::abi::sdk::auth_kit::json_error("token response"),
        )?;
        let mut held: [Option<Zeroizing<String>>; 3] = [None, None, None];
        let mut seen = [false; 3];
        let mut c = Cursor {
            s: body.as_bytes(),
            i: 0,
        };
        let malformed = || "token response: it is not well-formed JSON".to_string();
        c.ws();
        if !c.eat(b'{') {
            return Err("token response: it is not a JSON object".to_string());
        }
        c.ws();
        if !c.eat(b'}') {
            loop {
                c.ws();
                if !c.eat(b'"') {
                    return Err(malformed());
                }
                let key = c.raw_str().and_then(unescape).ok_or_else(malformed)?;
                c.ws();
                if !c.eat(b':') {
                    return Err(malformed());
                }
                c.ws();
                match MEMBERS.iter().position(|m| *m == key.as_str()) {
                    Some(at) => {
                        let name = MEMBERS[at];
                        if std::mem::replace(&mut seen[at], true) {
                            return Err(format!("token response: duplicate field `{name}`"));
                        }
                        match c.peek() {
                            Some(b'"') => {
                                c.i += 1;
                                let value = c.raw_str().and_then(unescape).ok_or_else(|| {
                                    format!("token response: `{name}` holds an invalid escape")
                                })?;
                                held[at] = Some(value);
                            }
                            Some(b'n') => c.skip_value().ok_or_else(malformed)?,
                            _ => return Err(format!("token response: `{name}` is not a string")),
                        }
                    }
                    None => c.skip_value().ok_or_else(malformed)?,
                }
                c.ws();
                if c.eat(b',') {
                    continue;
                }
                if c.eat(b'}') {
                    break;
                }
                return Err(malformed());
            }
        }
        let [id_token, access_token, refresh_token] = held;
        Ok(Self {
            id_token,
            access_token,
            refresh_token,
        })
    }
}

/// A read position over a body serde_json has already checked as well-formed JSON. Every step
/// still answers `None` rather than indexing past the end.
struct Cursor<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    /// The byte at the position.
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    /// Step past JSON whitespace.
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    /// Step past `b` if it is next.
    fn eat(&mut self, b: u8) -> bool {
        let next = self.peek() == Some(b);
        if next {
            self.i += 1;
        }
        next
    }

    /// The raw (still escaped) bytes of the string whose opening quote was just eaten, the position
    /// moved past its closing quote.
    fn raw_str(&mut self) -> Option<&'a [u8]> {
        let start = self.i;
        loop {
            match self.peek()? {
                b'"' => {
                    let raw = self.s.get(start..self.i)?;
                    self.i += 1;
                    return Some(raw);
                }
                b'\\' => self.i += 2,
                _ => self.i += 1,
            }
        }
    }

    /// Step past one value, unread: a string, an object or array (iteratively, so nesting depth
    /// costs no stack), or a scalar.
    fn skip_value(&mut self) -> Option<()> {
        match self.peek()? {
            b'"' => {
                self.i += 1;
                self.raw_str().map(drop)
            }
            b'{' | b'[' => {
                let mut depth = 0usize;
                loop {
                    match self.peek()? {
                        b'"' => {
                            self.i += 1;
                            self.raw_str()?;
                            continue;
                        }
                        b'{' | b'[' => depth += 1,
                        b'}' | b']' => {
                            depth = depth.checked_sub(1)?;
                            if depth == 0 {
                                self.i += 1;
                                return Some(());
                            }
                        }
                        _ => {}
                    }
                    self.i += 1;
                }
            }
            _ => {
                while !matches!(
                    self.peek(),
                    None | Some(b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r')
                ) {
                    self.i += 1;
                }
                Some(())
            }
        }
    }
}

/// The JSON string content `raw` (between its quotes, still escaped) decoded into a wiped holder.
/// The holder is allocated once at `raw`'s length, which no decoding exceeds (an escape never
/// decodes to more bytes than it spans), so it never reallocates and leaves no unwiped copy.
/// `None` for an invalid escape, including a lone or mismatched UTF-16 surrogate.
fn unescape(raw: &[u8]) -> Option<Zeroizing<String>> {
    let mut out = Zeroizing::new(String::with_capacity(raw.len()));
    let mut i = 0;
    loop {
        let start = i;
        while raw.get(i).is_some_and(|b| *b != b'\\') {
            i += 1;
        }
        out.push_str(std::str::from_utf8(raw.get(start..i)?).ok()?);
        if i == raw.len() {
            return Some(out);
        }
        let escape = *raw.get(i + 1)?;
        i += 2;
        let ch = match escape {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let hi = hex4(raw.get(i..i + 4)?)?;
                i += 4;
                if (0xD800..0xDC00).contains(&hi) {
                    if raw.get(i..i + 2)? != b"\\u" {
                        return None;
                    }
                    let lo = hex4(raw.get(i + 2..i + 6)?)?;
                    i += 6;
                    if !(0xDC00..0xE000).contains(&lo) {
                        return None;
                    }
                    char::from_u32(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00))?
                } else {
                    char::from_u32(hi)?
                }
            }
            _ => return None,
        };
        out.push(ch);
    }
}

/// Four hex digits as their value.
fn hex4(digits: &[u8]) -> Option<u32> {
    digits
        .iter()
        .try_fold(0u32, |n, d| Some(n * 16 + char::from(*d).to_digit(16)?))
}

#[cfg(test)]
#[path = "tests/token_response_tests.rs"]
mod tests;
