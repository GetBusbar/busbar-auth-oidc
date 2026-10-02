// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MODULE'S WAY OUT, THROUGH THE HOST (THE DESIGN 5, Connections: "No plugin opens a socket,
//! dials, binds or does TLS"; OWNER LAW 2026-09-27: the reqwest users move onto kernel
//! transports). The module states three outbound needs ([`NEEDS`]) and makes every request as ONE
//! framed `exchange()` over the host's connector ([`HostIo`]): the issuer's discovery document, the
//! JWKS, and the login's code-for-token POST. Each answers PENDING while it is in flight and is
//! re-asked when the op re-enters on its wake (the replay rule, `abi::sdk::conn`).
//!
//! Every need is `open-web` (public destinations over a secure connection only; the auth mint
//! endpoints' class), over `https`, and trusts the operator's `ca_cert_pem` on top of the public
//! roots (`trust_from`: 1.5.5's extra root, never a replacement). The discovery need is pinned to
//! the `issuer` setting's target (`target_from`); the JWKS and token endpoints may be discovered,
//! so the module names them per request.
//!
//! What the module reads back keeps 1.5.5's words: [`document`] (a non-2xx GET, the 1 MiB cap, a
//! body that is not UTF-8) and [`failed`] (a request that never got an answer, the connector's own
//! text after 1.5.5's prefix).

use std::fmt::Display;
use std::task::Poll;

use busbar_contract::abi::host::conn::connector::{Need, DIRECTION_OUTBOUND, EGRESS_OPEN_WEB};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::conn::{ConnFailure, Host};
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::sdk::exchange::{exchange, Exchange, ExchangeResponse, Request};
use busbar_contract::auth::{LoginHop, LoginHttpResponse};

/// Upper bound on a JWKS / discovery document, and on a token endpoint's answer. A real JWKS is a
/// handful of keys — a few KiB; even a tenant rotating aggressively stays well under this. The bound
/// exists because the body arrives from a remote IdP whose `jwks_uri` is itself read out of a remote
/// discovery document.
pub const MAX_JWKS_BYTES: usize = 1024 * 1024;

/// The bound on one request, milliseconds: 1.5.5's 10s fetch timeout. Generous enough for a cold
/// DNS + TLS handshake to a public IdP, short enough that a hung endpoint cannot hold an op.
pub const FETCH_TIMEOUT_MS: u64 = 10_000;

/// The need the discovery document is fetched on (its index in [`NEEDS`]).
pub const NEED_DISCOVERY: u32 = 0;
/// The need the JWKS is fetched on.
pub const NEED_JWKS: u32 = 1;
/// The need the login's token exchange is made on.
pub const NEED_TOKEN: u32 = 2;

/// The setting the discovery need's target comes from (a config path the host reads).
const ISSUER_PATH: &str = "settings.issuer";
/// The setting every need's extra trusted root comes from.
const CA_CERT_PATH: &str = "settings.ca_cert_pem";

const ABSENT: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// One outbound `https` need in the open-web class, trusting `ca_cert_pem` beside the public roots.
const fn need(target_from: AbiStr) -> Need {
    Need {
        direction: DIRECTION_OUTBOUND,
        egress_class: EGRESS_OPEN_WEB,
        transport: abi_str("https"),
        auth: ABSENT,
        target_from,
        trust_from: abi_str(CA_CERT_PATH),
        details: Blob::ABSENT,
        keep_response_headers: std::ptr::null(),
        keep_response_headers_len: 0,
        timeout_ms: FETCH_TIMEOUT_MS,
    }
}

/// THE NEEDS, in index order: discovery (pinned to the `issuer` setting's target), the JWKS and
/// the token endpoint (named per request: either may be discovered).
pub const NEEDS: &[Need] = &[need(abi_str(ISSUER_PATH)), need(ABSENT), need(ABSENT)];

/// Which document a GET fetches, so which need it goes out on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Doc {
    /// The issuer's OIDC discovery document.
    Discovery,
    /// The JWKS.
    Jwks,
}

impl Doc {
    const fn need(self) -> u32 {
        match self {
            Self::Discovery => NEED_DISCOVERY,
            Self::Jwks => NEED_JWKS,
        }
    }
}

/// THE MODULE'S I/O SEAM: one request, answered `Pending` while it is in flight and asked again
/// (same request, same order) when the op re-enters. The door implements it over the host's
/// connector ([`HostIo`]); tests answer from a script.
pub trait Fetch {
    /// The op making the requests: the owner of any fetch it claims. `None` when the call runs on
    /// no ticket, which may not pend, so may neither fetch nor wait.
    fn caller(&self) -> Option<Ticket>;

    /// GET `doc` at `url`: the body of a 2xx answer, or 1.5.5's error text ([`document`],
    /// [`failed`]).
    fn get(&mut self, doc: Doc, url: &str) -> Poll<Result<String, String>>;

    /// THE LOGIN TOKEN EXCHANGE, made by the plugin itself (THE DESIGN 6.7: an IdP login holds its
    /// own client secret and makes its own token exchange): `hop` sent as a form ([`form`]). The
    /// answer is the status and the body, whatever the status; a request that got no answer is
    /// `Err`.
    fn post(
        &mut self,
        hop: &LoginHop,
        secret: Option<&str>,
    ) -> Poll<Result<LoginHttpResponse, String>>;
}

/// A request to `url` that got no answer: 1.5.5's prefix, then why.
pub fn failed(url: &str, why: impl Display) -> String {
    format!("request to {url} failed: {why}")
}

/// A GET's answer as the document it carries: a non-2xx status is refused naming the status as
/// 1.5.5's client printed it (`404 Not Found`), then the body is [`capped`].
///
/// # Errors
/// 1.5.5's texts: `"{url} returned HTTP {status}"`, or [`capped`]'s.
pub fn document(url: &str, status: u16, body: Vec<u8>) -> Result<String, String> {
    if !(200..300).contains(&status) {
        let shown = http::StatusCode::from_u16(status)
            .map_or_else(|_| status.to_string(), |s| s.to_string());
        return Err(format!("{url} returned HTTP {shown}"));
    }
    capped(url, body, MAX_JWKS_BYTES)
}

/// `body` as text, refusing anything over `cap` bytes or not UTF-8.
///
/// # Errors
/// 1.5.5's texts: `"{url} JWKS body exceeds the {cap}-byte cap"`, `"{url} JWKS body is not UTF-8"`.
pub fn capped(url: &str, body: Vec<u8>, cap: usize) -> Result<String, String> {
    if body.len() > cap {
        return Err(format!("{url} JWKS body exceeds the {cap}-byte cap"));
    }
    String::from_utf8(body).map_err(|_| format!("{url} JWKS body is not UTF-8"))
}

/// The form `hop` is sent as, as 1.5.5's core sent it, with `secret` filling the field
/// `hop.secret_form_field` names. With no secret lent, that field is dropped rather than sent empty
/// (a public client sends none).
pub fn form(hop: &LoginHop, secret: Option<&str>) -> Vec<(String, String)> {
    let mut form = hop.form.clone();
    if let Some(field) = hop.secret_form_field.as_deref() {
        match secret {
            Some(secret) => match form.iter_mut().find(|(k, _)| k == field) {
                Some(slot) => slot.1 = secret.to_string(),
                None => form.push((field.to_string(), secret.to_string())),
            },
            None => form.retain(|(k, _)| k != field),
        }
    }
    form
}

/// The path and query a request to `url` names.
fn head_target(url: &url::Url) -> Vec<u8> {
    match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    }
    .into_bytes()
}

/// The GET of `url`, as 1.5.5's client sent it.
pub fn get_request(url: &url::Url) -> Request {
    Request {
        method: b"GET".to_vec(),
        target: head_target(url),
        fields: vec![(b"accept".to_vec(), b"*/*".to_vec())],
        body: Vec::new(),
        timeout_ms: FETCH_TIMEOUT_MS,
    }
}

/// The token exchange `hop` to `url` with `secret`: its method (POST when it names none a request
/// can carry), the form url-encoded as 1.5.5's client encoded it, then the hop's own fields.
pub fn post_request(url: &url::Url, hop: &LoginHop, secret: Option<&str>) -> Request {
    let method = http::Method::from_bytes(hop.method.as_bytes()).unwrap_or(http::Method::POST);
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form(hop, secret))
        .finish();
    let mut fields = vec![
        (b"accept".to_vec(), b"*/*".to_vec()),
        (
            b"content-type".to_vec(),
            b"application/x-www-form-urlencoded".to_vec(),
        ),
    ];
    fields.extend(
        hop.headers
            .iter()
            .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec())),
    );
    Request {
        method: method.as_str().as_bytes().to_vec(),
        target: head_target(url),
        fields,
        body: body.into_bytes(),
        timeout_ms: FETCH_TIMEOUT_MS,
    }
}

/// What an op parks of its requests across PENDING: the handles its finished exchanges issued, and
/// the exchange in flight (with the URL it fetches).
#[derive(Debug, Default)]
pub struct IoState {
    issued: u32,
    current: Option<(String, Exchange)>,
}

/// [`Fetch`] over the host's connector, for ONE entry of one op on `ticket`.
#[derive(Debug)]
pub struct HostIo<'h> {
    host: Option<&'h Host>,
    ticket: Ticket,
    state: IoState,
}

impl<'h> HostIo<'h> {
    /// The op's requests on `ticket` through `host`'s connector, resumed from `state`.
    pub fn new(host: Option<&'h Host>, ticket: Ticket, state: IoState) -> Self {
        Self {
            host,
            ticket,
            state,
        }
    }

    /// What to park across PENDING.
    pub fn into_state(self) -> IoState {
        self.state
    }

    /// The https-only exchange `request` builds for `url`, on `need`: resumed when it is the one in
    /// flight, else started.
    fn run(
        &mut self,
        need: u32,
        url: &str,
        request: impl FnOnce(&url::Url) -> Request,
    ) -> Poll<Result<ExchangeResponse, String>> {
        let parsed = match url::Url::parse(url) {
            Ok(u) => u,
            Err(e) => return Poll::Ready(Err(failed(url, e))),
        };
        // HTTPS-ONLY (1.5.5's `https_only`): a JWKS/discovery endpoint fetched over plaintext could
        // be MITM'd to serve attacker keys.
        if parsed.scheme() != "https" {
            return Poll::Ready(Err(failed(url, "URL scheme is not allowed")));
        }
        let Some(host) = self.host else {
            return Poll::Ready(Err(failed(url, ConnFailure::Unarmed)));
        };
        let mut c = host.connector_from(self.ticket, self.state.issued);
        let mut ex = match self.state.current.take() {
            Some((at, ex)) if at == url => ex,
            _ => match Exchange::request(request(&parsed)) {
                Ok(ex) => ex,
                Err(e) => return Poll::Ready(Err(failed(url, e))),
            },
        };
        match exchange(&mut c, &mut ex, need, Some(url)) {
            Poll::Pending => {
                self.state.current = Some((url.to_string(), ex));
                Poll::Pending
            }
            Poll::Ready(r) => {
                self.state.issued = c.issued();
                Poll::Ready(r.map_err(|e| failed(url, e)))
            }
        }
    }
}

impl Fetch for HostIo<'_> {
    fn caller(&self) -> Option<Ticket> {
        (!self.ticket.is_none()).then_some(self.ticket)
    }

    fn get(&mut self, doc: Doc, url: &str) -> Poll<Result<String, String>> {
        self.run(doc.need(), url, get_request)
            .map(|r| r.and_then(|reply| document(url, reply.status, reply.body)))
    }

    fn post(
        &mut self,
        hop: &LoginHop,
        secret: Option<&str>,
    ) -> Poll<Result<LoginHttpResponse, String>> {
        let url = hop.url.as_str();
        self.run(NEED_TOKEN, url, |u| post_request(u, hop, secret))
            .map(|r| {
                r.and_then(|reply| {
                    Ok(LoginHttpResponse {
                        status: reply.status,
                        body: capped(url, reply.body, MAX_JWKS_BYTES)?,
                    })
                })
            })
    }
}

#[cfg(test)]
#[path = "tests/fetch_tests.rs"]
mod tests;
