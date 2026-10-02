// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR: the OIDC module on the auth kind's table (`busbar_contract::abi::auth`), every slot a
//! [`SafeSlot`] over the SDK's safe surface. The SDK's verify-only kit (`auth_verify_door!`)
//! refuses login, so this plugin writes its own `plugin_door!` (THE DESIGN 11, the auth row of the
//! per-kind table): the SDK's generic lifecycle over [`Oidc`] (`lifecycle: life(Oidc)`), and
//!
//! * `verify` — the bearer credential judged by [`OidcModule`]'s verify path: an identity, REJECT or
//!   PASS, written into the host's identity buffer;
//! * `begin_login` — the IdP authorize URL, held under the answer's lease;
//! * `complete_login` — the token exchange made by the plugin itself, with the client secret the
//!   host lends at `open` (THE DESIGN 6.7: an IdP login holds its own client secret and makes its
//!   own exchange), and the returned `id_token` verified into an identity;
//! * `open_outbound`, `outbound_ready`, `fields` — not served (the tail states no
//!   [`CAP_OUTBOUND`](busbar_contract::abi::auth::CAP_OUTBOUND)): REFUSED.
//!
//! Every request goes out through the HOST's connector, over the needs the Statement declares
//! ([`crate::fetch::NEEDS`]): the plugin never dials. An op whose request is in flight answers
//! PENDING with its exchange parked on its ticket and is re-entered on the wake; an op waiting on
//! ANOTHER op's discovery or JWKS fetch (single-flight) answers PENDING with a short timer
//! (`wake_at` on the host's clock) and asks again.
//!
//! A linked build registers [`door`]; the dropped-in `cdylib` (`busbar-auth-oidc-plugin`) exports
//! the same door as its one symbol.

use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::task::Poll;
use std::time::Instant;

use busbar_contract::abi::auth::{
    AuthTail, BeginLoginIn, BeginLoginOut, CompleteLoginIn, FieldsIn, FieldsOut, IdentifyOut,
    IdentityBuf, OpenOutboundIn, OpenOutboundOut, OutboundReadyIn, OutboundReadyOut, VerifyIn,
    BEGIN_AUTHORIZE, CANCEL_ABANDONED, CAP_INBOUND, CAP_LOGIN, FACT_CACHEABLE, IDENTITY_HAS_TTL,
    LOGIN_BAD_CREDENTIAL, LOGIN_IDENTITY, LOGIN_KIND_REDIRECT, LOGIN_OUTAGE, SPAN_ABSENT,
    VERDICT_IDENTITY, VERDICT_PASS, VERDICT_REJECT,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, Span, BLOB_ABSENT};
use busbar_contract::abi::mechanism::door::{Rewrite, Statement, REWRITE_ALIAS};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::auth_door::{verify_tail, with_tail};
use busbar_contract::abi::sdk::conn::{ConnFailure, Host};
use busbar_contract::abi::sdk::door::{abi_str, statement, AbiIn, AbiOut};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::auth::{AuthVerdict, BeginLogin, LoginHttpResponse, LoginOutcome, Principal};
use zeroize::Zeroizing;

use crate::fetch::{Fetch, HostIo, IoState, NEEDS};
use crate::open::{config, module};
use crate::{now_unix, OidcModule, Step};

/// The plugin's name: the manifest name its release packs it under.
pub const NAME: &str = "busbar-auth-oidc";

/// The auth tail: it verifies and it logs in through a redirect to the IdP; its verdicts may be
/// cached (1.5.5's `cacheable`).
const TAIL: AuthTail = AuthTail {
    caps: CAP_INBOUND | CAP_LOGIN,
    login_kind: LOGIN_KIND_REDIRECT,
    ..verify_tail(FACT_CACHEABLE)
};

/// The settings key whose value is the confidential-client secret's reference: the kernel
/// resolves it into `OpenIn::secrets[0]`.
const SECRET_REFS: &[AbiStr] = &[abi_str("client_secret")];

/// The name an operator's config calls the module by.
const REWRITES: &[Rewrite] = &[Rewrite {
    class: REWRITE_ALIAS,
    _reserved: 0,
    from: abi_str("oidc"),
    to: AbiStr {
        ptr: std::ptr::null(),
        len: 0,
    },
}];

/// This plugin's Statement: its name and alias, its version, the most calls one instance holds in
/// flight, its one secret reference, its three outbound needs and its auth tail.
pub const STATEMENT: Statement = Statement {
    secret_refs: SECRET_REFS.as_ptr(),
    secret_refs_len: SECRET_REFS.len(),
    rewrites: REWRITES.as_ptr(),
    rewrites_len: REWRITES.len(),
    needs: NEEDS.as_ptr(),
    needs_len: NEEDS.len(),
    ..with_tail(statement(NAME, env!("CARGO_PKG_VERSION"), 64), &TAIL)
};

/// The most short answers kept for their re-call at once.
const REACHED_MAX: usize = 1024;

/// How long an op waiting on another op's fetch waits before it asks again, nanoseconds on the
/// host's monotonic clock.
const WAIT_NS: u64 = 25_000_000;

/// One opened module: what `open` built from one settings blob and its lent secrets.
struct Opened {
    module: OidcModule,
    /// The confidential-client secret the host lent, if any.
    secret: Option<Zeroizing<String>>,
    /// The settings and secret it was opened with: a `refresh` with the same ones keeps it.
    settings: Vec<u8>,
}

impl Opened {
    fn new(settings: &[u8], secrets: &[&[u8]]) -> Result<Self, Refusal> {
        let module = module(text(settings)?).map_err(Refusal::failed)?;
        let secret = secrets
            .first()
            .map(|s| {
                std::str::from_utf8(s)
                    .map(|s| Zeroizing::new(s.to_string()))
                    .map_err(|_| Refusal::failed("oidc: the lent client secret is not UTF-8"))
            })
            .transpose()?;
        Ok(Self {
            module,
            secret,
            settings: settings.to_vec(),
        })
    }

    /// The callback's code exchanged at the token endpoint (once: the answer is kept in `answer`
    /// across PENDING, the code redeems once), and the `id_token` it answers verified.
    fn login(
        &self,
        code: Option<&str>,
        redirect_uri: Option<&str>,
        verifier: Option<&str>,
        answer: &mut Option<LoginHttpResponse>,
        io: &mut HostIo<'_>,
    ) -> Step<Login> {
        let now = Instant::now();
        if answer.is_none() {
            let hop = match step!(self
                .module
                .token_exchange(code, redirect_uri, verifier, now, io))
            {
                Ok(Some(hop)) => hop,
                Ok(None) => return Step::Ready(Login::Bad),
                Err(e) => return Step::Ready(Login::Outage(e)),
            };
            match io.post(&hop, self.secret.as_deref().map(String::as_str)) {
                Poll::Pending => return Step::Pending,
                Poll::Ready(Ok(r)) if r.status < 500 => *answer = Some(r),
                Poll::Ready(Ok(r)) => {
                    return Step::Ready(Login::Outage(format!(
                        "the token endpoint answered HTTP {}",
                        r.status
                    )))
                }
                Poll::Ready(Err(e)) => return Step::Ready(Login::Outage(e)),
            }
        }
        let Some(response) = answer.as_ref() else {
            return Step::Ready(Login::Bad);
        };
        Step::Ready(
            match step!(self
                .module
                .identity_from_token_response(response, now_unix(), now, io))
            {
                Ok(LoginOutcome::Identify(p)) => Login::Identity(p),
                Ok(_) => Login::Bad,
                Err(e) => Login::Outage(e),
            },
        )
    }
}

/// How one login ended.
enum Login {
    Identity(Principal),
    Bad,
    Outage(String),
}

/// An identity `complete_login` reached but could not fit into the host's buffer, kept for the
/// host's one re-call on the same ticket (the code redeems once): served only to the same callback.
struct Reached {
    state: Vec<u8>,
    code: Zeroizing<Vec<u8>>,
    principal: Principal,
}

/// THE INSTANCE: the opened module (replaced whole by a `refresh` with new settings) and the
/// identities kept for a short-buffer re-call.
pub struct Oidc {
    now: RwLock<Arc<Opened>>,
    reached: Mutex<HashMap<Ticket, Reached>>,
}

impl std::fmt::Debug for Oidc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Oidc").finish_non_exhaustive()
    }
}

impl Oidc {
    fn now(&self) -> Arc<Opened> {
        self.now
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// The settings blob as the JSON text it must be.
fn text(settings: &[u8]) -> Result<&str, Refusal> {
    std::str::from_utf8(settings)
        .map_err(|_| Refusal::failed("invalid oidc plugin config: the settings are not UTF-8"))
}

impl Life for Oidc {
    const CANCEL: u32 = CANCEL_ABANDONED;
    /// Ops pend on their own tickets only, so there is no driver ticket.
    const DRIVE: Outcome = Outcome::Refused;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        config(text(settings)?).map(|_| ()).map_err(Refusal::failed)
    }

    fn open(settings: &[u8], secrets: &[&[u8]], _generation: u64) -> Result<Self, Refusal> {
        Ok(Self {
            now: RwLock::new(Arc::new(Opened::new(settings, secrets)?)),
            reached: Mutex::default(),
        })
    }

    /// The same settings and secret keep the opened module and its key cache (the admin cache
    /// flush is one of these); new ones re-open it, a refusal keeping the running one. The plugin
    /// holds no verdict cache, so it reports no flushed count.
    fn refresh(
        &self,
        settings: &[u8],
        secrets: &[&[u8]],
        _generation: u64,
    ) -> Result<Refreshed, Refusal> {
        let now = self.now();
        let same_secret = now.secret.as_deref().map(String::as_bytes) == secrets.first().copied();
        if now.settings != settings || !same_secret {
            let opened = Arc::new(Opened::new(settings, secrets)?);
            *self.now.write().unwrap_or_else(PoisonError::into_inner) = opened;
        }
        Ok(Refreshed::default())
    }
}

/// What an op parks on its ticket across PENDING: its requests' state and, for a login, the token
/// endpoint's answer (the code redeems once).
#[derive(Default)]
struct Parked {
    io: IoState,
    answer: Option<LoginHttpResponse>,
}

/// The op's requests on its ticket, resumed from what it parked.
fn resume<'h>(instance: &Instance<'_, Held<Oidc>>, h: &'h Held<Oidc>) -> (HostIo<'h>, Parked) {
    let mut parked = instance
        .resume::<Parked>()
        .map_or_else(Parked::default, |p| *p);
    let io = HostIo::new(h.host(), instance.ticket(), std::mem::take(&mut parked.io));
    (io, parked)
}

/// Answer PENDING with `parked` (the requests' state from `io`) on the op's ticket: on its own
/// exchange's wake, or — `wait` — on a short timer while another op's fetch is in flight.
fn pend<O: AbiOut>(
    instance: &Instance<'_, Held<Oidc>>,
    host: Option<&Host>,
    io: HostIo<'_>,
    mut parked: Parked,
    out: &mut Out<'_, O>,
    wait: bool,
) -> Outcome {
    if wait {
        let clock = host.map_or(Err(ConnFailure::Unarmed), |h| {
            match h.connector(instance.ticket()).clock_now() {
                Poll::Ready(r) => r,
                Poll::Pending => Err(ConnFailure::Fault),
            }
        });
        match clock {
            Ok(r) => out.wake_at(r.mono_ns.saturating_add(WAIT_NS)),
            Err(e) => {
                return out.fail(Refusal::failed(format!(
                    "oidc: cannot wait for the fetch another call is making: {e}"
                )))
            }
        }
    }
    parked.io = io.into_state();
    instance.park(parked);
    Outcome::Pending
}

/// A blob's bytes as text; `None` when absent or not UTF-8.
fn blob_text(b: Lent<'_, Blob>) -> Option<&str> {
    (b.fmt != BLOB_ABSENT && !b.ptr.is_null())
        .then(|| std::str::from_utf8(b.bytes()).ok())
        .flatten()
}

/// A string's text; `None` when absent or not UTF-8.
fn str_text(s: Lent<'_, AbiStr>) -> Option<&str> {
    (!s.ptr.is_null()).then(|| s.as_str().ok()).flatten()
}

const ABSENT: Span = Span {
    offset: SPAN_ABSENT,
    len: 0,
};

/// Write `p` into the host's identity buffer `buf` and answer READY with `verdict`, or the short
/// FAILED (every `needed_*` at its full size) when it does not fit.
fn identify(
    p: &Principal,
    buf: Lent<'_, IdentityBuf>,
    out: &mut Out<'_, IdentifyOut>,
    verdict: u32,
) -> Outcome {
    let (mut bytes, mut groups) = (buf.buf(), buf.groups());
    let subject = bytes.span(p.id.as_bytes());
    let name = p.name.as_deref().map(|n| bytes.span(n.as_bytes()));
    for role in &p.roles {
        let s = bytes.span(role.as_bytes());
        groups.push(s);
    }
    if !bytes.fits() || !groups.fits() {
        out.set(|o| &o.needed_bytes, bytes.asked() as u64);
        out.set(
            |o| &o.needed_groups,
            u32::try_from(groups.asked()).unwrap_or(u32::MAX),
        );
        return Outcome::Failed;
    }
    out.set(|o| &o.identity.subject, subject);
    out.set(|o| &o.identity.name, name.unwrap_or(ABSENT));
    out.set(|o| &o.identity.key_id, ABSENT);
    out.set(|o| &o.identity.key_name, ABSENT);
    out.set(|o| &o.identity.user, ABSENT);
    out.set(|o| &o.identity.provider, ABSENT);
    out.set(|o| &o.identity.claims, ABSENT);
    out.set(|o| &o.identity.claims_fmt, BLOB_ABSENT);
    out.set(
        |o| &o.identity.groups_len,
        u32::try_from(groups.written()).unwrap_or(u32::MAX),
    );
    let (flags, ttl) = p.ttl_secs.map_or((0, 0), |t| (IDENTITY_HAS_TTL, t));
    out.set(|o| &o.identity.flags, flags);
    out.set(|o| &o.identity.ttl_secs, ttl);
    out.set(|o| &o.verdict, verdict);
    Outcome::Ready
}

/// `verify`: the presented credential judged as a bearer token.
#[derive(Debug)]
pub struct Verify;
impl SafeSlot for Verify {
    type In = VerifyIn;
    type Out = IdentifyOut;
    type State = Held<Oidc>;
    fn call(
        instance: Instance<'_, Held<Oidc>>,
        input: Lent<'_, VerifyIn>,
        mut out: Out<'_, IdentifyOut>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return Outcome::Fault;
        };
        let c = input.field(|i| &i.credential);
        let credential = (c.fmt != BLOB_ABSENT && !c.ptr.is_null()).then(|| c.bytes());
        let token = match credential.map(std::str::from_utf8) {
            // Bytes that are not text are no JWT: not this module's credential.
            Some(Err(_)) => {
                out.set(|o| &o.verdict, VERDICT_PASS);
                return Outcome::Ready;
            }
            Some(Ok(token)) => Some(token),
            None => None,
        };
        let (mut io, parked) = resume(&instance, h);
        let opened = h.life().now();
        let verdict = match opened
            .module
            .verify(token, now_unix(), Instant::now(), &mut io)
        {
            Step::Ready(Ok(v)) => v,
            Step::Ready(Err(e)) => return out.fail(Refusal::failed(e)),
            Step::Pending => return pend(&instance, h.host(), io, parked, &mut out, false),
            Step::Wait => return pend(&instance, h.host(), io, parked, &mut out, true),
        };
        match verdict {
            AuthVerdict::Identify(p) => {
                identify(&p, input.field(|i| &i.out_buf), &mut out, VERDICT_IDENTITY)
            }
            AuthVerdict::Reject => {
                out.set(|o| &o.verdict, VERDICT_REJECT);
                Outcome::Ready
            }
            AuthVerdict::Pass => {
                out.set(|o| &o.verdict, VERDICT_PASS);
                Outcome::Ready
            }
        }
    }
}

/// `begin_login`: the IdP authorize URL for the core's state, PKCE challenge and nonce.
#[derive(Debug)]
pub struct Begin;
impl SafeSlot for Begin {
    type In = BeginLoginIn;
    type Out = BeginLoginOut;
    type State = Held<Oidc>;
    fn call(
        instance: Instance<'_, Held<Oidc>>,
        input: Lent<'_, BeginLoginIn>,
        mut out: Out<'_, BeginLoginOut>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return Outcome::Fault;
        };
        let field = |s: Lent<'_, AbiStr>| s.as_str().map(str::to_string);
        let (Ok(redirect_uri), Ok(state), Ok(code_challenge)) = (
            field(input.field(|i| &i.redirect_uri)),
            field(input.field(|i| &i.state)),
            field(input.field(|i| &i.code_challenge)),
        ) else {
            return out.fail(Refusal::failed("oidc: a begin_login field is not UTF-8"));
        };
        // The request's extra scopes are not read: the safe SDK lends no accessor for the list,
        // and 1.5.5's core never sent any.
        let begin = BeginLogin {
            redirect_uri,
            state,
            code_challenge,
            nonce: str_text(input.field(|i| &i.nonce)).map(str::to_string),
            scopes: Vec::new(),
        };
        let (mut io, parked) = resume(&instance, h);
        let opened = h.life().now();
        match opened.module.begin_login(&begin, Instant::now(), &mut io) {
            Step::Ready(Ok(LoginOutcome::Authorize(url))) => {
                out.set(|o| &o.shape, BEGIN_AUTHORIZE);
                out.lease_str(|o| &o.authorize_url, h.leases(), url);
                Outcome::Ready
            }
            Step::Ready(Ok(_)) => out.fail(Refusal::failed(
                "oidc: browser login is unavailable: no authorization_endpoint is configured or \
                 was discovered",
            )),
            Step::Ready(Err(e)) => out.fail(Refusal::failed(e)),
            Step::Pending => pend(&instance, h.host(), io, parked, &mut out, false),
            Step::Wait => pend(&instance, h.host(), io, parked, &mut out, true),
        }
    }
}

/// `complete_login`: the callback's code exchanged and the `id_token` verified into an identity.
#[derive(Debug)]
pub struct Complete;
impl SafeSlot for Complete {
    type In = CompleteLoginIn;
    type Out = IdentifyOut;
    type State = Held<Oidc>;
    fn call(
        instance: Instance<'_, Held<Oidc>>,
        input: Lent<'_, CompleteLoginIn>,
        mut out: Out<'_, IdentifyOut>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return Outcome::Fault;
        };
        let oidc = h.life();
        let state = input.field(|i| &i.state).bytes();
        let code = blob_text(input.field(|i| &i.code));
        let code_bytes = code.map_or(&[][..], str::as_bytes);
        let mut reached = oidc.reached.lock().unwrap_or_else(PoisonError::into_inner);
        let kept = reached
            .remove(&instance.ticket())
            .filter(|r| r.state == state && r.code.as_slice() == code_bytes);
        drop(reached);
        let principal = match kept {
            Some(r) => r.principal,
            None => {
                let (mut io, mut parked) = resume(&instance, h);
                let login = oidc.now().login(
                    code,
                    str_text(input.field(|i| &i.redirect_uri)),
                    blob_text(input.field(|i| &i.code_verifier)),
                    &mut parked.answer,
                    &mut io,
                );
                match login {
                    Step::Ready(Login::Identity(p)) => p,
                    Step::Ready(Login::Bad) => {
                        out.set(|o| &o.verdict, LOGIN_BAD_CREDENTIAL);
                        return Outcome::Ready;
                    }
                    Step::Ready(Login::Outage(e)) => {
                        tracing::warn!(module = "oidc", error = %e, "OIDC token exchange failed");
                        out.set(|o| &o.verdict, LOGIN_OUTAGE);
                        return Outcome::Ready;
                    }
                    Step::Pending => return pend(&instance, h.host(), io, parked, &mut out, false),
                    Step::Wait => return pend(&instance, h.host(), io, parked, &mut out, true),
                }
            }
        };
        let answered = identify(
            &principal,
            input.field(|i| &i.out_buf),
            &mut out,
            LOGIN_IDENTITY,
        );
        if answered == Outcome::Failed {
            let mut reached = oidc.reached.lock().unwrap_or_else(PoisonError::into_inner);
            if reached.len() >= REACHED_MAX {
                reached.clear();
            }
            reached.insert(
                instance.ticket(),
                Reached {
                    state: state.to_vec(),
                    code: Zeroizing::new(code_bytes.to_vec()),
                    principal,
                },
            );
        }
        answered
    }
}

/// An op the tail does not state (the outbound family): REFUSED, never called.
#[derive(Debug)]
pub struct NotServed<I, O>(PhantomData<(I, O)>);
impl<I: AbiIn, O: AbiOut> SafeSlot for NotServed<I, O> {
    type In = I;
    type Out = O;
    type State = Held<Oidc>;
    fn call(_: Instance<'_, Held<Oidc>>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
        Outcome::Refused
    }
}

mod table {
    use super::{
        Begin, Complete, FieldsIn, FieldsOut, NotServed, Oidc, OpenOutboundIn, OpenOutboundOut,
        OutboundReadyIn, OutboundReadyOut, Safe, Verify,
    };

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::auth::Ops,
        statement: super::STATEMENT,
        lifecycle: life(Oidc),
        kind_ops: {
            verify: Safe<Verify>,
            begin_login: Safe<Begin>,
            complete_login: Safe<Complete>,
            open_outbound: Safe<NotServed<OpenOutboundIn, OpenOutboundOut>>,
            outbound_ready: Safe<NotServed<OutboundReadyIn, OutboundReadyOut>>,
            fields: Safe<NotServed<FieldsIn, FieldsOut>>,
        },
    }
}

/// This plugin's door: the one a compiled-in build links and the dropped-in image exports.
pub use table::door;
