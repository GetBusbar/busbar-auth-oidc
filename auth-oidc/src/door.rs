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
//! ANOTHER op's discovery or JWKS fetch (single-flight) answers PENDING and is woken when that fetch
//! lands, a timer at the fetch's own bound (`wake_at` on the host's clock) its backstop.
//!
//! The lifecycle is the SDK's generic one over [`Oidc`], but for two slots: `tick` refreshes the
//! key set ahead of its TTL on the instance's driver ticket ([`Tick`]), and `drive` carries that
//! fetch on when its wake comes ([`Drive`]). `refresh` drops the module's verdict cache and reports
//! how many entries it held under [`METRIC_CACHE_FLUSHED`] (the admin cache flush's
//! `{"flushed": N}`).
//!
//! A linked build registers [`door`]; the dropped-in `cdylib` (`busbar-auth-oidc-plugin`) exports
//! the same door as its one symbol.

use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::task::Poll;
use std::time::Instant;

use busbar_contract::abi::auth::{
    AuthPoints, AuthTail, BeginLoginIn, BeginLoginOut, CompleteLoginIn, FieldsIn, FieldsOut,
    IdentifyOut, IdentityBuf, OpenOutboundIn, OpenOutboundOut, OutboundReadyIn, OutboundReadyOut,
    StripName, VerifyIn, BEGIN_AUTHORIZE, CANCEL_ABANDONED, CAP_INBOUND, CAP_LOGIN,
    DECISION_CONTINUE, DECISION_STOP, FACT_CACHEABLE, IDENTITY_HAS_TTL, LOGIN_BAD_CREDENTIAL,
    LOGIN_KIND_REDIRECT, LOGIN_OUTAGE, LOGIN_SECURITY_CHECK_FAILED, METRIC_CACHE_FLUSHED,
    SPAN_ABSENT, STRIP_FIELD, VERDICT_IDENTITY, VERDICT_PASS, VERDICT_REJECT,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, OutHead, Outcome, Span, BLOB_ABSENT, SEVERITY_ERROR, SEVERITY_WARN,
};
use busbar_contract::abi::mechanism::door::{
    MarkWord, MetricFamily, Rewrite, Statement, FAMILY_COUNTER,
};
use busbar_contract::abi::mechanism::lifecycle::{DriveIn, TickIn, TickOut};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::auth_door::{carrier, verify_tail, with_tail};
use busbar_contract::abi::sdk::auth_kit::login_identity;
use busbar_contract::abi::sdk::conn::{ConnFailure, Host};
use busbar_contract::abi::sdk::cred::{self, Cred};
use busbar_contract::abi::sdk::door::{abi_str, alias, statement, AbiIn, AbiOut};
use busbar_contract::abi::sdk::lent::HostBuf;
use busbar_contract::abi::sdk::life::{Counted, Flagged, Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::auth::{AuthVerdict, BeginLogin, LoginHttpResponse, LoginOutcome, Principal};
use zeroize::Zeroizing;

use crate::fetch::{Fetch, HostIo, IoState, NEEDS};
use crate::flight::FLIGHT_MAX;
use crate::open::{config, module};
use crate::{OidcModule, Step};

/// The plugin's name: the manifest name its release packs it under.
pub const NAME: &str = "busbar-auth-oidc";

/// The auth tail: it verifies and it logs in through a redirect to the IdP; its verdicts may be
/// cached (1.5.5's `cacheable`).
const TAIL: AuthTail = AuthTail {
    caps: CAP_INBOUND | CAP_LOGIN,
    login_kind: LOGIN_KIND_REDIRECT,
    ..verify_tail(FACT_CACHEABLE, AuthPoints::HEAD)
};

/// The settings key whose value is the confidential-client secret's reference: the kernel
/// resolves it into `OpenIn::secrets[0]`.
const SECRET_REFS: &[AbiStr] = &[abi_str("client_secret")];

/// The name an operator's config calls the module by.
const REWRITES: &[Rewrite] = &[alias("oidc")];

/// The metric families `refresh`'s envelope indexes into: the verdict cache's flush count
/// (`abi::auth`: "an auth plugin that caches verdicts declares a counter family of this name (no
/// labels) ... the host sums it ... into the admin cache flush's `{"flushed": N}`").
const FAMILIES: &[MetricFamily] = &[MetricFamily {
    name: abi_str(METRIC_CACHE_FLUSHED),
    help: abi_str("inbound verdict cache entries dropped by refresh"),
    unit: AbiStr::ABSENT,
    label_keys: std::ptr::null(),
    label_keys_len: 0,
    kind: FAMILY_COUNTER,
    _reserved: [0; 7],
}];

/// The index of the flush-count family in [`FAMILIES`].
pub const CACHE_FAMILY: u32 = 0;

/// The diagnostics this plugin declares, in index order: the ids its envelopes report and the host
/// audits on its behalf.
pub const DIAG_NAMES: &[&str] = &["OIDC_IDP_DESTINATION_REFUSED", "OIDC_JWKS_PLAIN_HTTP"];

/// The declared diagnostic a refused IdP destination raises ([`raise_refusals`]): the module's own
/// refusal (a discovered `jwks_uri` or `token_endpoint` over plain http, a scheme) or the
/// host's (the destination guard refusing the address), naming the host and the rule.
pub const DIAG_DESTINATION_REFUSED: u32 = 0;

/// The declared diagnostic a plain http `jwks_url` raises at warn on the `open` or `refresh` that
/// built the module ([`crate::check_jwks_url`], [`Life::flagged`]), in the words `open` logs: the
/// host audits the loaded but flagged instance on the plugin's behalf (`plugin.open`, `degraded`).
pub const DIAG_JWKS_PLAIN_HTTP: u32 = 1;

/// [`DIAG_NAMES`] as the Statement carries them.
const DIAG_IDS: &[AbiStr] = &[
    abi_str(DIAG_NAMES[DIAG_DESTINATION_REFUSED as usize]),
    abi_str(DIAG_NAMES[DIAG_JWKS_PLAIN_HTTP as usize]),
];

/// This plugin's Statement: its name and alias, its version, the most calls one instance holds in
/// flight, its one secret reference, its six outbound needs, its one metric family and its auth
/// tail.
pub const STATEMENT: Statement = Statement {
    families: FAMILIES.as_ptr(),
    families_len: FAMILIES.len(),
    secret_refs: SECRET_REFS.as_ptr(),
    secret_refs_len: SECRET_REFS.len(),
    rewrites: REWRITES.as_ptr(),
    rewrites_len: REWRITES.len(),
    needs: NEEDS.as_ptr(),
    needs_len: NEEDS.len(),
    mark_words: CARRIERS.as_ptr(),
    mark_words_len: CARRIERS.len(),
    diag_ids: DIAG_IDS.as_ptr(),
    diag_ids_len: DIAG_IDS.len(),
    ..with_tail(statement(NAME, env!("CARGO_PKG_VERSION"), 64), &TAIL)
};

/// EVERY REFUSED IdP DESTINATION IS AUDITED: each refusal the op met (`io`'s, [`HostIo::take_refusals`])
/// that `module` has not raised before is reported in the op's envelope as
/// [`DIAG_DESTINATION_REFUSED`] at error, the host auditing a declared diagnostic on the plugin's
/// behalf. Once per module per refusal ([`OidcModule::first_report`]), so a refusal every request
/// meets is not a flood; the words name the host and the rule, never a URL's path or a secret.
fn raise_refusals<O: AbiOut>(module: &OidcModule, io: &mut HostIo<'_>, out: &mut Out<'_, O>) {
    for why in io.take_refusals() {
        if module.first_report(&why) {
            tracing::warn!(module = "oidc", "{why}");
            out.diag(DIAG_DESTINATION_REFUSED, SEVERITY_ERROR, why);
        }
    }
}

/// The most short answers kept for their re-call at once.
const REACHED_MAX: usize = 1024;

/// How long a short answer is kept for its re-call: an older one (its host never came back for
/// it) goes on the next access of the map.
const REACHED_TTL: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// Drop every kept answer older than [`REACHED_TTL`] at `now`.
fn expire(map: &mut HashMap<Ticket, Reached>, now: Instant) {
    map.retain(|_, r| now.saturating_duration_since(r.at) <= REACHED_TTL);
}

/// The BACKSTOP of an op waiting on another op's fetch, nanoseconds on the host's monotonic clock:
/// it is woken when that fetch lands ([`Fetch::wake`]), and asks again after this long only if the
/// fetch never settles — the fetch's own bound, after which its flight may be taken over.
const WAIT_NS: u64 = FLIGHT_MAX.as_nanos() as u64;

/// The client secret `secrets` lends: its first entry, an empty one being none (the host lends an
/// empty entry for a provider with no `browser_login.client_secret`).
fn lent_secret(secrets: &[&[u8]]) -> Option<Cred> {
    secrets
        .first()
        .filter(|s| !s.is_empty())
        .map(|s| Cred::captured(Zeroizing::new(s.to_vec())))
}

/// One opened module: what `open` built from one settings blob and its lent secrets.
struct Opened {
    module: OidcModule,
    /// The confidential-client secret the host lent, if any.
    secret: Option<Cred>,
    /// The settings and secret it was opened with: a `refresh` with the same ones keeps it.
    settings: Vec<u8>,
    /// The warning its settings raise ([`crate::check_jwks_url`]), in the words `open` logs.
    flagged: Option<String>,
}

impl Opened {
    fn new(settings: &[u8], secrets: &[&[u8]]) -> Result<Self, Refusal> {
        let module = module(text(settings)?).map_err(Refusal::failed)?;
        // `module` opened these settings, so they parse and their `jwks_url` checks.
        let flagged = config(text(settings)?)
            .ok()
            .and_then(|c| crate::check_jwks_url(&c).ok().flatten());
        // An empty lent secret is none (a provider with no `browser_login.client_secret`): the
        // token exchange then sends no secret field, as 1.5.5's core sent none.
        let secret = lent_secret(secrets);
        if secret.as_ref().is_some_and(|s| !s.is_text()) {
            return Err(Refusal::failed("secrets: `client_secret` is not UTF-8"));
        }
        Ok(Self {
            module,
            secret,
            settings: settings.to_vec(),
            flagged,
        })
    }

    /// The callback's code exchanged at the token endpoint (once: the answer is kept in `answer`
    /// across PENDING, the code redeems once), the answer bound to the login's `nonce`, and the
    /// `id_token` it answers verified.
    ///
    /// 1.5.5's order, now the plugin's (THE DESIGN 6.7: the plugin makes its own exchange): a
    /// request that got no answer is an outage; ANY answer whose body carries an `id_token` must
    /// carry the nonce the core minted at `begin` (else the security check fails, before anything
    /// is verified); then a non-2xx answer, or an `id_token` that does not verify, is a declined
    /// login.
    fn login(
        &self,
        code: Option<&str>,
        redirect_uri: Option<&str>,
        verifier: Option<&str>,
        nonce: &str,
        answer: &mut Option<LoginHttpResponse>,
        io: &mut HostIo<'_>,
    ) -> Step<Login> {
        let now = Instant::now();
        if answer.is_none() {
            let secret = self.secret.as_ref();
            let request = match step!(self.module.token_exchange(
                code,
                redirect_uri,
                verifier,
                secret,
                now,
                io
            )) {
                Ok(Some(request)) => request,
                Ok(None) => return Step::Ready(Login::Bad),
                Err(e) => return Step::Ready(Login::Outage(e)),
            };
            match io.post(&request.url, &request.form) {
                Poll::Pending => return Step::Pending,
                Poll::Ready(Ok(r)) => *answer = Some(r),
                Poll::Ready(Err(e)) => return Step::Ready(Login::Outage(e)),
            }
        }
        let Some(response) = answer.as_ref() else {
            return Step::Ready(Login::Bad);
        };
        if !crate::nonce_binds(&response.body, nonce) {
            tracing::warn!(
                module = "oidc",
                "the IdP's id_token does not carry this login's nonce; login refused"
            );
            return Step::Ready(Login::SecurityCheck);
        }
        Step::Ready(
            match step!(self
                .module
                .identity_from_token_response(response, io.wall_now(), now, io))
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
    /// The IdP's identity token does not carry the login's nonce.
    SecurityCheck,
}

/// An identity `complete_login` reached but could not fit into the host's buffer, kept for the
/// host's one re-call on the same ticket (the code redeems once): served only to the same callback.
struct Reached {
    /// When it was kept: at the cap the oldest goes ([`keep`]).
    at: Instant,
    state: cred::Held<Vec<u8>>,
    code: cred::Held<Vec<u8>>,
    principal: Principal,
}

impl Reached {
    /// Whether it was kept for the callback naming `state` and `code`: both compared in constant
    /// time, and both always compared.
    fn serves(&self, state: &[u8], code: &[u8]) -> bool {
        let state = self.state == cred::Held::new(state.to_vec());
        let code = self.code == cred::Held::new(code.to_vec());
        state & code
    }
}

/// Keep `r` for `ticket`'s re-call, at most `max` at once: entries past [`REACHED_TTL`] go, and at
/// the cap the OLDEST entry goes, never the rest (an in-flight short answer awaiting its re-call
/// must survive).
fn keep(map: &mut HashMap<Ticket, Reached>, max: usize, ticket: Ticket, r: Reached) {
    expire(map, r.at);
    if map.len() >= max && !map.contains_key(&ticket) {
        let oldest = map.iter().min_by_key(|(_, k)| k.at).map(|(t, _)| *t);
        if let Some(oldest) = oldest {
            map.remove(&oldest);
        }
    }
    map.insert(ticket, r);
}

/// THE INSTANCE: the opened module (replaced whole by a `refresh` with new settings) and the
/// identities kept for a short-buffer re-call.
pub struct Oidc {
    now: RwLock<Arc<Opened>>,
    reached: Mutex<HashMap<Ticket, Reached>>,
    /// A `ready` in flight: its requests' state, by its ticket, across PENDING.
    readying: Mutex<HashMap<Ticket, IoState>>,
    /// The tick's key-set refresh in flight on the driver ticket: the module it refreshes and its
    /// requests' state, carried on by `drive` (a `drive` is a fresh op, so the SDK parks nothing
    /// across it).
    driving: Mutex<Option<(Arc<Opened>, IoState)>>,
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

    /// The tick's refresh ahead of the TTL on `opened`, over `host`'s connector on the driver
    /// ticket `ticket`, from `state`: PENDING (parked for `drive`) while its fetch is in flight,
    /// READY when it is done or nothing is due.
    fn refresh_ahead(
        &self,
        host: Option<&Host>,
        ticket: Ticket,
        opened: Arc<Opened>,
        state: IoState,
    ) -> Outcome {
        let mut io = HostIo::new(host, ticket, state, opened.module.anchored());
        match opened.module.refresh_ahead(Instant::now(), &mut io) {
            Step::Pending => {
                let state = io.into_state();
                *self.driving.lock().unwrap_or_else(PoisonError::into_inner) =
                    Some((opened, state));
                Outcome::Pending
            }
            // Done; or nothing to do this tick (another call's discovery is in flight); or the
            // fetch failed with no key set to keep, as the request path's own refresh would have,
            // and the next tick asks again.
            Step::Ready(_) | Step::Wait => Outcome::Ready,
        }
    }
}

/// The settings blob as the JSON text it must be.
fn text(settings: &[u8]) -> Result<&str, Refusal> {
    std::str::from_utf8(settings).map_err(|_| Refusal::failed("settings: not UTF-8 text"))
}

impl Life for Oidc {
    const CANCEL: u32 = CANCEL_ABANDONED;
    /// The generic drive slot is not this plugin's: its `Drive` slot replaces it and carries the
    /// tick's key-set refresh on the driver ticket.
    const DRIVE: Outcome = Outcome::Refused;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        // The checks `open` makes of the settings alone, so a config `--validate` accepts is one
        // boot opens: parsed, and an explicit `jwks_url` https or http.
        config(text(settings)?)
            .and_then(|c| crate::check_jwks_url(&c).map(drop))
            .map_err(Refusal::failed)
    }

    fn open(settings: &[u8], secrets: &[&[u8]], _generation: u64) -> Result<Self, Refusal> {
        Ok(Self {
            now: RwLock::new(Arc::new(Opened::new(settings, secrets)?)),
            reached: Mutex::default(),
            readying: Mutex::default(),
            driving: Mutex::default(),
        })
    }

    /// READY (after `open`, before any listener binds): discovery, a failure refusing the boot in
    /// 1.5.5's words, then the key set's warm-up ([`OidcModule::ready`]), over the instance's needs
    /// on `ticket`. PENDING while a request is in flight; its state is kept by ticket and the op
    /// resumes on the connector's wake.
    fn ready(&self, host: &Host, ticket: Ticket) -> Poll<Result<(), Refusal>> {
        let opened = self.now();
        let state = self
            .readying
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&ticket)
            .unwrap_or_default();
        let mut io = HostIo::new(Some(host), ticket, state, opened.module.anchored());
        match opened.module.ready(Instant::now(), &mut io) {
            // This call's own request in flight, or ANOTHER call's fetch of the same document or
            // key set: either way `ready` is woken when it settles (the other call's fetch wakes
            // its waiters) and judges its outcome then — never approving the boot unseen.
            Step::Pending | Step::Wait => {
                self.readying
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(ticket, io.into_state());
                Poll::Pending
            }
            Step::Ready(Ok(())) => Poll::Ready(Ok(())),
            Step::Ready(Err(e)) => Poll::Ready(Err(Refusal::failed(e))),
        }
    }

    /// The same settings and secret keep the opened module and its key cache (the admin cache
    /// flush is one of these; a secret lent empty is the same as none, as `open` reads it); new
    /// ones re-open it, a refusal keeping the running one untouched. Either way the verdict cache
    /// the running module held is dropped (`abi::auth`: an auth plugin drops its inbound cache on
    /// every `refresh`) and its count reported under [`CACHE_FAMILY`].
    fn refresh(
        &self,
        settings: &[u8],
        secrets: &[&[u8]],
        _generation: u64,
    ) -> Result<Refreshed, Refusal> {
        let now = self.now();
        let same_secret = now.secret == lent_secret(secrets);
        let reopened = if now.settings == settings && same_secret {
            None
        } else {
            Some(Arc::new(Opened::new(settings, secrets)?))
        };
        let flushed = now.module.flush_verdicts();
        match reopened {
            Some(opened) => *self.now.write().unwrap_or_else(PoisonError::into_inner) = opened,
            // The module kept: its discovery document is asked for again, as a re-opened one's is.
            None => now.module.rediscover(),
        }
        Ok(Refreshed {
            counted: Some(Counted {
                family: CACHE_FAMILY,
                value: flushed as f64,
            }),
        })
    }

    /// A plain http `jwks_url` raises [`DIAG_JWKS_PLAIN_HTTP`] at warn on the `open` or `refresh`
    /// that built the running module, in the words its log line says.
    fn flagged(&self) -> Option<Flagged> {
        self.now().flagged.clone().map(|text| Flagged {
            id_idx: DIAG_JWKS_PLAIN_HTTP,
            severity: SEVERITY_WARN,
            text,
        })
    }
}

/// What an op parks on its ticket across PENDING: its requests' state and, for a login, the token
/// endpoint's answer (the code redeems once). The answer carries the issued tokens, so its body is
/// wiped when the parked op goes.
#[derive(Default)]
struct Parked {
    io: IoState,
    answer: Option<LoginHttpResponse>,
}

impl Drop for Parked {
    fn drop(&mut self) {
        if let Some(answer) = self.answer.as_mut() {
            zeroize::Zeroize::zeroize(&mut answer.body);
        }
    }
}

/// The op's requests on its ticket, resumed from what it parked, for the `opened` module.
fn resume<'h>(
    instance: &Instance<'_, Held<Oidc>>,
    h: &'h Held<Oidc>,
    opened: &Opened,
) -> (HostIo<'h>, Parked) {
    let mut parked = instance
        .resume::<Parked>()
        .map_or_else(Parked::default, |p| *p);
    let anchored = opened.module.anchored();
    let io = HostIo::new(
        h.host(),
        instance.ticket(),
        std::mem::take(&mut parked.io),
        anchored,
    );
    (io, parked)
}

/// Answer PENDING with `parked` (the requests' state from `io`) on the op's ticket: on its own
/// exchange's wake, or — `wait` — on the wake of the fetch another op is making, with a backstop
/// timer at that fetch's bound.
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

/// The one line this plugin's credential arrives on, named whatever its verdict.
const AUTHORIZATION: &str = "authorization";

/// The Statement's carrier marks: the line `verify` reads its bearer from.
const CARRIERS: &[MarkWord] = &[carrier(AUTHORIZATION)];

/// Write the answer into the host's buffers and answer READY with `verdict`: for `verify` the strip
/// names and the decision (`strip`), and the identity `p` (if any); or the SHORT FAILED, every
/// `needed_*` at its full size and NOTHING written, when any of them does not fit (THE DESIGN
/// §11.13 M-SB: capacity is checked before anything is written).
fn answer(
    p: Option<&Principal>,
    ttl: Option<u64>,
    credential: Option<&[u8]>,
    strip: Option<(HostBuf<'_, StripName>, u32)>,
    buf: Lent<'_, IdentityBuf>,
    out: &mut Out<'_, IdentifyOut>,
    verdict: u32,
) -> Outcome {
    let (mut bytes, mut groups) = (buf.buf(), buf.groups());
    let strips: &[&str] = if strip.is_some() {
        &[AUTHORIZATION]
    } else {
        &[]
    };
    let roles: &[String] = p.map_or(&[][..], |p| p.roles.as_slice());
    // The credential the identity was verified from goes to the kernel with it (the
    // `caller-credential` style's passthrough; THE DESIGN §6 "Auth points and guest lists", step
    // 4): only with an identity.
    let credential = credential.filter(|_| p.is_some()).unwrap_or_default();
    // The FULL sizes first.
    let need_bytes = p.map_or(0, |p| p.id.len() + p.name.as_deref().map_or(0, str::len))
        + roles.iter().map(String::len).sum::<usize>()
        + strips.iter().map(|s| s.len()).sum::<usize>()
        + credential.len();
    let strip_cap = strip.as_ref().map_or(0, |(h, _)| h.cap());
    if need_bytes > bytes.cap() || roles.len() > groups.cap() || strips.len() > strip_cap {
        out.set(|o| &o.needed_bytes, need_bytes as u64);
        out.set(
            |o| &o.needed_groups,
            u32::try_from(roles.len()).unwrap_or(u32::MAX),
        );
        out.set(
            |o| &o.needed_strip,
            u32::try_from(strips.len()).unwrap_or(u32::MAX),
        );
        return Outcome::Failed;
    }
    if let Some((mut host, decision)) = strip {
        for name in strips {
            let span = bytes.span(name.as_bytes());
            host.push(StripName {
                name: span,
                place: STRIP_FIELD,
                _reserved: 0,
            });
        }
        out.set(
            |o| &o.strip_len,
            u32::try_from(host.written()).unwrap_or(u32::MAX),
        );
        out.set(|o| &o.decision, decision);
    }
    let Some(p) = p else {
        out.set(|o| &o.verdict, verdict);
        return Outcome::Ready;
    };
    let subject = bytes.span(p.id.as_bytes());
    let name = p.name.as_deref().map(|n| bytes.span(n.as_bytes()));
    for role in roles {
        let s = bytes.span(role.as_bytes());
        groups.push(s);
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
    let (flags, ttl) = ttl.map_or((0, 0), |t| (IDENTITY_HAS_TTL, t));
    out.set(|o| &o.identity.flags, flags);
    out.set(|o| &o.identity.ttl_secs, ttl);
    if !credential.is_empty() {
        let held = bytes.span(credential);
        out.set(|o| &o.identity.credential, held);
    }
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
            // Bytes that are not text are no JWT: not this module's credential, answered as one (as
            // 1.5.5 passed a header that did not read as text): PASS, the chain continues, and the
            // credential line is named for the transport to strip, whatever the verdict (THE DESIGN
            // §6, "Auth points and guest lists").
            Some(Err(_)) => {
                return answer(
                    None,
                    None,
                    None,
                    Some((input.strip(), DECISION_CONTINUE)),
                    input.field(|i| &i.out_buf),
                    &mut out,
                    VERDICT_PASS,
                );
            }
            Some(Ok(token)) => Some(token),
            None => None,
        };
        // ONE CLOCK (THE DESIGN §1): expiry is judged at the request's own timestamp, the host's
        // clock as it arrived; a request stating none (`0`) fails closed.
        let timestamp = input.field(|i| &i.request).timestamp;
        let request_now = crate::clock_or_fail_closed(i64::try_from(timestamp).unwrap_or(i64::MAX));
        let ticketless = instance.ticket().is_none();
        let opened = h.life().now();
        let (mut io, parked) = resume(&instance, h, &opened);
        // A HIT is answered from the cached identity itself, with no copy of it, stating the TTL
        // it has left — unless the op re-enters with its own fetch in flight: that fetch is
        // landed (its flight settled, its waiters woken) by judging the token, never dropped.
        let hit = (!io.in_flight())
            .then(|| token.and_then(|t| opened.module.cached(t, request_now)))
            .flatten();
        if let Some(hit) = hit {
            return answer(
                Some(&*hit.principal),
                hit.ttl_secs,
                token.map(str::as_bytes),
                Some((input.strip(), DECISION_CONTINUE)),
                input.field(|i| &i.out_buf),
                &mut out,
                VERDICT_IDENTITY,
            );
        }
        let judged = opened
            .module
            .judge(token, request_now, Instant::now(), &mut io);
        raise_refusals(&opened.module, &mut io, &mut out);
        let verdict = match judged {
            // ON THE SPOT (no ticket): a verify that needs a fetch, or waits on another call's, may
            // not pend, so it answers REFUSED and the host makes it again on a ticket
            // (`abi::auth`: a plugin whose `verify` must wait on I/O answers REFUSED on the spot).
            // A verdict reached WITHOUT a fetch it asked for (the module fails closed on keys it
            // could not reach) is not its verdict either: it is answered on a ticket too.
            Step::Ready(_) | Step::Pending | Step::Wait if ticketless && io.wanted_io() => {
                return Outcome::Refused
            }
            Step::Ready(Err(_)) | Step::Pending | Step::Wait if ticketless => {
                return Outcome::Refused
            }
            Step::Ready(Ok(v)) => v,
            Step::Ready(Err(e)) => return out.fail(Refusal::failed(e)),
            Step::Pending => return pend(&instance, h.host(), io, parked, &mut out, false),
            Step::Wait => return pend(&instance, h.host(), io, parked, &mut out, true),
        };
        // The transport's decision, the SDK's default for each verdict (`Answer::from(Verdict)`):
        // continue on an identity or a pass, stop on a reject; and the credential line named for
        // the transport to strip WHATEVER the verdict (THE DESIGN §6, "Auth points and guest
        // lists": every auth called names its credential lines).
        let (p, verdict, decision) = match &verdict {
            AuthVerdict::Identify(p) => (Some(p), VERDICT_IDENTITY, DECISION_CONTINUE),
            AuthVerdict::Pass => (None, VERDICT_PASS, DECISION_CONTINUE),
            AuthVerdict::Reject => (None, VERDICT_REJECT, DECISION_STOP),
        };
        answer(
            p,
            p.and_then(|p| p.ttl_secs),
            token.map(str::as_bytes),
            Some((input.strip(), decision)),
            input.field(|i| &i.out_buf),
            &mut out,
            verdict,
        )
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
        let opened = h.life().now();
        let (mut io, parked) = resume(&instance, h, &opened);
        let begun = opened.module.begin_login(&begin, Instant::now(), &mut io);
        raise_refusals(&opened.module, &mut io, &mut out);
        match begun {
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
        expire(&mut reached, Instant::now());
        let kept = reached
            .remove(&instance.ticket())
            .filter(|r| r.serves(state, code_bytes));
        drop(reached);
        let principal = match kept {
            Some(r) => r.principal,
            None => {
                let opened = oidc.now();
                let (mut io, mut parked) = resume(&instance, h, &opened);
                let login = opened.login(
                    code,
                    str_text(input.field(|i| &i.redirect_uri)),
                    blob_text(input.field(|i| &i.code_verifier)),
                    str_text(input.field(|i| &i.nonce)).unwrap_or(""),
                    &mut parked.answer,
                    &mut io,
                );
                raise_refusals(&opened.module, &mut io, &mut out);
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
                    Step::Ready(Login::SecurityCheck) => {
                        out.set(|o| &o.verdict, LOGIN_SECURITY_CHECK_FAILED);
                        return Outcome::Ready;
                    }
                    Step::Pending => return pend(&instance, h.host(), io, parked, &mut out, false),
                    Step::Wait => return pend(&instance, h.host(), io, parked, &mut out, true),
                }
            }
        };
        let answered = login_identity(&principal, input.field(|i| &i.out_buf), &mut out);
        if answered == Outcome::Failed {
            let mut reached = oidc.reached.lock().unwrap_or_else(PoisonError::into_inner);
            keep(
                &mut reached,
                REACHED_MAX,
                instance.ticket(),
                Reached {
                    at: Instant::now(),
                    state: cred::Held::new(state.to_vec()),
                    code: cred::Held::new(code_bytes.to_vec()),
                    principal,
                },
            );
        }
        answered
    }
}

/// `tick` (THE DESIGN, auth: "`tick` refreshes ahead of the TTL, with 1.5.5's timings"): on the
/// instance's driver ticket, the key set fetched again once it is within one tick period of its
/// TTL ([`OidcModule::refresh_ahead`]); PENDING while that fetch is in flight, carried on by
/// [`Drive`]. Asks for the next tick one period on (`jwks_min_refetch_secs`, 1.5.5's 60 s). A tick
/// on no ticket may not pend, so it fetches nothing.
#[derive(Debug)]
pub struct Tick;
impl SafeSlot for Tick {
    type In = TickIn;
    type Out = TickOut;
    type State = Held<Oidc>;
    fn call(
        instance: Instance<'_, Held<Oidc>>,
        input: Lent<'_, TickIn>,
        mut out: Out<'_, TickOut>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            out.set(|o| &o.next_tick_ns, 0);
            return Outcome::Ready;
        };
        let oidc = h.life();
        let opened = oidc.now();
        let period = u64::try_from(opened.module.tick_period().as_nanos()).unwrap_or(u64::MAX);
        out.set(|o| &o.next_tick_ns, input.now_ns.saturating_add(period));
        let ticket = instance.ticket();
        if ticket.is_none() {
            return Outcome::Ready;
        }
        // A refresh the last tick left in flight on this driver ticket is carried on, not
        // restarted: its flight is still this ticket's, and a fresh exchange would be a second
        // fetch of the same key set.
        let parked = oidc
            .driving
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        match parked {
            Some((parked, state)) => oidc.refresh_ahead(h.host(), ticket, parked, state),
            None => oidc.refresh_ahead(h.host(), ticket, opened, IoState::default()),
        }
    }
}

/// `drive`: the driver ticket was woken — the tick's key-set fetch goes on from where it parked.
#[derive(Debug)]
pub struct Drive;
impl SafeSlot for Drive {
    type In = DriveIn;
    type Out = OutHead;
    type State = Held<Oidc>;
    fn call(
        instance: Instance<'_, Held<Oidc>>,
        _: Lent<'_, DriveIn>,
        _: Out<'_, OutHead>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return Outcome::Fault;
        };
        let oidc = h.life();
        let parked = oidc
            .driving
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        match parked {
            Some((opened, state)) => oidc.refresh_ahead(h.host(), instance.ticket(), opened, state),
            None => Outcome::Ready,
        }
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
        Begin, Complete, Drive, FieldsIn, FieldsOut, NotServed, Oidc, OpenOutboundIn,
        OpenOutboundOut, OutboundReadyIn, OutboundReadyOut, Safe, Tick, Verify,
    };
    use busbar_contract::abi::sdk::life::{
        Cancel, Close, Open, Ready, Refresh, Release, Retire, Validate,
    };

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::auth::Ops,
        statement: super::STATEMENT,
        lifecycle: {
            validate: Safe<Validate<Oidc>>,
            open: Safe<Open<Oidc>>,
            refresh: Safe<Refresh<Oidc>>,
            retire: Safe<Retire<Oidc>>,
            tick: Safe<Tick>,
            drive: Safe<Drive>,
            cancel: Safe<Cancel<Oidc>>,
            release: Safe<Release<Oidc>>,
            close: Safe<Close<Oidc>>,
        },
        ready: Safe<Ready<Oidc>>,
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

#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod tests;
