// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR: the OIDC module on the auth kind's table (`busbar_contract::abi::auth`), every slot a
//! [`SafeSlot`] over the SDK's safe surface. The SDK's verify-only kit (`auth_verify_door!`)
//! refuses login, so this plugin writes its own `plugin_door!`: the SDK's generic lifecycle over
//! [`Oidc`], plus `verify` (the bearer credential judged by [`OidcModule`]), `begin_login` (the IdP
//! authorize URL) and `complete_login` (the token exchange made by the plugin itself with the
//! client secret the host lends at `open`, and the returned `id_token` verified into an identity).
//! `open_outbound`, `outbound_ready` and `fields` are not served and are REFUSED. Every request
//! goes out through the HOST's connector, over the needs the Statement declares
//! ([`crate::fetch::NEEDS`]): the plugin never dials. A linked build registers [`door`]; the
//! dropped-in `cdylib` (`busbar-auth-oidc-plugin`) exports the same door as its one symbol.

use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex, PoisonError, RwLock, Weak};
use std::task::Poll;
use std::time::Instant;

use busbar_contract::abi::auth::{
    AuthPoints, AuthTail, BeginLoginIn, BeginLoginOut, CompleteLoginIn, FieldsIn, FieldsOut,
    IdentifyOut, IdentityBuf, OpenOutboundIn, OpenOutboundOut, OutboundReadyIn, OutboundReadyOut,
    StripName, VerifyIn, BEGIN_AUTHORIZE, CANCEL_ABANDONED, CAP_INBOUND, CAP_LOGIN,
    DECISION_CONTINUE, DECISION_STOP, FACT_CACHEABLE, IDENTITY_HAS_TTL, LOGIN_BAD_CREDENTIAL,
    LOGIN_KIND_REDIRECT, LOGIN_SECURITY_CHECK_FAILED, METRIC_CACHE_FLUSHED, SPAN_ABSENT,
    STRIP_FIELD, VERDICT_IDENTITY, VERDICT_PASS, VERDICT_REJECT,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, OutHead, Outcome, Span, BLOB_ABSENT, BLOB_OCTETS, SEVERITY_ERROR,
};
use busbar_contract::abi::mechanism::door::{
    MarkWord, MetricFamily, Rewrite, Statement, FAMILY_COUNTER,
};
use busbar_contract::abi::mechanism::extensions::{self, EXT_DECLARES};
use busbar_contract::abi::mechanism::lifecycle::{DriveIn, ReadyIn, TickIn, TickOut};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::auth_door::{carrier, short_reply, verify_tail, with_tail};
use busbar_contract::abi::sdk::auth_kit::{login_identity, login_outage};
use busbar_contract::abi::sdk::conn::{ConnFailure, Host};
use busbar_contract::abi::sdk::cred::{self, Cred};
use busbar_contract::abi::sdk::door::{abi_str, alias, statement, AbiIn, AbiOut};
use busbar_contract::abi::sdk::lent::HostBuf;
use busbar_contract::abi::sdk::life::{Counted, Held, Life, Refreshed, Refusal};
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
/// cached.
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
pub const DIAG_NAMES: &[&str] = &["BUSBAR-4031"];

/// The declared diagnostic a refused IdP destination raises ([`raise_refusals`]): the module's own
/// refusal (a discovered `jwks_uri` or `token_endpoint` over plain http, a scheme) or the host's
/// (the destination guard refusing the address), naming the host and the rule.
pub const DIAG_DESTINATION_REFUSED: u32 = 0;

/// [`DIAG_NAMES`] as the Statement carries them.
const DIAG_IDS: &[AbiStr] = &[abi_str(DIAG_NAMES[DIAG_DESTINATION_REFUSED as usize])];

const DECLARES: &[u8] = include_bytes!("../declares.json");
const DECLARES_EXTENSION: [u8; extensions::entry_len(EXT_DECLARES, DECLARES)] =
    extensions::entry(EXT_DECLARES, DECLARES);

/// JSON Schema for the lifecycle settings document, embedded in the signed Statement.
const SETTINGS_SCHEMA: &[u8] = include_bytes!("../settings.schema.json");

/// This plugin's Statement: its name and alias, its version, the most calls one instance holds in
/// flight, its secret reference, its outbound needs, its metric family and its auth tail.
pub const STATEMENT: Statement = Statement {
    settings_schema: busbar_contract::abi::mechanism::call::Blob::json(SETTINGS_SCHEMA),
    extensions: Blob {
        ptr: DECLARES_EXTENSION.as_ptr(),
        len: DECLARES_EXTENSION.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    },
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
    ..with_tail(
        statement(NAME, env!("CARGO_PKG_VERSION"), IN_FLIGHT_MAX),
        &TAIL,
    )
};

/// EVERY REFUSED IdP DESTINATION IS AUDITED: each refusal the op met (`io`'s, [`HostIo::take_refusals`])
/// that `module` has not raised before is reported in the op's envelope as
/// [`DIAG_DESTINATION_REFUSED`] at error, once per module per refusal
/// ([`OidcModule::first_report`]).
fn raise_refusals<O: AbiOut>(module: &OidcModule, io: &mut HostIo<'_>, out: &mut Out<'_, O>) {
    for why in io.take_refusals() {
        if module.first_report(&why) {
            tracing::warn!(module = "oidc", "{why}");
            out.diag(DIAG_DESTINATION_REFUSED, SEVERITY_ERROR, why);
        }
    }
}

/// The most calls one instance has in flight at once (the statement's `max_inflight`).
const IN_FLIGHT_MAX: u32 = 64;

/// The most short answers kept for their re-call at once.
const REACHED_MAX: usize = 1024;

/// How long a short answer is kept for its re-call: an older one (its host never came back for
/// it) goes on the next access of the map.
const REACHED_TTL: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// Whether an answer kept at `at` is still held at `now` (host monotonic nanoseconds): kept for
/// [`REACHED_TTL`], the one rule every held short answer (login or verify) lives by.
fn fresh(at: u64, now: u64) -> bool {
    std::time::Duration::from_nanos(now.saturating_sub(at)) <= REACHED_TTL
}

/// Drop every kept answer older than [`REACHED_TTL`] at `now`.
fn expire(map: &mut HashMap<Ticket, Reached>, now: u64) {
    map.retain(|_, r| fresh(r.at, now));
}

/// The short-answer cache uses the host's monotonic clock. An unreadable clock permits neither
/// reuse nor retention of a cached identity.
fn reached_now(
    host: Option<&Host<busbar_contract::plugin::markers::AuthKind>>,
    ticket: Ticket,
) -> Option<u64> {
    match host?.connector(ticket).clock_now() {
        Poll::Ready(Ok(reading)) => Some(reading.mono_ns),
        _ => None,
    }
}

/// The BACKSTOP of an op waiting on another op's fetch, nanoseconds on the host's monotonic clock:
/// it is woken when that fetch lands ([`Fetch::wake`]), and asks again after this long only if the
/// fetch never settles.
const WAIT_NS: u64 = FLIGHT_MAX.as_nanos() as u64;

/// When an op waiting on another op's fetch is woken at the latest: [`WAIT_NS`] past the host's
/// monotonic clock, or why that clock cannot be read.
fn wait_until(
    host: Option<&Host<busbar_contract::plugin::markers::AuthKind>>,
    ticket: Ticket,
) -> Result<u64, ConnFailure> {
    let host = host.ok_or(ConnFailure::Unarmed)?;
    match host.connector(ticket).clock_now() {
        Poll::Ready(Ok(r)) => Ok(r.mono_ns.saturating_add(WAIT_NS)),
        Poll::Ready(Err(e)) => Err(e),
        Poll::Pending => Err(ConnFailure::Fault),
    }
}

/// The words of an op that cannot arm its backstop wake ([`wait_until`]).
fn cannot_wait(e: &ConnFailure) -> Refusal {
    Refusal::failed(format!(
        "oidc: cannot wait for the fetch another call is making: {e}"
    ))
}

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
}

impl Opened {
    fn new(settings: &[u8], secrets: &[&[u8]]) -> Result<Self, Refusal> {
        let module = module(text(settings)?).map_err(Refusal::failed)?;

        let secret = lent_secret(secrets);
        if secret.as_ref().is_some_and(|s| !s.is_text()) {
            return Err(Refusal::failed("secrets: `client_secret` is not UTF-8"));
        }
        Ok(Self {
            module,
            secret,
            settings: settings.to_vec(),
        })
    }

    /// The callback's code exchanged at the token endpoint (once: the answer is kept in `answer`
    /// across PENDING, the code redeems once), the answer bound to the login's `nonce`, and the
    /// `id_token` it answers verified.
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
                Err(e) => return Step::Ready(Login::Outage(e, io.retry_after_secs())),
            };
            match io.post(&request.url, &request.form) {
                Poll::Pending => return Step::Pending,
                Poll::Ready(Ok(r)) => *answer = Some(r),
                Poll::Ready(Err(e)) => return Step::Ready(Login::Outage(e, io.retry_after_secs())),
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

                Ok(LoginOutcome::Reject) => Login::Bad,
                Ok(LoginOutcome::Outage { retry_after_secs }) => Login::Outage(
                    "the identity provider is unavailable".to_string(),
                    retry_after_secs.or_else(|| io.retry_after_secs()),
                ),
                Ok(LoginOutcome::SecurityCheckFailed) => Login::SecurityCheck,
                Ok(
                    LoginOutcome::Authorize(_)
                    | LoginOutcome::Prompt(_)
                    | LoginOutcome::Exchange(_),
                ) => Login::Bad,
                Err(e) => Login::Outage(e, io.retry_after_secs()),
            },
        )
    }
}

/// How one login ended.
enum Login {
    Identity(Principal),
    Bad,
    Outage(String, Option<u64>),
    /// The IdP's identity token does not carry the login's nonce.
    SecurityCheck,
}

/// An identity `complete_login` reached but could not fit into the host's buffer, kept for the
/// host's one re-call on the same ticket (the code redeems once): served only to the same callback.
struct Reached {
    /// When it was kept on the host's monotonic clock: at the cap the oldest goes ([`keep`]).
    at: u64,
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
/// the cap the OLDEST entry goes, never the rest.
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

/// The identity a short login answer kept for this same-ticket re-call (`held`), when it serves
/// the callback's `state` and `code`. With the host clock unreadable (`now` absent) a held
/// identity's age cannot be told, and the re-call must not redeem the single-use code again
/// either: a real failure.
fn recall(
    held: Option<Reached>,
    now: Option<u64>,
    state: &[u8],
    code: &[u8],
) -> Result<Option<Reached>, &'static str> {
    match (held, now) {
        (Some(_), None) => Err("oidc: host clock unavailable for short login continuation"),
        (held, _) => Ok(held.filter(|r| r.serves(state, code))),
    }
}

/// What a short login answer holds for its re-call: the completion handles its exchange used,
/// the callback it answered, and the identity it reached.
struct ShortLogin<'a> {
    issued: u32,
    state: &'a [u8],
    code: &'a [u8],
    principal: Principal,
}

/// Hold a SHORT login answer for its same-ticket re-call ([`IdentifyOut`]'s short-buffer rule: the
/// re-call is served from the identity reached, never by redeeming the code again): its cursor and
/// its identity, both or neither. `now` is the host's monotonic reading; without one nothing is
/// held, since a cursor kept without its identity would have the re-call exchange the code a
/// second time. Answers the marker the answer's lease guard ([`ReleaseLogin`]) is made with.
fn hold_short_login(
    oidc: &Oidc,
    ticket: Ticket,
    now: Option<u64>,
    short: ShortLogin<'_>,
) -> Result<Arc<()>, &'static str> {
    let Some(now) = now else {
        return Err("oidc: host clock unavailable for short login answer");
    };
    let marker = Arc::new(());
    {
        let mut cursors = oidc
            .login_cursors
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if cursors.len() >= REACHED_MAX && !cursors.contains_key(&ticket) {
            return Err("oidc: too many held short login answers");
        }
        cursors.insert(
            ticket,
            LoginCursor {
                marker: Arc::clone(&marker),
                issued: short.issued,
            },
        );
    }
    let mut reached = oidc.reached.lock().unwrap_or_else(PoisonError::into_inner);
    keep(
        &mut reached,
        REACHED_MAX,
        ticket,
        Reached {
            at: now,
            state: cred::Held::new(short.state.to_vec()),
            code: cred::Held::new(short.code.to_vec()),
            principal: short.principal,
        },
    );
    Ok(marker)
}

/// A short callback's service cursor survives identity expiry, but not its answer's lease.
struct LoginCursor {
    marker: Arc<()>,
    issued: u32,
}

type LoginCursors = Mutex<HashMap<Ticket, LoginCursor>>;
type ReachedMap = Mutex<HashMap<Ticket, Reached>>;

/// RELEASE, cancellation and instance teardown must not leave a callback's cursor or identity.
struct ReleaseLogin {
    ticket: Ticket,
    marker: Arc<()>,
    cursors: Weak<LoginCursors>,
    reached: Weak<ReachedMap>,
}

impl Drop for ReleaseLogin {
    fn drop(&mut self) {
        let Some(cursors) = self.cursors.upgrade() else {
            return;
        };
        let retired = {
            let mut cursors = cursors.lock().unwrap_or_else(PoisonError::into_inner);
            if cursors
                .get(&self.ticket)
                .is_some_and(|c| Arc::ptr_eq(&c.marker, &self.marker))
            {
                cursors.remove(&self.ticket);

                self.reached.upgrade().and_then(|reached| {
                    reached
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .remove(&self.ticket)
                })
            } else {
                None
            }
        };
        drop(retired);
    }
}

/// An immutable VERIFY result awaiting its same-ticket SHORT retry. The credential is wiped
/// when the result is served, expired, released or abandoned.
struct Verified {
    at: u64,
    lease: u64,
    marker: Arc<()>,
    principal: Option<Principal>,
    ttl: Option<u64>,
    credential: Zeroizing<Vec<u8>>,
    decision: u32,
    verdict: u32,
}
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum VerifyKey {
    Ticket(Ticket),
    // The marker's allocation stays alive under both the result and its release guard.
    Ticketless(usize),
}
type VerifiedMap = Mutex<HashMap<VerifyKey, Verified>>;

struct ReleaseVerify {
    key: VerifyKey,
    marker: Arc<()>,
    verified: Weak<VerifiedMap>,
}
impl Drop for ReleaseVerify {
    fn drop(&mut self) {
        let Some(verified) = self.verified.upgrade() else {
            return;
        };
        let retired = {
            let mut verified = verified.lock().unwrap_or_else(PoisonError::into_inner);
            if verified
                .get(&self.key)
                .is_some_and(|v| Arc::ptr_eq(&v.marker, &self.marker))
            {
                verified.remove(&self.key)
            } else {
                None
            }
        };
        drop(retired);
    }
}

/// THE INSTANCE: the opened module (replaced whole by a `refresh` with new settings) and the
/// identities kept for a short-buffer re-call.
pub struct Oidc {
    now: RwLock<Arc<Opened>>,
    reached: Arc<ReachedMap>,
    verified: Arc<VerifiedMap>,
    login_cursors: Arc<LoginCursors>,
    /// A `ready` in flight: its requests' state, by its ticket, across PENDING.
    readying: Mutex<HashMap<Ticket, IoState>>,
    /// The tick's key-set refresh in flight on the driver ticket: the module it refreshes and its
    /// requests' state, carried on by `drive`.
    driving: Mutex<Driving>,
}

/// Driver work belongs to the refresh epoch in which it started. A successful refresh changes
/// this identity even when it keeps the same module, so an executing tick cannot republish old IO.
#[derive(Default)]
struct Driving {
    epoch: Arc<()>,
    pending: Option<(Ticket, Arc<Opened>, IoState)>,
}

impl std::fmt::Debug for Oidc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Oidc").finish_non_exhaustive()
    }
}

impl Oidc {
    /// The existing ready flow, optionally reporting refusals through the READY envelope.
    fn ready_with(
        &self,
        host: &Host<busbar_contract::plugin::markers::AuthKind>,
        ticket: Ticket,
        out: Option<&mut Out<'_, OutHead>>,
    ) -> Poll<Result<(), Refusal>> {
        let opened = self.now();
        let state = self
            .readying
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&ticket)
            .unwrap_or_default();
        let mut io = HostIo::new(Some(host), ticket, state, opened.module.anchored());
        let readied = opened.module.ready(Instant::now(), &mut io);
        if let Some(out) = out {
            raise_refusals(&opened.module, &mut io, out);
            // Waiting on another op's fetch: its settle wakes this ticket, and the backstop
            // re-enters it should that op never come back ([`WAIT_NS`]).
            if matches!(readied, Step::Wait) {
                match wait_until(Some(host), ticket) {
                    Ok(at) => out.wake_at(at),
                    Err(e) => return Poll::Ready(Err(cannot_wait(&e))),
                }
            }
        }
        match readied {
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

    fn now(&self) -> Arc<Opened> {
        self.now
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The tick's refresh ahead of the TTL on `opened`, over `host`'s connector on the driver
    /// ticket `ticket`, from `state`: PENDING (parked for `drive`) while its fetch is in flight,
    /// READY when it is done or nothing is due.
    fn refresh_ahead<O: AbiOut>(
        &self,
        host: Option<&Host<busbar_contract::plugin::markers::AuthKind>>,
        ticket: Ticket,
        opened: Arc<Opened>,
        state: IoState,
        epoch: Arc<()>,
        out: &mut Out<'_, O>,
    ) -> Outcome {
        let mut io = HostIo::new(host, ticket, state, opened.module.anchored());
        let refreshed = opened.module.refresh_ahead(Instant::now(), &mut io);
        raise_refusals(&opened.module, &mut io, out);
        match refreshed {
            Step::Pending => {
                // Published only while its refresh epoch is current; what it replaces, or the
                // state of a fetch a refresh has since discarded, drops after the lock.
                let mut driver = self.driving.lock().unwrap_or_else(PoisonError::into_inner);
                if !Arc::ptr_eq(&driver.epoch, &epoch) {
                    return Outcome::Ready;
                }
                let previous = driver.pending.replace((ticket, opened, io.into_state()));
                drop(driver);
                drop(previous);
                Outcome::Pending
            }

            Step::Ready(_) | Step::Wait => Outcome::Ready,
        }
    }
}

/// The settings blob as the JSON text it must be.
fn text(settings: &[u8]) -> Result<&str, Refusal> {
    std::str::from_utf8(settings).map_err(|_| Refusal::failed("settings: not UTF-8 text"))
}

impl Life for Oidc {
    type Kind = busbar_contract::plugin::markers::AuthKind;
    const CANCEL: u32 = CANCEL_ABANDONED;
    /// The generic drive slot is not this plugin's: its `Drive` slot replaces it and carries the
    /// tick's key-set refresh on the driver ticket.
    const DRIVE: Outcome = Outcome::Refused;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        config(text(settings)?)
            .and_then(|c| crate::check_jwks_url(&c))
            .map_err(Refusal::failed)
    }

    fn open(settings: &[u8], secrets: &[&[u8]], _generation: u64) -> Result<Self, Refusal> {
        Ok(Self {
            now: RwLock::new(Arc::new(Opened::new(settings, secrets)?)),
            reached: Arc::default(),
            verified: Arc::default(),
            login_cursors: Arc::default(),
            readying: Mutex::default(),
            driving: Mutex::default(),
        })
    }

    /// READY (after `open`, before any listener binds): discovery, a failure refusing the boot in
    /// 1.5.5's words, then the key set's warm-up ([`OidcModule::ready`]), over the instance's needs
    /// on `ticket`. PENDING while a request is in flight.
    fn ready(
        &self,
        host: &Host<busbar_contract::plugin::markers::AuthKind>,
        ticket: Ticket,
    ) -> Poll<Result<(), Refusal>> {
        self.ready_with(host, ticket, None)
    }

    /// The same settings and secret keep the opened module and its key cache (the admin cache
    /// flush is one of these); new ones re-open it, a refusal keeping the running one untouched.
    /// Either way the verdict cache the running module held is dropped and its count reported under
    /// [`CACHE_FAMILY`].
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
        let driving = {
            let mut driver = self.driving.lock().unwrap_or_else(PoisonError::into_inner);
            match reopened {
                Some(opened) => *self.now.write().unwrap_or_else(PoisonError::into_inner) = opened,

                None => now.module.rediscover(),
            }
            driver.epoch = Arc::new(());
            driver.pending.take()
        };
        let ready =
            std::mem::take(&mut *self.readying.lock().unwrap_or_else(PoisonError::into_inner));
        drop((ready, driving));
        Ok(Refreshed {
            counted: Some(Counted {
                family: CACHE_FAMILY,
                value: flushed as f64,
            }),
        })
    }

    fn retire(&self, _generation: u64) {
        let cursors = std::mem::take(
            &mut *self
                .login_cursors
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        let reached =
            std::mem::take(&mut *self.reached.lock().unwrap_or_else(PoisonError::into_inner));
        let verified =
            std::mem::take(&mut *self.verified.lock().unwrap_or_else(PoisonError::into_inner));
        drop((cursors, reached, verified));
    }

    fn cancel(&self, ticket: Ticket) -> u32 {
        let cursor = self
            .login_cursors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&ticket);
        let ready = self
            .readying
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&ticket);
        let reached = self
            .reached
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&ticket);
        let driving = {
            let mut driving = self.driving.lock().unwrap_or_else(PoisonError::into_inner);
            if driving
                .pending
                .as_ref()
                .is_some_and(|(owner, _, _)| *owner == ticket)
            {
                driving.pending.take()
            } else {
                None
            }
        };

        let verified = self
            .verified
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&VerifyKey::Ticket(ticket));
        drop((ready, reached, driving, cursor, verified));
        CANCEL_ABANDONED
    }
}

/// What an op parks on its ticket across PENDING: its requests' state, the exact module it began
/// on, and, for a login, the token endpoint's answer (the code redeems once). A settings refresh
/// affects fresh calls; it must not retarget a pending call's issuer, client or trust.
struct Parked {
    io: IoState,
    answer: Option<LoginHttpResponse>,
    opened: Arc<Opened>,
}

impl Drop for Parked {
    fn drop(&mut self) {
        if let Some(answer) = self.answer.as_mut() {
            zeroize::Zeroize::zeroize(&mut answer.body);
        }
    }
}

/// The op's requests and module, resumed from what it parked or captured for a fresh call.
fn resume<'h>(
    instance: &Instance<'_, Held<Oidc>, busbar_contract::plugin::markers::AuthKind>,
    h: &'h Held<Oidc>,
) -> (Arc<Opened>, HostIo<'h>, Parked) {
    resume_after(instance, h, None, instance.resume::<Parked>())
}

fn resume_after<'h>(
    instance: &Instance<'_, Held<Oidc>, busbar_contract::plugin::markers::AuthKind>,
    h: &'h Held<Oidc>,
    issued: Option<u32>,
    resumed: Option<Box<Parked>>,
) -> (Arc<Opened>, HostIo<'h>, Parked) {
    let mut parked = resumed.map_or_else(
        || Parked {
            io: IoState::following(issued.unwrap_or(0)),
            answer: None,
            opened: h.life().now(),
        },
        |p| *p,
    );
    let opened = Arc::clone(&parked.opened);
    let anchored = opened.module.anchored();
    let io = HostIo::new(
        h.host(),
        instance.ticket(),
        std::mem::take(&mut parked.io),
        anchored,
    );
    (opened, io, parked)
}

/// Answer PENDING with `parked` (the requests' state from `io`) on the op's ticket: on its own
/// exchange's wake, or, when `wait` is set, on the wake of the fetch another op is making, with a
/// backstop timer at that fetch's bound.
fn pend<O: AbiOut>(
    instance: &Instance<'_, Held<Oidc>, busbar_contract::plugin::markers::AuthKind>,
    host: Option<&Host<busbar_contract::plugin::markers::AuthKind>>,
    io: HostIo<'_>,
    mut parked: Parked,
    out: &mut Out<'_, O>,
    wait: bool,
) -> Outcome {
    if wait {
        match wait_until(host, instance.ticket()) {
            Ok(at) => out.wake_at(at),
            Err(e) => return out.fail(cannot_wait(&e)),
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
/// `needed_*` at its full size and NOTHING written, when any of them does not fit.
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

    let credential = credential.filter(|_| p.is_some()).unwrap_or_default();

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

/// The immutable verdict fields passed together from judgment to SHORT retention.
struct VerifyAnswer<'a> {
    principal: Option<&'a Principal>,
    ttl: Option<u64>,
    credential: Option<&'a [u8]>,
    decision: u32,
    verdict: u32,
}

/// Retain only when the actual answer is SHORT. The existing lease mechanism owns cleanup;
/// the marker prevents an old lease from discarding a later result that reused the ticket.
fn verify_answer(
    h: &Held<Oidc>,
    ticket: Ticket,
    fields: VerifyAnswer<'_>,
    input: Lent<'_, VerifyIn>,
    out: &mut Out<'_, IdentifyOut>,
) -> Outcome {
    let VerifyAnswer {
        principal,
        ttl,
        credential,
        decision,
        verdict,
    } = fields;
    let answered = answer(
        principal,
        ttl,
        credential,
        Some((input.strip(), decision)),
        input.field(|i| &i.out_buf),
        out,
        verdict,
    );
    if answered != Outcome::Failed {
        return answered;
    }
    let Some(now) = reached_now(h.host(), ticket) else {
        out.set(|o| &o.needed_bytes, 0);
        out.set(|o| &o.needed_groups, 0);
        out.set(|o| &o.needed_strip, 0);
        return out.fail(Refusal::failed(
            "oidc: host clock unavailable for short verify answer",
        ));
    };
    let marker = Arc::new(());
    let key = if ticket.is_none() {
        VerifyKey::Ticketless(Arc::as_ptr(&marker) as usize)
    } else {
        VerifyKey::Ticket(ticket)
    };
    let mut verified = h
        .life()
        .verified
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    verified.retain(|_, v| fresh(v.at, now));
    if verified.len() >= REACHED_MAX || verified.contains_key(&key) {
        out.set(|o| &o.needed_bytes, 0);
        out.set(|o| &o.needed_groups, 0);
        out.set(|o| &o.needed_strip, 0);
        return out.fail(Refusal::failed("oidc: too many held short verify answers"));
    }
    // Reserve under the bound, but never call lease code while holding this map's lock:
    // releasing the lease invokes ReleaseVerify, which takes the same lock.
    verified.insert(
        key,
        Verified {
            at: now,
            lease: 0,
            marker: marker.clone(),
            principal: principal.cloned(),
            ttl,
            credential: Zeroizing::new(
                credential
                    .filter(|_| principal.is_some())
                    .unwrap_or_default()
                    .to_vec(),
            ),
            decision,
            verdict,
        },
    );
    drop(verified);
    out.keep(
        h.leases(),
        ReleaseVerify {
            key,
            marker: marker.clone(),
            verified: Arc::downgrade(&h.life().verified),
        },
    );
    let lease = out.get().head.lease;
    {
        let mut verified = h
            .life()
            .verified
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(kept) = verified
            .get_mut(&key)
            .filter(|v| Arc::ptr_eq(&v.marker, &marker))
        {
            kept.lease = lease;
        }
    }
    out.lease(
        |o| &o.head.extensions,
        h.leases(),
        short_reply::encode(lease),
        BLOB_OCTETS,
    );
    answered
}

/// `verify`: the presented credential judged as a bearer token.
#[derive(Debug)]
pub struct Verify;
impl SafeSlot for Verify {
    type Kind = busbar_contract::plugin::markers::AuthKind;
    type In = VerifyIn;
    type Out = IdentifyOut;
    type State = Held<Oidc>;
    fn call(
        instance: Instance<'_, Held<Oidc>, busbar_contract::plugin::markers::AuthKind>,
        input: Lent<'_, VerifyIn>,
        mut out: Out<'_, IdentifyOut>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return Outcome::Fault;
        };
        let continuation = match short_reply::decode(input.field(|i| &i.head.extensions).bytes()) {
            Ok(lease) => lease,
            Err(why) => return out.fail(Refusal::refused(why)),
        };
        // A ticket identifies the logical call even when the host's fresh retry carries no
        // continuation extension. Ticketless recalls use the loader's private lease marker.
        let retained = !instance.ticket().is_none()
            && h.life()
                .verified
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains_key(&VerifyKey::Ticket(instance.ticket()));
        if continuation.is_some() || retained {
            let now = reached_now(h.host(), instance.ticket());
            let kept = {
                let mut verified = h
                    .life()
                    .verified
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                if let Some(now) = now {
                    verified.retain(|_, v| fresh(v.at, now));
                }
                let key = if instance.ticket().is_none() {
                    verified.iter().find_map(|(key, v)| {
                        (matches!(key, VerifyKey::Ticketless(_)) && continuation == Some(v.lease))
                            .then_some(*key)
                    })
                } else {
                    Some(VerifyKey::Ticket(instance.ticket()))
                };
                key.filter(|key| {
                    now.is_some()
                        && verified
                            .get(key)
                            .is_some_and(|v| continuation.is_none_or(|lease| v.lease == lease))
                })
                .and_then(|key| verified.remove(&key))
            };
            let Some(kept) = kept else {
                if now.is_none() {
                    return out.fail(Refusal::failed(
                        "oidc: host clock unavailable for short verify continuation",
                    ));
                }
                return out.fail(Refusal::refused(
                    "oidc: short verify continuation is no longer held",
                ));
            };
            return answer(
                kept.principal.as_ref(),
                kept.ttl,
                Some(&kept.credential),
                Some((input.strip(), kept.decision)),
                input.field(|i| &i.out_buf),
                &mut out,
                kept.verdict,
            );
        }
        let c = input.field(|i| &i.credential);
        let credential = (c.fmt != BLOB_ABSENT && !c.ptr.is_null()).then(|| c.bytes());
        let token = match credential.map(std::str::from_utf8) {
            Some(Err(_)) => {
                tracing::debug!(
                    module = "oidc",
                    reason = "non-text-bearer",
                    "credential is not a text JWT; passing to the next auth module"
                );
                return verify_answer(
                    h,
                    instance.ticket(),
                    VerifyAnswer {
                        principal: None,
                        ttl: None,
                        credential: None,
                        decision: DECISION_CONTINUE,
                        verdict: VERDICT_PASS,
                    },
                    input,
                    &mut out,
                );
            }
            Some(Ok(token)) => Some(token),
            None => None,
        };

        let timestamp = input.field(|i| &i.request).timestamp;
        let request_now = crate::clock_or_fail_closed(i64::try_from(timestamp).unwrap_or(i64::MAX));
        let ticketless = instance.ticket().is_none();
        let (opened, mut io, parked) = resume(&instance, h);

        let hit = (!io.in_flight())
            .then(|| token.and_then(|t| opened.module.cached(t, request_now)))
            .flatten();
        if let Some(hit) = hit {
            return verify_answer(
                h,
                instance.ticket(),
                VerifyAnswer {
                    principal: Some(&*hit.principal),
                    ttl: hit.ttl_secs,
                    credential: token.map(str::as_bytes),
                    decision: DECISION_CONTINUE,
                    verdict: VERDICT_IDENTITY,
                },
                input,
                &mut out,
            );
        }
        let judged = opened
            .module
            .judge(token, request_now, Instant::now(), &mut io);
        raise_refusals(&opened.module, &mut io, &mut out);
        let verdict = match judged {
            Step::Ready(_) | Step::Pending | Step::Wait if ticketless && io.wanted_io() => {
                return Outcome::Refused;
            }
            Step::Ready(Err(e)) if ticketless => return out.fail(Refusal::refused(e)),
            Step::Pending | Step::Wait if ticketless => return Outcome::Refused,
            Step::Ready(Ok(v)) => v,
            Step::Ready(Err(e)) => return out.fail(Refusal::failed(e)),
            Step::Pending => return pend(&instance, h.host(), io, parked, &mut out, false),
            Step::Wait => return pend(&instance, h.host(), io, parked, &mut out, true),
        };

        let (p, verdict, decision) = match &verdict {
            AuthVerdict::Identify(p) => (Some(p), VERDICT_IDENTITY, DECISION_CONTINUE),
            AuthVerdict::Pass => (None, VERDICT_PASS, DECISION_CONTINUE),
            AuthVerdict::Reject => (None, VERDICT_REJECT, DECISION_STOP),
        };
        verify_answer(
            h,
            instance.ticket(),
            VerifyAnswer {
                principal: p,
                ttl: p.and_then(|p| p.ttl_secs),
                credential: token.map(str::as_bytes),
                decision,
                verdict,
            },
            input,
            &mut out,
        )
    }
}

/// `begin_login`: the IdP authorize URL for the core's state, PKCE challenge and nonce.
#[derive(Debug)]
pub struct Begin;
impl SafeSlot for Begin {
    type Kind = busbar_contract::plugin::markers::AuthKind;
    type In = BeginLoginIn;
    type Out = BeginLoginOut;
    type State = Held<Oidc>;
    fn call(
        instance: Instance<'_, Held<Oidc>, busbar_contract::plugin::markers::AuthKind>,
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

        let begin = BeginLogin {
            redirect_uri,
            state,
            code_challenge,
            nonce: str_text(input.field(|i| &i.nonce)).map(str::to_string),
            scopes: Vec::new(),
        };
        let (opened, mut io, parked) = resume(&instance, h);
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
    type Kind = busbar_contract::plugin::markers::AuthKind;
    type In = CompleteLoginIn;
    type Out = IdentifyOut;
    type State = Held<Oidc>;
    fn call(
        instance: Instance<'_, Held<Oidc>, busbar_contract::plugin::markers::AuthKind>,
        input: Lent<'_, CompleteLoginIn>,
        mut out: Out<'_, IdentifyOut>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return Outcome::Fault;
        };
        let oidc = h.life();
        let Some(nonce) = str_text(input.field(|i| &i.nonce)).filter(|n| !n.is_empty()) else {
            tracing::warn!(
                module = "oidc",
                "complete_login carries no readable nonce; login refused"
            );
            out.set(|o| &o.verdict, LOGIN_SECURITY_CHECK_FAILED);
            return Outcome::Ready;
        };
        let state = input.field(|i| &i.state).bytes();
        let code = blob_text(input.field(|i| &i.code));
        let code_bytes = code.map_or(&[][..], str::as_bytes);
        let cursor = oidc
            .login_cursors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&instance.ticket())
            .map(|c| c.issued);
        let resumed = instance.resume::<Parked>();
        match short_reply::decode(input.field(|i| &i.head.extensions).bytes()) {
            Ok(Some(_)) if cursor.is_none() && resumed.is_none() => {
                return out.fail(Refusal::refused(
                    "oidc: short login continuation is no longer held",
                ));
            }
            Err(why) => return out.fail(Refusal::refused(why)),
            _ => {}
        }
        let now = reached_now(h.host(), instance.ticket());
        let mut reached = oidc.reached.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(now) = now {
            expire(&mut reached, now);
        }
        let held = reached.remove(&instance.ticket());
        drop(reached);
        let kept = match recall(held, now, state, code_bytes) {
            Ok(kept) => kept,
            Err(why) => return out.fail(Refusal::failed(why)),
        };
        let (principal, issued) = match kept {
            Some(r) => (r.principal, cursor.unwrap_or(0)),
            None => {
                let (opened, mut io, mut parked) = resume_after(&instance, h, cursor, resumed);
                let login = opened.login(
                    code,
                    str_text(input.field(|i| &i.redirect_uri)),
                    blob_text(input.field(|i| &i.code_verifier)),
                    nonce,
                    &mut parked.answer,
                    &mut io,
                );
                raise_refusals(&opened.module, &mut io, &mut out);
                match login {
                    Step::Ready(Login::Identity(p)) => (p, io.issued()),
                    Step::Ready(Login::Bad) => {
                        out.set(|o| &o.verdict, LOGIN_BAD_CREDENTIAL);
                        return Outcome::Ready;
                    }
                    Step::Ready(Login::Outage(e, retry_after_secs)) => {
                        tracing::warn!(module = "oidc", error = %e, "OIDC token exchange failed");
                        return login_outage(
                            retry_after_secs,
                            input.field(|i| &i.out_buf),
                            &mut out,
                        );
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
            let now = reached_now(h.host(), instance.ticket());
            let short = ShortLogin {
                issued,
                state,
                code: code_bytes,
                principal,
            };
            let marker = match hold_short_login(oidc, instance.ticket(), now, short) {
                Ok(marker) => marker,
                Err(why) => {
                    out.set(|o| &o.needed_bytes, 0);
                    out.set(|o| &o.needed_groups, 0);
                    return out.fail(Refusal::failed(why));
                }
            };
            out.keep(
                h.leases(),
                ReleaseLogin {
                    ticket: instance.ticket(),
                    marker,
                    cursors: Arc::downgrade(&oidc.login_cursors),
                    reached: Arc::downgrade(&oidc.reached),
                },
            );
            let lease = out.get().head.lease;
            out.lease(
                |o| &o.head.extensions,
                h.leases(),
                short_reply::encode(lease),
                BLOB_OCTETS,
            );
        }
        answered
    }
}

/// `ready`: the normal lifecycle flow with its existing output envelope available for diagnostics.
#[derive(Debug)]
pub struct Ready;
impl SafeSlot for Ready {
    type Kind = busbar_contract::plugin::markers::AuthKind;
    type In = ReadyIn;
    type Out = OutHead;
    type State = Held<Oidc>;
    fn call(
        instance: Instance<'_, Held<Oidc>, busbar_contract::plugin::markers::AuthKind>,
        input: Lent<'_, ReadyIn>,
        mut out: Out<'_, OutHead>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return Outcome::Fault;
        };
        let Some(host) = input.host().map(|loan| Host::of(instance.host(loan))) else {
            return Outcome::Fault;
        };
        match h
            .life()
            .ready_with(&host, instance.ticket(), Some(&mut out))
        {
            Poll::Pending => Outcome::Pending,
            Poll::Ready(Ok(())) => Outcome::Ready,
            Poll::Ready(Err(refusal)) => out.fail(refusal),
        }
    }
}

/// `tick` refreshes ahead of the TTL with 1.5.5's timings: on the
/// instance's driver ticket, the key set fetched again once it is within one tick period of its
/// TTL ([`OidcModule::refresh_ahead`]); PENDING while that fetch is in flight, carried on by
/// [`Drive`]. Asks for the next tick one period on (`jwks_min_refetch_secs`, 1.5.5's 60 s). A tick
/// on no ticket may not pend, so it fetches nothing.
#[derive(Debug)]
pub struct Tick;
impl SafeSlot for Tick {
    type Kind = busbar_contract::plugin::markers::AuthKind;
    type In = TickIn;
    type Out = TickOut;
    type State = Held<Oidc>;
    fn call(
        instance: Instance<'_, Held<Oidc>, busbar_contract::plugin::markers::AuthKind>,
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

        let (epoch, opened, parked) = {
            let mut driver = oidc.driving.lock().unwrap_or_else(PoisonError::into_inner);
            (driver.epoch.clone(), oidc.now(), driver.pending.take())
        };
        match parked {
            Some((owner, parked, state)) => {
                oidc.refresh_ahead(h.host(), owner, parked, state, epoch, &mut out)
            }
            None => oidc.refresh_ahead(
                h.host(),
                ticket,
                opened,
                IoState::default(),
                epoch,
                &mut out,
            ),
        }
    }
}

/// `drive`: the driver ticket was woken — the tick's key-set fetch goes on from where it parked.
#[derive(Debug)]
pub struct Drive;
impl SafeSlot for Drive {
    type Kind = busbar_contract::plugin::markers::AuthKind;
    type In = DriveIn;
    type Out = OutHead;
    type State = Held<Oidc>;
    fn call(
        instance: Instance<'_, Held<Oidc>, busbar_contract::plugin::markers::AuthKind>,
        _: Lent<'_, DriveIn>,
        mut out: Out<'_, OutHead>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return Outcome::Fault;
        };
        let oidc = h.life();
        let (epoch, parked) = {
            let mut driver = oidc.driving.lock().unwrap_or_else(PoisonError::into_inner);
            (driver.epoch.clone(), driver.pending.take())
        };
        match parked {
            Some((ticket, opened, state)) => {
                oidc.refresh_ahead(h.host(), ticket, opened, state, epoch, &mut out)
            }
            None => Outcome::Ready,
        }
    }
}

/// An op the tail does not state (the outbound family): REFUSED, never called.
#[derive(Debug)]
pub struct NotServed<I, O>(PhantomData<(I, O)>);
impl<I: AbiIn, O: AbiOut> SafeSlot for NotServed<I, O> {
    type Kind = busbar_contract::plugin::markers::AuthKind;
    type In = I;
    type Out = O;
    type State = Held<Oidc>;
    fn call(
        _: Instance<'_, Held<Oidc>, busbar_contract::plugin::markers::AuthKind>,
        _: Lent<'_, I>,
        _: Out<'_, O>,
    ) -> Outcome {
        Outcome::Refused
    }
}

mod table {
    use super::{
        Begin, Complete, Drive, FieldsIn, FieldsOut, NotServed, Oidc, OpenOutboundIn,
        OpenOutboundOut, OutboundReadyIn, OutboundReadyOut, Ready, Safe, Tick, Verify,
    };
    use busbar_contract::abi::sdk::life::{
        Cancel, Close, Open, Refresh, Release, Retire, Validate,
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
        ready: Safe<Ready>,
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
pub use table::{door, MACRO_DOOR};

#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "settings_schema_tests.rs"]
mod settings_schema_tests;
