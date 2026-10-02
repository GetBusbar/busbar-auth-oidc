// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared by this crate's integration tests (`e2e.rs`, `conformance.rs`):
//!
//! * the logic crate's own local issuer (`busbar_auth_oidc::testkit`, feature `testkit`) — a REAL
//!   ES256 key, its JWKS, and genuinely signed tokens;
//! * THE IdP AS THE HOST'S CONNECTION TABLE ([`Idp`]): the module never dials, its needs do, so the
//!   far end is what the host's connector hands its framed requests to. It answers each request by
//!   its path (the discovery document, the JWKS, the token endpoint), and answers the FIRST read of
//!   every reply PENDING, waking the op's ticket from another thread, so every request crosses
//!   PENDING and its op is re-entered on the wake;
//! * the HOST side of the auth door, through the real loader: a dispatcher serving the host's clock,
//!   a bind lending the connection table, and one call per op on a fresh ticket, each answer
//!   rendered as one comparable line.
//!
//! No stubbed crypto, no stubbed door.
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::abi::auth::{
    slot, BeginLoginIn, BeginLoginOut, CompleteLoginIn, IdentifyOut, IdentityBuf, VerifyIn,
    IDENTITY_BUF_BYTES, IDENTITY_GROUPS, SPAN_ABSENT,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, Outcome, Span, BLOB_JSON, BLOB_OCTETS,
};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut, ReleaseIn};
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::conn::{
    ConnError, ConnId, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece, PieceKind,
};
use busbar_contract::ids::StreamId;
use busbar_contract::services::{
    Caller, HostServices, Later, Ran, Reading, RecordsList, Stored, UNSERVED,
};
use busbar_contract::transport::ConnFacts;
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_dropped_bytes, load_linked, now_ns, out_head, Bind, DispatchConfig,
    Dispatcher, Done, Frame, InFrame, LinkedRow, LoadError, NoSink, OutFrame, Plugin, NO_BLOB,
};

pub use busbar_auth_oidc::testkit::Issuer;

/// The `iss` of a key used only for its signature (the tests configure the issuer they check).
pub const UNUSED_ISSUER: &str = "https://issuer.unused.invalid";

/// The IdP the tests play: its issuer, and where its documents are.
pub const ISSUER: &str = "https://idp.conformance.example/v2.0";
pub const DISCOVERY_PATH: &str = "/v2.0/.well-known/openid-configuration";
pub const JWKS_URL: &str = "https://idp.conformance.example/keys";
pub const TOKEN_URL: &str = "https://idp.conformance.example/token";
pub const AUTHORIZE_URL: &str = "https://idp.conformance.example/authorize";

/// An all-zero `T`.
pub fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { std::mem::zeroed() }
}

// ── the host's clock ─────────────────────────────────────────────────────────────────────────────

/// The host services a test host serves: the kernel's one clock (what an op waiting on another's
/// fetch sets its timer by, on the dispatcher's own monotonic clock); nothing else.
pub struct Clock;

impl HostServices for Clock {
    fn now(&self) -> Reading {
        Reading {
            wall_ns: 0,
            mono_ns: now_ns(),
        }
    }
    fn dest_judge(&self, _: &str, _: u32, _: bool, _: Option<Later>) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn records_get(&self, _: &Caller, _: &str, _: &[u8], _: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn records_list(&self, _: &Caller, _: RecordsList, _: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn records_claim(&self, _: &Caller, _: &str, _: &[u8], _: u64, _: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn sign(&self, _: &Caller, _: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_sight(&self, _: &Caller, _: &str, _: &str, _: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn trust_due(&self, _: &Caller) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn entitlement_check(&self, _: &Caller, _: Option<u64>, _: &str) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn random_fill(&self, _: u64) -> Stored {
        Stored::refused(UNSERVED)
    }
}

// ── the IdP, as the host's connection table ──────────────────────────────────────────────────────

/// The dispatcher's connection-table wake.
type Wake = Arc<dyn Fn(u64) + Send + Sync>;

/// One request as the host's framer was handed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sent {
    pub conn: u64,
    pub need: u32,
    pub target: String,
    pub method: String,
    pub path: String,
    pub body: String,
}

/// One reply being read: how far, and what.
struct Reply {
    step: u8,
    at: usize,
    status: u32,
    body: Vec<u8>,
}

/// THE IdP: every need framed; an open is the whole request (kept in `sent`), answered by its path
/// from `answers` (404 when none); the first read of every reply PENDING, the op's ticket woken
/// `delay` later from another thread.
pub struct Idp {
    wake: Mutex<Option<Wake>>,
    /// `(connection, the waking ticket)` of every first read: which op made each request.
    woken: Mutex<Vec<(u64, u64)>>,
    answers: Mutex<HashMap<String, (u32, Vec<u8>)>>,
    sent: Mutex<Vec<Sent>>,
    declared: Mutex<Vec<String>>,
    reads: Mutex<HashMap<u64, Reply>>,
    next: AtomicU64,
    pended: AtomicU32,
    delay: Mutex<Duration>,
}

impl Idp {
    /// The IdP of `ISSUER`, signing with `key`: its discovery document (naming its JWKS, authorize
    /// and token endpoints), its JWKS, and a token endpoint answering `{}`.
    pub fn new(key: &Issuer) -> Arc<Self> {
        let idp = Arc::new(Self {
            wake: Mutex::new(None),
            woken: Mutex::new(Vec::new()),
            answers: Mutex::new(HashMap::new()),
            sent: Mutex::new(Vec::new()),
            declared: Mutex::new(Vec::new()),
            reads: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            pended: AtomicU32::new(0),
            delay: Mutex::new(Duration::from_millis(5)),
        });
        let doc = serde_json::json!({
            "issuer": ISSUER,
            "jwks_uri": JWKS_URL,
            "authorization_endpoint": AUTHORIZE_URL,
            "token_endpoint": TOKEN_URL,
        });
        idp.answer(DISCOVERY_PATH, 200, &doc.to_string());
        idp.answer("/keys", 200, key.jwks());
        idp.answer("/token", 200, "{}");
        idp
    }

    /// What a request to `path` is answered from now on.
    pub fn answer(&self, path: &str, status: u32, body: &str) {
        self.answers
            .lock()
            .unwrap()
            .insert(path.to_string(), (status, body.as_bytes().to_vec()));
    }

    /// How long a reply's first read pends before the op's ticket is woken.
    pub fn pend_for(&self, delay: Duration) {
        *self.delay.lock().unwrap() = delay;
    }

    /// Every request, in order.
    pub fn sent(&self) -> Vec<Sent> {
        self.sent.lock().unwrap().clone()
    }

    /// The requests to `path`.
    pub fn sent_to(&self, path: &str) -> Vec<Sent> {
        self.sent().into_iter().filter(|s| s.path == path).collect()
    }

    /// `(connection, waking ticket)` of every first read, in order.
    pub fn woken(&self) -> Vec<(u64, u64)> {
        self.woken.lock().unwrap().clone()
    }

    /// How many reads answered PENDING.
    pub fn pended(&self) -> u32 {
        self.pended.load(Ordering::SeqCst)
    }

    /// Every need the loader declared, as it declared it, sorted.
    pub fn declared(&self) -> Vec<String> {
        let mut d = self.declared.lock().unwrap().clone();
        d.sort();
        d
    }
}

fn piece(kind: PieceKind, len: usize) -> Piece {
    Piece {
        kind,
        stream: StreamId(0),
        len,
        end: true,
        status: None,
        status_code: None,
        status_namespace: None,
        retry_after_secs: None,
        reason: None,
    }
}

impl Conns for Idp {
    fn open(&self, _: InstanceId, need: NeedId, desc: &OpenDesc<'_>) -> Result<ConnId, ConnError> {
        let path = String::from_utf8_lossy(desc.head_target).into_owned();
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        self.sent.lock().unwrap().push(Sent {
            conn: id,
            need: need.0,
            target: desc.target.to_owned(),
            method: String::from_utf8_lossy(desc.method).into_owned(),
            path: path.clone(),
            body: String::from_utf8_lossy(desc.body).into_owned(),
        });
        let (status, body) = self
            .answers
            .lock()
            .unwrap()
            .get(&path)
            .cloned()
            .unwrap_or((404, b"{}".to_vec()));
        self.reads.lock().unwrap().insert(
            id,
            Reply {
                step: 0,
                at: 0,
                status,
                body,
            },
        );
        Ok(ConnId(id))
    }
    fn write(&self, _: InstanceId, _: ConnId, _: &[u8], _: bool) -> Result<usize, ConnError> {
        Err(ConnError::Closed)
    }
    fn read(
        &self,
        _: InstanceId,
        conn: ConnId,
        ticket: u64,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        let mut reads = self.reads.lock().unwrap();
        let r = reads.get_mut(&conn.0).ok_or(ConnError::Closed)?;
        match r.step {
            0 => {
                // The far end has not answered yet: the wake comes later, from elsewhere.
                r.step = 1;
                self.pended.fetch_add(1, Ordering::SeqCst);
                self.woken.lock().unwrap().push((conn.0, ticket));
                let wake = self
                    .wake
                    .lock()
                    .unwrap()
                    .clone()
                    .expect("the table is armed");
                let delay = *self.delay.lock().unwrap();
                std::thread::spawn(move || {
                    std::thread::sleep(delay);
                    wake(ticket);
                });
                Err(ConnError::Pending)
            }
            1 => {
                r.step = 2;
                let reason = b"X";
                buf[..reason.len()].copy_from_slice(reason);
                Ok(Piece {
                    status_code: Some(r.status),
                    reason: Some(0..reason.len()),
                    ..piece(PieceKind::Fields, 0)
                })
            }
            _ if r.at < r.body.len() => {
                let n = (r.body.len() - r.at).min(buf.len());
                buf[..n].copy_from_slice(&r.body[r.at..r.at + n]);
                r.at += n;
                Ok(piece(PieceKind::Body, n))
            }
            _ => Ok(piece(PieceKind::Completion, 0)),
        }
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
        Err(ConnError::Closed)
    }
    fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
        Err(ConnError::Closed)
    }
    fn close(&self, _: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        self.reads.lock().unwrap().remove(&conn.0);
        Ok(())
    }
}

impl DeclaredConns for Idp {
    fn declare(
        &self,
        _: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
    ) -> Result<(), ConnError> {
        self.declared.lock().unwrap().push(format!(
            "need {} direction={} class={} transport={} target_from={:?} trust_from={:?} \
             timeout_ms={} target={target:?}",
            need.0,
            spec.direction,
            spec.egress_class,
            spec.transport,
            spec.target_from,
            spec.trust_from,
            spec.timeout_ms,
        ));
        Ok(())
    }
    fn declared(&self, _: InstanceId, _: NeedId) -> Option<Result<(), ConnError>> {
        Some(Ok(()))
    }
    fn framed(&self, _: InstanceId, _: NeedId) -> bool {
        true
    }
}

// ── the host's side ──────────────────────────────────────────────────────────────────────────────

/// This crate's built cdylib (uplifted or under `deps`, newest wins), when it is built.
pub fn cdylib_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let profile = exe.parent()?.parent()?;
    let file = busbar_plugin_loader::plugin_library_filename("busbar_auth_oidc_plugin");
    [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
}

/// THE LINKED ROW: the door and the Statement it states.
pub fn row() -> LinkedRow {
    LinkedRow::of(busbar_auth_oidc_plugin::door::door).expect("the door states itself")
}

/// Which door.
pub enum Arm<'a> {
    /// The logic crate's door, linked.
    Linked,
    /// A cdylib's bytes, admitted against a stated Statement.
    Dropped { lib: &'a [u8], stated: &'a [u8] },
    /// The cdylib on disk, admitted against the Statement it renders.
    File(&'a std::path::Path),
}

/// One door bound to a dispatcher serving the host's clock and to the IdP `idp` as its connection
/// table: the plugin (not yet opened).
pub struct Bound {
    pub dispatcher: Arc<Dispatcher>,
    pub idp: Arc<Idp>,
    pub plugin: Plugin<Auth>,
}

/// `arm` bound as `kind` would be loaded (`load_dropped_bytes`), for the RED arms' refusals.
pub fn bind_as<K: busbar_plugin_loader::dispatch::Kind>(
    arm: &Arm<'_>,
    idp: &Arc<Idp>,
) -> (Arc<Dispatcher>, Result<Plugin<K>, LoadError>) {
    let dispatcher = Arc::new(Dispatcher::with_services(
        DispatchConfig {
            workers: 2,
            ..Default::default()
        },
        Arc::new(Clock),
    ));
    *idp.wake.lock().unwrap() = Some(dispatcher.conn_waker());
    let conns: Arc<dyn DeclaredConns> = idp.clone();
    let bind = Bind {
        instance: Arc::from("oidc"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: Some(conns),
    };
    let plugin = match arm {
        Arm::Linked => load_linked::<K>(&row(), bind),
        Arm::Dropped { lib, stated } => {
            load_dropped_bytes::<K>(lib, busbar_auth_oidc_plugin::door::NAME, stated, bind)
        }
        Arm::File(path) => {
            let stated = busbar_plugin_loader::dispatch::rendering_of_library(path)
                .expect("the cdylib opens")
                .expect("the cdylib exports the door");
            load_dropped::<K>(path, &stated, bind)
        }
    };
    (dispatcher, plugin)
}

/// `arm` bound to `idp`.
pub fn bind(arm: &Arm<'_>, idp: &Arc<Idp>) -> Bound {
    let (dispatcher, plugin) = bind_as::<Auth>(arm, idp);
    Bound {
        dispatcher,
        idp: idp.clone(),
        plugin: plugin.expect("the door loads"),
    }
}

fn blob(bytes: &[u8], fmt: u32) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt,
        flags: 0,
    }
}

fn abi_str(s: &str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

/// The plugin memory `s` names, as text (valid until its lease is released).
fn text(s: AbiStr) -> String {
    if s.ptr.is_null() {
        return String::new();
    }
    // SAFETY: the door answered `s` READY under a lease the caller has not released yet.
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(s.ptr, s.len) }).into_owned()
}

/// The text a FAILED/REFUSED answer carried.
fn error_of(error: Option<&[u8]>) -> String {
    error
        .map(|e| String::from_utf8_lossy(e).into_owned())
        .unwrap_or_default()
}

/// The identity an answer wrote into the host's buffers, as one line.
fn identity(out: &IdentifyOut, bytes: &[u8], groups: &[Span]) -> String {
    let at = |s: Span| {
        (s.offset != SPAN_ABSENT).then(|| {
            String::from_utf8_lossy(&bytes[s.offset as usize..(s.offset + s.len) as usize])
                .into_owned()
        })
    };
    let id = &out.identity;
    let groups: Vec<_> = groups[..id.groups_len as usize]
        .iter()
        .map(|g| at(*g).unwrap_or_default())
        .collect();
    format!(
        "subject={:?} name={:?} groups={groups:?} key={:?}/{:?} user={:?} provider={:?} ttl={}/{}",
        at(id.subject),
        at(id.name),
        at(id.key_id),
        at(id.key_name),
        at(id.user),
        at(id.provider),
        id.flags,
        id.ttl_secs,
    )
}

/// `open` `p` over `settings`, lending `secret` as its one secret; the operator's text for a
/// refusal.
pub fn open(p: &Plugin<Auth>, settings: &str, secret: Option<&str>) -> Result<(), String> {
    let secrets: Vec<Blob> = secret
        .iter()
        .map(|s| blob(s.as_bytes(), BLOB_OCTETS))
        .collect();
    let mut reason = vec![0_u8; 1024];
    let mut i: OpenIn = z();
    i.head = in_head();
    i.settings = blob(settings.as_bytes(), BLOB_JSON);
    i.secrets = secrets.as_ptr();
    i.secrets_len = secrets.len();
    i.generation = 1;
    i.err_buf = reason.as_mut_ptr();
    i.err_cap = reason.len();
    let mut o: OpenOut = z();
    o.head = out_head();
    let called = p.call(life::OPEN, &mut Frame::new(i, o));
    match called.outcome {
        Outcome::Ready => Ok(()),
        _ => Err(called.open_failure(p.name())),
    }
}

impl Bound {
    /// Op `s` on `ticket`, through the dispatcher: it may pend, and is resumed on its wake.
    pub fn submit<I: InFrame, O: OutFrame>(
        &self,
        ticket: busbar_contract::abi::mechanism::ticket::Ticket,
        s: u32,
        input: I,
        out: O,
    ) -> Done<I, O> {
        self.dispatcher
            .submit(
                &self.plugin,
                ticket,
                s,
                Frame::new(input, out),
                DeadlineClass::Call,
                now_ns() + 20_000_000_000,
            )
            .wait(Duration::from_secs(30))
            .expect("the op completes")
    }

    /// One identity op (`verify`, `complete_login`) on a fresh ticket, with host buffers of `cap`
    /// bytes and groups; a short answer is re-submitted once on the same ticket with buffers of the
    /// size it named.
    fn identify<I: InFrame>(
        &self,
        op: u32,
        input: impl Fn(IdentityBuf) -> I,
        cap: (usize, u32),
    ) -> String {
        let ticket = self.dispatcher.mint(0).expect("a ticket");
        let (mut bytes, mut groups) = (vec![0_u8; cap.0], vec![z::<Span>(); cap.1 as usize]);
        let buf = |bytes: &mut Vec<u8>, groups: &mut Vec<Span>| IdentityBuf {
            buf: bytes.as_mut_ptr(),
            buf_cap: bytes.len(),
            groups: groups.as_mut_ptr(),
            groups_cap: groups.len() as u32,
            _reserved: 0,
        };
        let fresh = || {
            let mut out: IdentifyOut = z();
            out.head = out_head();
            out
        };
        let mut done = self.submit(ticket, op, input(buf(&mut bytes, &mut groups)), fresh());
        let mut short = String::new();
        if done.short {
            let o = done.frame.as_ref().expect("the frame comes back").out;
            short = format!("short(needed {}/{}) ", o.needed_bytes, o.needed_groups);
            bytes = vec![0_u8; o.needed_bytes as usize];
            groups = vec![z::<Span>(); o.needed_groups as usize];
            done = self.submit(ticket, op, input(buf(&mut bytes, &mut groups)), fresh());
        }
        self.dispatcher.recycle(ticket);
        match (done.outcome, done.frame.as_ref()) {
            (Outcome::Ready, Some(f)) => format!(
                "{short}verdict {} {}",
                f.out.verdict,
                if f.out.verdict == 1 {
                    identity(&f.out, &bytes, &groups)
                } else {
                    String::new()
                }
            ),
            (other, _) => format!("{short}{other:?} {}", error_of(done.error.as_deref())),
        }
    }

    /// `verify` of `credential` (none = none presented), with the host's starting buffers or `cap`.
    pub fn verify(&self, credential: Option<&str>, cap: Option<(usize, u32)>) -> String {
        self.identify(
            slot::VERIFY,
            |out_buf| verify_in(credential, out_buf),
            cap.unwrap_or((IDENTITY_BUF_BYTES, IDENTITY_GROUPS)),
        )
    }

    /// `begin_login` for the core's `state`, `challenge` and `nonce`: the authorize URL, or the
    /// refusal.
    pub fn begin(&self, redirect: &str, state: &str, challenge: &str, nonce: &str) -> String {
        let mut i: BeginLoginIn = z();
        i.head = in_head();
        i.redirect_uri = abi_str(redirect);
        i.state = abi_str(state);
        i.nonce = abi_str(nonce);
        i.code_challenge = abi_str(challenge);
        let mut o: BeginLoginOut = z();
        o.head = out_head();
        let ticket = self.dispatcher.mint(0).expect("a ticket");
        let done = self.submit(ticket, slot::BEGIN_LOGIN, i, o);
        self.dispatcher.recycle(ticket);
        let (Outcome::Ready, Some(f)) = (done.outcome, done.frame.as_ref()) else {
            return format!("{:?} {}", done.outcome, error_of(done.error.as_deref()));
        };
        let line = format!("shape {} {}", f.out.shape, text(f.out.authorize_url));
        let mut r: ReleaseIn = z();
        r.head = in_head();
        r.lease = done.lease;
        let released = self
            .plugin
            .call(life::RELEASE, &mut Frame::new(r, out_head()));
        format!("{line} (release {:?})", released.outcome)
    }

    /// `complete_login` of the callback's `code`, with the host's starting buffers or `cap`.
    pub fn complete(
        &self,
        code: &str,
        state: &str,
        redirect: &str,
        verifier: &str,
        cap: Option<(usize, u32)>,
    ) -> String {
        self.identify(
            slot::COMPLETE_LOGIN,
            |out_buf| {
                let mut i: CompleteLoginIn = z();
                i.head = in_head();
                i.code = blob(code.as_bytes(), BLOB_OCTETS);
                i.state = abi_str(state);
                i.redirect_uri = abi_str(redirect);
                i.code_verifier = blob(verifier.as_bytes(), BLOB_OCTETS);
                i.out_buf = out_buf;
                i
            },
            cap.unwrap_or((IDENTITY_BUF_BYTES, IDENTITY_GROUPS)),
        )
    }
}

/// A `verify` `in` for `credential` over `out_buf`.
pub fn verify_in(credential: Option<&str>, out_buf: IdentityBuf) -> VerifyIn {
    let mut i: VerifyIn = z();
    i.head = in_head();
    i.credential = credential.map_or(NO_BLOB, |c| blob(c.as_bytes(), BLOB_OCTETS));
    i.out_buf = out_buf;
    i
}

/// A host identity buffer over `bytes` and `groups`.
pub fn identity_buf(bytes: &mut [u8], groups: &mut [Span]) -> IdentityBuf {
    IdentityBuf {
        buf: bytes.as_mut_ptr(),
        buf_cap: bytes.len(),
        groups: groups.as_mut_ptr(),
        groups_cap: groups.len() as u32,
        _reserved: 0,
    }
}

/// A `verify` made with NO ticket (`Plugin::call`): a call that may not pend.
pub fn verify_ticketless(p: &Plugin<Auth>, credential: Option<&str>) -> String {
    let (mut bytes, mut groups) = (
        vec![0_u8; IDENTITY_BUF_BYTES],
        vec![z::<Span>(); IDENTITY_GROUPS as usize],
    );
    let mut out: IdentifyOut = z();
    out.head = out_head();
    let mut f = Frame::new(
        verify_in(credential, identity_buf(&mut bytes, &mut groups)),
        out,
    );
    let called = p.call(slot::VERIFY, &mut f);
    match called.outcome {
        Outcome::Ready => format!("verdict {}", f.out.verdict),
        other => format!("{other:?} {}", error_of(called.error.as_deref())),
    }
}
