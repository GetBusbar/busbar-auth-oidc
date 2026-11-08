// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared by this crate's integration tests (`e2e.rs`, `conformance.rs`):

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::abi::auth::{
    slot, BeginLoginIn, BeginLoginOut, CompleteLoginIn, IdentifyOut, IdentityBuf, StripName,
    VerifyIn, FIELDS_MAX, IDENTITY_BUF_BYTES, IDENTITY_GROUPS, SPAN_ABSENT,
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
    Caller, DiskDest, HookAsk, Later, NestAsk, Ran, Reading, RecordsList, Stored, TrustKeyRef,
    UNSERVED,
};
use busbar_contract::transport::{CertFacts, ConnFacts};
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_dropped_bytes, load_linked, now_ns, out_head, Bind, ConnTable,
    Diagnostic, DispatchConfig, Dispatcher, Done, Dropped, EnvelopeSink, Frame, InFrame, LinkedRow,
    LoadError, Metric, OutFrame, Plugin, NO_BLOB,
};

mod issuer;
pub use issuer::Issuer;

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

/// ONE DISPATCHER AT A TIME in a test process. The loader keeps a ticketed service's answer for
pub fn serial() -> std::sync::MutexGuard<'static, ()> {
    static ONE: Mutex<()> = Mutex::new(());
    ONE.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The host services a test host serves: the kernel's one clock (what an op waiting on another's
pub struct Clock;

/// How many times an op read the host's clock: once per PENDING answer that waits on another op's
static CLOCK_READS: AtomicU32 = AtomicU32::new(0);

static CLOCK_MONO: Mutex<Option<u64>> = Mutex::new(None);

/// A fixed host wall reading (unix nanoseconds), set apart from the process clock.
static CLOCK_WALL: Mutex<Option<u64>> = Mutex::new(None);

/// A fixed host monotonic (or wall) reading for a test holding [`serial`]; restored even on panic.
pub struct HeldClock;

impl HeldClock {
    pub fn at(mono_ns: u64) -> Self {
        Self::set(mono_ns);
        Self
    }

    pub fn set(mono_ns: u64) {
        *CLOCK_MONO.lock().unwrap() = Some(mono_ns);
    }

    /// The host's wall clock held at `wall_ns`, whatever the process clock reads: what proves the
    /// plugin judges at the HOST clock.
    pub fn wall_at(wall_ns: u64) -> Self {
        *CLOCK_WALL.lock().unwrap() = Some(wall_ns);
        Self
    }
}

impl Drop for HeldClock {
    fn drop(&mut self) {
        *CLOCK_MONO.lock().unwrap() = None;
        *CLOCK_WALL.lock().unwrap() = None;
    }
}

/// The host clock reads so far (every test that binds holds [`serial`], so they are its own).
pub fn clock_reads() -> u32 {
    CLOCK_READS.load(Ordering::SeqCst)
}

impl busbar_contract::services::HostServices for Clock {
    fn now(&self) -> Reading {
        CLOCK_READS.fetch_add(1, Ordering::SeqCst);
        let process_wall = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos() as u64)
        };
        Reading {
            wall_ns: CLOCK_WALL.lock().unwrap().unwrap_or_else(process_wall),
            mono_ns: CLOCK_MONO.lock().unwrap().unwrap_or_else(now_ns),
        }
    }
    fn dest_judge(&self, _dest: &str, _class: u32, _flags: u32, _later: Option<Later>) -> Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
            busbar_contract::services::UNSERVED,
        ))
    }

    fn records_get(&self, _caller: &Caller, _kind: &str, _key: &[u8], _later: Later) -> Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
            busbar_contract::services::UNSERVED,
        ))
    }

    fn records_list(&self, _caller: &Caller, _list: RecordsList, _later: Later) -> Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
            busbar_contract::services::UNSERVED,
        ))
    }

    fn records_claim(
        &self,
        _caller: &Caller,
        _kind: &str,
        _key: &[u8],
        _ttl_ms: u64,
        _later: Later,
    ) -> Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
            busbar_contract::services::UNSERVED,
        ))
    }

    fn sign(&self, _caller: &Caller, _data: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn trust_sight(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _hash: &str,
        _later: Later,
    ) -> Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
            busbar_contract::services::UNSERVED,
        ))
    }

    fn trust_unreached(&self, _caller: &Caller, _counterparty: &str) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn trust_sight_item(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _item: &str,
        _digest: &str,
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }

    fn trust_decide(
        &self,
        _caller: &Caller,
        _ticket: busbar_contract::abi::mechanism::ticket::Ticket,
        _key: TrustKeyRef<'_>,
        _expected: Option<&str>,
        _approve: bool,
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }

    fn trust_state(&self, _caller: &Caller, _counterparty: &str) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn trust_serves(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _item: Option<&str>,
        _digest: Option<&str>,
    ) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn trust_due(&self, _caller: &Caller) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn trust_verify(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _payload: &[u8],
        _signatures: &[u8],
    ) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn entitlement_check(&self, _caller: &Caller, _unit: Option<u64>, _target: &str) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn session_emit(&self, _caller: &Caller, _session: u64, _bytes: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn ticket_mint(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _ttl_secs: u64,
        _record: &[u8],
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }

    fn ticket_take(&self, _caller: &Caller, _unit: Option<u64>) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn random_fill(&self, _len: u64) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn records_secret(&self, _kind: &str, _id: &str, _later: Later) -> Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
            busbar_contract::services::UNSERVED,
        ))
    }

    fn unit_nest(&self, _caller: &Caller, _unit: Option<u64>, _ask: NestAsk, _later: Later) -> Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
            busbar_contract::services::UNSERVED,
        ))
    }

    fn work_open(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _kind: &str,
        _record: &[u8],
        _later: Later,
    ) -> Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
            busbar_contract::services::UNSERVED,
        ))
    }

    fn work_find(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _reference: &[u8],
        _later: Later,
    ) -> Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
            busbar_contract::services::UNSERVED,
        ))
    }

    fn work_settle(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _handle: u64,
        _record: &[u8],
        _later: Later,
    ) -> Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
            busbar_contract::services::UNSERVED,
        ))
    }

    fn work_resume(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _handle: u64,
        _later: Later,
    ) -> Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
            busbar_contract::services::UNSERVED,
        ))
    }

    fn disk_append(&self, _dest: &DiskDest, _bytes: Vec<u8>, _later: Later) -> Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
            busbar_contract::services::UNSERVED,
        ))
    }

    fn verify_lookup(&self, _caller: &Caller, _key: &[u8], _later: Later) -> Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
            busbar_contract::services::UNSERVED,
        ))
    }

    fn verify_store(&self, _caller: &Caller, _key: &[u8], _entry: &[u8], _ttl_ms: u64) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn content_scan(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _content: &[u8],
        _later: Later,
    ) -> Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
            busbar_contract::services::UNSERVED,
        ))
    }

    fn hook_call(&self, _caller: &Caller, _unit: Option<u64>, _ask: HookAsk, _later: Later) -> Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
            busbar_contract::services::UNSERVED,
        ))
    }

    fn snapshot_read(&self, _caller: &Caller, _scope: u32, _later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
}

/// The dispatcher's connection-table wake.
type Wake = busbar_contract::conn::ConnWake;

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

/// THE DECLARED NEEDS AND THEIR TARGETS: `(need index, the URL the operator's config names for
pub fn declared_targets(base: u32) -> Vec<(u32, String)> {
    vec![
        (
            base,
            format!("https://idp.conformance.example{DISCOVERY_PATH}"),
        ),
        (base + 1, JWKS_URL.to_string()),
        (base + 2, TOKEN_URL.to_string()),
    ]
}

/// Every request in `sent` that is NOT on a declared need index (`< needs`) or whose target is not
pub fn strays(sent: &[Sent], needs: u32, allowed: &[(u32, String)]) -> Vec<String> {
    sent.iter()
        .filter_map(|s| {
            if s.need >= needs {
                return Some(format!("undeclared need {} -> {}", s.need, s.target));
            }
            (!allowed.iter().any(|(n, t)| *n == s.need && *t == s.target))
                .then(|| format!("need {} to a foreign target {}", s.need, s.target))
        })
        .collect()
}

/// One reply being read: how far, and what.
struct Reply {
    step: u8,
    at: usize,
    status: u32,
    fields: Vec<u8>,
    body: Vec<u8>,
    timeout_body: bool,
}

/// A configured provider response, including the actual field block read through the connector.
#[derive(Clone)]
struct Response {
    status: u32,
    fields: Vec<u8>,
    body: Vec<u8>,
    timeout_body: bool,
}

/// One paused provider path and the actual instance/ticket reads waiting for its release.
type HeldReads = (String, Vec<(InstanceId, u64)>);

/// Security established by the scripted carrier, independent of the requested URL.
#[derive(Clone, Copy, Debug)]
pub enum CarrierSecurity {
    Unavailable,
    Insecure,
    Secure,
}

struct Connection {
    owner: InstanceId,
    need: NeedId,
    target: String,
    security: CarrierSecurity,
    committed: bool,
}

/// THE IdP: framed requests are captured only after committing the prepared carrier.
pub struct Idp {
    security: CarrierSecurity,
    connections: Mutex<HashMap<u64, Connection>>,
    wake: Mutex<Option<Wake>>,
    /// `(connection, the waking ticket)` of every first read: which op made each request.
    woken: Mutex<Vec<(u64, u64)>>,
    answers: Mutex<HashMap<String, Response>>,
    sent: Mutex<Vec<Sent>>,
    declared: Mutex<Vec<String>>,
    /// The needs whose declaration the table refused, as the host's connector refuses them (a
    refused: Mutex<HashSet<u32>>,
    reads: Mutex<HashMap<u64, Reply>>,
    next: AtomicU64,
    pended: AtomicU32,
    /// Reply body bytes handed to the plugin so far, over every request.
    served: AtomicU64,
    delay: Mutex<Duration>,
    /// A test-controlled reply path and its wakes, released by `ReadHold` outside this lock.
    read_hold: Mutex<Option<HeldReads>>,
    read_pause: Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
    /// Every declared diagnostic the door's envelopes raised, as `name severity text`.
    diags: Mutex<Vec<String>>,
}

/// The envelope sink a bound door reports into: its declared diagnostics, kept on the IdP the
struct Recorder(Arc<Idp>);

impl EnvelopeSink for Recorder {
    fn metric(&self, _: Metric<'_>) {}
    fn diag(&self, d: Diagnostic<'_>) {
        if !d.name.is_empty() {
            self.0.diags.lock().unwrap().push(format!(
                "{} {} {}",
                String::from_utf8_lossy(d.name),
                d.severity,
                String::from_utf8_lossy(d.text)
            ));
        }
    }
    fn dropped(&self, _: Dropped) {}
}

impl Idp {
    /// Explicitly model a carrier whose handshake established peer authentication.
    pub fn secure_carrier(key: &Issuer) -> Arc<Self> {
        Self::with_carrier(key, CarrierSecurity::Secure)
    }

    pub fn with_carrier(key: &Issuer, security: CarrierSecurity) -> Arc<Self> {
        let idp = Arc::new(Self {
            security,
            connections: Mutex::new(HashMap::new()),
            wake: Mutex::new(None),
            woken: Mutex::new(Vec::new()),
            answers: Mutex::new(HashMap::new()),
            sent: Mutex::new(Vec::new()),
            declared: Mutex::new(Vec::new()),
            refused: Mutex::new(HashSet::new()),
            reads: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            pended: AtomicU32::new(0),
            served: AtomicU64::new(0),
            delay: Mutex::new(Duration::from_millis(5)),
            read_hold: Mutex::new(None),
            read_pause: Mutex::new(None),
            diags: Mutex::new(Vec::new()),
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
        self.answer_bytes(path, status, body.as_bytes());
    }

    /// A response whose bytes need not be UTF-8.
    pub fn answer_bytes(&self, path: &str, status: u32, body: &[u8]) {
        self.answer_fields(path, status, body, &[]);
    }

    /// A provider reply with field lines, encoded with the framed transport's own field grammar.
    pub fn answer_fields(&self, path: &str, status: u32, body: &[u8], fields: &[(&[u8], &[u8])]) {
        use busbar_contract::abi::transport::fields::{LINE_END, SEPARATOR};
        let mut encoded = Vec::new();
        for (name, value) in fields {
            encoded.extend_from_slice(name);
            encoded.extend_from_slice(SEPARATOR);
            encoded.extend_from_slice(value);
            encoded.extend_from_slice(LINE_END);
        }
        self.answers.lock().unwrap().insert(
            path.to_string(),
            Response {
                status,
                fields: encoded,
                body: body.to_vec(),
                timeout_body: false,
            },
        );
    }

    /// Fail the next body read with the connector's timeout, after delivering the response head.
    pub fn timeout_body(&self, path: &str) {
        self.answers
            .lock()
            .unwrap()
            .get_mut(path)
            .expect("configured provider response")
            .timeout_body = true;
    }

    /// How long a reply's first read pends before the op's ticket is woken.
    pub fn pend_for(&self, delay: Duration) {
        *self.delay.lock().unwrap() = delay;
    }

    /// Hold this path's first reply read until the returned guard is dropped, including unwind.
    pub fn hold_reads(&self, path: &str) -> ReadHold<'_> {
        let mut held = self.read_hold.lock().unwrap();
        assert!(held.is_none(), "only one controlled reply path at a time");
        *held = Some((path.to_owned(), Vec::new()));
        ReadHold(self)
    }

    /// Wake the real driver for the controlled reply without releasing its read hold.
    pub fn wake_held_reads(&self) -> usize {
        let wakes = self
            .read_hold
            .lock()
            .unwrap()
            .as_ref()
            .map(|(_, wakes)| wakes.clone())
            .unwrap_or_default();
        let count = wakes.len();
        let wake = self.wake.lock().unwrap().clone().expect("bound IdP");
        for (caller, ticket) in wakes {
            wake(caller, ticket);
        }
        count
    }

    pub fn read_is_held(&self) -> bool {
        self.read_hold
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|(_, wakes)| !wakes.is_empty())
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

    /// How many reply body bytes the plugin has read from this IdP.
    pub fn served(&self) -> u64 {
        self.served.load(Ordering::SeqCst)
    }

    /// Every declared diagnostic the door raised, in order (`name severity text`).
    pub fn diags(&self) -> Vec<String> {
        self.diags.lock().unwrap().clone()
    }

    /// Refuse every open on `need`, as the host's destination guard refuses an address.
    pub fn refuse(&self, need: u32) {
        self.refused.lock().unwrap().insert(need);
    }

    /// Every need the loader declared, as it declared it, sorted.
    pub fn declared(&self) -> Vec<String> {
        let mut d = self.declared.lock().unwrap().clone();
        d.sort();
        d
    }

    pub fn connection_is_open(&self, connection: u64) -> bool {
        self.reads.lock().unwrap().contains_key(&connection)
    }

    /// Pause one executing connector read until released; no IdP lock is held while paused.
    pub fn pause_next_read(&self) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        *self.read_pause.lock().unwrap() = Some((entered_tx, resume_rx));
        (entered_rx, resume_tx)
    }
}

/// Releases controlled replies before a scoped caller is joined, even if an assertion panics.
pub struct ReadHold<'a>(&'a Idp);

impl Drop for ReadHold<'_> {
    fn drop(&mut self) {
        let held = self.0.read_hold.lock().unwrap().take();
        if let Some((_, wakes)) = held {
            let wake = self.0.wake.lock().unwrap().clone().expect("bound IdP");
            for (caller, ticket) in wakes {
                wake(caller, ticket);
            }
        }
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
        fault: None,
        reason: None,
        declared_len: None,
    }
}

impl Conns for Idp {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        let conn = self.prepare_request(caller, need, desc, desc.timeout_ms)?;
        self.commit_request(caller, conn, desc, false)?;
        Ok(conn)
    }
    fn write(
        &self,
        _: InstanceId,
        _: ConnId,
        _: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        Err(ConnError::Closed)
    }
    fn read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        ticket: u64,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        let connections = self.connections.lock().unwrap();
        let connection = connections.get(&conn.0).ok_or(ConnError::Closed)?;
        if connection.owner != caller || !connection.committed {
            return Err(ConnError::Closed);
        }
        drop(connections);
        let paused = self.read_pause.lock().unwrap().take();
        if let Some((entered, resume)) = paused {
            entered
                .send(())
                .expect("the test waits for the actual read");
            resume
                .recv_timeout(Duration::from_secs(5))
                .expect("the test releases the read");
            return Err(ConnError::Pending);
        }
        let mut reads = self.reads.lock().unwrap();
        let r = reads.get_mut(&conn.0).ok_or(ConnError::Closed)?;
        match r.step {
            0 => {
                r.step = 1;
                self.pended.fetch_add(1, Ordering::SeqCst);
                self.woken.lock().unwrap().push((conn.0, ticket));
                {
                    let mut held = self.read_hold.lock().unwrap();
                    if let Some((path, wakes)) = held.as_mut() {
                        if self
                            .sent
                            .lock()
                            .unwrap()
                            .iter()
                            .any(|s| s.conn == conn.0 && s.path == *path)
                        {
                            wakes.push((caller, ticket));
                            return Err(ConnError::Pending);
                        }
                    }
                }
                let wake = self
                    .wake
                    .lock()
                    .unwrap()
                    .clone()
                    .expect("the table is armed");
                let delay = *self.delay.lock().unwrap();
                std::thread::spawn(move || {
                    std::thread::sleep(delay);
                    wake(caller, ticket);
                });
                Err(ConnError::Pending)
            }
            1 => {
                r.step = 2;
                let reason = b"X";
                let fields_len = r.fields.len();
                buf[..fields_len].copy_from_slice(&r.fields);
                buf[fields_len..fields_len + reason.len()].copy_from_slice(reason);
                Ok(Piece {
                    status_code: Some(r.status),
                    status_namespace: Some("http".to_owned()),
                    reason: Some(fields_len..fields_len + reason.len()),
                    ..piece(PieceKind::Fields, fields_len)
                })
            }
            _ if r.timeout_body => Err(ConnError::Timeout),
            _ if r.at < r.body.len() => {
                let n = (r.body.len() - r.at).min(buf.len());
                buf[..n].copy_from_slice(&r.body[r.at..r.at + n]);
                r.at += n;
                self.served.fetch_add(n as u64, Ordering::SeqCst);
                Ok(piece(PieceKind::Body, n))
            }
            _ => Ok(piece(PieceKind::Completion, 0)),
        }
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
        Err(ConnError::Closed)
    }
    fn facts(&self, caller: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        let connections = self.connections.lock().unwrap();
        let connection = connections.get(&conn.0).ok_or(ConnError::Closed)?;
        if connection.owner != caller {
            return Err(ConnError::Closed);
        }
        let peer_cert = match connection.security {
            CarrierSecurity::Unavailable => return Err(ConnError::Closed),
            CarrierSecurity::Insecure => None,
            CarrierSecurity::Secure => Some(CertFacts {
                subject: "scripted IdP peer".into(),
                issuer: "scripted test authority".into(),
                fingerprint: "scripted-peer-fingerprint".into(),
            }),
        };
        Ok(ConnFacts {
            sni: None,
            alpn: None,
            peer_cert,
            claim: Some("http".into()),
            peer_key_pin: None,
            client_identity: false,
        })
    }
    fn close(&self, caller: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        let mut connections = self.connections.lock().unwrap();
        if connections.get(&conn.0).is_none_or(|c| c.owner != caller) {
            return Err(ConnError::Closed);
        }
        connections.remove(&conn.0);
        self.reads.lock().unwrap().remove(&conn.0);
        Ok(())
    }
}

impl DeclaredConns for Idp {
    fn prepare_request(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        _: u64,
    ) -> Result<ConnId, ConnError> {
        if self.refused.lock().unwrap().contains(&need.0) {
            return Err(ConnError::Refused);
        }
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        self.connections.lock().unwrap().insert(
            id,
            Connection {
                owner: caller,
                need,
                target: desc.target.to_owned(),
                security: self.security,
                committed: false,
            },
        );
        Ok(ConnId(id))
    }

    fn commit_request(
        &self,
        caller: InstanceId,
        conn: ConnId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
    ) -> Result<(), ConnError> {
        let mut connections = self.connections.lock().unwrap();
        let connection = connections.get_mut(&conn.0).ok_or(ConnError::Closed)?;
        if connection.owner != caller {
            return Err(ConnError::Closed);
        }
        if connection.committed || connection.target != desc.target {
            return Err(ConnError::Refused);
        }
        if require_secure && !matches!(connection.security, CarrierSecurity::Secure) {
            return Err(ConnError::AuthRefused);
        }
        let id = conn.0;
        let path = String::from_utf8_lossy(desc.head_target).into_owned();
        self.sent.lock().unwrap().push(Sent {
            conn: id,
            need: connection.need.0,
            target: desc.target.to_owned(),
            method: String::from_utf8_lossy(desc.method).into_owned(),
            path: path.clone(),
            body: String::from_utf8_lossy(&desc.body).into_owned(),
        });
        let response = self
            .answers
            .lock()
            .unwrap()
            .get(&path)
            .cloned()
            .unwrap_or(Response {
                status: 404,
                fields: Vec::new(),
                body: b"{}".to_vec(),
                timeout_body: false,
            });
        self.reads.lock().unwrap().insert(
            id,
            Reply {
                step: 0,
                at: 0,
                status: response.status,
                fields: response.fields,
                body: response.body,
                timeout_body: response.timeout_body,
            },
        );
        connection.committed = true;
        Ok(())
    }

    fn serves_scheme(&self, transport: &str) -> bool {
        transport == "http"
    }
    fn declare(
        &self,
        _: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
        trust: Option<&str>,
    ) -> Result<(), ConnError> {
        let unresolved = (!spec.target_from.is_empty() && target.is_none())
            || (!spec.trust_from.is_empty() && trust.is_none());
        let answer = if unresolved {
            self.refused.lock().unwrap().insert(need.0);
            Err(ConnError::Refused)
        } else {
            self.refused.lock().unwrap().remove(&need.0);
            Ok(())
        };
        self.declared.lock().unwrap().push(format!(
            "need {} direction={} class={} transport={} target_from={:?} trust_from={:?} \
             timeout_ms={} target={target:?} trusted={} answer={answer:?}",
            need.0,
            spec.direction,
            spec.egress_class,
            spec.transport,
            spec.target_from,
            spec.trust_from,
            spec.timeout_ms,
            trust.is_some(),
        ));
        answer
    }
    fn declared(&self, _: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        Some(if self.refused.lock().unwrap().contains(&need.0) {
            Err(ConnError::Refused)
        } else {
            Ok(())
        })
    }
    fn framed(&self, _: InstanceId, _: NeedId) -> bool {
        true
    }
}

/// The build lane supplies the fresh image explicitly. An absent image is a hard failure.
pub fn cdylib_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("BUSBAR_PLUGIN_CDYLIB") {
        let path = PathBuf::from(path);
        assert!(path.is_absolute(), "BUSBAR_PLUGIN_CDYLIB must be absolute");
        assert!(
            path.is_file(),
            "BUSBAR_PLUGIN_CDYLIB must name the freshly built OIDC cdylib: {}",
            path.display()
        );
        return Some(path);
    }
    let exe = std::env::current_exe().ok()?;
    let profile = exe.parent()?.parent()?;
    let file = busbar_plugin_loader::plugin_library_filename("busbar_auth_oidc_plugin");
    [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .find(|p| p.is_file())
}

/// THE LINKED ROW: the door and the Statement it states.
pub fn row() -> LinkedRow {
    LinkedRow::of(busbar_auth_oidc_plugin::door).expect("the door states itself")
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
pub struct Bound {
    pub dispatcher: Arc<Dispatcher>,
    pub idp: Arc<Idp>,
    pub plugin: Plugin<Auth>,
}

/// Loads `arm` as `kind` through `load_dropped_bytes` for refusal checks.
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
        busbar_contract::services::test_caller_binding(),
    ));
    *idp.wake.lock().unwrap() = Some(dispatcher.conn_waker());
    let conns: Arc<dyn DeclaredConns> = idp.clone();
    let bind = Bind {
        instance: Arc::from("oidc"),
        max_inflight_cap: 64,
        sink: Arc::new(Recorder(idp.clone())),
        dispatcher: dispatcher.adopter(),
        conns: ConnTable::Host(conns),
    };
    let plugin = match arm {
        Arm::Linked => load_linked::<K>(&row(), bind),
        Arm::Dropped { lib, stated } => {
            load_dropped_bytes::<K>(lib, "busbar-auth-oidc", stated, bind)
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
pub fn identity(out: &IdentifyOut, bytes: &[u8], groups: &[Span]) -> String {
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
    assert_eq!(
        called.lease, 0,
        "OPEN never lends a lease, including refusal"
    );
    if called.outcome == Outcome::Ready {
        assert!(called.error.is_none());
    }
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
    fn identify<I: InFrame>(
        &self,
        op: u32,
        input: impl Fn(IdentityBuf) -> I,
        cap: (usize, u32),
    ) -> String {
        self.identify_after_short(op, input, cap, || {})
    }

    pub fn identify_after_short<I: InFrame>(
        &self,
        op: u32,
        input: impl Fn(IdentityBuf) -> I,
        cap: (usize, u32),
        after_short: impl FnOnce(),
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
            after_short();
            done = self.submit(ticket, op, input(buf(&mut bytes, &mut groups)), fresh());
        }
        self.dispatcher.recycle(ticket);
        assert!(self
            .dispatcher
            .retirement_barrier(ticket, Duration::from_secs(10)));
        if done.outcome == Outcome::Ready {
            assert_eq!(done.lease, 0);
            assert!(done.error.is_none());
        }
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

    /// `verify` of `credential` with the request's facts stating `timestamp` (unix seconds).
    pub fn verify_at(&self, credential: Option<&str>, timestamp: u64) -> String {
        self.identify(
            slot::VERIFY,
            |out_buf| verify_in_at(credential, out_buf, timestamp),
            (IDENTITY_BUF_BYTES, IDENTITY_GROUPS),
        )
    }

    /// `verify` with explicit request time and capacity, including the exact short-buffer recall.
    pub fn verify_at_with_cap(
        &self,
        credential: Option<&str>,
        timestamp: u64,
        cap: Option<(usize, u32)>,
    ) -> String {
        self.identify(
            slot::VERIFY,
            |out_buf| verify_in_at(credential, out_buf, timestamp),
            cap.unwrap_or((IDENTITY_BUF_BYTES, IDENTITY_GROUPS)),
        )
    }

    /// `begin_login` for the core's `state`, `challenge` and `nonce`: the authorize URL, or the
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
        assert_ne!(done.lease, 0, "redirect begin returns a leased URL");
        assert!(done.error.is_none());
        let line = format!("shape {} {}", f.out.shape, text(f.out.authorize_url));
        let mut r: ReleaseIn = z();
        r.head = in_head();
        r.lease = done.lease;
        let released = self
            .plugin
            .call(life::RELEASE, &mut Frame::new(r, out_head()));
        assert_eq!(released.outcome, Outcome::Ready);
        assert_eq!(released.lease, 0);
        assert!(released.error.is_none());
        format!("{line} (release {:?})", released.outcome)
    }

    /// `complete_login` of the callback's `code`, with the host's starting buffers or `cap`.
    pub fn complete(
        &self,
        code: &str,
        (state, nonce): (&str, &str),
        redirect: &str,
        verifier: &str,
        cap: Option<(usize, u32)>,
    ) -> String {
        self.complete_after_short(code, (state, nonce), redirect, verifier, cap, || {})
    }

    /// Complete a login, changing host state only after the first actual short-buffer answer.
    pub fn complete_after_short(
        &self,
        code: &str,
        (state, nonce): (&str, &str),
        redirect: &str,
        verifier: &str,
        cap: Option<(usize, u32)>,
        after_short: impl FnOnce(),
    ) -> String {
        self.identify_after_short(
            slot::COMPLETE_LOGIN,
            |out_buf| {
                let mut i: CompleteLoginIn = z();
                i.head = in_head();
                i.code = blob(code.as_bytes(), BLOB_OCTETS);
                i.state = abi_str(state);
                i.nonce = abi_str(nonce);
                i.redirect_uri = abi_str(redirect);
                i.code_verifier = blob(verifier.as_bytes(), BLOB_OCTETS);
                i.out_buf = out_buf;
                i
            },
            cap.unwrap_or((IDENTITY_BUF_BYTES, IDENTITY_GROUPS)),
            after_short,
        )
    }
}

/// A `verify` `in` for `credential` over `out_buf`.
pub fn verify_in(credential: Option<&str>, out_buf: IdentityBuf) -> VerifyIn {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    verify_in_at(credential, out_buf, now)
}

/// [`verify_in`] with the request's facts stating `timestamp` (unix seconds): the host's clock as
pub fn verify_in_at(credential: Option<&str>, out_buf: IdentityBuf, timestamp: u64) -> VerifyIn {
    let mut i: VerifyIn = z();
    i.request.timestamp = timestamp;
    i.head = in_head();
    i.credential = credential.map_or(NO_BLOB, |c| blob(c.as_bytes(), BLOB_OCTETS));
    i.out_buf = out_buf;

    let strips: &'static mut [StripName] =
        Box::leak(vec![z::<StripName>(); FIELDS_MAX as usize].into_boxed_slice());
    i.strip = strips.as_mut_ptr();
    i.strip_cap = FIELDS_MAX;
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

/// A `verify` of the raw `credential` bytes made with NO ticket: `(verdict, decision, strip_len)`,
pub fn verify_ticketless_raw(
    p: &Plugin<Auth>,
    credential: &[u8],
) -> Result<(u32, u32, u32), Outcome> {
    let (mut bytes, mut groups) = (
        vec![0_u8; IDENTITY_BUF_BYTES],
        vec![z::<Span>(); IDENTITY_GROUPS as usize],
    );
    let mut out: IdentifyOut = z();
    out.head = out_head();
    let mut i = verify_in(None, identity_buf(&mut bytes, &mut groups));
    i.credential = blob(credential, BLOB_OCTETS);
    let mut f = Frame::new(i, out);
    let called = p.call(slot::VERIFY, &mut f);
    match called.outcome {
        Outcome::Ready => Ok((f.out.verdict, f.out.decision, f.out.strip_len)),
        other => Err(other),
    }
}
