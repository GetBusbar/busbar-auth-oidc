//! Real-world proof against an actual Entra ID (Azure AD) tenant — not a fixture, not a mock. Reads
//! a live tenant/client id + a disposable test user's credentials from env, performs a genuine
//! password-grant token request against Entra's real token endpoint, then drives that real
//! Entra-issued token through this crate's DOOR (`busbar_auth_oidc::door`, its only public item), the way busbar's loader
//! drives a linked plugin: the ABI's `open` and `verify` ops on a dispatcher, the module's requests made by a
//! blocking HTTPS client standing in for the host's connector (every need framed): real discovery, real JWKS fetch, real RS256
//! signature check, real claim validation. Also verifies a tampered copy of the same token is genuinely rejected, so this isn't
//! a rubber stamp.
//!
//! Requires (all via env, all optional — this example exits early with a clear message if any are
//! missing rather than failing loudly in an environment where the tenant isn't provisioned):
//!   ENTRA_TENANT_ID       Entra tenant GUID
//!   ENTRA_CLIENT_ID       App registration (public client) allowed for the ROPC grant
//!   ENTRA_TEST_USERNAME   A disposable test user in that tenant (never a real employee account)
//!   ENTRA_TEST_PASSWORD   That user's current (non-expired) password
//!
//! Run: `cargo run -p busbar-auth-oidc --example entra_live_check`

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::abi::auth::{
    slot, IdentifyOut, IdentityBuf, StripName, VerifyIn, FIELDS_MAX, IDENTITY_BUF_BYTES,
    IDENTITY_GROUPS, VERDICT_IDENTITY, VERDICT_REJECT,
};
use busbar_contract::abi::mechanism::call::{
    Blob, DeadlineClass, Outcome, Span, BLOB_JSON, BLOB_OCTETS,
};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::conn::{
    ConnError, ConnId, ConnWake, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
    PieceKind,
};
use busbar_contract::ids::StreamId;
use busbar_contract::services::Reading;
use busbar_contract::transport::ConnFacts;
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::{
    in_head, load_linked, now_ns, out_head, Bind, ConnTable, DispatchConfig, Dispatcher, Frame,
    LinkedRow, LoadedDoor, NoSink, Plugin,
};

/// An all-zero `T` (every ABI `in`/`out` is plain C data).
fn z<T>() -> T {
    // SAFETY: all-zero is a valid value of each ABI struct built here.
    unsafe { std::mem::zeroed() }
}

/// The host services this example serves: the shared test double's clock, nothing else.
struct Clock;

impl busbar_contract::services::double::ServicesDouble for Clock {
    fn now(&self) -> Reading {
        Reading {
            wall_ns: 0,
            mono_ns: now_ns(),
        }
    }
}

/// One request the door made, as the host's framer was handed it.
#[derive(Debug, Clone)]
struct Sent {
    target: String,
    path: String,
}

/// One reply being read.
struct Reply {
    step: u8,
    at: usize,
    status: u32,
    body: Vec<u8>,
}

/// THE HOST'S CONNECTION TABLE over the REAL network: a need's request is made at once by a
/// blocking HTTPS client (the host's connector makes it in production); its reply's first read is
/// answered PENDING and the op's ticket is woken from another thread, so every request crosses
/// PENDING as it does in the loader.
struct Live {
    wake: Mutex<Option<ConnWake>>,
    client: reqwest::blocking::Client,
    sent: Mutex<Vec<Sent>>,
    reads: Mutex<HashMap<u64, Reply>>,
    next: AtomicU64,
}

impl Live {
    fn sent(&self) -> Vec<Sent> {
        self.sent.lock().unwrap().clone()
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

impl Conns for Live {
    fn open(&self, _: InstanceId, _: NeedId, desc: &OpenDesc<'_>) -> Result<ConnId, ConnError> {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        self.sent.lock().unwrap().push(Sent {
            target: desc.target.to_owned(),
            path: String::from_utf8_lossy(desc.head_target).into_owned(),
        });
        let method = reqwest::Method::from_bytes(desc.method).map_err(|_| ConnError::Refused)?;
        let reply = self
            .client
            .request(method, desc.target)
            .body(desc.body.to_vec())
            .send()
            .map_err(|_| ConnError::Refused)?;
        let status = u32::from(reply.status().as_u16());
        let body = reply.bytes().map_err(|_| ConnError::Refused)?.to_vec();
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
        let mut reads = self.reads.lock().unwrap();
        let r = reads.get_mut(&conn.0).ok_or(ConnError::Closed)?;
        match r.step {
            0 => {
                r.step = 1;
                let wake = self
                    .wake
                    .lock()
                    .unwrap()
                    .clone()
                    .expect("the table is armed");
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(5));
                    wake(caller, ticket);
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

impl DeclaredConns for Live {
    fn serves_scheme(&self, transport: &str) -> bool {
        transport == "http"
    }
    fn declare(
        &self,
        _: InstanceId,
        _: NeedId,
        _: &ReadNeed,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<(), ConnError> {
        Ok(())
    }
    fn declared(&self, _: InstanceId, _: NeedId) -> Option<Result<(), ConnError>> {
        Some(Ok(()))
    }
    fn framed(&self, _: InstanceId, _: NeedId) -> bool {
        true
    }
}

/// The door, linked and bound the way the loader binds it: a dispatcher serving the host's clock,
/// the live connection table, and the opened plugin.
struct Host {
    dispatcher: Arc<Dispatcher>,
    idp: Arc<Live>,
    plugin: Plugin<Auth>,
}

impl Host {
    /// Link `busbar_auth_oidc::door` and `open` it over `settings`.
    fn bind(settings: &str) -> Self {
        let idp = Arc::new(Live {
            wake: Mutex::new(None),
            client: reqwest::blocking::Client::builder()
                .https_only(true)
                .timeout(Duration::from_secs(10))
                .build()
                .expect("an HTTPS client"),
            sent: Mutex::new(Vec::new()),
            reads: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        });
        let dispatcher = Arc::new(Dispatcher::with_services(
            DispatchConfig {
                workers: 2,
                ..Default::default()
            },
            Arc::new(Clock),
        ));
        *idp.wake.lock().unwrap() = Some(dispatcher.conn_waker());
        let conns: Arc<dyn DeclaredConns> = idp.clone();
        // SAFETY: `door` is this crate's own `plugin_door!` entry: it answers the `'static`, fully
        // initialised door the SDK laid out.
        #[allow(unused_unsafe)]
        let door = unsafe { LoadedDoor::from_raw(busbar_auth_oidc::door) };
        let row = LinkedRow::of_loaded(door).expect("the door states its Statement");
        let plugin = load_linked::<Auth>(
            &row,
            Bind {
                instance: Arc::from("oidc"),
                max_inflight_cap: 64,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns: ConnTable::Host(conns),
            },
        )
        .expect("the door loads");
        let mut reason = vec![0_u8; 1024];
        let mut i: OpenIn = z();
        i.head = in_head();
        // SAFETY: `settings` outlives the `open` this `in` is read by.
        i.settings =
            unsafe { Blob::from_raw_parts(settings.as_ptr(), settings.len(), BLOB_JSON, 0) };
        i.generation = 1;
        i.err_buf = reason.as_mut_ptr();
        i.err_cap = reason.len();
        let mut o: OpenOut = z();
        o.head = out_head();
        let called = plugin.call(life::OPEN, &mut Frame::new(i, o));
        assert_eq!(
            called.outcome,
            Outcome::Ready,
            "the door opens over the settings"
        );
        Self {
            dispatcher,
            idp,
            plugin,
        }
    }

    /// The `verify` op's verdict for `token`, on a fresh ticket through the dispatcher (it pends on
    /// every fetch and is re-entered on the wake).
    fn verify(&self, token: &str) -> u32 {
        let (mut bytes, mut groups) = (
            vec![0_u8; IDENTITY_BUF_BYTES],
            vec![z::<Span>(); IDENTITY_GROUPS as usize],
        );
        let mut i: VerifyIn = z();
        i.head = in_head();
        // SAFETY: `token` outlives the `verify` this `in` is read by.
        i.credential = unsafe { Blob::from_raw_parts(token.as_ptr(), token.len(), BLOB_OCTETS, 0) };
        i.out_buf = IdentityBuf {
            buf: bytes.as_mut_ptr(),
            buf_cap: bytes.len(),
            groups: groups.as_mut_ptr(),
            groups_cap: groups.len() as u32,
            _reserved: 0,
        };
        let mut strips = vec![z::<StripName>(); FIELDS_MAX as usize];
        i.strip = strips.as_mut_ptr();
        i.strip_cap = FIELDS_MAX;
        let mut o: IdentifyOut = z();
        o.head = out_head();
        let ticket = self.dispatcher.mint(0).expect("a ticket");
        let done = self
            .dispatcher
            .submit(
                &self.plugin,
                ticket,
                slot::VERIFY,
                Frame::new(i, o),
                DeadlineClass::Call,
                now_ns() + 20_000_000_000,
            )
            .wait(Duration::from_secs(30))
            .expect("the op completes");
        self.dispatcher.recycle(ticket);
        assert_eq!(done.outcome, Outcome::Ready, "verify answers READY");
        done.frame
            .as_ref()
            .expect("the frame comes back")
            .out
            .verdict
    }
}

fn env_or_skip(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn main() {
    let (Some(tenant), Some(client_id), Some(username), Some(password)) = (
        env_or_skip("ENTRA_TENANT_ID"),
        env_or_skip("ENTRA_CLIENT_ID"),
        env_or_skip("ENTRA_TEST_USERNAME"),
        env_or_skip("ENTRA_TEST_PASSWORD"),
    ) else {
        // Locally, an absent tenant is a skip. In CI it is a FAILURE, because a workflow named
        // "entra-live-check" reporting green having verified nothing is worse than no workflow at
        // all: it is a badge asserting a live Entra token was validated when none was fetched. The
        // secrets are the only thing arming this check, so an unset or empty one is the exact
        // condition that must be loud.
        let msg = "ENTRA_TENANT_ID / ENTRA_CLIENT_ID / ENTRA_TEST_USERNAME / ENTRA_TEST_PASSWORD \
                   are not all set and non-empty";
        if std::env::var_os("CI").is_some() {
            panic!(
                "{msg}: refusing to report a green live-Entra check that verified nothing. Provide \
                 the secrets, or remove this job rather than letting it pass vacuously."
            );
        }
        eprintln!("SKIP: {msg}; this environment has no live Entra tenant provisioned.");
        return;
    };

    let token_endpoint = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token");
    let http = reqwest::blocking::Client::new();
    let resp = http
        .post(&token_endpoint)
        .form(&[
            ("grant_type", "password"),
            ("client_id", &client_id),
            ("username", &username),
            ("password", &password),
            ("scope", "openid profile email"),
        ])
        .send()
        .expect("real POST to Entra's real token endpoint");

    let status = resp.status();
    let text = resp
        .text()
        .expect("Entra's token response body is readable");
    let body: serde_json::Value =
        serde_json::from_str(&text).expect("Entra's token response is JSON");
    assert!(
        status.is_success(),
        "Entra rejected the real password grant ({status}): {body}. If this is \
         AADSTS50055 (password expired), sign in interactively once as the test user to set a \
         permanent password, then re-provision the ENTRA_TEST_PASSWORD secret."
    );
    let id_token = body["id_token"]
        .as_str()
        .expect("a successful grant includes id_token")
        .to_string();

    let settings = serde_json::json!({
        "issuer": format!("https://login.microsoftonline.com/{tenant}/v2.0"),
        "audience": client_id,
    })
    .to_string();

    let host = Host::bind(&settings);
    let outcome = host.verify(&id_token);
    println!("real Entra token outcome: {outcome:?}");
    assert_eq!(
        outcome, VERDICT_IDENTITY,
        "a real, freshly-issued Entra token must verify as an identity through the door"
    );
    let sent = host.idp.sent();
    assert!(
        sent.iter()
            .any(|s| s.path.contains("/.well-known/openid-configuration")),
        "the door fetched the real discovery document: {sent:?}"
    );
    assert!(
        sent.iter()
            .any(|s| s.target.contains("/discovery/v2.0/keys")),
        "the door fetched the real JWKS: {sent:?}"
    );

    // Tamper check: a corrupted signature over the SAME real Entra JWKS must be rejected, so this
    // isn't a rubber stamp that accepts anything shaped like a JWT.
    let (header, payload, sig) = {
        let mut parts = id_token.split('.');
        (
            parts.next().unwrap().to_string(),
            parts.next().unwrap().to_string(),
            parts.next().unwrap().to_string(),
        )
    };
    let mut tampered_sig = sig.into_bytes();
    tampered_sig[0] = if tampered_sig[0] != b'A' { b'A' } else { b'B' };
    let tampered = format!(
        "{header}.{payload}.{}",
        String::from_utf8(tampered_sig).unwrap()
    );

    let tampered_outcome = Host::bind(&settings).verify(&tampered);
    println!("tampered token outcome: {tampered_outcome:?}");
    assert_eq!(
        tampered_outcome, VERDICT_REJECT,
        "a tampered signature over a real Entra-issued token must be rejected"
    );

    println!("PASS: real Entra ID token verified end-to-end, tampered token correctly rejected.");
}
