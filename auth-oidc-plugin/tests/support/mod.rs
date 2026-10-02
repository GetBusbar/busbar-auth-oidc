// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared by this crate's integration tests (`e2e.rs`, `conformance.rs`):
//!
//! * the logic crate's own local issuer (`busbar_auth_oidc::testkit`, feature `testkit`) — a REAL
//!   ES256 key, its JWKS and token endpoint served over a certificate-verified loopback endpoint
//!   (trusted through the module's `ca_cert_pem`), and genuinely signed tokens;
//! * the HOST side of the auth door, through the real loader: a dispatcher, a bind, and one call
//!   per op, each answer rendered as one comparable line.
//!
//! No stubbed crypto, no stubbed fetch, no stubbed door.
#![allow(dead_code)]

use std::sync::Arc;

use busbar_contract::abi::auth::{
    slot, BeginLoginIn, BeginLoginOut, CompleteLoginIn, IdentifyOut, IdentityBuf, VerifyIn,
    IDENTITY_BUF_BYTES, IDENTITY_GROUPS, SPAN_ABSENT,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, Span, BLOB_JSON, BLOB_OCTETS};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut, ReleaseIn};
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::{
    in_head, out_head, Bind, DispatchConfig, Dispatcher, Frame, InFrame, NoSink, Plugin, NO_BLOB,
};

pub use busbar_auth_oidc::testkit::Issuer;

/// The `iss` of a key used only for its signature (the tests configure the issuer they check).
pub const UNUSED_ISSUER: &str = "https://issuer.unused.invalid";

/// An all-zero `T`.
pub fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { std::mem::zeroed() }
}

/// A dispatcher for the doors a test loads.
pub fn dispatcher() -> Dispatcher {
    Dispatcher::new(DispatchConfig::default())
}

/// The host's bind for one instance on `d`.
pub fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("oidc"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: None,
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

/// `open` the instance over `settings`, lending `secret` as its one secret; the operator's text
/// for a refusal.
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

/// One identity op (`verify`, `complete_login`) with host buffers of `cap` bytes and groups; a
/// short answer is re-called once with buffers of the size it named.
fn identify<I: InFrame>(
    p: &Plugin<Auth>,
    op: u32,
    input: impl Fn(IdentityBuf) -> I,
    cap: (usize, u32),
) -> String {
    let (mut bytes, mut groups) = (vec![0_u8; cap.0], vec![z::<Span>(); cap.1 as usize]);
    let buf = |bytes: &mut Vec<u8>, groups: &mut Vec<Span>| IdentityBuf {
        buf: bytes.as_mut_ptr(),
        buf_cap: bytes.len(),
        groups: groups.as_mut_ptr(),
        groups_cap: groups.len() as u32,
        _reserved: 0,
    };
    let mut out: IdentifyOut = z();
    out.head = out_head();
    let mut f = Frame::new(input(buf(&mut bytes, &mut groups)), out);
    let mut called = p.call(op, &mut f);
    let mut short = String::new();
    if let Some(token) = called.recall.take() {
        short = format!(
            "short(needed {}/{}) ",
            f.out.needed_bytes, f.out.needed_groups
        );
        bytes = vec![0_u8; f.out.needed_bytes as usize];
        groups = vec![z::<Span>(); f.out.needed_groups as usize];
        let mut out: IdentifyOut = z();
        out.head = out_head();
        f = Frame::new(input(buf(&mut bytes, &mut groups)), out);
        called = p.recall(token, op, &mut f);
    }
    match called.outcome {
        Outcome::Ready => format!(
            "{short}verdict {} {}",
            f.out.verdict,
            if f.out.verdict == 1 {
                identity(&f.out, &bytes, &groups)
            } else {
                String::new()
            }
        ),
        other => format!(
            "{short}{other:?} {}",
            String::from_utf8_lossy(&called.error.unwrap_or_default())
        ),
    }
}

/// `verify` of `credential` (none = none presented), with the host's starting buffers or `cap`.
pub fn verify(p: &Plugin<Auth>, credential: Option<&str>, cap: Option<(usize, u32)>) -> String {
    identify(
        p,
        slot::VERIFY,
        |out_buf| {
            let mut i: VerifyIn = z();
            i.head = in_head();
            i.credential = credential.map_or(NO_BLOB, |c| blob(c.as_bytes(), BLOB_OCTETS));
            i.out_buf = out_buf;
            i
        },
        cap.unwrap_or((IDENTITY_BUF_BYTES, IDENTITY_GROUPS)),
    )
}

/// `begin_login` for the core's `state`, `challenge` and `nonce`: the authorize URL, or the refusal.
pub fn begin(
    p: &Plugin<Auth>,
    redirect: &str,
    state: &str,
    challenge: &str,
    nonce: &str,
) -> String {
    let mut i: BeginLoginIn = z();
    i.head = in_head();
    i.redirect_uri = abi_str(redirect);
    i.state = abi_str(state);
    i.nonce = abi_str(nonce);
    i.code_challenge = abi_str(challenge);
    let mut o: BeginLoginOut = z();
    o.head = out_head();
    let mut f = Frame::new(i, o);
    let called = p.call(slot::BEGIN_LOGIN, &mut f);
    if called.outcome != Outcome::Ready {
        return format!(
            "{:?} {}",
            called.outcome,
            String::from_utf8_lossy(&called.error.unwrap_or_default())
        );
    }
    let line = format!("shape {} {}", f.out.shape, text(f.out.authorize_url));
    let mut r: ReleaseIn = z();
    r.head = in_head();
    r.lease = called.lease;
    let released = p.call(life::RELEASE, &mut Frame::new(r, out_head()));
    format!("{line} (release {:?})", released.outcome)
}

/// `complete_login` of the callback's `code`, with the host's starting buffers or `cap`.
pub fn complete(
    p: &Plugin<Auth>,
    code: &str,
    state: &str,
    redirect: &str,
    verifier: &str,
    cap: Option<(usize, u32)>,
) -> String {
    identify(
        p,
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
