// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! No unwiped copy of an issued token is freed while a token-endpoint response is read.
//!
//! This binary's global allocator zero-fills every block it hands out, so every byte it later
//! reads is initialised. On free, while the current thread is armed, it scans the block for a
//! canary. A copy the reader wiped before freeing it holds no canary, but a decoder's scratch
//! buffer (or a reallocated partial copy) freed unwiped does. The tokens below carry JSON
//! escapes, which is what sends a serde decoder through its scratch buffer.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::task::Poll;
use std::time::Instant;

use crate::fetch::Doc;
use crate::{Fetch, OidcModule};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::cred::FormBody;
use busbar_contract::auth::LoginHttpResponse;

/// The marker each token below carries, before its escape.
const CANARY: &[u8] = b"CANARY-7f3e9a51";

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static FOUND: Cell<usize> = const { Cell::new(0) };
}

/// The scanning allocator: [`System`], zero-filled, with the canary scan on free.
struct Scan;

// SAFETY: every call forwards to `System` with the caller's own arguments. The scan reads only
// the `layout.size()` bytes of a live block this allocator zero-filled at allocation, before the
// block is returned to `System`. It allocates nothing and touches only const-initialised
// thread-locals through `try_with`, which never panics.
unsafe impl GlobalAlloc for Scan {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.try_with(Cell::get).unwrap_or(false) {
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if block.windows(CANARY.len()).any(|w| w == CANARY) {
                let _ = FOUND.try_with(|f| f.set(f.get() + 1));
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static SCAN: Scan = Scan;

/// How many blocks freed during `f` still held the canary.
fn unwiped_frees(f: impl FnOnce()) -> usize {
    FOUND.with(|n| n.set(0));
    ARMED.with(|a| a.set(true));
    f();
    ARMED.with(|a| a.set(false));
    FOUND.with(Cell::get)
}

/// A `Fetch` with no network: the bodies below never reach a fetch.
struct NoNet;

impl Fetch for NoNet {
    fn caller(&self) -> Option<Ticket> {
        None
    }

    fn get(&mut self, _doc: Doc, _url: &str) -> Poll<Result<String, String>> {
        Poll::Ready(Err("no network in this test".to_string()))
    }

    fn post(&mut self, _url: &str, _form: &FormBody) -> Poll<Result<LoginHttpResponse, String>> {
        Poll::Ready(Err("no network in this test".to_string()))
    }
}

/// The detector itself: a freed block holding the canary is counted, a wiped one is not.
#[test]
fn the_scan_counts_an_unwiped_free_and_not_a_wiped_one() {
    let canary = || String::from_utf8(CANARY.to_vec()).expect("ascii");
    assert_eq!(unwiped_frees(|| drop(canary())), 1);
    assert_eq!(unwiped_frees(|| drop(zeroize::Zeroizing::new(canary()))), 0);
}

#[test]
fn reading_a_token_response_frees_no_unwiped_copy_of_a_token() {
    let module = OidcModule::new(
        &crate::open::config(r#"{"issuer":"https://idp.example","audience":"aud"}"#)
            .expect("settings"),
    );
    let canary = std::str::from_utf8(CANARY).expect("ascii");
    // Each body must reach and pass through `TokenResponse::parse`: the answer is pinned so an
    // early return cannot keep this green.
    let reject = "Ready(Ok(Reject))";
    for (body, expected) in [
        (
            format!(r#"{{"id_token":"{canary}\n{canary}\u00e9\"tail","token_type":"Bearer"}}"#),
            reject,
        ),
        (
            format!(
                r#"{{"access_token":"{canary}\/at","refresh_token":"{canary}\\rt","id_token":"{canary}\ud83d\ude00"}}"#
            ),
            reject,
        ),
        (
            format!(r#"{{"id_token":"{canary}\t","id_token":"{canary}\t"}}"#),
            r#"Ready(Err("token response: a field is missing or has the wrong type (line 1, column 42; the decoder's text is withheld)"))"#,
        ),
        (
            format!(r#"{{"id_token":"{canary}\ud800"}}"#),
            r#"Ready(Err("token response: a field is missing or has the wrong type (line 1, column 35; the decoder's text is withheld)"))"#,
        ),
        (
            format!(r#"{{"{canary}\u0041":{{"nested":"{canary}\n"}},"id_token":"{canary}\t"}}"#),
            reject,
        ),
    ] {
        let resp = LoginHttpResponse { status: 200, body };
        let mut answered = String::new();
        let found = unwiped_frees(|| {
            let answer = module.identity_from_token_response(
                &resp,
                1_900_000_000,
                Instant::now(),
                &mut NoNet,
            );
            answered = format!("{answer:?}");
            drop(answer);
        });
        assert_eq!(answered, expected);
        assert_eq!(found, 0, "an unwiped token copy was freed");
    }
}

/// A late invalid signature must also wipe the payload decoded before it, and a late base64
/// error must wipe bytes the decoder wrote before detecting the malformed suffix.
#[test]
fn malformed_jwt_parts_free_no_unwiped_decoded_bytes() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256"}"#);
    let payload = URL_SAFE_NO_PAD.encode(CANARY.repeat(8));
    for token in [
        format!("{header}.{payload}.!"),
        format!("{header}.{payload}AAAA!AAA.c2ln"),
        format!("{header}.e30.{payload}AAAA!AAA"),
    ] {
        assert_eq!(
            unwiped_frees(|| {
                assert!(crate::jwt::split(&token).is_err());
            }),
            0
        );
    }
    let token = format!("{header}.{payload}AAAA!AAA.c2ln");
    assert_eq!(
        unwiped_frees(|| {
            assert!(crate::jwt::payload(&token).is_none());
        }),
        0
    );
}

#[test]
fn dropping_the_token_request_wipes_code_and_verifier_copies() {
    let module = OidcModule::new(
        &crate::open::config(r#"{"issuer":"https://idp.example","audience":"aud","token_endpoint":"https://idp.example/token"}"#)
            .expect("settings"),
    );
    let canary = std::str::from_utf8(CANARY).expect("ascii");
    assert_eq!(
        unwiped_frees(|| {
            let request = module.token_exchange(
                Some(canary),
                Some("https://app.example/callback"),
                Some(canary),
                None,
                Instant::now(),
                &mut NoNet,
            );
            assert!(matches!(request, crate::Step::Ready(Ok(Some(_)))));
            drop(request);
        }),
        0
    );
}
