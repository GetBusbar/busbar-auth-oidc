// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A SCRIPTED IdP for the module's sans-IO tests: one document every GET answers (or an error), the
//! token endpoint's reply, and a count of every request made. A [`Caller`] is one op's requests
//! against it, as the door's exchange makes them: one that pends answers its FIRST ask of a request
//! `Pending` and the same ask on the op's re-entry `Ready`, like an exchange whose first read
//! pends. No network.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::task::Poll;

use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::auth::{LoginHop, LoginHttpResponse};

use crate::fetch::{Doc, Fetch};
use crate::flight::Step;

/// The ticket a test's one op runs on.
pub const ME: Ticket = Ticket {
    slot: 1,
    generation: 1,
};

/// The ticket of the `n`th concurrent op.
pub const fn ticket(n: u32) -> Ticket {
    Ticket {
        slot: n,
        generation: 1,
    }
}

/// `Step::Ready(v)` → `v`; anything else is a test failure.
pub fn ready<T>(step: Step<T>) -> T {
    match step {
        Step::Ready(v) => v,
        Step::Pending => panic!("expected READY, got PENDING"),
        Step::Wait => panic!("expected READY, got WAIT"),
    }
}

/// The IdP: what it serves and what it was asked.
pub struct Idp {
    body: Mutex<Result<String, String>>,
    calls: AtomicUsize,
    reply: Mutex<Result<LoginHttpResponse, String>>,
}

impl Idp {
    /// An IdP answering every GET with `body`.
    pub fn new(body: String) -> Self {
        Self::answering(Ok(body))
    }

    /// An IdP answering every GET with `answer`.
    pub fn answering(answer: Result<String, String>) -> Self {
        Self {
            body: Mutex::new(answer),
            calls: AtomicUsize::new(0),
            reply: Mutex::new(Ok(LoginHttpResponse {
                status: 200,
                body: "{}".to_string(),
            })),
        }
    }

    /// Swap the served body in place — the provider rotating its JWKS underneath an
    /// already-running module.
    pub fn set_body(&self, body: String) {
        self.set_answer(Ok(body));
    }

    /// Swap what every GET answers.
    pub fn set_answer(&self, answer: Result<String, String>) {
        *self.body.lock().unwrap() = answer;
    }

    /// How many requests were made (GETs and POSTs).
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// One op on `ticket` whose requests answer at once.
    pub fn at_once(&self, ticket: Option<Ticket>) -> Caller<'_> {
        Caller {
            idp: self,
            ticket,
            pend: false,
            in_flight: None,
        }
    }

    /// One op on `ticket` whose every request answers `Pending` first.
    pub fn pending(&self, ticket: Ticket) -> Caller<'_> {
        Caller {
            idp: self,
            ticket: Some(ticket),
            pend: true,
            in_flight: None,
        }
    }

    fn start(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

/// One op's requests against an [`Idp`]: what the door's parked exchange state is to a real one.
pub struct Caller<'a> {
    idp: &'a Idp,
    ticket: Option<Ticket>,
    pend: bool,
    in_flight: Option<String>,
}

impl Caller<'_> {
    /// Whether a request to `url` is answered now: a re-ask of the one in flight is; a new one is
    /// started, and answered now unless this op pends.
    fn answered(&mut self, url: &str) -> bool {
        if self.in_flight.as_deref() == Some(url) {
            self.in_flight = None;
            return true;
        }
        self.idp.start();
        if self.pend {
            self.in_flight = Some(url.to_string());
            return false;
        }
        true
    }
}

impl Fetch for Caller<'_> {
    fn caller(&self) -> Option<Ticket> {
        self.ticket
    }

    fn get(&mut self, _: Doc, url: &str) -> Poll<Result<String, String>> {
        if !self.answered(url) {
            return Poll::Pending;
        }
        Poll::Ready(self.idp.body.lock().unwrap().clone())
    }

    fn post(&mut self, hop: &LoginHop, _: Option<&str>) -> Poll<Result<LoginHttpResponse, String>> {
        if !self.answered(&hop.url) {
            return Poll::Pending;
        }
        Poll::Ready(self.idp.reply.lock().unwrap().clone())
    }
}
