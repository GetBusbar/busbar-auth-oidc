// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SINGLE-FLIGHT, SANS-IO (THE DESIGN, auth: "JWKS fetching is sans-IO single-flight: a cold key id
//! pends verify, one `exchange()` fetches, every waiter wakes"). The module never blocks and never
//! dials: a read that needs the IdP answers [`Step::Pending`] while the caller's own exchange is in
//! flight, or [`Step::Wait`] while ANOTHER caller's is, and the op re-enters (on its wake, or on its
//! timer) and asks again. [`Flight`] is who is fetching, and since when.

use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::ticket::Ticket;

/// How long one fetch may hold its flight before another caller takes it over: 1.5.5's bound on a
/// discovery or JWKS fetch (connect + total). An op whose exchange outlived it was cancelled or
/// faulted, and never settles its flight.
pub const FLIGHT_MAX: Duration = Duration::from_secs(10);

/// Where a sans-IO read stands after one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step<T> {
    /// Done.
    Ready(T),
    /// The caller's own exchange is in flight: its wake re-enters the op.
    Pending,
    /// Another caller's fetch is in flight and this caller has nothing to serve: re-enter after a
    /// short wait and ask again.
    Wait,
}

/// `Step::Ready(v)` → `v`; `Pending`/`Wait` return from the calling function.
macro_rules! step {
    ($e:expr) => {
        match $e {
            $crate::flight::Step::Ready(v) => v,
            $crate::flight::Step::Pending => return $crate::flight::Step::Pending,
            $crate::flight::Step::Wait => return $crate::flight::Step::Wait,
        }
    };
}

/// `Step::Ready(Ok(v))` → `v`; an `Err` is answered READY; `Pending`/`Wait` return.
macro_rules! step_ok {
    ($e:expr) => {
        match step!($e) {
            Ok(v) => v,
            Err(e) => return $crate::flight::Step::Ready(Err(e)),
        }
    };
}

/// One fetch in flight: whose op makes it, and the instant it was claimed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flight {
    /// The ticket of the op whose exchange makes the fetch.
    pub owner: Ticket,
    /// When it was claimed (the claimer's `now`).
    pub at: Instant,
}

impl Flight {
    /// Whether `me` makes this fetch.
    pub fn mine(&self, me: Option<Ticket>) -> bool {
        me == Some(self.owner)
    }

    /// Whether another caller's fetch still holds the flight at `now` (one past [`FLIGHT_MAX`] was
    /// abandoned).
    pub fn held_against(&self, me: Option<Ticket>, now: Instant) -> bool {
        !self.mine(me) && now.saturating_duration_since(self.at) < FLIGHT_MAX
    }
}
