// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INBOUND VERDICT CACHE, the plugin's own (owner ruling Q-INCACHE, `abi::auth`: "THE CACHE
//! LIVES IN THE PLUGIN ... the kernel keeps no verdict cache"). 1.5.5's engine credential cache
//! (`crates/busbar/src/auth_cache.rs` at v1.5.5) held every OIDC identity it verified, so a repeat
//! bearer was answered without a second decode, parse and signature check; this is that cache, moved
//! into the module with 1.5.5's rules:
//!
//! - key = SHA-256 of the credential bytes (the credential itself is never stored); one instance is
//!   one provider, so the provider half of 1.5.5's `(provider, hash)` key is the instance;
//! - an identity is held for its own `ttl_secs` (the token's remaining life, at most 300 s:
//!   [`crate::OidcVerifier::validate_claims`]), absent = 300 s, never past 3600 s;
//! - a REJECT is never cached, and neither is a PASS (`abi::auth`: Pass buffering is the kernel's);
//! - at most 4096 entries: at capacity the expired ones go, then the oldest-inserted;
//! - [`VerdictCache::flush`] drops everything and answers how many it held: the admin flush's
//!   `{"flushed": N}`, reported on `refresh`. A FLUSH GENERATION ([`VerdictCache::generation`],
//!   1.5.5's `CacheGeneration`) is captured before a verify judges and handed to
//!   [`VerdictCache::put`], which drops the insert when a flush landed in between, so a verdict
//!   reached before a flush never outlives it.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use busbar_contract::auth::Principal;

/// TTL of a cached identity whose module suggested none, seconds (1.5.5 `DEFAULT_IDENTIFY_TTL_SECS`).
const DEFAULT_TTL_SECS: u64 = 300;
/// The ceiling on any identity's cache TTL, seconds (1.5.5 `MAX_IDENTIFY_TTL_SECS`).
const MAX_TTL_SECS: u64 = 3600;
/// The most entries held (1.5.5 `MAX_ENTRIES`).
pub const MAX_ENTRIES: usize = 4096;

/// A flush generation: the cache's flush counter at one moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Generation(u64);

struct Entry {
    /// UNIX seconds; served while `expires_at > now`.
    expires_at: i64,
    inserted: u64,
    principal: Principal,
}

#[derive(Default)]
struct State {
    entries: HashMap<[u8; 32], Entry>,
    /// Monotonic insert counter: the eviction order.
    seq: u64,
    /// Bumped by every flush, in the critical section that clears the map.
    flushes: u64,
}

/// The cache of identities this module verified.
#[derive(Default)]
pub struct VerdictCache {
    state: Mutex<State>,
}

fn key(credential: &str) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, credential.as_bytes());
    let mut k = [0_u8; 32];
    k.copy_from_slice(digest.as_ref());
    k
}

impl VerdictCache {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The current flush generation: capture it BEFORE judging a credential.
    pub fn generation(&self) -> Generation {
        Generation(self.lock().flushes)
    }

    /// The identity cached for `credential` at UNIX second `now`; an expired entry is a miss and
    /// goes.
    pub fn get(&self, credential: &str, now: i64) -> Option<Principal> {
        let k = key(credential);
        let mut state = self.lock();
        match state.entries.get(&k) {
            Some(e) if e.expires_at > now => Some(e.principal.clone()),
            Some(_) => {
                state.entries.remove(&k);
                None
            }
            None => None,
        }
    }

    /// Hold `principal`, the identity `credential` verified as at UNIX second `now`, unless a flush
    /// landed since `generation` was captured.
    pub fn put(&self, credential: &str, principal: &Principal, now: i64, generation: Generation) {
        let ttl = principal
            .ttl_secs
            .unwrap_or(DEFAULT_TTL_SECS)
            .min(MAX_TTL_SECS);
        let k = key(credential);
        let mut state = self.lock();
        if state.flushes != generation.0 {
            return;
        }
        let State { entries, seq, .. } = &mut *state;
        if entries.len() >= MAX_ENTRIES && !entries.contains_key(&k) {
            entries.retain(|_, e| e.expires_at > now);
            if entries.len() >= MAX_ENTRIES {
                if let Some(oldest) = entries
                    .iter()
                    .min_by_key(|(_, e)| e.inserted)
                    .map(|(k, _)| *k)
                {
                    entries.remove(&oldest);
                }
            }
        }
        *seq += 1;
        entries.insert(
            k,
            Entry {
                expires_at: now.saturating_add(i64::try_from(ttl).unwrap_or(i64::MAX)),
                inserted: *seq,
                principal: principal.clone(),
            },
        );
    }

    /// Drop every entry (the admin flush, every `refresh`): how many there were.
    pub fn flush(&self) -> usize {
        let mut state = self.lock();
        state.flushes += 1;
        let n = state.entries.len();
        state.entries.clear();
        n
    }

    /// How many entries are held.
    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    /// Whether none is.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
#[path = "tests/verdicts_tests.rs"]
mod tests;
