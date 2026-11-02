// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The inbound verdict cache, the plugin's own (the kernel keeps no verdict cache). It holds every

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use busbar_contract::auth::Principal;

/// TTL of a cached identity whose module suggested none, seconds.
const DEFAULT_TTL_SECS: u64 = 300;
/// The ceiling on any identity's cache TTL, seconds.
const MAX_TTL_SECS: u64 = 3600;
/// The most entries held.
pub const MAX_ENTRIES: usize = 4096;
/// The largest serialized identity held. A bigger one is judged afresh. The 4096 × 8 KiB bound
pub const MAX_PRINCIPAL_BYTES: usize = 8 * 1024;

/// Count the serialized identity without allocating a second copy of its strings. Stop at the
fn size_of(p: &Principal) -> usize {
    #[derive(serde::Serialize)]
    struct View<'a> {
        id: &'a str,
        name: Option<&'a str>,
        roles: &'a [String],
        ttl_secs: Option<u64>,
    }
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            if self.0 > MAX_PRINCIPAL_BYTES {
                return Err(std::io::Error::other("identity exceeds cache bound"));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    let view = View {
        id: &p.id,
        name: p.name.as_deref(),
        roles: &p.roles,
        ttl_secs: p.ttl_secs,
    };
    match serde_json::to_writer(&mut count, &view) {
        Ok(()) => count.0,
        Err(_) => MAX_PRINCIPAL_BYTES + 1,
    }
}

/// A cache hit: the identity held, and the TTL it has LEFT at the hit (`None` when its module
/// suggested none, as when it was first answered).
#[derive(Debug, Clone)]
pub struct Hit {
    /// The identity held.
    pub principal: Arc<Principal>,
    /// Its remaining TTL, seconds.
    pub ttl_secs: Option<u64>,
}

/// A flush generation: the cache's flush counter at one moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Generation(u64);

struct Entry {
    /// UNIX seconds; served while `expires_at > now`.
    expires_at: i64,
    inserted: u64,
    principal: Arc<Principal>,
}

#[derive(Default)]
struct State {
    entries: HashMap<[u8; 32], Entry>,
    /// Monotonic insert counter: the eviction order.
    seq: u64,
    /// Bumped by every flush, in the critical section that clears the map.
    flushes: u64,
}

/// The cache of identities this module verified. A hit takes the read lock and an `Arc` clone, so
/// concurrent hits never serialise.
#[derive(Default)]
pub struct VerdictCache {
    state: RwLock<State>,
}

fn key(credential: &str) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, credential.as_bytes());
    let mut k = [0_u8; 32];
    k.copy_from_slice(digest.as_ref());
    k
}

impl VerdictCache {
    fn read(&self) -> RwLockReadGuard<'_, State> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn lock(&self) -> RwLockWriteGuard<'_, State> {
        self.state.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// The current flush generation: capture it BEFORE judging a credential.
    pub fn generation(&self) -> Generation {
        Generation(self.read().flushes)
    }

    /// The identity cached for `credential` at UNIX second `now`, with the TTL it has left; an
    pub fn get(&self, credential: &str, now: i64) -> Option<Hit> {
        let k = key(credential);
        match self.read().entries.get(&k) {
            Some(e) if e.expires_at > now => {
                let left = u64::try_from(e.expires_at.saturating_sub(now)).unwrap_or(0);
                return Some(Hit {
                    principal: Arc::clone(&e.principal),
                    ttl_secs: e.principal.ttl_secs.map(|_| left),
                });
            }
            Some(_) => {}
            None => return None,
        }
        let mut state = self.lock();
        if state.entries.get(&k).is_some_and(|e| e.expires_at <= now) {
            state.entries.remove(&k);
        }
        None
    }

    /// Hold `principal`, the identity `credential` verified as at UNIX second `now`, unless a flush
    pub fn put(&self, credential: &str, principal: &Principal, now: i64, generation: Generation) {
        let ttl = principal
            .ttl_secs
            .unwrap_or(DEFAULT_TTL_SECS)
            .min(MAX_TTL_SECS);

        if ttl == 0 || size_of(principal) > MAX_PRINCIPAL_BYTES {
            return;
        }
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
                principal: Arc::new(principal.clone()),
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
}

#[cfg(test)]
#[path = "tests/verdicts_tests.rs"]
mod tests;
