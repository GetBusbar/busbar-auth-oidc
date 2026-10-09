// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The verdict cache's rules, as 1.5.5's engine credential cache held them (v1.5.5
//! `crates/busbar/src/auth_cache.rs`, its `verdict_rules_and_expiry`, `bounded_eviction` and
//! flush-generation tests): an identity held for its TTL (default 300 s, never past 3600 s), a
//! flush drops everything and counts it, an insert computed before a flush is dropped, the bound
//! holds.

use super::*;

fn principal(ttl: Option<u64>) -> Principal {
    let mut p = Principal::from_id("oidc:u1");
    p.ttl_secs = ttl;
    p
}

#[test]
fn an_identity_is_held_for_its_ttl_and_never_past_the_ceiling() {
    let c = VerdictCache::default();
    let t = 1_700_000_000;
    c.put("cred-a", &principal(None), t, c.generation());
    assert!(c.get("cred-a", t + 299).is_some(), "the 300 s default");
    assert!(c.get("cred-a", t + 300).is_none(), "expired is a miss");
    assert!(c.is_empty(), "and goes");

    c.put("cred-b", &principal(Some(10)), t, c.generation());
    assert!(c.get("cred-b", t + 9).is_some());
    assert!(c.get("cred-b", t + 10).is_none(), "the token's own TTL");

    c.put("cred-c", &principal(Some(999_999)), t, c.generation());
    assert!(c.get("cred-c", t + 3599).is_some());
    assert!(c.get("cred-c", t + 3600).is_none(), "the 3600 s ceiling");

    c.put("cred-d", &principal(Some(0)), t, c.generation());
    assert!(c.get("cred-d", t).is_none(), "a zero TTL holds nothing");
}

#[test]
fn a_flush_drops_everything_and_counts_it() {
    let c = VerdictCache::default();
    let t = 1_700_000_000;
    c.put("cred-a", &principal(None), t, c.generation());
    c.put("cred-b", &principal(None), t, c.generation());
    assert_eq!(c.flush(), 2);
    assert!(c.get("cred-a", t + 1).is_none());
    assert_eq!(c.flush(), 0, "nothing left to drop");
}

/// 1.5.5's flush-generation rule: a verify in flight across a flush cannot put back the identity
/// it judged before the flush.
#[test]
fn an_identity_judged_before_a_flush_is_not_put_back_after_it() {
    let c = VerdictCache::default();
    let t = 1_700_000_000;
    let before = c.generation();
    assert_eq!(c.flush(), 0);
    c.put("cred-a", &principal(None), t, before);
    assert!(
        c.get("cred-a", t + 1).is_none(),
        "the pre-flush verdict is dropped"
    );
    c.put("cred-a", &principal(None), t, c.generation());
    assert!(
        c.get("cred-a", t + 1).is_some(),
        "a post-flush verdict lands"
    );
}

#[test]
fn the_bound_holds_by_evicting_the_oldest_inserted() {
    let c = VerdictCache::default();
    let t = 1_700_000_000;
    for i in 0..MAX_ENTRIES {
        c.put(
            &format!("cred-{i}"),
            &principal(Some(300)),
            t,
            c.generation(),
        );
    }
    c.put("one-more", &principal(Some(300)), t, c.generation());
    assert_eq!(c.len(), MAX_ENTRIES);
    assert!(c.get("cred-0", t + 1).is_none(), "the oldest went");
    assert!(c.get("one-more", t + 1).is_some());
}
