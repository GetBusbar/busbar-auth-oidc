// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The verdict cache's rules, as 1.5.5's engine credential cache held them (v1.5.5

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
    assert!(c.lock().entries.is_empty(), "and goes");

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
    assert_eq!(c.lock().entries.len(), MAX_ENTRIES);
    assert!(c.get("cred-0", t + 1).is_none(), "the oldest went");
    assert!(c.get("one-more", t + 1).is_some());
}

#[test]
fn a_zero_ttl_identity_is_not_inserted() {
    let c = VerdictCache::default();
    let t = 1_700_000_000;
    c.put("cred-z", &principal(Some(0)), t, c.generation());
    assert_eq!(c.flush(), 0, "nothing was held");
}

#[test]
fn an_identity_over_8_kib_is_not_cached() {
    let c = VerdictCache::default();
    let t = 1_700_000_000;
    let mut big = principal(Some(300));
    big.roles = (0..200).map(|i| format!("{i:0>48}")).collect();
    c.put("cred-big", &big, t, c.generation());
    assert!(c.get("cred-big", t + 1).is_none(), "over 8 KiB: not held");
    let mut fits = principal(Some(300));
    fits.roles = (0..100).map(|i| format!("{i:0>48}")).collect();
    c.put("cred-fits", &fits, t, c.generation());
    assert!(c.get("cred-fits", t + 1).is_some(), "under 8 KiB: held");
}

#[test]
fn many_tiny_roles_count_their_serialized_overhead_toward_the_existing_bound() {
    let c = VerdictCache::default();
    let mut p = principal(Some(300));
    p.roles = vec!["r".to_string(); 4096];
    assert!(p.id.len() + p.roles.iter().map(String::len).sum::<usize>() < MAX_PRINCIPAL_BYTES);
    c.put("tiny-role-token", &p, 1_700_000_000, c.generation());
    assert!(c.get("tiny-role-token", 1_700_000_001).is_none());
    p.roles.truncate(16);
    c.put("small-token", &p, 1_700_000_000, c.generation());
    assert!(c.get("small-token", 1_700_000_001).is_some());
}
