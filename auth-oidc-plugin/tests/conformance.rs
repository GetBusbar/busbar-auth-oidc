// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE AUTH MODULE, BOTH DOORS, ONE CONNECTOR** — the OIDC module's linked + dropped-in

mod support;

#[path = "support/retry_after.rs"]
mod retry_after;

#[path = "support/net_ban.rs"]
mod net_ban;

#[path = "support/import_ban.rs"]
mod import_ban;

use std::time::Duration;

use busbar_contract::abi::auth::{
    slot, IdentifyOut, IDENTITY_BUF_BYTES, IDENTITY_GROUPS, LOGIN_BAD_CREDENTIAL, LOGIN_OUTAGE,
    LOGIN_SECURITY_CHECK_FAILED, METRIC_CACHE_FLUSHED,
};
use busbar_contract::abi::host::conn::connector::{
    DIRECTION_OUTBOUND, EGRESS_DEFAULT, EGRESS_OPEN_WEB,
};
use busbar_contract::abi::mechanism::call::{Outcome, Span};
use busbar_contract::abi::mechanism::rendering;
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::kinds::secret::Secret;
use busbar_plugin_loader::dispatch::{now_ns, out_head, Frame, LoadError};
use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};
use busbar_plugin_loader::PluginRegistry;
use support::{
    bind, bind_as, identity_buf, open, row, verify_in, verify_ticketless, verify_ticketless_raw, z,
    Arm, Bound, Idp, Issuer, DISCOVERY_PATH, ISSUER, UNUSED_ISSUER,
};

/// The module's registry name and alias (what an operator's `identity-providers:` names).
const NAME: &str = "busbar-auth-oidc";
const ALIAS: &str = "oidc";

const AUDIENCE: &str = "api://busbar-conformance";
const REDIRECT: &str = "https://node.example/auth/token";
/// The confidential-client secret the host lends at `open`.
const CLIENT_SECRET: &str = "conformance-client-secret";
const KID: &str = "conformance-kid";

/// The release key the dropped-in arm is signed with, and the policy's first-party key.
fn release() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

/// This crate's built cdylib's bytes. A missing artifact is a failure, never a skip.
fn cdylib() -> Vec<u8> {
    let path = support::cdylib_path()
        .unwrap_or_else(|| panic!("the busbar-auth-oidc-plugin cdylib is not built"));
    std::fs::read(path).expect("read the cdylib")
}

/// The manifest the packer signs for the module as `kind`, stating the Statement rendering
fn manifest(kind: &str, statement: &[u8]) -> Manifest {
    Manifest {
        name: NAME.into(),
        alias: ALIAS.into(),
        former_names: Vec::new(),
        kind: kind.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        publisher: busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER.into(),
        abi_version: *busbar_plugin_loader::supported_abi(kind)
            .iter()
            .max()
            .expect("a payload schema for the kind"),
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: Default::default(),
        statement: Some(statement.iter().map(|b| format!("{b:02x}")).collect()),
    }
}

/// `lib` signed first-party under `manifest` into a fresh `plugins/` directory, scanned under a
fn scanned(tag: &str, manifest: Manifest, lib: &[u8]) -> PluginRegistry {
    let dir = std::env::temp_dir().join(format!("auth-oidc-conf-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let signed = sign(&release(), manifest, lib);
    let tarball = busbar_plugin_loader::tarball::package(&signed, "libauth.so", lib).unwrap();
    std::fs::write(dir.join("auth.tar.gz"), tarball).unwrap();
    let policy = TrustPolicy {
        first_party_key: Some(release().verifying_key()),
        first_party_keys: Vec::new(),
        revoked: Default::default(),
        release_keys_floor: 0,
        release_clock: None,
        release_enforce_expiry: false,
        binary_version: env!("CARGO_PKG_VERSION").into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: Default::default(),
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: Default::default(),
    };
    let registry =
        busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("the signed module scans");
    let _ = std::fs::remove_dir_all(&dir);
    registry
}

/// The verified library bytes and the signed Statement rendering the scan resolved the alias to.
fn admitted(registry: &PluginRegistry) -> (Vec<u8>, Vec<u8>) {
    let p = registry.resolve(ALIAS).expect("the alias resolves");
    assert_eq!(p.manifest.name, NAME);
    let stated = p
        .manifest
        .stated_rendering()
        .expect("the manifest's statement is hex")
        .expect("the signed manifest states the door's Statement");
    (p.lib_bytes.to_vec(), stated)
}

/// The operator config: only the issuer and the audience (the JWKS url and both login endpoints
fn config(audience: &str) -> String {
    serde_json::json!({
        "issuer": ISSUER,
        "audience": audience,
        "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nconformance\n-----END CERTIFICATE-----\n",
        "role_claim": "roles",
    })
    .to_string()
}

/// The same config with NO extra trusted root (`ca_cert_pem` is optional, as in 1.5.5): the
fn config_public(audience: &str) -> String {
    let mut cfg: serde_json::Value = serde_json::from_str(&config(audience)).unwrap();
    cfg.as_object_mut().unwrap().remove("ca_cert_pem");
    cfg.to_string()
}

/// The tokens the script presents, minted once so both doors judge the same bytes.
struct Tokens {
    valid: String,
    forged: String,
    wrong_audience: String,
    /// Validly signed, for the right audience, but carrying another login's nonce.
    other_nonce: String,
}

/// The nonce the core minted at `begin` (in the login cookie), handed to `complete_login`; every
const NONCE: &str = "conformance-nonce";

fn claims(aud: &str) -> serde_json::Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    serde_json::json!({
        "iss": ISSUER,
        "aud": aud,
        "exp": now + 3600,
        "nbf": now - 10,
        "sub": "conformance-subject",
        "name": "Conformance Caller",
        "roles": ["Gateway.User", "Gateway.Admin"],
        "nonce": NONCE,
    })
}

fn tokens(key: &Issuer) -> Tokens {
    Tokens {
        valid: key.sign(&claims(AUDIENCE)),
        forged: Issuer::start(UNUSED_ISSUER, KID).sign(&claims(AUDIENCE)),
        wrong_audience: key.sign(&claims("api://someone-else")),
        other_nonce: {
            let mut c = claims(AUDIENCE);
            c["nonce"] = serde_json::json!("another-login");
            key.sign(&c)
        },
    }
}

/// A signed audience must still have the JWT string-or-array-of-strings shape. Exercise the
#[test]
fn signed_mixed_type_audiences_are_refused_by_both_doors_and_login_modes() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let row = row();
    let registry = scanned("mixed-aud", manifest("auth", &row.statement), &cdylib());
    let (lib, stated) = admitted(&registry);
    let mut cfg: serde_json::Value = serde_json::from_str(&config(AUDIENCE)).unwrap();
    const CLIENT: &str = "conformance-login-client";
    cfg["client_id"] = serde_json::json!(CLIENT);
    let cfg = cfg.to_string();
    for arm in [
        Arm::Linked,
        Arm::Dropped {
            lib: &lib,
            stated: &stated,
        },
    ] {
        let b = bind(&arm, &Idp::secure_carrier(&key));
        open(&b.plugin, &cfg, Some(CLIENT_SECRET)).unwrap();
        for (index, extra) in [
            serde_json::json!(42),
            serde_json::json!(null),
            serde_json::json!({ "aud": AUDIENCE }),
            serde_json::json!([AUDIENCE]),
        ]
        .into_iter()
        .enumerate()
        {
            let mut bearer = claims(AUDIENCE);
            bearer["aud"] = serde_json::json!([AUDIENCE, extra.clone()]);
            assert_eq!(b.verify(Some(&key.sign(&bearer)), None), "verdict 2 ");
            let mut login = claims(CLIENT);
            login["aud"] = serde_json::json!([CLIENT, extra]);
            login["azp"] = serde_json::json!(CLIENT);
            b.idp.answer(
                "/token",
                200,
                &serde_json::json!({ "id_token": key.sign(&login) }).to_string(),
            );
            assert_eq!(
                b.complete(
                    &format!("mixed-aud-{index}"),
                    ("mixed-aud-state", NONCE),
                    REDIRECT,
                    "the-verifier",
                    None,
                ),
                "verdict 2 ",
                "a valid client azp and login nonce cannot repair a non-string audience"
            );
        }
        let mut bearer = claims(AUDIENCE);
        bearer["aud"] = serde_json::json!([AUDIENCE, "another-resource"]);
        assert!(
            b.verify(Some(&key.sign(&bearer)), None)
                .starts_with("verdict 1 "),
            "a valid bearer can name several resource audiences without azp"
        );
        let mut login = claims(CLIENT);
        login["aud"] = serde_json::json!([CLIENT, "another-client"]);
        login["azp"] = serde_json::json!(CLIENT);
        b.idp.answer(
            "/token",
            200,
            &serde_json::json!({ "id_token": key.sign(&login) }).to_string(),
        );
        assert!(
            b.complete(
                "valid-multi-aud",
                ("mixed-aud-state", NONCE),
                REDIRECT,
                "the-verifier",
                None,
            )
            .starts_with("verdict 1 "),
            "an all-string id_token audience array keeps the authorized-party rule"
        );
        assert!(b.idp.pended() > 0, "the loaded door crossed Pending IO");
    }
}

/// What one door does with the module opened under `cfg`, against its own IdP, as one comparable
fn transcript(b: &Bound, cfg: &str, t: &Tokens) -> Vec<String> {
    let id_token = |token: &str| serde_json::json!({ "id_token": token }).to_string();
    let callback = |code: &str, cap| b.complete(code, ("st", NONCE), REDIRECT, "the-verifier", cap);
    let mut lines = vec![
        format!("name {}", b.plugin.name()),
        format!("open {:?}", open(&b.plugin, cfg, Some(CLIENT_SECRET))),
    ];
    for credential in [
        Some(t.valid.as_str()),
        Some(&t.forged),
        Some(&t.wrong_audience),
        Some("not-a-jwt"),
        None,
    ] {
        lines.push(b.verify(credential, None));
    }
    lines.push(b.verify(Some(&t.valid), Some((8, 0))));
    lines.push(b.begin(
        REDIRECT,
        "conformance-state",
        "conformance-challenge",
        "conformance-nonce",
    ));
    b.idp.answer("/token", 200, &id_token(&t.valid));
    lines.push(callback("code-1", None));
    let before = b.idp.sent_to("/token").len();
    lines.push(callback("code-2", Some((8, 0))));
    lines.push(format!(
        "exchanges {}",
        b.idp.sent_to("/token").len() - before
    ));
    b.idp.answer("/token", 200, &id_token(&t.forged));
    lines.push(callback("code-3", None));
    b.idp.answer("/token", 400, r#"{"error":"invalid_grant"}"#);
    lines.push(callback("code-4", None));
    b.idp.answer("/token", 503, "{}");
    lines.push(callback("code-5", None));
    b.idp.answer("/token", 200, &id_token(&t.other_nonce));
    lines.push(callback("code-6", None));
    lines.extend(b.idp.declared());
    lines.extend(b.idp.sent().iter().map(|s| {
        format!(
            "sent need={} target={} {} {} body={}",
            s.need, s.target, s.method, s.path, s.body
        )
    }));
    lines.push(format!("pended {}", b.idp.pended()));
    lines
}

/// The OIDC module behaves as ONE module through either door, every request through the host's
#[test]
fn the_linked_and_the_dropped_in_oidc_module_are_one_module() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let cfg = config(AUDIENCE);
    let t = tokens(&key);
    let row = row();

    let registry = scanned("dropped", manifest("auth", &row.statement), &cdylib());
    let (lib, stated) = admitted(&registry);
    assert_eq!(
        stated, row.statement,
        "the signed manifest states the door's own Statement"
    );

    let linked = bind(&Arm::Linked, &Idp::secure_carrier(&key));
    let dropped = bind(
        &Arm::Dropped {
            lib: &lib,
            stated: &stated,
        },
        &Idp::secure_carrier(&key),
    );
    let a = transcript(&linked, &cfg, &t);
    let b = transcript(&dropped, &cfg, &t);
    assert_eq!(a, b, "the two doors are not one module");

    let text = a.join("\n");
    assert_eq!(a[0], format!("name {NAME}"), "{text}");
    assert_eq!(a[1], "open Ok(())", "{text}");
    assert!(
        a[2].starts_with("verdict 1 subject=Some(\"oidc-v2:aHR0cHM6Ly9pZHAuY29uZm9ybWFuY2UuZXhhbXBsZS92Mi4w:conformance-subject\")")
            && a[2].contains("\"Gateway.Admin\""),
        "the valid token identifies the caller with its roles, after discovery and the JWKS \
         fetch both crossed PENDING: {text}"
    );
    assert_eq!(a[3], "verdict 2 ", "the forged token is rejected: {text}");
    assert_eq!(a[4], "verdict 2 ", "the wrong audience is rejected: {text}");
    assert_eq!(a[5], "verdict 3 ", "not a JWT passes: {text}");
    assert_eq!(a[6], "verdict 3 ", "no credential passes: {text}");
    assert!(
        a[7].starts_with("short(needed ") && a[7].ends_with(&a[2]),
        "a short buffer is re-called once and answers the same identity: {text}"
    );
    assert!(
        a[8].starts_with("shape 1 https://idp.conformance.example/authorize?")
            && a[8].contains("state=conformance-state")
            && a[8].contains("nonce=conformance-nonce")
            && a[8].ends_with("(release Ready)"),
        "the authorize URL is the DISCOVERED endpoint's: {text}"
    );
    assert!(
        a[9].starts_with("verdict 1 subject=Some(\"oidc-v2:aHR0cHM6Ly9pZHAuY29uZm9ybWFuY2UuZXhhbXBsZS92Mi4w:conformance-subject\")"),
        "the login's token exchange answers an identity: {text}"
    );
    assert!(
        a[10].starts_with("short(needed ") && a[10].ends_with(&a[9]),
        "{text}"
    );
    assert_eq!(
        a[11], "exchanges 1",
        "the short re-call redeems no code twice: {text}"
    );
    assert_eq!(
        a[12], "verdict 2 ",
        "a forged id_token is a bad credential: {text}"
    );
    assert_eq!(
        a[13], "verdict 2 ",
        "invalid_grant is a bad credential: {text}"
    );
    assert_eq!(
        a[14], "verdict 3 ",
        "an IdP 5xx is an outage (LOGIN_OUTAGE; the host answers 503, retryable), never a declined \
         login (ruling 2026-10-27; 1.5.5 declined it): {text}"
    );
    assert_eq!(
        a[15], "verdict 4 ",
        "an identity token minted for another login's nonce fails the security check: {text}"
    );

    let anchor = "\"settings.ca_cert_pem\"";
    for (need, target_from, trust_from, target) in [
        (
            0,
            "\"settings.issuer\"",
            anchor,
            format!("Some({ISSUER:?})"),
        ),
        (1, "\"\"", anchor, "None".to_string()),
        (2, "\"\"", anchor, "None".to_string()),
        (
            3,
            "\"settings.issuer\"",
            "\"\"",
            format!("Some({ISSUER:?})"),
        ),
        (4, "\"\"", "\"\"", "None".to_string()),
        (5, "\"\"", "\"\"", "None".to_string()),
    ] {
        let trusted = trust_from == anchor;
        let class = if need % 3 == 2 {
            EGRESS_DEFAULT
        } else {
            EGRESS_OPEN_WEB
        };
        let want = format!(
            "need {need} direction={DIRECTION_OUTBOUND} class={class} transport=http \
             target_from={target_from} trust_from={trust_from} timeout_ms=10000 \
             target={target} trusted={trusted} answer=Ok(())"
        );
        assert!(a.contains(&want), "missing {want:?} in:\n{text}");
    }

    let sent = linked.idp.sent();

    let needs = rendering::read(&row.statement).expect("reads").needs.len() as u32;
    for idp in [&linked.idp, &dropped.idp] {
        assert_eq!(
            support::strays(&idp.sent(), needs, &support::declared_targets(0)),
            Vec::<String>::new(),
            "{text}"
        );
    }
    let discovery: Vec<_> = sent.iter().filter(|s| s.path == DISCOVERY_PATH).collect();
    let jwks: Vec<_> = sent.iter().filter(|s| s.path == "/keys").collect();
    assert_eq!(discovery.len(), 1, "{text}");
    assert_eq!(
        (discovery[0].need, discovery[0].method.as_str()),
        (0, "GET")
    );
    assert_eq!(
        discovery[0].target,
        format!("https://idp.conformance.example{DISCOVERY_PATH}")
    );
    assert_eq!(jwks.len(), 1, "{text}");
    assert_eq!((jwks[0].need, jwks[0].method.as_str()), (1, "GET"));
    let posts = linked.idp.sent_to("/token");
    assert_eq!(
        posts.len(),
        6,
        "one per code; code 2's short re-call made none (`exchanges 1`): {text}"
    );
    assert!(posts.iter().all(|p| p.need == 2 && p.method == "POST"));
    for field in [
        "grant_type=authorization_code",
        "code=code-1",
        "code_verifier=the-verifier",
        &format!("client_secret={CLIENT_SECRET}"),
    ] {
        assert!(
            posts[0].body.contains(field),
            "the exchange sends {field}: {:?}",
            posts[0].body
        );
    }
    assert!(
        linked.idp.pended() as usize >= sent.len(),
        "every request crossed PENDING and was resumed on its wake: {text}"
    );

    let other = bind(
        &Arm::Dropped {
            lib: &lib,
            stated: &stated,
        },
        &Idp::secure_carrier(&key),
    );
    assert_ne!(
        transcript(&other, &config("api://someone-else"), &t),
        a,
        "a different config must not read as the same module"
    );

    let public = bind(
        &Arm::Dropped {
            lib: &lib,
            stated: &stated,
        },
        &Idp::secure_carrier(&key),
    );
    let p = transcript(&public, &config_public(AUDIENCE), &t);
    let answers = a
        .iter()
        .position(|l| l.starts_with("need "))
        .expect("needs");
    assert_eq!(
        p[..answers],
        a[..answers],
        "the public-roots module answers as the anchored one:\n{}",
        p.join("\n")
    );
    for need in 0..3 {
        assert!(
            p.iter().any(|l| l.starts_with(&format!("need {need} "))
                && l.ends_with("trusted=false answer=Err(Refused)")),
            "need {need} (trusting an absent ca_cert_pem) is refused:\n{}",
            p.join("\n")
        );
    }
    assert!(!public.idp.sent().is_empty());
    assert_eq!(
        support::strays(
            &public.idp.sent(),
            needs,
            &support::declared_targets(busbar_auth_oidc::fetch::PUBLIC)
        ),
        Vec::<String>::new(),
        "every request rides a public-roots need:\n{}",
        p.join("\n")
    );

    let arm = Arm::Dropped {
        lib: &lib,
        stated: &stated,
    };
    match bind_as::<Secret>(&arm, &Idp::secure_carrier(&key)).1 {
        Err(LoadError::ManifestKind { .. }) => {}
        Err(e) => panic!("an auth door stated as secret must be refused at its kind: {e}"),
        Ok(_) => panic!("an auth door stated as secret must not load"),
    }

    let mut tampered = stated.clone();
    let version = env!("CARGO_PKG_VERSION").as_bytes();
    let at = tampered
        .windows(version.len())
        .position(|bytes| bytes == version)
        .expect("the Statement carries the package version");
    tampered[at] = if tampered[at] == b'9' { b'8' } else { b'9' };
    busbar_contract::abi::mechanism::rendering::read(&tampered)
        .expect("the different Statement still has a valid rendering");
    assert_ne!(tampered, stated);
    let arm = Arm::Dropped {
        lib: &lib,
        stated: &tampered,
    };
    match bind_as::<Auth>(&arm, &Idp::secure_carrier(&key)).1 {
        Err(LoadError::StatementMismatch) => {}
        Err(e) => panic!("a Statement that is not the door's must be refused as one: {e}"),
        Ok(_) => panic!("a Statement that is not the door's must not load"),
    }
}

#[test]
fn red_an_unreachable_issuer_and_a_ticketless_call_fail_verify_in_1_5_5_s_words() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let token = key.sign(&claims(AUDIENCE));
    let lib = cdylib();
    let stated = row().statement;
    let url =
        busbar_auth_oidc::fetch::shown(&format!("https://idp.conformance.example{DISCOVERY_PATH}"));
    let mut seen = Vec::new();
    for arm in [
        Arm::Linked,
        Arm::Dropped {
            lib: &lib,
            stated: &stated,
        },
    ] {
        let idp = Idp::secure_carrier(&key);
        idp.answer(DISCOVERY_PATH, 503, "{}");
        let b = bind(&arm, &idp);
        open(&b.plugin, &config(AUDIENCE), None).expect("opens: nothing is fetched at open");

        let ticketless = verify_ticketless(&b.plugin, Some(&token));
        assert!(ticketless.starts_with("Refused"), "{ticketless}");
        assert!(
            idp.sent().is_empty(),
            "a ticketless call asks the IdP nothing"
        );

        let refused = b.verify(Some(&token), None);
        assert_eq!(
            refused,
            format!(
                "Failed OIDC discovery fetch failed ({url}): {url} returned HTTP 503 Service \
                 Unavailable; configure the required endpoints explicitly"
            )
        );
        seen.push((ticketless, refused));
    }
    assert_eq!(seen[0], seen[1], "both doors alike");
}

#[test]
fn concurrent_cold_verifies_make_one_discovery_and_one_jwks_request() {
    cold_verifies(true);
}

/// The same two cold verifies submitted back to back, neither waiting for the other to pend.
#[test]
fn simultaneous_cold_verifies_make_one_discovery_and_one_jwks_request() {
    cold_verifies(false);
}

/// Two cold verifies on one instance; the second submitted once the first pended (`staggered`) or
fn cold_verifies(staggered: bool) {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let token = key.sign(&claims(AUDIENCE));
    let idp = Idp::secure_carrier(&key);
    idp.pend_for(Duration::from_millis(300));
    let b = bind(&Arm::Linked, &idp);
    open(&b.plugin, &config(AUDIENCE), None).expect("opens");

    let mut bufs: Vec<(Vec<u8>, Vec<Span>)> = (0..2)
        .map(|_| {
            (
                vec![0_u8; IDENTITY_BUF_BYTES],
                vec![z::<Span>(); IDENTITY_GROUPS as usize],
            )
        })
        .collect();

    let mut replies = Vec::new();
    for (i, (bytes, groups)) in bufs.iter_mut().enumerate() {
        if i == 1 && staggered {
            let until = std::time::Instant::now() + Duration::from_secs(10);
            while idp.pended() == 0 {
                assert!(
                    std::time::Instant::now() < until,
                    "the first verify never pended"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        let ticket = b.dispatcher.mint(0).expect("a ticket");
        let mut out: IdentifyOut = z();
        out.head = out_head();
        let reply = b.dispatcher.submit(
            &b.plugin,
            ticket,
            slot::VERIFY,
            Frame::new(verify_in(Some(&token), identity_buf(bytes, groups)), out),
            busbar_contract::abi::mechanism::call::DeadlineClass::Call,
            now_ns() + 20_000_000_000,
        );
        replies.push((ticket, reply));
    }
    let tickets: Vec<_> = replies.iter().map(|(t, _)| *t).collect();
    for (ticket, reply) in replies {
        let done = reply
            .wait(Duration::from_secs(30))
            .expect("the op completes");
        assert_eq!(done.outcome, Outcome::Ready, "{:?}", done.error);
        assert_eq!(done.frame.expect("the frame").out.verdict, 1, "identified");
        b.dispatcher.recycle(ticket);
    }
    let seen = format!(
        "tickets {tickets:?}; requests {:?}; first reads (conn, ticket) {:?}",
        idp.sent(),
        idp.woken()
    );
    assert_eq!(idp.sent_to(DISCOVERY_PATH).len(), 1, "{seen}");
    assert_eq!(idp.sent_to("/keys").len(), 1, "{seen}");
}

/// A discovery reply far past the 1 MiB cap names the document and stops reading at the cap,
#[test]
fn red_an_oversized_reply_is_cut_off_at_the_cap_not_buffered_whole() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let token = key.sign(&claims(AUDIENCE));
    let idp = Idp::secure_carrier(&key);
    let huge = "x".repeat(4 * 1024 * 1024);
    idp.answer(DISCOVERY_PATH, 200, &huge);
    let b = bind(&Arm::Linked, &idp);
    open(&b.plugin, &config(AUDIENCE), None).expect("opens");

    let refused = b.verify(Some(&token), None);
    let url =
        busbar_auth_oidc::fetch::shown(&format!("https://idp.conformance.example{DISCOVERY_PATH}"));
    assert_eq!(
        refused,
        format!(
            "Failed OIDC discovery fetch failed ({url}): {url} discovery body exceeds the 1048576-byte \
             cap; configure the required endpoints explicitly"
        )
    );
    assert!(
        idp.served() < 2 * 1024 * 1024,
        "the plugin read {} bytes of a reply capped at 1 MiB",
        idp.served()
    );
}

#[test]
fn a_non_utf8_discovery_reply_names_the_document_without_echoing_the_body() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let token = key.sign(&claims(AUDIENCE));
    let idp = Idp::secure_carrier(&key);
    idp.answer_bytes(DISCOVERY_PATH, 200, b"private-document-contents\xff");
    let b = bind(&Arm::Linked, &idp);
    open(&b.plugin, &config(AUDIENCE), None).expect("opens");

    let refused = b.verify(Some(&token), None);
    assert!(refused.contains("discovery body is not UTF-8"), "{refused}");
    assert!(!refused.contains("JWKS body"), "{refused}");
    assert!(!refused.contains("private-document-contents"), "{refused}");
    assert_eq!(idp.sent_to(DISCOVERY_PATH).len(), 1);
}

/// THE STATUS IS JUDGED BEFORE THE BODY, as 1.5.5 judged it: a non-2xx discovery reply with a body
#[test]
fn red_an_oversized_error_reply_names_its_status_and_is_cut_off_at_the_cap() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let token = key.sign(&claims(AUDIENCE));
    let idp = Idp::secure_carrier(&key);
    let huge = "x".repeat(4 * 1024 * 1024);
    idp.answer(DISCOVERY_PATH, 500, &huge);
    let b = bind(&Arm::Linked, &idp);
    open(&b.plugin, &config(AUDIENCE), None).expect("opens");

    let refused = b.verify(Some(&token), None);
    let url =
        busbar_auth_oidc::fetch::shown(&format!("https://idp.conformance.example{DISCOVERY_PATH}"));
    assert_eq!(
        refused,
        format!(
            "Failed OIDC discovery fetch failed ({url}): {url} returned HTTP 500 Internal Server \
             Error; configure the required endpoints explicitly"
        )
    );
    assert!(
        idp.served() < 2 * 1024 * 1024,
        "the plugin read {} bytes of a reply capped at 1 MiB",
        idp.served()
    );
}

#[test]
fn a_login_whose_key_set_cannot_be_had_is_an_outage_not_declined() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let idp = Idp::secure_carrier(&key);
    idp.answer(DISCOVERY_PATH, 503, "{}");
    let id_token = serde_json::json!({ "id_token": key.sign(&claims(AUDIENCE)) }).to_string();
    idp.answer("/token", 200, &id_token);
    let b = bind(&Arm::Linked, &idp);
    let mut cfg: serde_json::Value = serde_json::from_str(&config(AUDIENCE)).unwrap();
    cfg["token_endpoint"] = serde_json::json!(support::TOKEN_URL);
    open(&b.plugin, &cfg.to_string(), Some(CLIENT_SECRET)).expect("opens");

    let answer = b.complete("code-1", ("st", NONCE), REDIRECT, "the-verifier", None);
    assert_eq!(answer.trim_end(), format!("verdict {LOGIN_OUTAGE}"));
    assert_ne!(answer.trim_end(), format!("verdict {LOGIN_BAD_CREDENTIAL}"));
    assert_eq!(idp.sent_to("/token").len(), 1, "the code was redeemed");
    assert_eq!(
        idp.sent_to(DISCOVERY_PATH).len(),
        1,
        "the key set's URL was asked for"
    );
}

#[test]
fn a_waiter_is_woken_by_the_fetch_it_waits_on_not_a_polling_timer() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let token = key.sign(&claims(AUDIENCE));
    let idp = Idp::secure_carrier(&key);
    idp.pend_for(Duration::from_millis(400));
    let b = bind(&Arm::Linked, &idp);
    open(&b.plugin, &config(AUDIENCE), None).expect("opens");
    let reads = support::clock_reads();

    let mut bufs: Vec<(Vec<u8>, Vec<Span>)> = (0..2)
        .map(|_| {
            (
                vec![0_u8; IDENTITY_BUF_BYTES],
                vec![z::<Span>(); IDENTITY_GROUPS as usize],
            )
        })
        .collect();
    let mut replies = Vec::new();
    for (i, (bytes, groups)) in bufs.iter_mut().enumerate() {
        if i == 1 {
            let until = std::time::Instant::now() + Duration::from_secs(10);
            while idp.pended() == 0 {
                assert!(
                    std::time::Instant::now() < until,
                    "the first verify never pended"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        let ticket = b.dispatcher.mint(0).expect("a ticket");
        let mut out: IdentifyOut = z();
        out.head = out_head();
        let reply = b.dispatcher.submit(
            &b.plugin,
            ticket,
            slot::VERIFY,
            Frame::new(verify_in(Some(&token), identity_buf(bytes, groups)), out),
            busbar_contract::abi::mechanism::call::DeadlineClass::Call,
            now_ns() + 20_000_000_000,
        );
        replies.push((ticket, reply));
    }
    for (ticket, reply) in replies {
        let done = reply
            .wait(Duration::from_secs(30))
            .expect("the op completes");
        assert_eq!(done.outcome, Outcome::Ready, "{:?}", done.error);
        assert_eq!(done.frame.expect("the frame").out.verdict, 1, "identified");
        b.dispatcher.recycle(ticket);
    }
    assert_eq!(idp.sent_to(DISCOVERY_PATH).len(), 1);
    assert_eq!(idp.sent_to("/keys").len(), 1);
    let waited = support::clock_reads() - reads;
    assert!(
        (1..=4).contains(&waited),
        "the waiter armed its backstop once per wait (discovery, JWKS), not a timer every 25 ms: \
         {waited} clock reads"
    );
}

#[test]
fn a_tick_refreshes_the_key_set_ahead_of_its_ttl() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let token = key.sign(&claims(AUDIENCE));
    let idp = Idp::secure_carrier(&key);
    let b = bind(&Arm::Linked, &idp);
    let mut cfg: serde_json::Value = serde_json::from_str(&config(AUDIENCE)).unwrap();
    cfg["jwks_ttl_secs"] = serde_json::json!(3);
    cfg["jwks_min_refetch_secs"] = serde_json::json!(1);
    open(&b.plugin, &cfg.to_string(), None).expect("opens");
    assert!(b.verify(Some(&token), None).starts_with("verdict 1 "));
    assert_eq!(
        idp.sent_to("/keys").len(),
        1,
        "the first verify fetches the key set"
    );

    let driver = b.dispatcher.driver(&b.plugin, 0).expect("a driver ticket");
    let tick = |at: u64| {
        let done = b
            .dispatcher
            .tick(&b.plugin, driver, at)
            .wait(Duration::from_secs(30))
            .expect("the tick completes");
        assert!(
            matches!(done.outcome, Outcome::Ready | Outcome::Pending),
            "{:?}",
            done.outcome
        );
        done.frame.expect("the frame").out.next_tick_ns
    };
    let at = now_ns();
    assert_eq!(tick(at), at + 1_000_000_000, "the next tick, one period on");
    assert_eq!(idp.sent_to("/keys").len(), 1, "not due: nothing fetched");

    std::thread::sleep(Duration::from_millis(2100));
    tick(now_ns());
    let until = std::time::Instant::now() + Duration::from_secs(10);
    while idp.sent_to("/keys").len() < 2 {
        assert!(
            std::time::Instant::now() < until,
            "the tick never refreshed the key set: {:?}",
            idp.sent()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let refetch = idp.sent_to("/keys").pop().expect("the refresh");
    assert_eq!(refetch.need, 1, "on the JWKS need (anchored set)");
}

#[test]
fn red_an_undeclared_need_or_a_foreign_target_is_caught() {
    let sent = |need: u32, target: &str| support::Sent {
        conn: 1,
        need,
        target: target.to_string(),
        method: "GET".into(),
        path: "/".into(),
        body: String::new(),
    };
    let allowed = support::declared_targets(0);
    assert_eq!(
        support::strays(
            &[
                sent(1, support::JWKS_URL),
                sent(7, support::JWKS_URL),
                sent(1, "https://attacker.example/keys"),
                sent(2, support::JWKS_URL),
            ],
            3,
            &allowed,
        ),
        vec![
            format!("undeclared need 7 -> {}", support::JWKS_URL),
            "need 1 to a foreign target https://attacker.example/keys".to_string(),
            format!("need 2 to a foreign target {}", support::JWKS_URL),
        ]
    );
    assert!(support::strays(
        &[sent(0, &allowed[0].1), sent(2, support::TOKEN_URL)],
        3,
        &allowed
    )
    .is_empty());
}

#[test]
fn red_the_statement_declares_six_outbound_http_needs_in_their_classes() {
    let row = row();
    let read = rendering::read(&row.statement).expect("the rendering reads back");
    let needs: Vec<_> = read
        .needs
        .iter()
        .map(|n| {
            (
                n.direction,
                n.egress_class,
                n.transport.as_str(),
                n.auth.as_str(),
                n.target_from.as_str(),
                n.trust_from.as_str(),
            )
        })
        .collect();
    let need = |class, target_from, trust_from| {
        (
            DIRECTION_OUTBOUND,
            class,
            "http",
            "",
            target_from,
            trust_from,
        )
    };
    let families: Vec<_> = read.families.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        families,
        [METRIC_CACHE_FLUSHED],
        "the one family: the verdict cache's flush count"
    );
    let anchor = "settings.ca_cert_pem";
    assert_eq!(
        needs,
        vec![
            need(EGRESS_OPEN_WEB, "settings.issuer", anchor),
            need(EGRESS_OPEN_WEB, "", anchor),
            need(EGRESS_DEFAULT, "", anchor),
            need(EGRESS_OPEN_WEB, "settings.issuer", ""),
            need(EGRESS_OPEN_WEB, "", ""),
            need(EGRESS_DEFAULT, "", ""),
        ],
        "{read:?}"
    );
    // A provider's Retry-After crosses to the plugin (the login outage's hint): under KEEP_NAMED
    // the kernel copies only the named fields, so every need names it, and nothing else.
    for n in &read.needs {
        assert_eq!(
            n.keep_mode,
            busbar_contract::abi::host::conn::connector::KEEP_NAMED
        );
        assert_eq!(n.keep_response_headers, ["retry-after"], "{n:?}");
    }
    let packed = busbar_plugin_loader::dispatch::rendering_of_library(
        &support::cdylib_path().expect("the cdylib is built"),
    )
    .expect("the cdylib loads");
    assert_eq!(packed.as_deref(), Some(&row.statement[..]));
}

#[test]
fn a_bearer_that_is_not_utf8_passes_with_a_decision_and_its_line_named() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let lib = cdylib();
    let stated = row().statement;
    for arm in [
        Arm::Linked,
        Arm::Dropped {
            lib: &lib,
            stated: &stated,
        },
    ] {
        let idp = Idp::secure_carrier(&key);
        let b = bind(&arm, &idp);
        open(&b.plugin, &config(AUDIENCE), None).expect("opens");
        let (verdict, decision, strips) =
            verify_ticketless_raw(&b.plugin, b"eyJ\xff\xfe.not-text").expect("answered at once");
        assert_eq!(verdict, busbar_contract::abi::auth::VERDICT_PASS);
        assert_eq!(decision, busbar_contract::abi::auth::DECISION_CONTINUE);
        assert!(strips >= 1, "the credential line is named for stripping");
        assert!(idp.sent().is_empty(), "nothing is fetched for it");
    }
}

#[test]
fn an_identity_carries_the_credential_it_was_verified_from() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let token = key.sign(&claims(AUDIENCE));
    let idp = Idp::secure_carrier(&key);
    let b = bind(&Arm::Linked, &idp);
    open(&b.plugin, &config(AUDIENCE), None).expect("opens");
    let (mut bytes, mut groups) = (
        vec![0_u8; IDENTITY_BUF_BYTES],
        vec![z::<Span>(); IDENTITY_GROUPS as usize],
    );
    let ticket = b.dispatcher.mint(0).expect("a ticket");
    let mut out: IdentifyOut = z();
    out.head = out_head();
    let done = b
        .dispatcher
        .submit(
            &b.plugin,
            ticket,
            slot::VERIFY,
            Frame::new(
                verify_in(Some(&token), identity_buf(&mut bytes, &mut groups)),
                out,
            ),
            busbar_contract::abi::mechanism::call::DeadlineClass::Call,
            now_ns() + 20_000_000_000,
        )
        .wait(Duration::from_secs(30))
        .expect("the op completes");
    b.dispatcher.recycle(ticket);
    assert_eq!(done.outcome, Outcome::Ready, "{:?}", done.error);
    let out = done.frame.expect("the frame").out;
    assert_eq!(out.verdict, 1, "identified");
    let held = out.identity.credential;
    assert_eq!(
        &bytes[held.offset as usize..(held.offset as usize + held.len as usize)],
        token.as_bytes(),
        "the verified credential rides the identity"
    );
}

#[test]
fn a_token_s_expiry_is_judged_at_the_request_s_timestamp() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let token = key.sign(&claims(AUDIENCE));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for (at, expected) in [
        (now + 7200, "verdict 2 "),
        (0, "Failed "),
        (now, "verdict 1 "),
    ] {
        let idp = Idp::secure_carrier(&key);
        let b = bind(&Arm::Linked, &idp);
        open(&b.plugin, &config(AUDIENCE), None).expect("opens");
        let verdict = b.verify_at(Some(&token), at);
        assert!(verdict.starts_with(expected), "at {at}: {verdict}");
        if at == 0 {
            assert!(
                verdict.contains("clock"),
                "a zero timestamp fails closed naming the clock: {verdict}"
            );
        }
    }
}

/// A `verify` of `token` submitted on its own ticket and left in flight; the closure waits for
fn verify_in_flight<'b>(b: &'b Bound, token: &str) -> impl FnOnce() -> String + 'b {
    let bytes: &'static mut [u8] = Box::leak(vec![0_u8; IDENTITY_BUF_BYTES].into_boxed_slice());
    let groups: &'static mut [Span] =
        Box::leak(vec![z::<Span>(); IDENTITY_GROUPS as usize].into_boxed_slice());
    let ticket = b.dispatcher.mint(0).expect("a ticket");
    let mut out: IdentifyOut = z();
    out.head = out_head();
    let reply = b.dispatcher.submit(
        &b.plugin,
        ticket,
        slot::VERIFY,
        Frame::new(verify_in(Some(token), identity_buf(bytes, groups)), out),
        busbar_contract::abi::mechanism::call::DeadlineClass::Call,
        now_ns() + 20_000_000_000,
    );
    move || {
        let done = reply
            .wait(Duration::from_secs(30))
            .expect("the op completes");
        b.dispatcher.recycle(ticket);
        match (done.outcome, done.frame) {
            (Outcome::Ready, Some(f)) => format!("verdict {}", f.out.verdict),
            (other, _) => format!("{other:?}"),
        }
    }
}

/// Wait until the IdP has pended `n` reads in all.
fn until_pended(idp: &Idp, n: u32) {
    let until = std::time::Instant::now() + Duration::from_secs(10);
    while idp.pended() < n {
        assert!(
            std::time::Instant::now() < until,
            "never pended: {:?}",
            idp.sent()
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Replace the settings and secret through the existing lifecycle Door while another op is
fn refresh_pending(b: &Bound, settings: &str) {
    use busbar_contract::abi::mechanism::call::{Blob, BLOB_JSON, BLOB_OCTETS};
    use busbar_contract::abi::mechanism::lifecycle::{slot as life, RefreshIn};
    let secret = b"replacement-client-secret";
    let secrets = [Blob {
        ptr: secret.as_ptr(),
        len: secret.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }];
    let mut input: RefreshIn = z();
    input.head = busbar_plugin_loader::dispatch::in_head();
    input.generation = 2;
    input.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    input.secrets = secrets.as_ptr();
    input.secrets_len = secrets.len();
    let done = b
        .plugin
        .call(life::REFRESH, &mut Frame::new(input, out_head()));
    assert_eq!(done.outcome, Outcome::Ready, "refresh: {:?}", done.error);
}

fn until_read_held(b: &Bound) {
    let until = std::time::Instant::now() + Duration::from_secs(10);
    while !b.idp.read_is_held() {
        assert!(
            std::time::Instant::now() < until,
            "reply never held: {:?}",
            b.idp.sent()
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    // The connector publishes the held read before returning Pending. The real caller uses
    // worker 0; its retirement barrier runs after that crossing and its host-call guards retire.
    // The held operation stays pending, so refresh now exercises a parked original login.
    let barrier = b.dispatcher.mint(0).expect("a worker-0 barrier ticket");
    let retired = b.dispatcher.retirement_barrier(
        barrier,
        until.saturating_duration_since(std::time::Instant::now()),
    );
    b.dispatcher.recycle(barrier);
    assert!(
        retired,
        "the held read crossing must return Pending within 10s"
    );
    assert!(b.idp.read_is_held(), "the original login remains held");
}

/// Change issuer, audience, client, endpoints, secret and CA selection together. Old operations
fn replacement_config() -> String {
    serde_json::json!({
        "issuer": "https://replacement.conformance.example",
        "audience": "api://replacement",
        "client_id": "replacement-client",
        "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nreplacement\n-----END CERTIFICATE-----\n",
        "jwks_url": "https://replacement.conformance.example/new-keys",
        "authorization_endpoint": "https://replacement.conformance.example/authorize",
        "token_endpoint": "https://replacement.conformance.example/new-token",
        "role_claim": "roles",
    })
    .to_string()
}

#[test]
fn pending_verify_and_begin_keep_their_opened_configuration_across_refresh() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    for begin in [false, true] {
        let idp = Idp::secure_carrier(&key);
        let b = bind(&Arm::Linked, &idp);
        let mut cfg: serde_json::Value = serde_json::from_str(&config_public(AUDIENCE)).unwrap();
        cfg["client_id"] = serde_json::json!("original-client");
        open(&b.plugin, &cfg.to_string(), Some(CLIENT_SECRET)).expect("opens");
        let token = key.sign(&claims(AUDIENCE));
        let answer = std::thread::scope(|scope| {
            let held = idp.hold_reads(DISCOVERY_PATH);
            let call = scope.spawn(|| {
                if begin {
                    b.begin(REDIRECT, "state", "challenge", NONCE)
                } else {
                    b.verify(Some(&token), None)
                }
            });
            until_read_held(&b);
            refresh_pending(&b, &replacement_config());
            drop(held);
            call.join().expect("pending operation completes")
        });
        if begin {
            assert!(
                answer.contains("idp.conformance.example/authorize"),
                "{answer}"
            );
            assert!(answer.contains("client_id=original-client"), "{answer}");
        } else {
            assert!(answer.starts_with("verdict 1 "), "{answer}");
            assert_eq!(
                idp.sent_to("/keys")[0].need,
                4,
                "original public-roots JWKS need"
            );
        }
        assert_eq!(
            idp.sent_to(DISCOVERY_PATH).len(),
            1,
            "no replacement discovery"
        );
        assert!(
            b.verify(Some(&token), None).starts_with("verdict 3 "),
            "fresh verify uses new issuer"
        );
        let fresh = b.begin(REDIRECT, "fresh", "challenge", NONCE);
        assert!(
            fresh.contains("replacement.conformance.example/authorize"),
            "{fresh}"
        );
        assert!(fresh.contains("client_id=replacement-client"), "{fresh}");
        idp.answer("/new-keys", 200, key.jwks());
        let mut new_claims = claims("api://replacement");
        new_claims["iss"] = serde_json::json!("https://replacement.conformance.example");
        assert!(b
            .verify(Some(&key.sign(&new_claims)), None)
            .starts_with("verdict 1 "));
        assert_eq!(
            idp.sent_to("/new-keys")[0].need,
            1,
            "fresh verify uses its CA"
        );
    }
}

#[test]
fn pending_complete_keeps_its_client_and_token_answer_across_refresh() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);

    for path in ["/token", "/keys"] {
        let idp = Idp::secure_carrier(&key);
        let b = bind(&Arm::Linked, &idp);
        let mut cfg: serde_json::Value = serde_json::from_str(&config_public(AUDIENCE)).unwrap();
        cfg["client_id"] = serde_json::json!("original-client");
        open(&b.plugin, &cfg.to_string(), Some(CLIENT_SECRET)).expect("opens");
        idp.answer(
            "/token",
            200,
            &serde_json::json!({"id_token": key.sign(&claims("original-client"))}).to_string(),
        );
        let answer = std::thread::scope(|scope| {
            let held = idp.hold_reads(path);
            let call =
                scope.spawn(|| b.complete("code", ("state", NONCE), REDIRECT, "verifier", None));
            until_read_held(&b);
            refresh_pending(&b, &replacement_config());
            drop(held);
            call.join().expect("pending login completes")
        });
        assert!(answer.starts_with("verdict 1 "), "held {path}: {answer}");
        let posts = idp.sent_to("/token");
        assert_eq!(posts.len(), 1, "the code is exchanged once");
        assert!(posts[0].body.contains("client_id=original-client"));
        assert!(posts[0]
            .body
            .contains("client_secret=conformance-client-secret"));
        assert_eq!(posts[0].need, 5, "original public-roots token need");
        assert_eq!(
            idp.sent_to("/keys")[0].need,
            4,
            "original public-roots JWKS need"
        );
        assert!(idp.sent_to("/new-token").is_empty());
        assert!(idp.sent_to("/new-keys").is_empty());
        let fresh = b.begin(REDIRECT, "fresh", "challenge", NONCE);
        assert!(fresh.contains("client_id=replacement-client"), "{fresh}");
        let mut new_claims = claims("replacement-client");
        new_claims["iss"] = serde_json::json!("https://replacement.conformance.example");
        idp.answer("/new-keys", 200, key.jwks());
        idp.answer(
            "/new-token",
            200,
            &serde_json::json!({"id_token": key.sign(&new_claims)}).to_string(),
        );
        let fresh = b.complete("new-code", ("fresh", NONCE), REDIRECT, "verifier", None);
        assert!(fresh.starts_with("verdict 1 "), "{fresh}");
        let fresh_posts = idp.sent_to("/new-token");
        assert_eq!(fresh_posts.len(), 1);
        assert!(fresh_posts[0].body.contains("client_id=replacement-client"));
        assert!(fresh_posts[0]
            .body
            .contains("client_secret=replacement-client-secret"));
        assert_eq!(fresh_posts[0].need, 2, "fresh login uses its CA");
    }
}

#[test]
fn a_verify_meeting_the_verdict_cache_on_re_entry_still_lands_its_fetch() {
    let _one = support::serial();
    let old = Issuer::start(UNUSED_ISSUER, KID);
    let new = Issuer::start(UNUSED_ISSUER, "rotated-kid");
    let idp = Idp::secure_carrier(&old);
    let b = bind(&Arm::Linked, &idp);
    let mut cfg: serde_json::Value = serde_json::from_str(&config(AUDIENCE)).unwrap();
    cfg["jwks_ttl_secs"] = serde_json::json!(1);
    cfg["jwks_min_refetch_secs"] = serde_json::json!(2);
    open(&b.plugin, &cfg.to_string(), None).expect("opens");
    assert!(b
        .verify(Some(&old.sign(&claims(AUDIENCE))), None)
        .starts_with("verdict 1 "));

    std::thread::sleep(Duration::from_millis(2100));
    let keys = |i: &Issuer| {
        serde_json::from_str::<serde_json::Value>(i.jwks()).unwrap()["keys"][0].clone()
    };
    let both = serde_json::json!({ "keys": [keys(&old), keys(&new)] }).to_string();
    idp.answer("/keys", 200, &both);
    idp.pend_for(Duration::from_millis(800));
    let pended = idp.pended();

    let mut c = claims(AUDIENCE);
    c["sub"] = serde_json::json!("cached-meanwhile");
    let token = old.sign(&c);
    let a = verify_in_flight(&b, &token);
    until_pended(&idp, pended + 1);

    assert!(b.verify(Some(&token), None).starts_with("verdict 1 "));
    assert_eq!(a(), "verdict 1");

    assert!(
        b.verify(Some(&new.sign(&claims(AUDIENCE))), None)
            .starts_with("verdict 1 "),
        "the refresh the first verify claimed landed the rotated key"
    );
    assert_eq!(idp.sent_to("/keys").len(), 2, "{:?}", idp.sent());
}

#[test]
fn a_tick_during_the_last_tick_s_fetch_does_not_fetch_again() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let idp = Idp::secure_carrier(&key);
    let b = bind(&Arm::Linked, &idp);
    let mut cfg: serde_json::Value = serde_json::from_str(&config(AUDIENCE)).unwrap();
    cfg["jwks_ttl_secs"] = serde_json::json!(3);
    cfg["jwks_min_refetch_secs"] = serde_json::json!(1);
    open(&b.plugin, &cfg.to_string(), None).expect("opens");
    assert!(b
        .verify(Some(&key.sign(&claims(AUDIENCE))), None)
        .starts_with("verdict 1 "));
    assert_eq!(idp.sent_to("/keys").len(), 1);

    let driver = b.dispatcher.driver(&b.plugin, 0).expect("a driver ticket");
    let tick = || {
        b.dispatcher
            .tick(&b.plugin, driver, now_ns())
            .wait(Duration::from_secs(30))
            .expect("the tick completes")
            .outcome
    };
    std::thread::sleep(Duration::from_millis(2100));
    idp.pend_for(Duration::from_millis(1500));
    assert_eq!(tick(), Outcome::Pending, "the refresh is in flight");
    assert_eq!(idp.sent_to("/keys").len(), 2);
    tick();
    std::thread::sleep(Duration::from_millis(2000));
    assert_eq!(
        idp.sent_to("/keys").len(),
        2,
        "one exchange for the refresh: {:?}",
        idp.sent()
    );
}

#[test]
fn ready_waits_on_another_op_s_discovery_and_a_failure_refuses_the_boot() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let idp = Idp::secure_carrier(&key);
    idp.answer(DISCOVERY_PATH, 503, "{}");
    idp.pend_for(Duration::from_millis(500));
    let b = bind(&Arm::Linked, &idp);
    open(&b.plugin, &config(AUDIENCE), None).expect("opens");
    let token = key.sign(&claims(AUDIENCE));
    let a = verify_in_flight(&b, &token);
    until_pended(&idp, 1);
    let readied = b.plugin.ready(&b.dispatcher, Duration::from_secs(10));
    assert!(
        readied.as_ref().is_err_and(|e| e.contains("503")),
        "the boot is refused with the discovery's failure: {readied:?}"
    );
    assert!(a().starts_with("Failed"));
    assert_eq!(
        idp.sent_to(DISCOVERY_PATH).len(),
        1,
        "ready made no fetch of its own"
    );
}

#[test]
fn ready_audits_refused_warmup_destinations_without_changing_best_effort_boot() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let idp = Idp::secure_carrier(&key);
    let b = bind(&Arm::Linked, &idp);
    open(&b.plugin, &config(AUDIENCE), None).expect("opens");
    idp.refuse(1);
    for _ in 0..2 {
        b.plugin
            .ready(&b.dispatcher, Duration::from_secs(10))
            .expect("JWKS warmup remains best effort");
    }
    assert_eq!(
        idp.diags()
            .iter()
            .filter(|line| line.starts_with("BUSBAR-4031 2 "))
            .count(),
        1,
        "the existing READY envelope audits the destination once"
    );
    assert!(
        idp.sent_to("/keys").is_empty(),
        "refused before sending a request"
    );
}

#[test]
fn a_plaintext_loopback_jwks_url_is_refused_by_both_doors() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let lib = cdylib();
    let stated = row().statement;
    for arm in [
        Arm::Linked,
        Arm::Dropped {
            lib: &lib,
            stated: &stated,
        },
    ] {
        let idp = Idp::secure_carrier(&key);
        let b = bind(&arm, &idp);
        let mut cfg: serde_json::Value = serde_json::from_str(&config(AUDIENCE)).unwrap();
        cfg["jwks_url"] = serde_json::json!("http://127.0.0.1/keys");
        let error = open(&b.plugin, &cfg.to_string(), None).expect_err("plaintext JWKS is refused");
        assert!(error.contains("settings.jwks_url:"), "{error}");
        assert!(error.contains("https"), "{error}");
        assert!(idp.sent_to("/keys").is_empty(), "no fetch before refusal");
    }
}

#[test]
fn a_login_id_token_s_expiry_is_judged_at_the_host_clock() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut expired = claims(AUDIENCE);
    expired["exp"] = serde_json::json!(now - 7200);
    let mut early = claims(AUDIENCE);
    early["nbf"] = serde_json::json!(now + 7200);
    let mut past = claims(AUDIENCE);
    past["exp"] = serde_json::json!(now - 1800);
    past["nbf"] = serde_json::json!(now - 7200);
    let hour = 3600 * 1_000_000_000_u64;
    let process_wall = u64::try_from(now).unwrap() * 1_000_000_000;
    for (what, c, host_wall, identified) in [
        ("expired", expired, None, false),
        ("not yet valid", early, None, false),
        ("fresh", claims(AUDIENCE), None, true),
        (
            "fresh at the process clock, expired at the host's",
            claims(AUDIENCE),
            Some(process_wall + 2 * hour),
            false,
        ),
        (
            "expired at the process clock, fresh at the host's",
            past,
            Some(process_wall - hour),
            true,
        ),
    ] {
        let _wall = host_wall.map(support::HeldClock::wall_at);
        let idp = Idp::secure_carrier(&key);
        let body = serde_json::json!({ "id_token": key.sign(&c) }).to_string();
        idp.answer("/token", 200, &body);
        let b = bind(&Arm::Linked, &idp);
        open(&b.plugin, &config(AUDIENCE), Some(CLIENT_SECRET)).expect("opens");
        let answer = b.complete("code-1", ("st", NONCE), REDIRECT, "the-verifier", None);
        if identified {
            assert!(answer.starts_with("verdict 1 "), "{what}: {answer}");
        } else {
            assert_eq!(
                answer.trim_end(),
                format!("verdict {LOGIN_BAD_CREDENTIAL}"),
                "{what}"
            );
        }
    }
}

#[test]
fn a_short_login_answer_uses_the_host_monotonic_expiry_boundary() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    const TTL_NS: u64 = 600_000_000_000;
    for (elapsed, retained) in [
        (0, true),
        (TTL_NS - 1, true),
        (TTL_NS, true),
        (TTL_NS + 1, false),
    ] {
        let at = busbar_plugin_loader::dispatch::now_ns();
        let _clock = support::HeldClock::at(at);
        let idp = Idp::secure_carrier(&key);
        let body = serde_json::json!({ "id_token": key.sign(&claims(AUDIENCE)) }).to_string();
        idp.answer("/token", 200, &body);
        let b = bind(&Arm::Linked, &idp);
        open(&b.plugin, &config(AUDIENCE), Some(CLIENT_SECRET)).expect("opens");
        let answer = b.complete_after_short(
            "one-use-code",
            ("state", NONCE),
            REDIRECT,
            "verifier",
            Some((8, 0)),
            || {
                support::HeldClock::set(at + elapsed);
                idp.answer("/token", 400, r#"{"error":"invalid_grant"}"#);
            },
        );
        assert!(
            answer.starts_with("short(needed "),
            "the actual short path: {answer}"
        );
        if retained {
            assert!(
                answer.contains("verdict 1 subject="),
                "age {elapsed}: {answer}"
            );
            assert_eq!(
                idp.sent_to("/token").len(),
                1,
                "the cached identity is reused"
            );
        } else {
            assert!(
                answer
                    .trim_end()
                    .ends_with(&format!("verdict {LOGIN_BAD_CREDENTIAL}")),
                "age {elapsed}: {answer}"
            );
            assert_eq!(
                idp.sent_to("/token").len(),
                2,
                "the expired identity is not reused"
            );
        }
    }
}

/// A callback without the nonce that bound its browser session is refused before redeeming code.
#[test]
fn an_empty_callback_nonce_cannot_accept_an_empty_id_token_nonce() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let idp = Idp::secure_carrier(&key);
    let mut c = claims(AUDIENCE);
    c["nonce"] = serde_json::json!("");
    idp.answer(
        "/token",
        200,
        &serde_json::json!({"id_token": key.sign(&c)}).to_string(),
    );
    let b = bind(&Arm::Linked, &idp);
    open(&b.plugin, &config(AUDIENCE), Some(CLIENT_SECRET)).expect("opens");
    let answer = b.complete("code", ("state", ""), REDIRECT, "verifier", None);
    assert_eq!(
        answer.trim_end(),
        format!("verdict {LOGIN_SECURITY_CHECK_FAILED}")
    );
    assert!(
        idp.sent_to("/token").is_empty(),
        "an unbound callback redeems nothing"
    );
}

#[test]
fn a_tick_reports_a_refused_key_endpoint_through_its_envelope() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let idp = Idp::secure_carrier(&key);
    let b = bind(&Arm::Linked, &idp);
    let mut cfg: serde_json::Value = serde_json::from_str(&config(AUDIENCE)).unwrap();
    // Refuse the key request synchronously on TICK itself. Implicit discovery can pend,
    // leaving its later DRIVE to report the refusal after the tick's envelope has returned.
    cfg["jwks_url"] = serde_json::json!(support::JWKS_URL);
    open(&b.plugin, &cfg.to_string(), None).expect("HTTPS configuration opens");
    idp.refuse(1);
    let driver = b.dispatcher.driver(&b.plugin, 0).expect("driver");
    for _ in 0..2 {
        let done = b
            .dispatcher
            .tick(&b.plugin, driver, now_ns())
            .wait(Duration::from_secs(10))
            .expect("tick answers");
        assert_eq!(done.outcome, Outcome::Ready, "refusal settles on the tick");
    }
    assert_eq!(
        idp.diags()
            .iter()
            .filter(|s| s.starts_with("BUSBAR-4031 2 "))
            .count(),
        1
    );
    assert!(idp.sent_to("/keys").is_empty());
}

#[test]
fn a_broken_successful_token_response_is_a_login_outage() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    for body in [
        "<html>maintenance</html>",
        r#"{"access_token":"TokenCanary"}"#,
    ] {
        let idp = Idp::secure_carrier(&key);
        idp.answer("/token", 200, body);
        let b = bind(&Arm::Linked, &idp);
        open(&b.plugin, &config(AUDIENCE), Some(CLIENT_SECRET)).expect("opens");
        let answer = b.complete("code", ("state", NONCE), REDIRECT, "verifier", None);
        assert_eq!(answer.trim_end(), format!("verdict {LOGIN_OUTAGE}"));
        assert_eq!(idp.sent_to("/token").len(), 1);
        assert!(!answer.contains("TokenCanary"), "{answer}");
        assert!(
            !idp.diags().join("\n").contains("TokenCanary"),
            "the token answer is never echoed: {:?}",
            idp.diags()
        );
    }
}

#[test]
fn a_refused_idp_destination_raises_its_declared_diagnostic_once() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let idp = Idp::secure_carrier(&key);
    let b = bind(&Arm::Linked, &idp);
    let mut cfg: serde_json::Value = serde_json::from_str(&config(AUDIENCE)).unwrap();
    cfg["jwks_min_refetch_secs"] = serde_json::json!(1);
    open(&b.plugin, &cfg.to_string(), None).expect("opens");

    idp.refuse(1);
    let token = key.sign(&claims(AUDIENCE));
    assert!(b.verify(Some(&token), None).starts_with("Failed"));
    let raised = idp.diags();
    assert_eq!(raised.len(), 1, "{raised:?}");
    assert!(
        raised[0].starts_with("BUSBAR-4031 2 ")
            && raised[0].contains("idp.conformance.example")
            && !raised[0].contains("/keys"),
        "{raised:?}"
    );

    std::thread::sleep(Duration::from_millis(1100));
    assert!(b.verify(Some(&token), None).starts_with("Failed"));
    assert_eq!(idp.diags().len(), 1, "raised once: {:?}", idp.diags());
}

#[test]
fn ready_and_tick_release_held_connections_on_cancel_or_refresh() {
    use busbar_contract::abi::mechanism::lifecycle::{
        slot as life, CancelIn, CancelOut, ReadyIn, TickIn, TickOut,
    };
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let lib = cdylib();
    let stated = row().statement;
    for arm in [
        Arm::Linked,
        Arm::Dropped {
            lib: &lib,
            stated: &stated,
        },
    ] {
        for ready_slot in [true, false] {
            for cancel in [true, false] {
                let idp = Idp::secure_carrier(&key);
                let b = bind(&arm, &idp);
                let mut cfg: serde_json::Value = serde_json::from_str(&config(AUDIENCE)).unwrap();
                cfg["jwks_url"] = serde_json::json!(support::JWKS_URL);
                open(&b.plugin, &cfg.to_string(), None).expect("opens");
                let owner = b.dispatcher.inline_ticket().expect("owner ticket");
                let unrelated = b.dispatcher.inline_ticket().expect("unrelated ticket");
                let hold = idp.hold_reads("/keys");
                let pending = if ready_slot {
                    let mut input: ReadyIn = z();
                    input.head = busbar_plugin_loader::dispatch::in_head();
                    b.plugin
                        .call_inline(
                            owner.ticket(),
                            false,
                            life::READY,
                            &mut Frame::new(input, out_head()),
                        )
                        .outcome
                } else {
                    let mut input: TickIn = z();
                    input.head = busbar_plugin_loader::dispatch::in_head();
                    input.now_ns = now_ns();
                    let mut output: TickOut = z();
                    output.head = out_head();
                    b.plugin
                        .call_inline(
                            owner.ticket(),
                            false,
                            life::TICK,
                            &mut Frame::new(input, output),
                        )
                        .outcome
                };
                assert_eq!(pending, Outcome::Pending);
                assert!(idp.read_is_held());
                let sent = idp.sent_to("/keys");
                assert_eq!(sent.len(), 1);
                let connection = sent[0].conn;
                assert!(idp.connection_is_open(connection));
                let cancel_ticket = |ticket| {
                    let mut input: CancelIn = z();
                    input.head = busbar_plugin_loader::dispatch::in_head();
                    input.ticket = ticket;
                    let mut output: CancelOut = z();
                    output.head = out_head();
                    let mut frame = Frame::new(input, output);
                    let done = b.plugin.call(life::CANCEL, &mut frame);
                    assert_eq!(done.outcome, Outcome::Ready);
                    assert_eq!(
                        frame.out.disposition,
                        busbar_contract::abi::auth::CANCEL_ABANDONED
                    );
                };
                cancel_ticket(unrelated.ticket());
                assert!(
                    idp.connection_is_open(connection),
                    "another ticket cannot cancel this exchange"
                );
                if cancel {
                    cancel_ticket(owner.ticket());
                    cancel_ticket(owner.ticket());
                } else {
                    refresh_pending(&b, &replacement_config());
                }
                assert!(
                    !idp.connection_is_open(connection),
                    "the lifecycle transition closes the pending exchange"
                );
                assert_eq!(
                    idp.sent_to("/keys").len(),
                    1,
                    "cleanup starts no new request"
                );
                drop(hold);
            }
        }
    }
}

/// An executing host call retains its binding; a later refresh retires its parked exchange.
#[test]
fn executing_driver_defers_refresh_until_its_host_call_returns() {
    use busbar_contract::abi::mechanism::call::{Blob, BLOB_JSON};
    use busbar_contract::abi::mechanism::lifecycle::{
        slot as life, CancelIn, CancelOut, RefreshIn,
    };
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let lib = cdylib();
    let stated = row().statement;
    for arm in [
        Arm::Linked,
        Arm::Dropped {
            lib: &lib,
            stated: &stated,
        },
    ] {
        for drive in [false, true] {
            for refresh_kind in ["same", "changed", "refused"] {
                let idp = Idp::secure_carrier(&key);
                let b = bind(&arm, &idp);
                let mut cfg: serde_json::Value = serde_json::from_str(&config(AUDIENCE)).unwrap();
                cfg["jwks_url"] = serde_json::json!(support::JWKS_URL);
                let settings = cfg.to_string();
                open(&b.plugin, &settings, None).expect("opens");
                let ticket = b
                    .dispatcher
                    .driver(&b.plugin, 0)
                    .expect("real driver ticket");
                let tick = || {
                    b.dispatcher
                        .tick(&b.plugin, ticket, now_ns())
                        .wait(Duration::from_secs(5))
                        .expect("the real tick answers")
                        .outcome
                };
                let hold = idp.hold_reads("/keys");
                if drive {
                    assert_eq!(tick(), Outcome::Pending);
                    assert!(idp.read_is_held());
                }
                let (entered, resume) = idp.pause_next_read();
                std::thread::scope(|scope| {
                    let pending = scope.spawn(|| {
                        if drive {
                            let driven = &b.plugin.inner.driven;
                            let seen = driven.answers();
                            assert_eq!(idp.wake_held_reads(), 1, "one real driver wake");
                            let until = std::time::Instant::now() + Duration::from_secs(5);
                            while driven.answers() == seen {
                                assert!(
                                    std::time::Instant::now() < until,
                                    "the real drive answers"
                                );
                                std::thread::yield_now();
                            }
                            assert_eq!(driven.answers(), seen + 1, "exactly one drive answered");

                            let outcome = driven
                                .answered_after(seen, Duration::ZERO)
                                .unwrap_or(Outcome::Pending);
                            assert_eq!(driven.answers(), seen + 1, "the observed answer is stable");
                            outcome
                        } else {
                            tick()
                        }
                    });
                    entered
                        .recv_timeout(Duration::from_secs(5))
                        .expect("driver reached the connector");
                    let sent = idp.sent_to("/keys");
                    assert_eq!(sent.len(), 1);
                    let connection = sent[0].conn;
                    assert!(idp.connection_is_open(connection));
                    let replacement = match refresh_kind {
                        "same" => settings.clone(),
                        "changed" => replacement_config(),
                        "refused" => "{".to_string(),
                        _ => unreachable!(),
                    };
                    let refresh = || {
                        let mut input: RefreshIn = z();
                        input.head = busbar_plugin_loader::dispatch::in_head();
                        input.generation = 2;
                        input.settings = Blob {
                            ptr: replacement.as_ptr(),
                            len: replacement.len(),
                            fmt: BLOB_JSON,
                            flags: 0,
                        };
                        b.plugin
                            .call(life::REFRESH, &mut Frame::new(input, out_head()))
                            .outcome
                    };
                    assert_eq!(
                        refresh(),
                        Outcome::Refused,
                        "the host does not replace a binding during an executing call"
                    );
                    assert!(
                        idp.connection_is_open(connection),
                        "the refused crossing preserves the executing exchange"
                    );
                    resume.send(()).expect("release the executing read");
                    assert_eq!(pending.join().unwrap(), Outcome::Pending);
                    assert_eq!(
                        refresh(),
                        if refresh_kind == "refused" {
                            Outcome::Failed
                        } else {
                            Outcome::Ready
                        },
                        "the retry is judged after the original call has returned"
                    );
                    if refresh_kind == "refused" {
                        assert!(
                            idp.connection_is_open(connection),
                            "refused refresh preserves the driver"
                        );
                    } else {
                        assert!(
                            !idp.connection_is_open(connection),
                            "successful refresh closes the previously parked exchange"
                        );
                    }
                    assert_eq!(
                        idp.sent_to("/keys").len(),
                        1,
                        "the transition starts no replacement exchange"
                    );
                    let mut input: CancelIn = z();
                    input.head = busbar_plugin_loader::dispatch::in_head();
                    input.ticket = ticket;
                    let mut output: CancelOut = z();
                    output.head = out_head();
                    assert_eq!(
                        b.plugin
                            .call(life::CANCEL, &mut Frame::new(input, output))
                            .outcome,
                        Outcome::Ready
                    );
                    assert!(!idp.connection_is_open(connection));
                });
                b.dispatcher.recycle(ticket);
                drop(hold);
            }
        }
    }
}

/// Actual signed OIDC roles force both host identity buffers to grow. Advancing the request
/// past exp between SHORT and recall would reject a second judgment of the same credential.
#[test]
fn wide_verified_identity_keeps_its_first_judgment_through_both_doors() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let lib = cdylib();
    let stated = row().statement;
    let mut c = claims(AUDIENCE);
    c["roles"] = serde_json::json!((0..300).map(|i| format!("group-{i}")).collect::<Vec<_>>());
    let token = key.sign(&c);
    let valid_at = c["exp"].as_u64().unwrap() - 10;
    for arm in [
        Arm::Linked,
        Arm::Dropped {
            lib: &lib,
            stated: &stated,
        },
    ] {
        let idp = Idp::secure_carrier(&key);
        let b = bind(&arm, &idp);
        open(&b.plugin, &config(AUDIENCE), None).expect("opens");
        for _ in 0..4 {
            let timestamp = AtomicU64::new(valid_at);
            let before = idp.sent().len();
            let answer = b.identify_after_short(
                slot::VERIFY,
                |buf| support::verify_in_at(Some(&token), buf, timestamp.load(Ordering::SeqCst)),
                (8, 0),
                || {
                    timestamp.store(valid_at + 7200, Ordering::SeqCst);
                },
            );
            assert!(answer.starts_with("short(needed "), "{answer}");
            assert!(
                answer.contains("verdict 1 subject=Some(\"oidc-v2:aHR0cHM6Ly9pZHAuY29uZm9ybWFuY2UuZXhhbXBsZS92Mi4w:conformance-subject\")"),
                "{answer}"
            );
            assert_eq!(
                answer.matches("\"group-").count(),
                300,
                "all signed role entries survive"
            );
            assert!(
                answer.contains("\"group-299\""),
                "all 300 signed roles survive recall: {answer}"
            );
            assert_eq!(
                idp.sent().len() - before,
                if before == 0 { 2 } else { 0 },
                "one discovery/JWKS fetch, no recall fetch"
            );
        }
        let mut bytes = vec![0; 65536];
        let mut groups = vec![z::<Span>(); 300];
        let mut out: IdentifyOut = z();
        out.head = out_head();
        let mut frame = Frame::new(
            support::verify_in_at(
                Some(&token),
                identity_buf(&mut bytes, &mut groups),
                valid_at + 7200,
            ),
            out,
        );
        assert_eq!(
            b.plugin.call(slot::VERIFY, &mut frame).outcome,
            Outcome::Ready
        );
        assert_eq!(
            frame.out.verdict, 2,
            "a fresh judgment at the advanced timestamp rejects expiry"
        );
    }
}

#[test]
fn abandoned_wide_oidc_verdicts_release_and_closed_instances_refuse_recall_both_ways() {
    use busbar_contract::abi::mechanism::call::DeadlineClass;
    use busbar_contract::abi::mechanism::lifecycle::{slot as life, ReleaseIn, TickIn, TickOut};
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let lib = cdylib();
    let stated = row().statement;
    let mut c = claims(AUDIENCE);
    c["roles"] = serde_json::json!((0..300).map(|i| format!("group-{i}")).collect::<Vec<_>>());
    let token = key.sign(&c);
    let frame = || {
        let mut output: IdentifyOut = z();
        output.head = out_head();
        Frame::new(verify_in(Some(&token), z()), output)
    };
    for arm in [
        Arm::Linked,
        Arm::Dropped {
            lib: &lib,
            stated: &stated,
        },
    ] {
        let b = bind(&arm, &Idp::secure_carrier(&key));
        open(&b.plugin, &config(AUDIENCE), None).expect("opens");
        assert!(
            b.verify(Some(&token), None).contains("group-299"),
            "warm the actual JWKS and wide identity"
        );
        let mut first = frame();
        let short = b.plugin.call(slot::VERIFY, &mut first);
        assert_eq!(short.outcome, Outcome::Failed);
        assert_eq!(short.lease, 0, "negotiated storage stays private");
        let lease = first.out.head.lease;
        assert_ne!(lease, 0);
        drop(short.recall.expect("one recall token"));
        let release = |lease| {
            b.plugin
                .call(
                    life::RELEASE,
                    &mut Frame::new(
                        ReleaseIn {
                            head: busbar_plugin_loader::dispatch::in_head(),
                            lease,
                        },
                        out_head(),
                    ),
                )
                .outcome
        };
        assert_eq!(
            release(lease),
            Outcome::Refused,
            "token drop returned its lease"
        );
        for cancel in [false, true] {
            let ticket = b.dispatcher.mint(0).unwrap();
            let done = b
                .dispatcher
                .submit(
                    &b.plugin,
                    ticket,
                    slot::VERIFY,
                    frame(),
                    DeadlineClass::Call,
                    0,
                )
                .wait(Duration::from_secs(10))
                .unwrap();
            assert!(done.short);
            assert_eq!(done.lease, 0);
            let lease = done.frame.unwrap().out.head.lease;
            if cancel {
                b.dispatcher.drop_client(ticket);
            } else {
                b.dispatcher.recycle(ticket);
            }
            for _ in 0..2 {
                let barrier = b.dispatcher.mint(0).unwrap();
                let mut input: TickIn = z();
                input.head = busbar_plugin_loader::dispatch::in_head();
                let mut output: TickOut = z();
                output.head = out_head();
                assert_eq!(
                    b.dispatcher
                        .submit(
                            &b.plugin,
                            barrier,
                            life::TICK,
                            Frame::new(input, output),
                            DeadlineClass::Call,
                            0
                        )
                        .wait(Duration::from_secs(10))
                        .unwrap()
                        .outcome,
                    Outcome::Ready
                );
                b.dispatcher.recycle(barrier);
            }
            assert_eq!(
                release(lease),
                Outcome::Refused,
                "ticket lifecycle returned its lease"
            );
            if cancel {
                b.dispatcher.recycle(ticket);
            }
        }
        let token = b.plugin.call(slot::VERIFY, &mut frame()).recall.unwrap();
        assert_eq!(
            b.plugin
                .call(
                    life::CLOSE,
                    &mut Frame::new(busbar_plugin_loader::dispatch::in_head(), out_head())
                )
                .outcome,
            Outcome::Ready
        );
        assert!(!b.plugin.is_open());
        assert!(matches!(
            b.plugin.recall(token, slot::VERIFY, &mut frame()).outcome,
            Outcome::Refused | Outcome::Fault
        ));
    }
}

/// The JSON cases run through each actual door at their stated request timestamps.
#[test]
fn configured_oidc_cases_validate_refresh_close_and_never_echo_credentials_both_ways() {
    use busbar_contract::abi::mechanism::call::{Blob, BLOB_JSON};
    use busbar_contract::abi::mechanism::lifecycle::{
        slot as life, RefreshIn, TickIn, TickOut, ValidateIn,
    };
    let _one = support::serial();
    let input: serde_json::Value = serde_json::from_str(include_str!("conformance.json")).unwrap();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let lib = cdylib();
    let stated = row().statement;
    let settings = input["settings"].to_string();
    let cases = input["auth"]["cases"].as_array().unwrap();
    let credential = cases[0]["credential"].as_str().unwrap();
    let timestamp = cases[0]["timestamp"].as_u64().unwrap();
    let mut results = Vec::new();
    for arm in [
        Arm::Linked,
        Arm::Dropped {
            lib: &lib,
            stated: &stated,
        },
    ] {
        let idp = Idp::secure_carrier(&key);
        for far in input["far_ends"].as_array().unwrap() {
            let url = far["url"].as_str().unwrap();
            let path = format!(
                "/{}",
                url.strip_prefix("https://")
                    .unwrap()
                    .split_once('/')
                    .unwrap()
                    .1
            );
            idp.answer(
                &path,
                far["status"].as_u64().unwrap() as u32,
                far["body"].as_str().unwrap(),
            );
        }
        let b = bind(&arm, &idp);
        let crossings = || {
            use std::sync::atomic::Ordering::SeqCst;
            b.plugin.inner.crossings.load(SeqCst) - b.plugin.inner.resumes.load(SeqCst)
        };
        let mut answers = Vec::new();
        let mut counts = Vec::new();
        let before = crossings();
        let unopened = oidc_verify_answer(&b, Some(credential), timestamp, false, true);
        assert!(!unopened.starts_with("Ready"));
        assert_eq!(crossings() - before, 0);
        counts.push(crossings() - before);
        answers.push(unopened);
        for cfg in input["auth"]["bad_settings"]
            .as_array()
            .unwrap()
            .iter()
            .chain(std::iter::once(&input["settings"]))
        {
            let cfg = cfg
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| cfg.to_string());
            let mut reason = [0u8; 1024];
            let mut validation: ValidateIn = z();
            validation.head = busbar_plugin_loader::dispatch::in_head();
            validation.settings = Blob {
                ptr: cfg.as_ptr(),
                len: cfg.len(),
                fmt: BLOB_JSON,
                flags: 0,
            };
            validation.err_buf = reason.as_mut_ptr();
            validation.err_cap = reason.len();
            let before = crossings();
            let called = b
                .plugin
                .call(life::VALIDATE, &mut Frame::new(validation, out_head()));
            assert_eq!(crossings() - before, 1);
            counts.push(crossings() - before);
            assert_eq!(called.lease, 0);
            assert_eq!(
                called.outcome,
                if cfg == settings {
                    Outcome::Ready
                } else {
                    Outcome::Failed
                }
            );
            if cfg == settings {
                assert!(called.error.is_none());
            }
            answers.push(format!(
                "validate {:?} lease={} error={:?}",
                called.outcome,
                called.lease,
                called.error.as_deref().map(String::from_utf8_lossy)
            ));
            if cfg != settings {
                let before = crossings();
                let error = open(&b.plugin, &cfg, None).expect_err("bad open names why");
                assert!(!error.is_empty());
                assert_eq!(crossings() - before, 1);
                counts.push(crossings() - before);
                answers.push(error);
            }
        }
        let before = crossings();
        open(&b.plugin, &settings, None).expect("configured open");
        assert_eq!(crossings() - before, 1);
        counts.push(crossings() - before);
        answers.push("open Ready lease=false".to_owned());
        let before = crossings();
        let ready = b.plugin.ready(&b.dispatcher, Duration::from_secs(10));
        assert_eq!(crossings() - before, 1);
        counts.push(crossings() - before);
        answers.push(format!("ready {ready:?}"));
        ready.unwrap();
        assert_eq!(idp.sent_to("/keys").len(), 1);
        let mut expected_identity = String::new();
        for case in cases {
            let token = case["credential"].as_str();
            let at = case["timestamp"].as_u64().unwrap();
            let verdict = match case["verdict"].as_str().unwrap() {
                "reject" => 2,
                "pass" => 3,
                _ => 1,
            };
            let before = crossings();
            let now = oidc_verify_answer(&b, token, at, false, true);
            assert_eq!(crossings() - before, 1);
            counts.push(crossings() - before);
            let before = crossings();
            let submitted = oidc_verify_answer(&b, token, at, false, false);
            assert_eq!(crossings() - before, 1);
            counts.push(crossings() - before);
            assert_eq!(
                now, submitted,
                "ticketless and submitted retain identical full identity properties"
            );
            assert!(now.contains(&format!("verdict={verdict} ")), "{now}");
            if verdict == 1 {
                let subject = case["verdict"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("identity:")
                    .unwrap();
                assert!(now.contains(&format!("subject=Some({subject:?})")), "{now}");
                expected_identity = now.clone();
            }
            answers.extend([now, submitted]);
        }
        let before = crossings();
        let short = oidc_verify_answer(&b, Some(credential), timestamp, true, false);
        assert_eq!(crossings() - before, 3);
        counts.push(crossings() - before);
        assert_eq!(short, format!("short=true {expected_identity}"));
        answers.push(short);
        let before = crossings();
        let begin = b.begin(
            REDIRECT,
            "conformance-state",
            "conformance-challenge",
            NONCE,
        );
        assert_eq!(crossings() - before, 2);
        counts.push(crossings() - before);
        assert!(begin.starts_with("shape 1 https://idp.conformance.example/authorize?"));
        assert!(begin.ends_with("(release Ready)"));
        answers.push(begin);
        let before = crossings();
        let login = b.complete(
            "conformance-code",
            ("conformance-state", NONCE),
            REDIRECT,
            "conformance-verifier",
            None,
        );
        assert_eq!(crossings() - before, 1);
        counts.push(crossings() - before);
        assert!(login.starts_with("verdict 1 subject=Some(\"oidc-v2:aHR0cHM6Ly9pZHAuY29uZm9ybWFuY2UuZXhhbXBsZS92Mi4w:conformance-subject\")"));
        answers.push(login);
        assert_eq!(idp.sent_to("/token").len(), 1);
        let mut i: busbar_contract::abi::auth::OpenOutboundIn = z();
        i.head = busbar_plugin_loader::dispatch::in_head();
        let mut o: busbar_contract::abi::auth::OpenOutboundOut = z();
        o.head = out_head();
        let before = crossings();
        let called = b.plugin.call(slot::OPEN_OUTBOUND, &mut Frame::new(i, o));
        assert_eq!(crossings() - before, 1);
        counts.push(crossings() - before);
        assert_eq!(called.outcome, Outcome::Refused);
        assert_eq!(called.lease, 0);
        answers.push(format!(
            "OPEN_OUTBOUND {:?} lease={} error={:?}",
            called.outcome,
            called.lease,
            called.error.as_deref().map(String::from_utf8_lossy)
        ));
        let mut i: busbar_contract::abi::auth::OutboundReadyIn = z();
        i.head = busbar_plugin_loader::dispatch::in_head();
        let mut o: busbar_contract::abi::auth::OutboundReadyOut = z();
        o.head = out_head();
        let before = crossings();
        let called = b.plugin.call(slot::OUTBOUND_READY, &mut Frame::new(i, o));
        assert_eq!(crossings() - before, 1);
        counts.push(crossings() - before);
        assert_eq!(called.outcome, Outcome::Refused);
        assert_eq!(called.lease, 0);
        answers.push(format!(
            "OUTBOUND_READY {:?} lease={} error={:?}",
            called.outcome,
            called.lease,
            called.error.as_deref().map(String::from_utf8_lossy)
        ));
        let mut i: busbar_contract::abi::auth::FieldsIn = z();
        i.head = busbar_plugin_loader::dispatch::in_head();
        let mut o: busbar_contract::abi::auth::FieldsOut = z();
        o.head = out_head();
        let before = crossings();
        let called = b.plugin.call(slot::FIELDS, &mut Frame::new(i, o));
        assert_eq!(crossings() - before, 1);
        counts.push(crossings() - before);
        assert_eq!(called.outcome, Outcome::Refused);
        assert_eq!(called.lease, 0);
        answers.push(format!(
            "FIELDS {:?} lease={} error={:?}",
            called.outcome,
            called.lease,
            called.error.as_deref().map(String::from_utf8_lossy)
        ));
        let mut tick: TickIn = z();
        tick.head = busbar_plugin_loader::dispatch::in_head();
        tick.now_ns = 1;
        let mut output: TickOut = z();
        output.head = out_head();
        let mut frame = Frame::new(tick, output);
        let before = crossings();
        let called = b.plugin.call(life::TICK, &mut frame);
        assert_eq!(crossings() - before, 1);
        counts.push(crossings() - before);
        answers.push(format!(
            "tick {:?} lease={} error={:?} next={}",
            called.outcome,
            called.lease,
            called.error.as_deref().map(String::from_utf8_lossy),
            frame.out.next_tick_ns
        ));
        let mut refresh: RefreshIn = z();
        refresh.head = busbar_plugin_loader::dispatch::in_head();
        refresh.generation = 2;
        refresh.settings = Blob {
            ptr: settings.as_ptr(),
            len: settings.len(),
            fmt: BLOB_JSON,
            flags: 0,
        };
        let before = crossings();
        let called = b
            .plugin
            .call(life::REFRESH, &mut Frame::new(refresh, out_head()));
        assert_eq!(crossings() - before, 1);
        counts.push(crossings() - before);
        assert_eq!(called.outcome, Outcome::Ready);
        assert_eq!(called.lease, 0);
        assert!(called.error.is_none());
        answers.push(format!(
            "refresh {:?} lease={} error={:?}",
            called.outcome,
            called.lease,
            called.error.as_deref().map(String::from_utf8_lossy)
        ));
        let before = crossings();
        let after = oidc_verify_answer(&b, Some(credential), timestamp, false, true);
        assert_eq!(crossings() - before, 1);
        counts.push(crossings() - before);
        assert_eq!(after, expected_identity);
        answers.push(after);
        let before = crossings();
        let closed = b.plugin.call(
            life::CLOSE,
            &mut Frame::new(busbar_plugin_loader::dispatch::in_head(), out_head()),
        );
        assert_eq!(crossings() - before, 1);
        counts.push(crossings() - before);
        assert_eq!(closed.outcome, Outcome::Ready);
        assert_eq!(closed.lease, 0);
        assert!(closed.error.is_none());
        answers.push(format!(
            "close {:?} lease={} error={:?}",
            closed.outcome,
            closed.lease,
            closed.error.as_deref().map(String::from_utf8_lossy)
        ));
        let before = crossings();
        let after = oidc_verify_answer(&b, Some(credential), timestamp, false, true);
        assert_eq!(crossings() - before, 0);
        counts.push(crossings() - before);
        assert!(!after.starts_with("Ready"));
        answers.push(after);
        let rotated = bind(&arm, &idp);
        let rotated_settings = input["auth"]["rotated_settings"].to_string();
        let rotated_crossings = || {
            use std::sync::atomic::Ordering::SeqCst;
            rotated.plugin.inner.crossings.load(SeqCst) - rotated.plugin.inner.resumes.load(SeqCst)
        };
        let before = rotated_crossings();
        open(&rotated.plugin, &rotated_settings, None).expect("rotated open");
        assert_eq!(rotated_crossings() - before, 1);
        counts.push(rotated_crossings() - before);
        answers.push("rotated open Ready lease=false".into());
        let before = rotated_crossings();
        let ready = rotated
            .plugin
            .ready(&rotated.dispatcher, Duration::from_secs(10));
        assert_eq!(rotated_crossings() - before, 1);
        counts.push(rotated_crossings() - before);
        answers.push(format!("rotated ready {ready:?}"));
        ready.unwrap();
        for case in cases
            .iter()
            .filter(|c| c["verdict"].as_str().unwrap().starts_with("identity:"))
        {
            let before = rotated_crossings();
            let answer = oidc_verify_answer(
                &rotated,
                case["credential"].as_str(),
                case["timestamp"].as_u64().unwrap(),
                false,
                true,
            );
            assert_eq!(rotated_crossings() - before, 1);
            counts.push(rotated_crossings() - before);
            assert!(
                answer.starts_with("Ready lease=false") && !answer.contains("verdict=1 "),
                "{answer}"
            );
            answers.push(answer);
        }
        let before = rotated_crossings();
        let closed = rotated.plugin.call(
            life::CLOSE,
            &mut Frame::new(busbar_plugin_loader::dispatch::in_head(), out_head()),
        );
        assert_eq!(rotated_crossings() - before, 1);
        counts.push(rotated_crossings() - before);
        assert_eq!(closed.outcome, Outcome::Ready);
        assert_eq!(closed.lease, 0);
        assert!(closed.error.is_none());
        answers.push(format!(
            "rotated close {:?} lease={} error={:?}",
            closed.outcome,
            closed.lease,
            closed.error.as_deref().map(String::from_utf8_lossy)
        ));
        for secret in input["auth"]["never_echoed"].as_array().unwrap() {
            for answer in &answers {
                assert!(
                    !answer.contains(secret.as_str().unwrap()),
                    "no configured credential crosses back"
                );
            }
        }
        let pinned = vec![
            0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1,
            1, 1,
        ];
        assert_eq!(counts, pinned);
        results.push(answers);
    }
    assert_eq!(results[0], results[1]);
    assert!(!(cfg!(debug_assertions) && std::env::var_os("BUSBAR_EXPECT_RELEASE").is_some()));
}

/// One actual VERIFY, retaining every old fold property and full decoded identity.
fn oidc_verify_answer(
    b: &Bound,
    credential: Option<&str>,
    timestamp: u64,
    short: bool,
    ticketless: bool,
) -> String {
    let mut bytes = vec![0u8; if short { 0 } else { IDENTITY_BUF_BYTES }];
    let mut groups = vec![z::<Span>(); if short { 0 } else { IDENTITY_GROUPS as usize }];
    let mut output: IdentifyOut = z();
    output.head = out_head();
    let mut frame = Frame::new(
        support::verify_in_at(credential, identity_buf(&mut bytes, &mut groups), timestamp),
        output,
    );
    let (outcome, lease, error, out) = if ticketless {
        let called = b.plugin.call(slot::VERIFY, &mut frame);
        (called.outcome, called.lease, called.error, frame.out)
    } else {
        let ticket = b.dispatcher.mint(0).unwrap();
        let mut done = b.submit(ticket, slot::VERIFY, frame.input, frame.out);
        if short {
            assert!(done.short);
            assert_eq!(done.lease, 0);
            let first = done.frame.as_ref().unwrap().out;
            assert_ne!(first.head.lease, 0);
            bytes = vec![0; first.needed_bytes as usize];
            groups = vec![z::<Span>(); first.needed_groups as usize];
            let mut output: IdentifyOut = z();
            output.head = out_head();
            done = b.submit(
                ticket,
                slot::VERIFY,
                support::verify_in_at(credential, identity_buf(&mut bytes, &mut groups), timestamp),
                output,
            );
        }
        b.dispatcher.recycle(ticket);
        assert!(b
            .dispatcher
            .retirement_barrier(ticket, Duration::from_secs(10)));
        (
            done.outcome,
            done.lease,
            done.error,
            done.frame.unwrap().out,
        )
    };
    assert_eq!(lease, 0);
    if outcome == Outcome::Ready {
        assert!(error.is_none());
        assert_eq!(out.head.lease, 0);
    }
    format!(
        "{}{:?} lease={} error={:?} needed={}/{} groups={} verdict={} {}",
        if short { "short=true " } else { "" },
        outcome,
        lease != 0,
        error.as_deref().map(String::from_utf8_lossy),
        out.needed_bytes,
        out.needed_groups,
        out.identity.groups_len,
        out.verdict,
        if outcome == Outcome::Ready && out.verdict == 1 {
            support::identity(&out, &bytes, &groups)
        } else {
            String::new()
        }
    )
}

#[test]
fn real_oidc_requires_a_connection_table_and_refuses_a_mismatched_linked_statement() {
    use busbar_plugin_loader::dispatch::{
        load_dropped_bytes, load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, NoSink,
    };
    use std::sync::Arc;
    let _one = support::serial();
    let d = Dispatcher::new(DispatchConfig::default());
    let bind = |conns| Bind {
        instance: Arc::from("oidc-negative"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns,
    };
    let mut row = row();
    let lib = cdylib();
    let want = LoadError::NoConnectionTable {
        plugin: NAME.into(),
        needs: 6,
    };
    let linked = load_linked::<Auth>(&row, bind(ConnTable::NoNeeds))
        .map(|_| ())
        .expect_err("networked linked door requires table");
    assert_eq!(linked, want);
    assert!(linked.to_string().contains(&format!("plugin '{NAME}'")));
    assert_eq!(
        load_dropped_bytes::<Auth>(&lib, NAME, &row.statement, bind(ConnTable::NoNeeds))
            .map(|_| ())
            .err(),
        Some(want)
    );
    load_linked::<Auth>(&row, bind(ConnTable::Probe)).expect("a probe needs no serving table");
    assert_eq!(load_linked::<busbar_plugin_loader::dispatch::kinds::secret::Secret>(&row, bind(ConnTable::Probe)).map(|_| ()).err(), Some(LoadError::ManifestKind { stated: busbar_contract::abi::mechanism::KindCode::Auth, want: <busbar_plugin_loader::dispatch::kinds::secret::Secret as busbar_plugin_loader::dispatch::Kind>::CODE }));
    assert_eq!(load_dropped_bytes::<busbar_plugin_loader::dispatch::kinds::secret::Secret>(&lib, NAME, &row.statement, bind(ConnTable::Probe)).map(|_| ()).err(), Some(LoadError::ManifestKind { stated: busbar_contract::abi::mechanism::KindCode::Auth, want: <busbar_plugin_loader::dispatch::kinds::secret::Secret as busbar_plugin_loader::dispatch::Kind>::CODE }));
    assert_eq!(load_linked::<busbar_plugin_loader::dispatch::kinds::store::Store>(&row, bind(ConnTable::Probe)).map(|_| ()).err(), Some(LoadError::ManifestKind { stated: busbar_contract::abi::mechanism::KindCode::Auth, want: <busbar_plugin_loader::dispatch::kinds::store::Store as busbar_plugin_loader::dispatch::Kind>::CODE }));
    assert_eq!(load_dropped_bytes::<busbar_plugin_loader::dispatch::kinds::store::Store>(&lib, NAME, &row.statement, bind(ConnTable::Probe)).map(|_| ()).err(), Some(LoadError::ManifestKind { stated: busbar_contract::abi::mechanism::KindCode::Auth, want: <busbar_plugin_loader::dispatch::kinds::store::Store as busbar_plugin_loader::dispatch::Kind>::CODE }));
    assert_eq!(load_linked::<busbar_plugin_loader::dispatch::kinds::transport::Transport>(&row, bind(ConnTable::Probe)).map(|_| ()).err(), Some(LoadError::ManifestKind { stated: busbar_contract::abi::mechanism::KindCode::Auth, want: <busbar_plugin_loader::dispatch::kinds::transport::Transport as busbar_plugin_loader::dispatch::Kind>::CODE }));
    assert_eq!(load_dropped_bytes::<busbar_plugin_loader::dispatch::kinds::transport::Transport>(&lib, NAME, &row.statement, bind(ConnTable::Probe)).map(|_| ()).err(), Some(LoadError::ManifestKind { stated: busbar_contract::abi::mechanism::KindCode::Auth, want: <busbar_plugin_loader::dispatch::kinds::transport::Transport as busbar_plugin_loader::dispatch::Kind>::CODE }));
    assert_eq!(load_linked::<busbar_plugin_loader::dispatch::kinds::export::Export>(&row, bind(ConnTable::Probe)).map(|_| ()).err(), Some(LoadError::ManifestKind { stated: busbar_contract::abi::mechanism::KindCode::Auth, want: <busbar_plugin_loader::dispatch::kinds::export::Export as busbar_plugin_loader::dispatch::Kind>::CODE }));
    assert_eq!(load_dropped_bytes::<busbar_plugin_loader::dispatch::kinds::export::Export>(&lib, NAME, &row.statement, bind(ConnTable::Probe)).map(|_| ()).err(), Some(LoadError::ManifestKind { stated: busbar_contract::abi::mechanism::KindCode::Auth, want: <busbar_plugin_loader::dispatch::kinds::export::Export as busbar_plugin_loader::dispatch::Kind>::CODE }));
    assert_eq!(load_linked::<busbar_plugin_loader::dispatch::kinds::hook::Hook>(&row, bind(ConnTable::Probe)).map(|_| ()).err(), Some(LoadError::ManifestKind { stated: busbar_contract::abi::mechanism::KindCode::Auth, want: <busbar_plugin_loader::dispatch::kinds::hook::Hook as busbar_plugin_loader::dispatch::Kind>::CODE }));
    assert_eq!(load_dropped_bytes::<busbar_plugin_loader::dispatch::kinds::hook::Hook>(&lib, NAME, &row.statement, bind(ConnTable::Probe)).map(|_| ()).err(), Some(LoadError::ManifestKind { stated: busbar_contract::abi::mechanism::KindCode::Auth, want: <busbar_plugin_loader::dispatch::kinds::hook::Hook as busbar_plugin_loader::dispatch::Kind>::CODE }));
    assert_eq!(load_linked::<busbar_plugin_loader::dispatch::kinds::plane::Plane>(&row, bind(ConnTable::Probe)).map(|_| ()).err(), Some(LoadError::ManifestKind { stated: busbar_contract::abi::mechanism::KindCode::Auth, want: <busbar_plugin_loader::dispatch::kinds::plane::Plane as busbar_plugin_loader::dispatch::Kind>::CODE }));
    assert_eq!(load_dropped_bytes::<busbar_plugin_loader::dispatch::kinds::plane::Plane>(&lib, NAME, &row.statement, bind(ConnTable::Probe)).map(|_| ()).err(), Some(LoadError::ManifestKind { stated: busbar_contract::abi::mechanism::KindCode::Auth, want: <busbar_plugin_loader::dispatch::kinds::plane::Plane as busbar_plugin_loader::dispatch::Kind>::CODE }));
    let version = env!("CARGO_PKG_VERSION").as_bytes();
    let at = row
        .statement
        .windows(version.len())
        .position(|v| v == version)
        .unwrap();
    row.statement[at] = if row.statement[at] == b'9' {
        b'8'
    } else {
        b'9'
    };
    rendering::read(&row.statement).expect("the mismatched rendering remains well formed");
    assert_eq!(
        load_linked::<Auth>(&row, bind(ConnTable::Probe))
            .map(|_| ())
            .err(),
        Some(LoadError::StatementMismatch)
    );
    assert_eq!(
        load_dropped_bytes::<Auth>(&lib, NAME, &row.statement, bind(ConnTable::Probe))
            .map(|_| ())
            .err(),
        Some(LoadError::StatementMismatch)
    );
}

#[test]
fn the_declared_needs_are_the_statements() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let candidates: Vec<_> = [
        root.join("declares.json"),
        root.join("auth-oidc/declares.json"),
        root.join("auth-oidc-plugin/declares.json"),
    ]
    .into_iter()
    .filter(|p| p.is_file())
    .collect();
    assert_eq!(
        candidates.len(),
        1,
        "one actual declares.json is required; no absent-metadata skip"
    );
    let declared: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&candidates[0]).unwrap()).unwrap();
    let mut needs: Vec<_> = declared["needs"]
        .as_array()
        .map(|v| v.iter().map(|v| v.as_str().unwrap().to_owned()).collect())
        .unwrap_or_default();
    needs.sort();
    needs.dedup();
    let mut stated: Vec<_> = rendering::read(&row().statement)
        .unwrap()
        .needs
        .into_iter()
        .map(|n| n.transport)
        .collect();
    stated.sort();
    stated.dedup();
    assert_eq!(needs, stated);
}

/// Malformed metadata only: the actual product dispatch table and implementation stay intact.
#[test]
fn an_oidc_door_at_another_abi_or_layout_is_refused() {
    use busbar_contract::abi::mechanism::door::{Door, DoorParts};
    use busbar_plugin_loader::dispatch::{
        load_dropped_bytes, load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow,
        NoSink,
    };
    use std::sync::{
        atomic::{AtomicPtr, Ordering},
        Arc,
    };
    static MALFORMED: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());
    extern "C" fn malformed() -> *const Door {
        MALFORMED.load(Ordering::SeqCst)
    }
    let _one = support::serial();
    let actual = row();
    // SAFETY: the actual product's door has static storage and the documented door layout.
    let real = unsafe { Door::read_parts((actual.door)()) };
    let d = Dispatcher::new(DispatchConfig::default());
    let bind = || Bind {
        instance: Arc::from("oidc-malformed"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::Probe,
    };
    let lib = cdylib();
    load_linked::<Auth>(&actual, bind()).expect("actual linked door loads");
    load_dropped_bytes::<Auth>(&lib, NAME, &actual.statement, bind())
        .expect("actual dropped door loads");
    let path = support::cdylib_path().expect("actual built product image");
    let (dropped_door, dropped_ops) =
        busbar_plugin_loader::dispatch::load::door_addresses_of_library(&path)
            .expect("actual image opens")
            .expect("actual image exports door");
    assert_ne!(
        dropped_door,
        (actual.door)() as usize,
        "dropped and linked door addresses must differ"
    );
    assert_ne!(
        dropped_ops, real.ops as usize,
        "dropped and linked ops tables must differ"
    );
    for abi in [real.kind_abi + 1, real.kind_abi.wrapping_sub(1)] {
        // SAFETY: only a scalar ABI tag is invalidated, all pointers remain the actual static door's.
        let door = unsafe {
            Door::__from_parts(DoorParts {
                kind_abi: abi,
                ..real
            })
        };
        MALFORMED.store(Box::into_raw(Box::new(door)), Ordering::SeqCst);
        let error = LinkedRow::of_raw(malformed).expect_err("another ABI must not render");
        assert!(
            matches!(error, LoadError::KindAbi { door, host, .. } if door == abi && host == real.kind_abi)
        );
        assert!(error.to_string().contains("rebuild"));
        let mut statement = actual.statement.clone();
        let at = rendering::RENDERING_MAGIC.len() + 8;
        statement[at..at + 4].copy_from_slice(&abi.to_le_bytes());
        assert_eq!(
            load_dropped_bytes::<Auth>(&lib, NAME, &statement, bind())
                .map(|_| ())
                .err(),
            Some(LoadError::ManifestKindAbi {
                stated: abi,
                host: real.kind_abi
            })
        );
    }
    for layout in [real.layout ^ 1, 0] {
        // SAFETY: only the layout fingerprint is invalidated; nothing can dispatch this door.
        let door = unsafe { Door::__from_parts(DoorParts { layout, ..real }) };
        MALFORMED.store(Box::into_raw(Box::new(door)), Ordering::SeqCst);
        let error = LinkedRow::of_raw(malformed).expect_err("another layout must not render");
        assert!(
            matches!(error, LoadError::KindLayout { kind:busbar_contract::abi::mechanism::KindCode::Auth,stated,host,.. } if stated==layout&&host==real.layout)
        );
        assert!(error
            .to_string()
            .contains("rebuild against this busbar-contract"));
        let changed = busbar_plugin_loader::dispatch::LinkedRow {
            statement: actual.statement.clone(),
            door: malformed,
        };
        assert_eq!(
            load_linked::<Auth>(&changed, bind()).map(|_| ()).err(),
            Some(error.clone())
        );
        assert_eq!(
            busbar_plugin_loader::dispatch::LinkedRow::of_raw(malformed)
                .and_then(|row| load_linked::<Auth>(&row, bind()).map(|_| ()))
                .err(),
            Some(error)
        );
    }
    // SAFETY: the real static Statement is copied whole; only its static version string changes.
    let statement = unsafe { real.statement.read_unaligned() };
    let version = "0.0.0-conformance-restated";
    let changed = Box::leak(Box::new(busbar_contract::abi::mechanism::door::Statement {
        version: busbar_contract::abi::mechanism::call::AbiStr {
            ptr: version.as_ptr(),
            len: version.len(),
        },
        ..statement
    }));
    // SAFETY: static whole Statement over the real product table, no dispatch implementation copied.
    let door = unsafe {
        Door::__from_parts(DoorParts {
            statement: changed,
            ..real
        })
    };
    MALFORMED.store(Box::into_raw(Box::new(door)), Ordering::SeqCst);
    let inverse = busbar_plugin_loader::dispatch::LinkedRow {
        statement: actual.statement.clone(),
        door: malformed,
    };
    assert_eq!(
        load_linked::<Auth>(&inverse, bind()).map(|_| ()).err(),
        Some(LoadError::StatementMismatch)
    );
}

/// Ticketless calls share Ticket::NONE, but each SHORT answer owns a distinct private recall.
#[test]
fn two_ticketless_short_verifies_keep_independent_identities_and_cleanup_both_ways() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let lib = cdylib();
    let stated = row().statement;
    let mut c = claims(AUDIENCE);
    c["roles"] = serde_json::json!((0..300).map(|i| format!("group-{i}")).collect::<Vec<_>>());
    c["sub"] = serde_json::json!("ticketless-a");
    let a = key.sign(&c);
    c["sub"] = serde_json::json!("ticketless-b");
    let b = key.sign(&c);
    for arm in [
        Arm::Linked,
        Arm::Dropped {
            lib: &lib,
            stated: &stated,
        },
    ] {
        let idp = Idp::secure_carrier(&key);
        let bound = bind(&arm, &idp);
        open(&bound.plugin, &config(AUDIENCE), None).expect("opens");
        for token in [&a, &b] {
            assert!(bound.verify(Some(token), None).contains("group-299"));
        }
        let requests = idp.sent().len();
        for abandon_first in [false, true] {
            let mut out: IdentifyOut = z();
            out.head = out_head();
            let mut first = Frame::new(verify_in(Some(&a), z()), out);
            let first_call = bound.plugin.call(slot::VERIFY, &mut first);
            assert_eq!(first_call.outcome, Outcome::Failed);
            assert_eq!(first_call.lease, 0);
            assert_ne!(first.out.head.lease, 0);
            let first_lease = first.out.head.lease;
            let first_token = first_call.recall.expect("first private recall");
            let mut out: IdentifyOut = z();
            out.head = out_head();
            let mut second = Frame::new(verify_in(Some(&b), z()), out);
            let second_call = bound.plugin.call(slot::VERIFY, &mut second);
            assert_eq!(
                second_call.outcome,
                Outcome::Failed,
                "a second outstanding ticketless call has its own retained result"
            );
            assert_eq!(second_call.lease, 0);
            assert_ne!(second.out.head.lease, 0);
            assert_ne!(second.out.head.lease, first_lease);
            let second_token = second_call.recall.expect("second private recall");
            let first_token = if abandon_first {
                drop(first_token);
                None
            } else {
                Some(first_token)
            };
            let mut bytes = vec![0u8; 65536];
            let mut groups = vec![z::<Span>(); 300];
            let mut out: IdentifyOut = z();
            out.head = out_head();
            let mut retry = Frame::new(
                verify_in(Some(&b), identity_buf(&mut bytes, &mut groups)),
                out,
            );
            let answered = bound.plugin.recall(second_token, slot::VERIFY, &mut retry);
            assert_eq!(answered.outcome, Outcome::Ready);
            assert_eq!(answered.lease, 0);
            assert!(answered.error.is_none());
            let identity = support::identity(&retry.out, &bytes, &groups);
            assert!(
                identity.starts_with("subject=Some(\"oidc-v2:aHR0cHM6Ly9pZHAuY29uZm9ybWFuY2UuZXhhbXBsZS92Mi4w:ticketless-b\")"),
                "{identity}"
            );
            assert!(identity.contains("group-299"));
            if let Some(first_token) = first_token {
                let mut out: IdentifyOut = z();
                out.head = out_head();
                let mut retry = Frame::new(
                    verify_in(Some(&a), identity_buf(&mut bytes, &mut groups)),
                    out,
                );
                let answered = bound.plugin.recall(first_token, slot::VERIFY, &mut retry);
                assert_eq!(answered.outcome, Outcome::Ready);
                assert_eq!(answered.lease, 0);
                assert!(answered.error.is_none());
                let identity = support::identity(&retry.out, &bytes, &groups);
                assert!(
                    identity.starts_with("subject=Some(\"oidc-v2:aHR0cHM6Ly9pZHAuY29uZm9ybWFuY2UuZXhhbXBsZS92Mi4w:ticketless-a\")"),
                    "{identity}"
                );
                assert!(identity.contains("group-299"));
            }
            assert_eq!(
                idp.sent().len(),
                requests,
                "neither recall repeats provider work"
            );
        }
    }
}

#[test]
fn prepared_idp_carrier_commits_once_on_the_owned_connection() {
    use busbar_contract::conn::{ConnError, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc};
    use support::CarrierSecurity;

    let key = Issuer::start(UNUSED_ISSUER, KID);
    let owner = InstanceId(41);
    let other = InstanceId(42);
    for security in [
        CarrierSecurity::Unavailable,
        CarrierSecurity::Insecure,
        CarrierSecurity::Secure,
    ] {
        let idp = Idp::with_carrier(&key, security);
        let desc = OpenDesc {
            target: support::TOKEN_URL,
            ..Default::default()
        };
        let conn = idp.prepare_request(owner, NeedId(2), &desc, 0).unwrap();
        assert!(idp.sent().is_empty(), "preparation must send no request");
        assert!(matches!(idp.facts(other, conn), Err(ConnError::Closed)));
        match security {
            CarrierSecurity::Unavailable => {
                assert!(matches!(idp.facts(owner, conn), Err(ConnError::Closed)))
            }
            CarrierSecurity::Insecure => {
                assert!(idp.facts(owner, conn).unwrap().peer_cert.is_none())
            }
            CarrierSecurity::Secure => assert!(idp.facts(owner, conn).unwrap().peer_cert.is_some()),
        }
        let request = OpenDesc {
            method: b"POST",
            head_target: b"/token",
            body: b"code=private".as_slice().into(),
            ..desc.clone()
        };
        assert!(matches!(
            idp.commit_request(other, conn, &request, true),
            Err(ConnError::Closed)
        ));
        let foreign = OpenDesc {
            target: support::JWKS_URL,
            ..request.clone()
        };
        assert!(matches!(
            idp.commit_request(owner, conn, &foreign, true),
            Err(ConnError::Refused)
        ));
        let result = idp.commit_request(owner, conn, &request, true);
        if matches!(security, CarrierSecurity::Secure) {
            result.unwrap();
            assert_eq!(idp.sent().len(), 1);
            assert_eq!(idp.sent()[0].conn, conn.0);
            assert!(matches!(
                idp.commit_request(owner, conn, &request, true),
                Err(ConnError::Refused)
            ));
        } else {
            assert!(matches!(result, Err(ConnError::AuthRefused)));
            assert!(
                idp.sent().is_empty(),
                "HTTPS spelling cannot authorize credentials"
            );
        }
        assert!(matches!(idp.close(other, conn), Err(ConnError::Closed)));
        idp.close(owner, conn).unwrap();
        assert!(matches!(idp.facts(owner, conn), Err(ConnError::Closed)));
    }
}

#[test]
fn login_sends_no_credentials_without_secure_carrier_facts_both_ways() {
    use support::CarrierSecurity;

    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let lib = cdylib();
    let stated = row().statement;
    for security in [CarrierSecurity::Unavailable, CarrierSecurity::Insecure] {
        for arm in [
            Arm::Linked,
            Arm::Dropped {
                lib: &lib,
                stated: &stated,
            },
        ] {
            let idp = Idp::with_carrier(&key, security);
            let b = bind(&arm, &idp);
            let mut cfg: serde_json::Value = serde_json::from_str(&config(AUDIENCE)).unwrap();
            cfg["token_endpoint"] = serde_json::json!(support::TOKEN_URL);
            open(&b.plugin, &cfg.to_string(), Some(CLIENT_SECRET)).unwrap();
            let answer = b.complete(
                "private-code",
                ("st", NONCE),
                REDIRECT,
                "private-verifier",
                None,
            );
            assert_eq!(
                answer.trim_end(),
                format!("verdict {LOGIN_OUTAGE}"),
                "{security:?}"
            );
            assert!(
                idp.sent_to("/token").is_empty(),
                "credentials escaped without secure facts: {security:?}"
            );
            assert!(!answer.contains(CLIENT_SECRET));
            assert!(!answer.contains("private-code"));
            assert!(!answer.contains("private-verifier"));
        }
    }
}
