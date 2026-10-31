// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE AUTH MODULE, BOTH DOORS, ONE CONNECTOR** — the OIDC module's linked + dropped-in
//! conformance on the auth kind's memory ABI (THE DESIGN 11.4: compiled in or dropped in, one door,
//! one table), run against the busbar rev this repo pins (`.busbar-ref`).
//!
//! The door is held two ways at once: LINKED (`busbar_auth_oidc::door::door`, the row a busbar
//! build that compiles the module in registers, `LinkedRow::of`) and DROPPED IN (this crate's built
//! cdylib, signed first-party into a temp `plugins/` directory under a manifest stating the door's
//! Statement, found by the loader's scan and admitted against that signed Statement). Each is bound
//! to a real dispatcher serving the host's clock and to a connection table that PLAYS THE IdP
//! (`support::Idp`: discovery document, JWKS, token endpoint; the first read of every reply PENDING,
//! the op's ticket woken from another thread). The module never dials (THE DESIGN 5: "No plugin
//! opens a socket, dials, binds or does TLS"): its declared needs carry every request (three
//! trusting `ca_cert_pem`, three their public-roots twins for a config that names none).
//!
//! Both doors run the same script — open with NO jwks_url and NO login endpoints, so the first
//! verify discovers the JWKS url and fetches the JWKS, each request crossing PENDING; real ES256
//! tokens verified (valid, forged, wrong audience, not a JWT, none; a short identity buffer
//! re-called once); the authorize URL from the discovered endpoint; the login's own token exchange
//! (an identity, a short buffer served without a second exchange, a forged `id_token`, an
//! `invalid_grant`, an IdP outage) — and the two transcripts, the requests the IdP saw included,
//! must be identical.
//!
//! THE RED ARMS, same file: the same cdylib under a different config is a different transcript; the
//! same bytes stated as `secret` are refused at the manifest's kind; a Statement that is not the
//! door's is refused at admit; an unreachable issuer fails verify with 1.5.5's discovery text; a
//! ticketless call (which may not pend) fails at once and asks the IdP nothing; the rendered
//! Statement declares exactly the six needs; a config with no `ca_cert_pem` answers the same
//! script over the public-roots needs, the ones trusting it refused at declaration; and the net
//! ban's own RED arm (`support/net_ban.rs`). A missing cdylib PANICS — this test IS the dropped-in door's proof, and
//! never skips.

mod support;

// BUSBAR'S PUBLISHED CONFORMANCE SUITE (plugin-ci's conformance step): the linked door and this
// crate's cdylib through the one loader, driven by the auth kind's script (verify, the login
// family, the far ends the module's needs reach: `conformance.json`), exact crossings, both folds
// equal, its RED arms kept.
busbar_test_kit::conformance_suite! {
    door: busbar_auth_oidc::door::door,
    cdylib: "busbar_auth_oidc_plugin",
    inputs: include_str!("conformance.json"),
}

#[path = "support/net_ban.rs"]
mod net_ban;

#[path = "support/import_ban.rs"]
mod import_ban;

use std::time::Duration;

use busbar_contract::abi::auth::{
    slot, IdentifyOut, IDENTITY_BUF_BYTES, IDENTITY_GROUPS, LOGIN_BAD_CREDENTIAL, LOGIN_OUTAGE,
    METRIC_CACHE_FLUSHED,
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
/// `statement` (lowercase hex, as `busbar-plugin-pack` writes it).
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
/// policy holding the release key.
fn scanned(tag: &str, manifest: Manifest, lib: &[u8]) -> PluginRegistry {
    let dir = std::env::temp_dir().join(format!("auth-oidc-conf-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let signed = sign(&release(), manifest, lib);
    let tarball = busbar_plugin_loader::tarball::package(&signed, "libauth.so", lib).unwrap();
    std::fs::write(dir.join("auth.tar.gz"), tarball).unwrap();
    let policy = TrustPolicy {
        first_party_key: Some(release().verifying_key()),
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
/// are DISCOVERED), and an extra trusted root (the anchored needs' `trust_from`).
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
/// public roots only.
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
/// identity token the IdP answers for this login carries it.
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

/// What one door does with the module opened under `cfg`, against its own IdP, as one comparable
/// transcript: every answer, then every need the loader declared, every request the IdP saw and
/// how many reads pended.
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
/// connector — and the RED arms show the comparison is not vacuous.
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

    let linked = bind(&Arm::Linked, &Idp::new(&key));
    let dropped = bind(
        &Arm::Dropped {
            lib: &lib,
            stated: &stated,
        },
        &Idp::new(&key),
    );
    let a = transcript(&linked, &cfg, &t);
    let b = transcript(&dropped, &cfg, &t);
    assert_eq!(a, b, "the two doors are not one module");

    // Not a vacuous pass: the script did what the module is for.
    let text = a.join("\n");
    assert_eq!(a[0], format!("name {NAME}"), "{text}");
    assert_eq!(a[1], "open Ok(())", "{text}");
    assert!(
        a[2].starts_with("verdict 1 subject=Some(\"oidc:conformance-subject\")")
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
        a[9].starts_with("verdict 1 subject=Some(\"oidc:conformance-subject\")"),
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

    // THE NEEDS, as the loader declared them: six outbound https needs (discovery and the JWKS
    // open-web, the token exchange the default class: a private IdP address is refused unless
    // allowlisted, security item 3), the three
    // trusting `ca_cert_pem` then their public-roots twins; discovery pinned to the issuer
    // setting's value. With `ca_cert_pem` set every one is carried.
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

    // THE REQUESTS: ONE discovery GET and ONE JWKS GET for the whole script (single-flight and
    // the cache), each to the URL the module named, on its own need; the token POSTs on the token
    // need, carrying the lent secret.
    let sent = linked.idp.sent();
    // NO CONNECTION OUTSIDE THE DECLARED NEEDS: every establish names a declared need index and
    // that need's configured target.
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

    // RED ARM 1: the same cdylib under a different operator config (another audience) is a
    // different transcript — the token the linked door identified is now refused.
    let other = bind(
        &Arm::Dropped {
            lib: &lib,
            stated: &stated,
        },
        &Idp::new(&key),
    );
    assert_ne!(
        transcript(&other, &config("api://someone-else"), &t),
        a,
        "a different config must not read as the same module"
    );

    // THE PUBLIC ROOTS: with no `ca_cert_pem` (optional, as in 1.5.5) the needs trusting it are
    // refused at declaration (the host refuses a `trust_from` that names nothing), and the module
    // answers the same script the same way over their public-roots twins, asking nothing of a
    // refused need.
    let public = bind(
        &Arm::Dropped {
            lib: &lib,
            stated: &stated,
        },
        &Idp::new(&key),
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

    // RED ARM 2: the same bytes stated as `secret` are refused at the manifest's kind.
    let arm = Arm::Dropped {
        lib: &lib,
        stated: &stated,
    };
    match bind_as::<Secret>(&arm, &Idp::new(&key)).1 {
        Err(LoadError::ManifestKind { .. }) => {}
        Err(e) => panic!("an auth door stated as secret must be refused at its kind: {e}"),
        Ok(_) => panic!("an auth door stated as secret must not load"),
    }

    // RED ARM 3: a manifest whose Statement is not the door's is refused at admit.
    let mut tampered = stated.clone();
    *tampered.last_mut().expect("a rendering") ^= 1;
    let arm = Arm::Dropped {
        lib: &lib,
        stated: &tampered,
    };
    match bind_as::<Auth>(&arm, &Idp::new(&key)).1 {
        Err(LoadError::StatementMismatch) => {}
        Err(e) => panic!("a Statement that is not the door's must be refused as one: {e}"),
        Ok(_) => panic!("a Statement that is not the door's must not load"),
    }
}

/// RED: an unreachable issuer fails verify with 1.5.5's discovery text (1.5.5 refused boot with
/// it; the module now fetches nothing at open — THE SEAM), and a call on no ticket, which may not
/// pend, fails at once and asks the IdP nothing. Both doors alike.
#[test]
fn red_an_unreachable_issuer_and_a_ticketless_call_fail_verify_in_1_5_5_s_words() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let token = key.sign(&claims(AUDIENCE));
    let lib = cdylib();
    let stated = row().statement;
    let url = format!("https://idp.conformance.example{DISCOVERY_PATH}");
    let mut seen = Vec::new();
    for arm in [
        Arm::Linked,
        Arm::Dropped {
            lib: &lib,
            stated: &stated,
        },
    ] {
        let idp = Idp::new(&key);
        idp.answer(DISCOVERY_PATH, 503, "{}");
        let b = bind(&arm, &idp);
        open(&b.plugin, &config(AUDIENCE), None).expect("opens: nothing is fetched at open");

        // ON THE SPOT (no ticket) the verify needs a fetch it may not pend on: REFUSED, so the
        // host makes it again on a ticket (`abi::auth`).
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
                 Unavailable; set jwks_url explicitly"
            )
        );
        seen.push((ticketless, refused));
    }
    assert_eq!(seen[0], seen[1], "both doors alike");
}

/// SINGLE-FLIGHT through the real dispatcher (THE DESIGN, auth: "a cold key id pends verify, one
/// `exchange()` fetches, every waiter wakes"): two cold verifies in flight at once make ONE
/// discovery request and ONE JWKS request between them, and both identify.
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
/// at once.
fn cold_verifies(staggered: bool) {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let token = key.sign(&claims(AUDIENCE));
    let idp = Idp::new(&key);
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
    // The first verify is submitted, and the second only once the first has pended on its
    // discovery request: the second arrives while the first's fetch is in flight.
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

/// THE BODY CAP IS ENFORCED WHILE READING: a discovery reply far past the 1 MiB cap is refused in
/// 1.5.5's words, and the plugin stopped reading at the cap rather than buffering the SDK's
/// 16 MiB reply ceiling first (1.5.5 read at most cap + 1 bytes).
#[test]
fn red_an_oversized_reply_is_cut_off_at_the_cap_not_buffered_whole() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let token = key.sign(&claims(AUDIENCE));
    let idp = Idp::new(&key);
    let huge = "x".repeat(4 * 1024 * 1024);
    idp.answer(DISCOVERY_PATH, 200, &huge);
    let b = bind(&Arm::Linked, &idp);
    open(&b.plugin, &config(AUDIENCE), None).expect("opens");

    let refused = b.verify(Some(&token), None);
    let url = format!("https://idp.conformance.example{DISCOVERY_PATH}");
    assert_eq!(
        refused,
        format!(
            "Failed OIDC discovery fetch failed ({url}): {url} JWKS body exceeds the 1048576-byte \
             cap; set jwks_url explicitly"
        )
    );
    assert!(
        idp.served() < 2 * 1024 * 1024,
        "the plugin read {} bytes of a reply capped at 1 MiB",
        idp.served()
    );
}

/// THE STATUS IS JUDGED BEFORE THE BODY, as 1.5.5 judged it: a non-2xx discovery reply with a body
/// far past the cap is refused naming its status, and is still cut off at the cap while reading.
#[test]
fn red_an_oversized_error_reply_names_its_status_and_is_cut_off_at_the_cap() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let token = key.sign(&claims(AUDIENCE));
    let idp = Idp::new(&key);
    let huge = "x".repeat(4 * 1024 * 1024);
    idp.answer(DISCOVERY_PATH, 500, &huge);
    let b = bind(&Arm::Linked, &idp);
    open(&b.plugin, &config(AUDIENCE), None).expect("opens");

    let refused = b.verify(Some(&token), None);
    let url = format!("https://idp.conformance.example{DISCOVERY_PATH}");
    assert_eq!(
        refused,
        format!(
            "Failed OIDC discovery fetch failed ({url}): {url} returned HTTP 500 Internal Server \
             Error; set jwks_url explicitly"
        )
    );
    assert!(
        idp.served() < 2 * 1024 * 1024,
        "the plugin read {} bytes of a reply capped at 1 MiB",
        idp.served()
    );
}

/// THE LOGIN WHOSE KEY SET CANNOT BE HAD, through the real dispatcher (OWNER-SIGNED 2026-10-30:
/// an IdP outage is never a 401). The token endpoint answers an identity token, but the key set's
/// URL is to be discovered and the issuer's discovery answers 503: the door answers
/// `LOGIN_OUTAGE` (the IdP could not be had), never `LOGIN_BAD_CREDENTIAL` (1.5.5 rendered this
/// as the declined sign-in; the owner reversed that).
#[test]
fn a_login_whose_key_set_cannot_be_had_is_an_outage_not_declined() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let idp = Idp::new(&key);
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

/// THE WAKE through the real dispatcher (THE DESIGN, auth: "every waiter wakes"): a verify that
/// waits on another verify's discovery and JWKS fetches is woken when each lands, arming its
/// backstop timer once per wait, rather than polling a short timer for as long as the fetch takes.
/// Each IdP reply pends 400 ms; a waiter polling every 25 ms reads the host clock dozens of times.
#[test]
fn a_waiter_is_woken_by_the_fetch_it_waits_on_not_a_polling_timer() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let token = key.sign(&claims(AUDIENCE));
    let idp = Idp::new(&key);
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

/// THE TICK (THE DESIGN, auth: "`tick` refreshes ahead of the TTL, with 1.5.5's timings"), through
/// the real dispatcher on the instance's driver ticket: a tick before the key set is due fetches
/// nothing; once it is within one tick period (`jwks_min_refetch_secs`) of its TTL, the tick fetches
/// it — pending, carried on by `drive` when the IdP's answer wakes the driver ticket — before the
/// TTL runs out, so no request is the one that waits on the refresh. Each tick asks for the next one
/// a period on.
#[test]
fn a_tick_refreshes_the_key_set_ahead_of_its_ttl() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let token = key.sign(&claims(AUDIENCE));
    let idp = Idp::new(&key);
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

    // Within one period of the 3 s TTL, before it runs out.
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

/// RED: a request on an undeclared need index, or to a target its need does not name, is caught by
/// the check the conformance transcript holds every establish to.
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

/// RED: the rendered Statement declares exactly the six needs — outbound, `http`, discovery and the
/// JWKS open-web and the token exchange the default class (a private IdP address refused unless
/// allowlisted, security item 3; the token exchange still takes 1.5.5's http to a private host), three
/// trusting `ca_cert_pem` then their public-roots twins, discovery pinned to `issuer` — and both
/// doors state the same rendering.
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
    let packed = busbar_plugin_loader::dispatch::rendering_of_library(
        &support::cdylib_path().expect("the cdylib is built"),
    )
    .expect("the cdylib loads");
    assert_eq!(packed.as_deref(), Some(&row.statement[..]));
}

/// A BEARER THAT IS NOT UTF-8 IS NOT THIS MODULE'S CREDENTIAL, ANSWERED AS ONE (Q128 auth-oidc
/// MEDIUM, reader r61 on 7b84416; THE DESIGN §6 "Auth points and guest lists": every auth called
/// names its credential lines whatever its verdict): PASS with the chain's CONTINUE decision and the
/// credential line named for the transport to strip, as 1.5.5 passed a header that did not read as
/// text (no bearer for this module). RED before the fix: PASS with no decision and no strip name,
/// which the host faults.
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
        let idp = Idp::new(&key);
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

/// AN IDENTITY CARRIES THE CREDENTIAL IT WAS VERIFIED FROM (Q128 auth-oidc LOW, reader r81 on
/// 59293c0; THE DESIGN §6 "Auth points and guest lists", step 4; `IdentityOut::credential`): the
/// kernel holds it on the unit for the `caller-credential` style. RED before the fix: the span was
/// absent.
#[test]
fn an_identity_carries_the_credential_it_was_verified_from() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let token = key.sign(&claims(AUDIENCE));
    let idp = Idp::new(&key);
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

/// ONE CLOCK (THE DESIGN §1): a token's expiry is judged at the request's own timestamp, the
/// host's clock as it arrived, never one the plugin reads; a request stating none (`0`) fails
/// closed. A token valid for the next hour is refused at a request two hours on. RED before the fix:
/// the plugin judged expiry on the OS clock, so the late request was identified.
#[test]
fn a_token_s_expiry_is_judged_at_the_request_s_timestamp() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let token = key.sign(&claims(AUDIENCE));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for (at, identified) in [(now + 7200, false), (0, false), (now, true)] {
        let idp = Idp::new(&key);
        let b = bind(&Arm::Linked, &idp);
        open(&b.plugin, &config(AUDIENCE), None).expect("opens");
        let verdict = b.verify_at(Some(&token), at);
        assert_eq!(
            verdict.contains("verdict 1 "),
            identified,
            "at {at}: {verdict}"
        );
    }
}

/// A `verify` of `token` submitted on its own ticket and left in flight; the closure waits for
/// its answer (`verdict N`, or the outcome). `token` must outlive the call of the closure.
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
        assert!(std::time::Instant::now() < until, "never pended: {:?}", idp.sent());
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// L1: a verify that claimed the key set's refresh and pended on it, re-entered after ANOTHER
/// verify cached the same token's identity meanwhile, still LANDS its own fetch: the rotated key
/// the IdP answered is installed, so a token signed by it verifies at once. (Before, the re-entry
/// answered from the verdict cache and dropped the fetch: the flight stayed claimed, the new key
/// never arrived and the rate limit refused the rotation refetch.)
#[test]
fn a_verify_meeting_the_verdict_cache_on_re_entry_still_lands_its_fetch() {
    let _one = support::serial();
    let old = Issuer::start(UNUSED_ISSUER, KID);
    let new = Issuer::start(UNUSED_ISSUER, "rotated-kid");
    let idp = Idp::new(&old);
    let b = bind(&Arm::Linked, &idp);
    let mut cfg: serde_json::Value = serde_json::from_str(&config(AUDIENCE)).unwrap();
    cfg["jwks_ttl_secs"] = serde_json::json!(1);
    cfg["jwks_min_refetch_secs"] = serde_json::json!(2);
    open(&b.plugin, &cfg.to_string(), None).expect("opens");
    assert!(b.verify(Some(&old.sign(&claims(AUDIENCE))), None).starts_with("verdict 1 "));

    // The set goes stale and the rate limit lets a refresh through; the IdP has rotated.
    std::thread::sleep(Duration::from_millis(2100));
    let keys = |i: &Issuer| serde_json::from_str::<serde_json::Value>(i.jwks()).unwrap()["keys"][0].clone();
    let both = serde_json::json!({ "keys": [keys(&old), keys(&new)] }).to_string();
    idp.answer("/keys", 200, &both);
    idp.pend_for(Duration::from_millis(800));
    let pended = idp.pended();

    let mut c = claims(AUDIENCE);
    c["sub"] = serde_json::json!("cached-meanwhile");
    let token = old.sign(&c);
    let a = verify_in_flight(&b, &token);
    until_pended(&idp, pended + 1);
    // Another verify of the same token, on the stale set, caches its identity.
    assert!(b.verify(Some(&token), None).starts_with("verdict 1 "));
    assert_eq!(a(), "verdict 1");

    assert!(
        b.verify(Some(&new.sign(&claims(AUDIENCE))), None).starts_with("verdict 1 "),
        "the refresh the first verify claimed landed the rotated key"
    );
    assert_eq!(idp.sent_to("/keys").len(), 2, "{:?}", idp.sent());
}

/// L2: a tick arriving while the previous tick's refresh is still in flight on the driver ticket
/// carries THAT fetch on rather than starting a second exchange for the same key set.
#[test]
fn a_tick_during_the_last_tick_s_fetch_does_not_fetch_again() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let idp = Idp::new(&key);
    let b = bind(&Arm::Linked, &idp);
    let mut cfg: serde_json::Value = serde_json::from_str(&config(AUDIENCE)).unwrap();
    cfg["jwks_ttl_secs"] = serde_json::json!(3);
    cfg["jwks_min_refetch_secs"] = serde_json::json!(1);
    open(&b.plugin, &cfg.to_string(), None).expect("opens");
    assert!(b.verify(Some(&key.sign(&claims(AUDIENCE))), None).starts_with("verdict 1 "));
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

/// L6: `ready` meeting another op's discovery in flight WAITS for it (woken when it settles),
/// rather than approving the boot unseen: a discovery that then fails refuses the boot.
#[test]
fn ready_waits_on_another_op_s_discovery_and_a_failure_refuses_the_boot() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let idp = Idp::new(&key);
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
    assert_eq!(idp.sent_to(DISCOVERY_PATH).len(), 1, "ready made no fetch of its own");
}

/// T2: a login's id_token is judged for expiry at the HOST's wall clock (`clock.now`), through the
/// real door: one that expired, or is not yet valid, is a declined login; a fresh one identifies.
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
    for (what, c, identified) in [
        ("expired", expired, false),
        ("not yet valid", early, false),
        ("fresh", claims(AUDIENCE), true),
    ] {
        let idp = Idp::new(&key);
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

/// T3: an IdP destination the host's guard REFUSES is audited through the door: the verify fails,
/// and the door raises its declared `OIDC_IDP_DESTINATION_REFUSED` at error naming the host and
/// the rule (never the URL's path) — once per module, not once per request.
#[test]
fn a_refused_idp_destination_raises_its_declared_diagnostic_once() {
    let _one = support::serial();
    let key = Issuer::start(UNUSED_ISSUER, KID);
    let idp = Idp::new(&key);
    let b = bind(&Arm::Linked, &idp);
    let mut cfg: serde_json::Value = serde_json::from_str(&config(AUDIENCE)).unwrap();
    cfg["jwks_min_refetch_secs"] = serde_json::json!(1);
    open(&b.plugin, &cfg.to_string(), None).expect("opens");
    // The JWKS need (anchored set: `ca_cert_pem` is configured) is refused by the guard.
    idp.refuse(1);
    let token = key.sign(&claims(AUDIENCE));
    assert!(b.verify(Some(&token), None).starts_with("Failed"));
    let raised = idp.diags();
    assert_eq!(raised.len(), 1, "{raised:?}");
    assert!(
        raised[0].starts_with("OIDC_IDP_DESTINATION_REFUSED 2 ")
            && raised[0].contains("idp.conformance.example")
            && !raised[0].contains("/keys"),
        "{raised:?}"
    );
    // Past the retry bound the fetch is made, and refused, again: not raised again.
    std::thread::sleep(Duration::from_millis(1100));
    assert!(b.verify(Some(&token), None).starts_with("Failed"));
    assert_eq!(idp.diags().len(), 1, "raised once: {:?}", idp.diags());
}
