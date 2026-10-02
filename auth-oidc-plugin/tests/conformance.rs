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
//! opens a socket, dials, binds or does TLS"): its three declared needs carry every request.
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
//! Statement declares exactly the three needs; and the net ban's own RED arm
//! (`support/net_ban.rs`). A missing cdylib PANICS — this test IS the dropped-in door's proof, and
//! never skips.

mod support;

#[path = "support/net_ban.rs"]
mod net_ban;

#[path = "support/import_ban.rs"]
mod import_ban;

use std::time::Duration;

use busbar_contract::abi::auth::{slot, IdentifyOut, IDENTITY_BUF_BYTES, IDENTITY_GROUPS};
use busbar_contract::abi::host::conn::connector::{DIRECTION_OUTBOUND, EGRESS_OPEN_WEB};
use busbar_contract::abi::mechanism::call::{Outcome, Span};
use busbar_contract::abi::mechanism::rendering;
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::kinds::secret::Secret;
use busbar_plugin_loader::dispatch::{now_ns, out_head, Frame, LoadError};
use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};
use busbar_plugin_loader::PluginRegistry;
use support::{
    bind, bind_as, identity_buf, open, row, verify_in, verify_ticketless, z, Arm, Bound, Idp,
    Issuer, DISCOVERY_PATH, ISSUER, UNUSED_ISSUER,
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
    (p.lib_bytes.clone(), stated)
}

/// The operator config: only the issuer and the audience (the JWKS url and both login endpoints
/// are DISCOVERED), and an extra trusted root (the needs' `trust_from`).
fn config(audience: &str) -> String {
    serde_json::json!({
        "issuer": ISSUER,
        "audience": audience,
        "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nconformance\n-----END CERTIFICATE-----\n",
        "role_claim": "roles",
    })
    .to_string()
}

/// The tokens the script presents, minted once so both doors judge the same bytes.
struct Tokens {
    valid: String,
    forged: String,
    wrong_audience: String,
}

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
    })
}

fn tokens(key: &Issuer) -> Tokens {
    Tokens {
        valid: key.sign(&claims(AUDIENCE)),
        forged: Issuer::start(UNUSED_ISSUER, KID).sign(&claims(AUDIENCE)),
        wrong_audience: key.sign(&claims("api://someone-else")),
    }
}

/// What one door does with the module opened under `cfg`, against its own IdP, as one comparable
/// transcript: every answer, then every need the loader declared, every request the IdP saw and
/// how many reads pended.
fn transcript(b: &Bound, cfg: &str, t: &Tokens) -> Vec<String> {
    let id_token = |token: &str| serde_json::json!({ "id_token": token }).to_string();
    let callback = |code: &str, cap| b.complete(code, "st", REDIRECT, "the-verifier", cap);
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
    assert_eq!(a[14], "verdict 3 ", "an IdP 5xx is an outage: {text}");

    // THE NEEDS, as the loader declared them: three outbound open-web https needs trusting
    // `ca_cert_pem`; discovery pinned to the issuer setting's value.
    for (need, target_from, target) in [
        (0, "\"settings.issuer\"", format!("Some({ISSUER:?})")),
        (1, "\"\"", "None".to_string()),
        (2, "\"\"", "None".to_string()),
    ] {
        let want = format!(
            "need {need} direction={DIRECTION_OUTBOUND} class={EGRESS_OPEN_WEB} transport=https \
             target_from={target_from} trust_from=\"settings.ca_cert_pem\" timeout_ms=10000 \
             target={target}"
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
            support::strays(&idp.sent(), needs, &support::declared_targets()),
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
        5,
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

        let ticketless = verify_ticketless(&b.plugin, Some(&token));
        assert_eq!(
            ticketless,
            format!(
                "Failed OIDC discovery fetch failed ({url}): request to {url} failed: the call \
                 runs on no ticket and cannot pend; set jwks_url explicitly"
            )
        );
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
    let allowed = support::declared_targets();
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

/// RED: the rendered Statement declares exactly the three needs — outbound, open-web, `https`,
/// trusting `ca_cert_pem`, discovery pinned to `issuer` — and both doors state the same rendering.
#[test]
fn red_the_statement_declares_three_outbound_open_web_https_needs() {
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
    let need = |target_from| {
        (
            DIRECTION_OUTBOUND,
            EGRESS_OPEN_WEB,
            "https",
            "",
            target_from,
            "settings.ca_cert_pem",
        )
    };
    assert_eq!(
        needs,
        vec![need("settings.issuer"), need(""), need("")],
        "{read:?}"
    );
    let packed = busbar_plugin_loader::dispatch::rendering_of_library(
        &support::cdylib_path().expect("the cdylib is built"),
    )
    .expect("the cdylib loads");
    assert_eq!(packed.as_deref(), Some(&row.statement[..]));
}
