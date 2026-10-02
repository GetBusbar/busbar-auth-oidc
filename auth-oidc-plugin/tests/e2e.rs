// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! End-to-end coverage of the `busbar-auth-oidc-plugin` cdylib DROPPED IN through the real loader's
//! door validation and dispatcher (`load_dropped`), the auth kind's memory ABI: a real ES256-signed
//! JWT verified across the door against the JWKS the plugin fetched through the host's connection
//! table (`support::Idp`, the IdP as the host's connector hands it the request), a genuine
//! signature verification and claim-to-identity mapping.
//!
//! The admin-API install test drives a real `busbar` binary built from `BUSBAR_CHECKOUT`, whose
//! connector dials the logic crate's testkit issuer (a real self-signed cert, a real `rustls`
//! listener — a test server, never the plugin's).

use busbar_plugin_loader::plugin_library_filename;

/// Locate the built `busbar_auth_oidc_plugin` cdylib in the target dir (mirrors the loader's own
/// `auth_oidc_plugin_path` test helper). Under CI, a missing cdylib is a hard failure — this is the
/// only over-the-ABI coverage of the `kind: auth` dlopen seam and must never silently skip there.
/// Checks BOTH the "uplifted" `<profile_dir>/<name>` copy (only refreshed when `[lib]` is a ROOT
/// build target, e.g. `cargo build --all-targets`) and the raw `<profile_dir>/deps/<name>` compiler
/// output (refreshed on every build that recompiles the lib). A bare `cargo test --release` does
/// NOT uplift the cdylib to the top-level profile dir, only to `target/deps`, so checking only
/// `profile_dir` silently finds nothing even though the cdylib really was built.
fn plugin_path() -> Option<std::path::PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = plugin_library_filename("busbar_auth_oidc_plugin");
        let uplifted = profile_dir.join(&name);
        let raw = profile_dir.join("deps").join(&name);
        [uplifted, raw]
            .into_iter()
            .filter_map(|p| {
                std::fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .ok()
                    .map(|mtime| (p, mtime))
            })
            .max_by_key(|(_, mtime)| *mtime)
            .map(|(p, _)| p)
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "the auth-oidc plugin cdylib is not built under CI: `cargo test --workspace` must \
             build busbar_auth_oidc_plugin (checked both the uplifted target dir and target/deps). \
             Refusing to silently skip the only over-the-ABI coverage of the kind:auth dlopen seam."
        );
    }
    candidate
}

mod support;
use support::{Arm, Idp, Issuer, UNUSED_ISSUER};

/// End-to-end SUCCESS: dlopen the real auth-oidc-plugin cdylib, `open` it against a config naming
/// the IdP's JWKS explicitly (so no discovery), then `verify` a real ES256-signed JWT across the
/// door: the JWKS is fetched through the host's connection table on the JWKS need, and the identity
/// + mapped groups come back.
#[test]
fn load_and_exercise_auth_oidc_plugin_success() {
    let Some(path) = plugin_path() else {
        eprintln!("skip: auth-oidc plugin cdylib not built (run under --workspace)");
        return;
    };

    let key = Issuer::start(UNUSED_ISSUER, "test-kid-1");
    const AUDIENCE: &str = "api://busbar-client";
    let cfg = serde_json::json!({
        "issuer": support::ISSUER,
        "audience": AUDIENCE,
        "jwks_url": support::JWKS_URL,
    })
    .to_string();

    let idp = Idp::new(&key);
    let module = support::bind(&Arm::File(&path), &idp);
    assert_eq!(module.plugin.name(), "busbar-auth-oidc");
    support::open(&module.plugin, &cfg, None).expect("the module opens across the door");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = serde_json::json!({
        "iss": support::ISSUER,
        "aud": AUDIENCE,
        "exp": now + 3600,
        "nbf": now - 10,
        "sub": "subject-guid",
        "preferred_username": "alice@contoso.example",
        "name": "Alice Example",
        "groups": ["11111111-aaaa", "22222222-bbbb"],
    });
    let token = key.sign(&claims);

    // No `oid` claim in this fixture, so the IMMUTABLE `sub` is the identity of record —
    // `preferred_username` is display-only, never identity.
    let identified = module.verify(Some(&token), None);
    assert!(
        identified.starts_with(
            "verdict 1 subject=Some(\"oidc:subject-guid\") name=Some(\"Alice Example\") \
             groups=[\"11111111-aaaa\", \"22222222-bbbb\"]"
        ),
        "expected the JWKS fetch through the host + real signature verification to identify the \
         caller, got {identified}"
    );
    let sent = idp.sent();
    assert_eq!(sent.len(), 1, "one JWKS GET, no discovery: {sent:?}");
    assert_eq!(
        (sent[0].need, sent[0].target.as_str(), sent[0].path.as_str()),
        (1, support::JWKS_URL, "/keys")
    );

    // A token signed by a DIFFERENT key (same kid) must fail closed across the door too.
    let forged_token = Issuer::start(UNUSED_ISSUER, "test-kid-1").sign(&claims);
    assert_eq!(
        module.verify(Some(&forged_token), None),
        "verdict 2 ",
        "a token signed by the wrong key must be rejected across the door"
    );
}

/// The busbar checkout the live e2e builds the REAL `busbar` and `busbar-plugin-pack` binaries from:
/// `BUSBAR_CHECKOUT`, a checkout of GetBusbar/busbar at `.busbar-ref` field 1 (this repo's CI `e2e` job
/// checks it out and sets the variable). This repo builds against busbar by git rev, not a sibling
/// path, so the binaries' source is named explicitly. Unset ⇒ the live leg cannot run, and says so.
fn busbar_root() -> std::path::PathBuf {
    let dir = std::env::var_os("BUSBAR_CHECKOUT").expect(
        "BUSBAR_CHECKOUT is unset: the live e2e builds the real busbar binaries from a checkout of \
         GetBusbar/busbar at .busbar-ref (ci.yml `e2e` sets it)",
    );
    std::path::PathBuf::from(dir)
        .canonicalize()
        .expect("BUSBAR_CHECKOUT names an existing busbar checkout")
}

/// Build (once, cached by cargo) and return the real `busbar` and `busbar-plugin-pack` binaries from
/// the sibling busbar checkout — never a fixture, the exact binaries a real release ships.
fn build_real_binaries() -> (std::path::PathBuf, std::path::PathBuf) {
    let root = busbar_root();
    // Two invocations: in busbar 1.6.0 `busbar-plugin-pack` is a feature-gated bin of the
    // `busbar-plugin-loader` package (`--features pack`), not a package of its own, and building it
    // separately keeps the `pack` feature out of the `busbar` build.
    for args in [
        &["build", "--release", "-p", "busbar", "--bin", "busbar"][..],
        &[
            "build",
            "--release",
            "-p",
            "busbar-plugin-loader",
            "--features",
            "pack",
            "--bin",
            "busbar-plugin-pack",
        ][..],
    ] {
        let status = std::process::Command::new("cargo")
            .args(args)
            .current_dir(&root)
            // The binaries are read back from `<sibling>/target/release` below, so the build must
            // land there: an inherited CARGO_TARGET_DIR (set for the outer `cargo test`) would
            // redirect it into the plugin's own target dir.
            .env_remove("CARGO_TARGET_DIR")
            .status()
            .expect("run cargo build for busbar / busbar-plugin-pack");
        assert!(
            status.success(),
            "building the real busbar + busbar-plugin-pack binaries must succeed ({args:?})"
        );
    }
    (
        root.join("target/release/busbar"),
        root.join("target/release/busbar-plugin-pack"),
    )
}

/// Pack the built auth-oidc-plugin cdylib into a real signed-shape tarball via the real
/// `busbar-plugin-pack` tool, `--allow-unsigned` exactly like CI's own unsigned-key fallback.
fn pack_oidc_tarball(
    pack_bin: &std::path::Path,
    so_path: &std::path::Path,
    out: &std::path::Path,
) -> Vec<u8> {
    let status = std::process::Command::new(pack_bin)
        .args([
            "pack",
            "--lib",
            so_path.to_str().unwrap(),
            "--name",
            "busbar-auth-oidc",
            "--alias",
            "oidc",
            "--kind",
            "auth",
            "--version",
            "0.0.0-e2e",
            "--publisher",
            "busbar",
            "--description",
            "e2e admin-api install proof",
            "--license",
            "Apache-2.0",
            "--out",
            out.to_str().unwrap(),
            "--allow-unsigned",
        ])
        .status()
        .expect("run busbar-plugin-pack");
    assert!(status.success(), "packing the plugin must succeed");
    std::fs::read(out).unwrap()
}

/// An ephemeral local TCP port (bind :0, read back the OS-assigned port, drop the listener before the
/// real caller binds it — same tiny TOCTOU store-sqlite's own e2e test accepts, fine for a test).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Poll the admin API's `GET /api/v1/admin/plugins` until it answers (or the child exits early).
fn wait_for_admin_ready(
    client: &reqwest::blocking::Client,
    admin_addr: &str,
    admin_token: &str,
    child: &mut std::process::Child,
) -> bool {
    for _ in 0..150 {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("busbar exited early during admin-readiness poll: {status}");
        }
        if client
            .get(format!(
                "http://{admin_addr}/api/v1/admin/plugins?type=auth"
            ))
            .header("x-admin-token", admin_token)
            .send()
            .is_ok_and(|r| r.status().is_success())
        {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    false
}

/// The full install-path proof: not a direct ABI `load_auth_from_bytes` call (the tests above
/// already cover that seam) and not a
/// file-drop — an operator installing a NEW auth plugin onto a LIVE gateway does it over the real
/// Admin API (`POST /api/v1/admin/plugins`), then the auth chain picks it up on the next boot (auth
/// modules are, like store, restart-to-apply — a fresh process is the real mechanism, not an invented
/// shortcut). This test: boots a real busbar with the admin listener up, installs the built
/// auth-oidc-plugin cdylib over that live HTTP API, restarts onto `auth.chain: [oidc]` pointing at a
/// REAL local HTTPS JWKS fixture (the same `busbar_auth_oidc::testkit::Issuer` the direct-ABI test
/// above uses — a real self-signed TLS cert, a real ES256 keypair), then drives a REAL data-plane
/// HTTP request carrying a REAL signed bearer JWT through the live process and confirms it is
/// authenticated (not 401) — and that a token from the WRONG key is rejected (401), proving the full
/// real-world path: real admin API install -> real boot pickup -> real JWKS fetch -> real signature
/// verification -> a real request actually let through.
#[test]
fn install_oidc_plugin_via_admin_api_and_authenticate() {
    let Some(so_path) = plugin_path() else {
        eprintln!("skip: auth-oidc-plugin cdylib not built");
        return;
    };
    if std::env::var_os("BUSBAR_CHECKOUT").is_none() {
        // The live install leg boots the REAL busbar binary, built from a busbar checkout at
        // `.busbar-ref`; ci.yml's `e2e` job provides one and sets BUSBAR_CHECKOUT. Loud, never silent.
        eprintln!(
            "skip: BUSBAR_CHECKOUT unset — the admin-API install e2e needs a busbar checkout at \
             .busbar-ref to build the real busbar binary (ci.yml `e2e` runs it)"
        );
        return;
    }
    let (busbar_bin, pack_bin) = build_real_binaries();

    let key = Issuer::start(UNUSED_ISSUER, "admin-e2e-kid");
    let (jwks_url, cert_pem) = (key.jwks_url().to_string(), key.cert_pem().to_string());
    const ISSUER: &str = "https://oidc-admin-e2e.invalid/v2.0";
    const AUDIENCE: &str = "api://busbar-admin-e2e";

    let work = std::env::temp_dir().join(format!(
        "busbar-oidc-admin-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let plugins_dir = work.join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();
    const ADMIN_TOKEN: &str = "e2e-oidc-admin-token";

    let providers = work.join("providers.yaml");
    std::fs::write(
        &providers,
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();

    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(false)
        .build()
        .unwrap();

    // ── BOOT 1: auth.chain: [], just to reach a live admin listener to install against. ──
    let data_port1 = free_port();
    let admin_port1 = free_port();
    let config1 = work.join("config1.yaml");
    std::fs::write(
        &config1,
        format!(
            "listen: \"127.0.0.1:{data_port1}\"\n\
             admin_listen: \"127.0.0.1:{admin_port1}\"\n\
             plugins:\n  enabled: true\n  dir: {}\n  trust:\n    allow_unsigned: true\n\
             identity-providers:\n  admin-tokens: {{ module: admin-tokens, token: {{ env: BUSBAR_ADMIN_TOKEN }} }}\n\
             auth:\n  chain: []\n  admin_auth: [admin-tokens]\n\
             providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
             models:\n  test-model:\n    provider: mock\n",
            plugins_dir.display()
        ),
    )
    .unwrap();
    let admin_addr1 = format!("127.0.0.1:{admin_port1}");

    let mut child1 = std::process::Command::new(&busbar_bin)
        .env("BUSBAR_CONFIG", &config1)
        .env("BUSBAR_PROVIDERS", &providers)
        .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
        .env("MOCK_KEY", "unused-mock-provider-key")
        .env("BUSBAR_STATE_FILE", "")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn boot 1 (empty auth chain, admin listener up)");
    assert!(
        wait_for_admin_ready(&client, &admin_addr1, ADMIN_TOKEN, &mut child1),
        "boot 1's admin API must become ready within 15s"
    );

    // ── REAL ADMIN-API INSTALL: POST the packed auth-oidc plugin tarball to /api/v1/admin/plugins. ──
    let tarball_path = work.join("auth-oidc-admin.tar.gz");
    let tarball = pack_oidc_tarball(&pack_bin, &so_path, &tarball_path);
    let file = "auth-oidc-admin.tar.gz";
    use base64::Engine as _;
    let install_resp = client
        .post(format!("http://{admin_addr1}/api/v1/admin/plugins"))
        .header("x-admin-token", ADMIN_TOKEN)
        .json(&serde_json::json!({
            "file": file,
            "tarball_b64": base64::engine::general_purpose::STANDARD.encode(&tarball),
        }))
        .send()
        .expect("POST /api/v1/admin/plugins");
    assert_eq!(
        install_resp.status().as_u16(),
        201,
        "the real admin API must accept the auth-oidc plugin install: {}",
        install_resp.text().unwrap_or_default()
    );
    let installed: serde_json::Value = install_resp.json().unwrap();
    assert_eq!(installed["file"], file);
    assert_eq!(installed["name"], "busbar-auth-oidc");
    assert!(
        plugins_dir.join(file).exists(),
        "the admin API install must have written the tarball to the real plugins dir"
    );

    let catalog: serde_json::Value = client
        .get(format!(
            "http://{admin_addr1}/api/v1/admin/plugins?type=auth"
        ))
        .header("x-admin-token", ADMIN_TOKEN)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let listed = catalog["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["target"] == file)
        .expect("the just-installed auth-oidc plugin appears in the auth catalog");
    assert_eq!(listed["valid"], true);

    let _ = child1.kill();
    let _ = child1.wait();

    // ── BOOT 2: auth.chain: [oidc], over the SAME plugins dir the admin API wrote into above.
    // Restart-to-apply, mirroring store's own documented mechanism. ──
    let data_port2 = free_port();
    let admin_port2 = free_port();
    let config2 = work.join("config2.yaml");
    std::fs::write(
        &config2,
        format!(
            "listen: \"127.0.0.1:{data_port2}\"\n\
             admin_listen: \"127.0.0.1:{admin_port2}\"\n\
             plugins:\n  enabled: true\n  dir: {}\n  trust:\n    allow_unsigned: true\n\
             identity-providers:\n  admin-tokens: {{ module: admin-tokens, token: {{ env: BUSBAR_ADMIN_TOKEN }} }}\n\
             \x20 oidc:\n    module: oidc\n    settings:\n      issuer: \"{ISSUER}\"\n      audience: \"{AUDIENCE}\"\n\
             \x20     authorization_endpoint: \"{ISSUER}/authorize\"\n\
             \x20     token_endpoint: \"{ISSUER}/token\"\n\
             \x20     jwks_url: \"{jwks_url}\"\n      ca_cert_pem: |\n{}\n\
             auth:\n  admin_auth: [admin-tokens]\n  chain: [oidc]\n\
             \x20 role_bindings:\n    oidc:\n      \"11111111-aaaa\": {{}}\n\
             providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
             models:\n  test-model:\n    provider: mock\n",
            plugins_dir.display(),
            cert_pem
                .lines()
                .map(|l| format!("            {l}"))
                .collect::<Vec<_>>()
                .join("\n"),
        ),
    )
    .unwrap();
    let admin_addr2 = format!("127.0.0.1:{admin_port2}");
    let data_addr2 = format!("127.0.0.1:{data_port2}");

    let mut child2 = std::process::Command::new(&busbar_bin)
        .env("BUSBAR_CONFIG", &config2)
        .env("BUSBAR_PROVIDERS", &providers)
        .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
        .env("MOCK_KEY", "unused-mock-provider-key")
        .env("BUSBAR_STATE_FILE", "")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn boot 2 (auth.chain: [oidc], picking up the admin-API-installed tarball)");
    assert!(
        wait_for_admin_ready(&client, &admin_addr2, ADMIN_TOKEN, &mut child2),
        "boot 2's admin API must become ready within 15s (proves the oidc plugin loaded, not just \
         that the process is alive, since a load failure is a boot-time die())"
    );

    // ── THE REAL CALL: a genuine signed bearer JWT through the live data plane. ──
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = serde_json::json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + 3600,
        "nbf": now - 10,
        "sub": "admin-e2e-subject",
        "groups": ["11111111-aaaa"],
    });
    let good_token = key.sign(&claims);

    let resp = client
        .post(format!("http://{data_addr2}/v1/chat/completions"))
        .bearer_auth(&good_token)
        .json(&serde_json::json!({
            "model": "test-model",
            "messages": [{"role": "user", "content": "hi"}],
        }))
        .send()
        .expect("POST to the real data plane with a real OIDC bearer token");
    // NOT `assert_ne!(status, 401)`. That form passes on 400, 404, 500 and every other failure, so
    // it cannot distinguish "the plugin authenticated this token" from "the request died for an
    // unrelated reason before auth mattered". The chain is `[oidc]` and the upstream is a mock, so
    // a genuinely authenticated request reaches the proxy and comes back either as a success or as
    // an upstream-shaped failure. Both of those are downstream of authentication; a 401 or a 403 is
    // not. Assert that positively.
    let status = resp.status().as_u16();
    let body = resp.text().unwrap_or_default();
    assert!(
        status != 401 && status != 403,
        "a genuinely valid, real-signed OIDC token must be authenticated by the live installed \
         plugin, not rejected: status {status}, body {body}"
    );
    assert!(
        status < 400 || (502..=504).contains(&status),
        "an authenticated request must reach the proxy and return either a success or an \
         upstream-shaped failure; status {status} means it never got past the gateway's own \
         handling, so this assertion would not have noticed an auth regression: body {body}"
    );

    // A token from the WRONG key (same iss/aud/kid) must be rejected by the live installed plugin.
    let forged_key = Issuer::start(UNUSED_ISSUER, "admin-e2e-kid");
    let forged_token = forged_key.sign(&claims);
    let forged_resp = client
        .post(format!("http://{data_addr2}/v1/chat/completions"))
        .bearer_auth(&forged_token)
        .json(&serde_json::json!({
            "model": "test-model",
            "messages": [{"role": "user", "content": "hi"}],
        }))
        .send()
        .expect("POST with a wrong-key-signed token");
    assert_eq!(
        forged_resp.status().as_u16(),
        401,
        "a token signed by the wrong key must be rejected by the live installed plugin"
    );

    let _ = child2.kill();
    let _ = child2.wait();
    let _ = std::fs::remove_dir_all(&work);
}

/// End-to-end FAILURE: a plugin `open` refusal (malformed config) must surface back across the door
/// as the operator's text, not a panic or a silently-succeeded open.
#[test]
fn load_and_exercise_auth_oidc_plugin_bad_config_fails_over_abi() {
    let Some(path) = plugin_path() else {
        eprintln!("skip: auth-oidc plugin cdylib not built (run under --workspace)");
        return;
    };
    let key = Issuer::start(UNUSED_ISSUER, "k");
    let dropped = || support::bind(&Arm::File(&path), &Idp::new(&key));

    let err = support::open(&dropped().plugin, "", None)
        .expect_err("empty config must fail to open, not silently succeed");
    assert!(
        err.contains("config"),
        "the plugin's own error message should survive the door intact: {err}"
    );

    let err = support::open(
        &dropped().plugin,
        r#"{"issuer": "https://idp.example/v2.0"}"#, // missing required `audience`
        None,
    )
    .expect_err("config missing a required field must fail to open");
    assert!(err.contains("invalid oidc plugin config"), "got: {err}");
}
