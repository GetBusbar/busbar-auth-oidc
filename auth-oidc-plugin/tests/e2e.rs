// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! End-to-end coverage of the `busbar-auth-oidc-plugin` cdylib loaded over the REAL loader `kind:auth`
//! seam (`busbar_plugin_loader::auth::load_auth_from_bytes`) — the exact seam busbar's engine uses.
//! This is not a stub: it stands up a genuine local HTTPS JWKS fixture (a real self-signed cert minted
//! with `rcgen`, served over a real `rustls` TLS listener), mints a real ES256-signed JWT with `ring`,
//! and `dlopen`s the actually-built plugin cdylib to verify it end to end — a genuine JWKS fetch, a
//! genuine signature verification, and a genuine claim-to-`Principal` mapping across the real C ABI.
//!
//! This is the only over-the-ABI coverage of the `kind: auth` dlopen seam, and it lives here rather
//! than in the loader so it travels with the plugin it exercises.

use busbar_plugin_abi::kind as abi_kind;
use busbar_plugin_loader::{auth::load_auth_from_bytes, plugin_library_filename};

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

/// Install ring as the process-default rustls `CryptoProvider`, once. Idempotent: an already-installed
/// error means some other test (or the plugin's own reqwest/rustls stack under the SAME test binary)
/// already installed one; since everything here is ring, that's fine.
fn install_ring_provider_once() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// A minimal real HTTPS server: one self-signed cert, one background thread, one fixed response body
/// served to every request on every path (the test controls exactly what URL it configures, so
/// path-routing logic would be pure overhead). No framework — just `rustls` over a blocking
/// `TcpStream`, which is all `busbar_auth_oidc::ReqwestFetcher`'s blocking client needs to complete a
/// real TLS handshake, request, and response. Returns `(https url to the served body, the server's
/// cert PEM to trust via the plugin's optional `ca_cert_pem` config)`.
fn spawn_https_fixture(body: String) -> (String, String) {
    install_ring_provider_once();

    let cert_key = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
        .expect("generate self-signed cert");
    let cert_pem = cert_key.cert.pem();
    let cert_der = cert_key.cert.der().clone();
    use rustls::pki_types::pem::PemObject;
    let key_der = rustls::pki_types::PrivateKeyDer::from_pem_slice(
        cert_key.signing_key.serialize_pem().as_bytes(),
    )
    .expect("parse generated private key");

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("build TLS server config");
    let server_config = std::sync::Arc::new(server_config);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral test port");
    let port = listener.local_addr().expect("local_addr").port();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let Ok(conn) = rustls::ServerConnection::new(server_config.clone()) else {
                continue;
            };
            let mut tls = rustls::StreamOwned::new(conn, stream);
            let mut buf = [0u8; 4096];
            // Drive the handshake + read whatever of the request arrives; the response below doesn't
            // depend on the request content (fixed body, any path), so a short/partial read is fine —
            // we only need enough I/O to complete the handshake.
            let _ = std::io::Read::read(&mut tls, &mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = std::io::Write::write_all(&mut tls, response.as_bytes());
            let _ = std::io::Write::write_all(&mut tls, body.as_bytes());
            let _ = std::io::Write::flush(&mut tls);
        }
    });

    (format!("https://127.0.0.1:{port}/jwks"), cert_pem)
}

/// A ring ES256 signer, mirroring `busbar-auth-oidc`'s own test fixture
/// (`crates/auth-oidc/src/tests.rs::TestKey`) so this test mints and verifies REAL tokens rather than
/// stubbing the crypto.
struct TestKey {
    kp: ring::signature::EcdsaKeyPair,
    rng: ring::rand::SystemRandom,
    kid: &'static str,
}
impl TestKey {
    fn generate(kid: &'static str) -> Self {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let kp = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        Self { kp, rng, kid }
    }

    fn jwks(&self) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use ring::signature::KeyPair;
        let pt = self.kp.public_key().as_ref();
        assert_eq!(pt[0], 0x04, "uncompressed point");
        let x = URL_SAFE_NO_PAD.encode(&pt[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&pt[33..65]);
        serde_json::json!({
            "keys": [{
                "kty": "EC", "crv": "P-256", "kid": self.kid, "x": x, "y": y, "use": "sig", "alg": "ES256"
            }]
        })
        .to_string()
    }

    fn mint(&self, claims: &serde_json::Value) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let header = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": self.kid });
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig = self.kp.sign(&self.rng, signing_input.as_bytes()).unwrap();
        let s = URL_SAFE_NO_PAD.encode(sig.as_ref());
        format!("{signing_input}.{s}")
    }
}

/// End-to-end SUCCESS: dlopen the real auth-oidc-plugin cdylib, `open()` it against a config pointing
/// at a real local HTTPS JWKS fixture (trusted via `ca_cert_pem`), then `authenticate()` a real
/// ES256-signed JWT over the C ABI and confirm the identity + mapped groups come back correctly
/// through `DynAuth`/`AuthOutcome::Identify`.
#[test]
fn load_and_exercise_auth_oidc_plugin_success() {
    let Some(path) = plugin_path() else {
        eprintln!("skip: auth-oidc plugin cdylib not built (run under --workspace)");
        return;
    };

    let key = TestKey::generate("test-kid-1");
    let (jwks_url, cert_pem) = spawn_https_fixture(key.jwks());

    const ISSUER: &str = "https://oidc-test.invalid/v2.0";
    const AUDIENCE: &str = "api://busbar-client";

    let cfg = serde_json::json!({
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "jwks_url": jwks_url,
        "ca_cert_pem": cert_pem,
    })
    .to_string();

    let bytes = std::fs::read(&path).expect("read auth-oidc plugin cdylib");
    let module = load_auth_from_bytes(&bytes, &cfg, "auth-oidc", abi_kind::AUTH)
        .expect("load auth-oidc plugin over the ABI (real JWKS fetch at open/first-use time)");

    assert_eq!(module.name(), "oidc");
    assert!(module.cacheable());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = serde_json::json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + 3600,
        "nbf": now - 10,
        "sub": "subject-guid",
        "preferred_username": "alice@contoso.example",
        "name": "Alice Example",
        "groups": ["11111111-aaaa", "22222222-bbbb"],
    });
    let token = key.mint(&claims);

    match module.authenticate(Some(&token)) {
        busbar_api::AuthOutcome::Identify(p) => {
            // No `oid` claim in this fixture, so the IMMUTABLE `sub` is the identity of record —
            // `preferred_username` is display-only now, never identity (see lib.rs's subject-claim
            // precedence: oid/sub only, mutable claims are name-fallback, never id-fallback).
            assert_eq!(p.id, "oidc:subject-guid");
            assert_eq!(p.name.as_deref(), Some("Alice Example"));
            assert_eq!(p.roles, vec!["11111111-aaaa", "22222222-bbbb"]);
        }
        other => panic!(
            "expected the real JWKS fetch + real signature verification to identify the caller, \
             got {other:?}"
        ),
    }

    // A token signed by a DIFFERENT key (same kid) must fail closed over the real ABI too — not just
    // in `busbar-auth-oidc`'s own in-process tests.
    let forged_key = TestKey::generate("test-kid-1");
    let forged_token = forged_key.mint(&claims);
    assert!(
        matches!(
            module.authenticate(Some(&forged_token)),
            busbar_api::AuthOutcome::Reject
        ),
        "a token signed by the wrong key must be rejected across the real ABI"
    );
}

/// The sibling busbarAI checkout's root (same convention `store-postgres`/`store-sqlite`'s own e2e
/// tests already use for this).
fn busbarai_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../busbarAI")
        .canonicalize()
        .expect("sibling busbarAI checkout must exist (see Cargo.toml path deps)")
}

/// Build (once, cached by cargo) and return the real `busbar` and `busbar-plugin-pack` binaries from
/// the sibling busbarAI checkout — never a fixture, the exact binaries a real release ships.
fn build_real_binaries() -> (std::path::PathBuf, std::path::PathBuf) {
    let root = busbarai_root();
    let status = std::process::Command::new("cargo")
        .args([
            "build",
            "--release",
            "-p",
            "busbar",
            "-p",
            "busbar-plugin-pack",
        ])
        .current_dir(&root)
        .status()
        .expect("run cargo build for busbar + busbar-plugin-pack");
    assert!(status.success(), "building the real binaries must succeed");
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
            "busbar-auth-oidc-plugin",
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
/// REAL local HTTPS JWKS fixture (the same `TestKey`/`spawn_https_fixture` helpers the direct-ABI test
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
    let (busbar_bin, pack_bin) = build_real_binaries();

    let key = TestKey::generate("admin-e2e-kid");
    let (jwks_url, cert_pem) = spawn_https_fixture(key.jwks());
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
    assert_eq!(installed["name"], "busbar-auth-oidc-plugin");
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
    let good_token = key.mint(&claims);

    let resp = client
        .post(format!("http://{data_addr2}/v1/chat/completions"))
        .bearer_auth(&good_token)
        .json(&serde_json::json!({
            "model": "test-model",
            "messages": [{"role": "user", "content": "hi"}],
        }))
        .send()
        .expect("POST to the real data plane with a real OIDC bearer token");
    assert_ne!(
        resp.status().as_u16(),
        401,
        "a genuinely valid, real-signed OIDC token must be authenticated by the live installed \
         plugin, not rejected: {}",
        resp.text().unwrap_or_default()
    );

    // A token from the WRONG key (same iss/aud/kid) must be rejected by the live installed plugin.
    let forged_key = TestKey::generate("admin-e2e-kid");
    let forged_token = forged_key.mint(&claims);
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

/// End-to-end FAILURE: a plugin `open()` error (malformed config) must surface back across the C ABI
/// as a clean `Err`, not a panic or a silently-succeeded load.
#[test]
fn load_and_exercise_auth_oidc_plugin_bad_config_fails_over_abi() {
    let Some(path) = plugin_path() else {
        eprintln!("skip: auth-oidc plugin cdylib not built (run under --workspace)");
        return;
    };
    let bytes = std::fs::read(&path).expect("read auth-oidc plugin cdylib");

    let err = load_auth_from_bytes(&bytes, "", "auth-oidc", abi_kind::AUTH)
        .err()
        .expect("empty config must fail to load, not silently succeed");
    assert!(
        err.contains("config"),
        "the plugin's own error message should survive the ABI crossing intact: {err}"
    );

    let err = load_auth_from_bytes(
        &bytes,
        r#"{"issuer": "https://idp.example/v2.0"}"#, // missing required `audience`
        "auth-oidc",
        abi_kind::AUTH,
    )
    .err()
    .expect("config missing a required field must fail to load");
    assert!(err.contains("invalid oidc plugin config"), "got: {err}");
}
