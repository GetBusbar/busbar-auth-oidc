// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! End-to-end coverage of the `busbar-auth-oidc-plugin` cdylib DROPPED IN through the real loader's

use busbar_plugin_loader::plugin_library_filename;

/// Locate the built `busbar_auth_oidc_plugin` cdylib in the target dir (mirrors the loader's own

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

#[test]
fn load_and_exercise_auth_oidc_plugin_success() {
    let _one = support::serial();
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
        support::strays(
            &sent,
            2 * busbar_auth_oidc::fetch::PUBLIC,
            &support::declared_targets(busbar_auth_oidc::fetch::PUBLIC)
        ),
        Vec::<String>::new()
    );

    assert_eq!(
        (sent[0].need, sent[0].target.as_str(), sent[0].path.as_str()),
        (
            busbar_auth_oidc::fetch::NEED_JWKS + busbar_auth_oidc::fetch::PUBLIC,
            support::JWKS_URL,
            "/keys"
        )
    );

    let forged_token = Issuer::start(UNUSED_ISSUER, "test-kid-1").sign(&claims);
    assert_eq!(
        module.verify(Some(&forged_token), None),
        "verdict 2 ",
        "a token signed by the wrong key must be rejected across the door"
    );
}

/// The busbar checkout the live e2e builds the REAL `busbar` and `busbar-plugin-pack` binaries from:

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

fn build_real_binaries() -> (std::path::PathBuf, std::path::PathBuf) {
    let root = busbar_root();

    for args in [
        &[
            "build",
            "--release",
            "--manifest-path",
            "dist/default/Cargo.toml",
            "--target-dir",
            "target",
            "--bin",
            "busbar",
            "--features",
            "test-harness",
        ][..],
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

/// A fresh first-party test keypair from the real `busbar-plugin-pack keygen`: (private seed hex,

fn first_party_keypair(pack_bin: &std::path::Path) -> (String, String) {
    let out = std::process::Command::new(pack_bin)
        .arg("keygen")
        .output()
        .expect("run busbar-plugin-pack keygen");
    assert!(out.status.success(), "keygen must succeed");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let half = |label: &str| {
        text.lines()
            .find(|l| l.starts_with(label))
            .and_then(|l| l.rsplit(' ').next())
            .map(str::to_owned)
            .unwrap_or_else(|| panic!("keygen printed no {label} line: {text}"))
    };
    (half("private"), half("public"))
}

/// Pack the built auth-oidc-plugin cdylib into a real tarball via the real `busbar-plugin-pack`

fn pack_oidc_tarball(
    pack_bin: &std::path::Path,
    sign_key: &str,
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
            env!("CARGO_PKG_VERSION"),
            "--publisher",
            "busbar",
            "--description",
            "e2e admin-api install proof",
            "--license",
            "Apache-2.0",
            "--out",
            out.to_str().unwrap(),
        ])
        .env("BUSBAR_SIGN_KEY", sign_key)
        .status()
        .expect("run busbar-plugin-pack");
    assert!(status.success(), "packing the plugin must succeed");
    std::fs::read(out).unwrap()
}

/// An ephemeral local TCP port (bind :0, read back the OS-assigned port, drop the listener before the

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A spawned busbar, killed and reaped when it drops: a failing assertion between its spawn and

struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The test's scratch directory, removed when it drops (a failing run included).
struct Scratch(std::path::PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
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

#[test]
fn install_oidc_plugin_via_admin_api_and_authenticate() {
    let Some(so_path) = plugin_path() else {
        eprintln!("skip: auth-oidc-plugin cdylib not built");
        return;
    };
    if std::env::var_os("BUSBAR_CHECKOUT").is_none() {
        if std::env::var_os("CI").is_some() {
            panic!(
                "BUSBAR_CHECKOUT is unset under CI: plugin-ci's busbar_checkout must provide a \
                 busbar checkout at .busbar-ref so the admin-API install e2e runs instead of passing \
                 while checking nothing."
            );
        }

        eprintln!(
            "skip: BUSBAR_CHECKOUT unset — the admin-API install e2e needs a busbar checkout at \
             .busbar-ref to build the real busbar binary (ci.yml `e2e` runs it)"
        );
        return;
    }
    let (busbar_bin, pack_bin) = build_real_binaries();
    let (sign_key, first_party_pub) = first_party_keypair(&pack_bin);

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
    let _scratch = Scratch(work.clone());
    let plugins_dir = work.join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();
    const ADMIN_TOKEN: &str = "e2e-oidc-admin-token";

    let providers = work.join("providers.yaml");
    std::fs::write(
        &providers,
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n",
    )
    .unwrap();

    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(false)
        .build()
        .unwrap();

    let data_port1 = free_port();
    let admin_port1 = free_port();
    let config1 = work.join("config1.yaml");
    std::fs::write(
        &config1,
        format!(
            "listen: \"127.0.0.1:{data_port1}\"\n\
             admin_listen: \"127.0.0.1:{admin_port1}\"\n\
             store: {{ module: memory }}\n\
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

    let mut child1 = KillOnDrop(
        std::process::Command::new(&busbar_bin)
            .env("BUSBAR_CONFIG", &config1)
            .env("BUSBAR_TEST_HARNESS_FIRST_PARTY_KEY", &first_party_pub)
            .env("BUSBAR_PROVIDERS", &providers)
            .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
            .env("MOCK_KEY", "unused-mock-provider-key")
            .env("BUSBAR_STATE_FILE", "")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .expect("spawn boot 1 (empty auth chain, admin listener up)"),
    );
    assert!(
        wait_for_admin_ready(&client, &admin_addr1, ADMIN_TOKEN, &mut child1.0),
        "boot 1's admin API must become ready within 15s"
    );

    let tarball_path = work.join("auth-oidc-admin.tar.gz");
    let tarball = pack_oidc_tarball(&pack_bin, &sign_key, &so_path, &tarball_path);
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
    assert_eq!(listed["valid"], true, "the catalog entry: {listed}");

    drop(child1);

    let data_port2 = free_port();
    let admin_port2 = free_port();
    let config2 = work.join("config2.yaml");
    std::fs::write(
        &config2,
        format!(
            "listen: \"127.0.0.1:{data_port2}\"\n\
             admin_listen: \"127.0.0.1:{admin_port2}\"\n\
             store: {{ module: memory }}\n\
             advanced:\n  allow_destinations: [\"127.0.0.1\"]\n\
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

    let mut child2 = KillOnDrop(
        std::process::Command::new(&busbar_bin)
            .env("BUSBAR_CONFIG", &config2)
            .env("BUSBAR_TEST_HARNESS_FIRST_PARTY_KEY", &first_party_pub)
            .env("BUSBAR_PROVIDERS", &providers)
            .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
            .env("MOCK_KEY", "unused-mock-provider-key")
            .env("BUSBAR_STATE_FILE", "")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .expect(
                "spawn boot 2 (auth.chain: [oidc], picking up the admin-API-installed tarball)",
            ),
    );
    assert!(
        wait_for_admin_ready(&client, &admin_addr2, ADMIN_TOKEN, &mut child2.0),
        "boot 2's admin API must become ready within 15s (proves the oidc plugin loaded, not just \
         that the process is alive, since a load failure is a boot-time die())"
    );

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

    drop(child2);
}

/// End-to-end FAILURE: a plugin `open` refusal (malformed config) must surface back across the door

#[test]
fn load_and_exercise_auth_oidc_plugin_bad_config_fails_over_abi() {
    let _one = support::serial();
    let Some(path) = plugin_path() else {
        eprintln!("skip: auth-oidc plugin cdylib not built (run under --workspace)");
        return;
    };
    let key = Issuer::start(UNUSED_ISSUER, "k");
    let dropped = || support::bind(&Arm::File(&path), &Idp::new(&key));

    let err = support::open(&dropped().plugin, "", None)
        .expect_err("empty config must fail to open, not silently succeed");
    assert!(
        err.contains("settings: none provided"),
        "the plugin's own error message should survive the door intact: {err}"
    );

    let err = support::open(
        &dropped().plugin,
        r#"{"issuer": "https://idp.example/v2.0"}"#,
        None,
    )
    .expect_err("config missing a required field must fail to open");
    assert!(
        err.contains("settings: missing field `audience`"),
        "got: {err}"
    );
}
