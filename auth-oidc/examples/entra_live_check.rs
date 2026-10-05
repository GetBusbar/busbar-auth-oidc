//! Real-world proof against an actual Entra ID (Azure AD) tenant — not a fixture, not a mock. Reads
//! a live tenant/client id + a disposable test user's credentials from env, performs a genuine
//! password-grant token request against Entra's real token endpoint, then drives that real
//! Entra-issued token through this crate's own sans-IO `OidcModule`, its requests made by a blocking
//! HTTPS client standing in for the host's connector: real discovery, real JWKS fetch, real RS256
//! signature check, real claim validation. Also verifies a tampered copy of the same token is genuinely rejected, so this isn't
//! a rubber stamp.
//!
//! Requires (all via env, all optional — this example exits early with a clear message if any are
//! missing rather than failing loudly in an environment where the tenant isn't provisioned):
//!   ENTRA_TENANT_ID       Entra tenant GUID
//!   ENTRA_CLIENT_ID       App registration (public client) allowed for the ROPC grant
//!   ENTRA_TEST_USERNAME   A disposable test user in that tenant (never a real employee account)
//!   ENTRA_TEST_PASSWORD   That user's current (non-expired) password
//!
//! Run: `cargo run -p busbar-auth-oidc --example entra_live_check`

use busbar_auth_oidc::fetch::{document, failed, Doc, Fetch};
use busbar_auth_oidc::{OidcConfig, OidcModule, Step};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::auth::{AuthVerdict, LoginHop, LoginHttpResponse};
use std::task::Poll;
use std::time::Instant;

/// The module's requests, made at once by a blocking client (the plugin's host makes them through
/// its connector; this example has none).
struct Blocking(reqwest::blocking::Client);

impl Fetch for Blocking {
    fn caller(&self) -> Option<Ticket> {
        Some(Ticket {
            slot: 1,
            generation: 1,
        })
    }

    fn get(&mut self, _: Doc, url: &str) -> Poll<Result<String, String>> {
        Poll::Ready(
            self.0
                .get(url)
                .send()
                .map_err(|e| failed(url, e))
                .and_then(|r| {
                    let status = r.status().as_u16();
                    let body = r.bytes().map_err(|e| failed(url, e))?.to_vec();
                    document(url, status, body)
                }),
        )
    }

    fn post(&mut self, hop: &LoginHop, _: Option<&str>) -> Poll<Result<LoginHttpResponse, String>> {
        Poll::Ready(Err(failed(
            &hop.url,
            "this example makes no token exchange",
        )))
    }
}

/// The verdict on `token`: this example's requests answer at once, so the module answers READY.
fn verify(module: &OidcModule, token: &str) -> AuthVerdict {
    let client = reqwest::blocking::Client::builder()
        .https_only(true)
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("an HTTPS client");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs() as i64;
    match module.verify(Some(token), now, Instant::now(), &mut Blocking(client)) {
        Step::Ready(Ok(v)) => v,
        Step::Ready(Err(e)) => panic!("real Entra discovery failed: {e}"),
        Step::Pending | Step::Wait => unreachable!("a blocking fetch answers at once"),
    }
}

fn env_or_skip(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn main() {
    let (Some(tenant), Some(client_id), Some(username), Some(password)) = (
        env_or_skip("ENTRA_TENANT_ID"),
        env_or_skip("ENTRA_CLIENT_ID"),
        env_or_skip("ENTRA_TEST_USERNAME"),
        env_or_skip("ENTRA_TEST_PASSWORD"),
    ) else {
        // Locally, an absent tenant is a skip. In CI it is a FAILURE, because a workflow named
        // "entra-live-check" reporting green having verified nothing is worse than no workflow at
        // all: it is a badge asserting a live Entra token was validated when none was fetched. The
        // secrets are the only thing arming this check, so an unset or empty one is the exact
        // condition that must be loud.
        let msg = "ENTRA_TENANT_ID / ENTRA_CLIENT_ID / ENTRA_TEST_USERNAME / ENTRA_TEST_PASSWORD \
                   are not all set and non-empty";
        if std::env::var_os("CI").is_some() {
            panic!(
                "{msg}: refusing to report a green live-Entra check that verified nothing. Provide \
                 the secrets, or remove this job rather than letting it pass vacuously."
            );
        }
        eprintln!("SKIP: {msg}; this environment has no live Entra tenant provisioned.");
        return;
    };

    let token_endpoint = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token");
    let http = reqwest::blocking::Client::new();
    let resp = http
        .post(&token_endpoint)
        .form(&[
            ("grant_type", "password"),
            ("client_id", &client_id),
            ("username", &username),
            ("password", &password),
            ("scope", "openid profile email"),
        ])
        .send()
        .expect("real POST to Entra's real token endpoint");

    let status = resp.status();
    let text = resp
        .text()
        .expect("Entra's token response body is readable");
    let body: serde_json::Value =
        serde_json::from_str(&text).expect("Entra's token response is JSON");
    assert!(
        status.is_success(),
        "Entra rejected the real password grant ({status}): {body}. If this is \
         AADSTS50055 (password expired), sign in interactively once as the test user to set a \
         permanent password, then re-provision the ENTRA_TEST_PASSWORD secret."
    );
    let id_token = body["id_token"]
        .as_str()
        .expect("a successful grant includes id_token")
        .to_string();

    let cfg: OidcConfig = serde_json::from_value(serde_json::json!({
        "issuer": format!("https://login.microsoftonline.com/{tenant}/v2.0"),
        "audience": client_id,
    }))
    .unwrap();

    let module = OidcModule::new(&cfg);
    let outcome = verify(&module, &id_token);
    println!("real Entra token outcome: {outcome:?}");
    assert!(
        matches!(outcome, AuthVerdict::Identify(_)),
        "a real, freshly-issued Entra token must verify as Identify, got: {outcome:?}"
    );

    // Tamper check: a corrupted signature over the SAME real Entra JWKS must be rejected, so this
    // isn't a rubber stamp that accepts anything shaped like a JWT.
    let (header, payload, sig) = {
        let mut parts = id_token.split('.');
        (
            parts.next().unwrap().to_string(),
            parts.next().unwrap().to_string(),
            parts.next().unwrap().to_string(),
        )
    };
    let mut tampered_sig = sig.into_bytes();
    tampered_sig[0] = if tampered_sig[0] != b'A' { b'A' } else { b'B' };
    let tampered = format!(
        "{header}.{payload}.{}",
        String::from_utf8(tampered_sig).unwrap()
    );

    let tampered_outcome = verify(&OidcModule::new(&cfg), &tampered);
    println!("tampered token outcome: {tampered_outcome:?}");
    assert!(
        matches!(tampered_outcome, AuthVerdict::Reject),
        "a tampered signature over a real Entra-issued token must be rejected, got: {tampered_outcome:?}"
    );

    println!("PASS: real Entra ID token verified end-to-end, tampered token correctly rejected.");
}
