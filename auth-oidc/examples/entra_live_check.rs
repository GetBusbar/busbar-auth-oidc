//! Real-world proof against an actual Entra ID (Azure AD) tenant — not a fixture, not a mock. Reads
//! a live tenant/client id and a disposable test user's credentials from env, performs a genuine
//! password-grant token request against Entra's real token endpoint, then drives that real
//! Entra-issued token through this crate's own sans-IO `OidcModule`, its requests made by a
//! blocking HTTPS client standing in for the host's connector: real discovery, real JWKS fetch,
//! real RS256 signature check, real claim validation. It also verifies that a tampered copy of the
//! same token is genuinely rejected, so this is not a rubber stamp.

use busbar_auth_oidc::fetch::{document, failed, Doc, Fetch};
use busbar_auth_oidc::{OidcConfig, OidcModule, Step};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::cred::FormBody;
use busbar_contract::auth::{AuthVerdict, LoginHttpResponse};
use std::io::Read;
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
                    let mut body = Vec::new();
                    r.take(busbar_auth_oidc::fetch::MAX_JWKS_BYTES as u64 + 1)
                        .read_to_end(&mut body)
                        .map_err(|e| failed(url, e))?;
                    document(url, status, body)
                }),
        )
    }

    fn post(&mut self, url: &str, _: &FormBody) -> Poll<Result<LoginHttpResponse, String>> {
        Poll::Ready(Err(failed(url, "this example makes no token exchange")))
    }
}

/// The example's HTTPS client: https only, every request bounded at 10 s, so a stalled Entra
/// endpoint fails the live check instead of hanging it.
fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .https_only(true)
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("an HTTPS client")
}

/// The verdict on `token`: this example's requests answer at once, so the module answers READY.
fn verify(module: &OidcModule, token: &str) -> AuthVerdict {
    let client = client();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs() as i64;
    match module.verify(Some(token), now, Instant::now(), &mut Blocking(client)) {
        Step::Ready(Ok(v)) => v,

        Step::Ready(Err(e)) => panic!("real Entra discovery or JWKS fetch failed: {e}"),
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
    let resp = client()
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
    let body: Option<serde_json::Value> = serde_json::from_str(&text).ok();
    if !status.is_success() {
        let said = |member: &str| {
            body.as_ref()
                .and_then(|b| b[member].as_str())
                .unwrap_or("(none)")
                .to_string()
        };
        panic!(
            "Entra rejected the real password grant ({status}): error {}, {}. If this is \
             AADSTS50055 (password expired), sign in interactively once as the test user to set a \
             permanent password, then re-provision the ENTRA_TEST_PASSWORD secret.",
            said("error"),
            said("error_description")
        );
    }
    let body = body.expect("Entra's token response is JSON");
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
    assert!(
        matches!(outcome, AuthVerdict::Identify(_)),
        "a real, freshly-issued Entra token must verify as Identify"
    );

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
    assert!(
        matches!(tampered_outcome, AuthVerdict::Reject),
        "a tampered signature over a real Entra-issued token must be rejected"
    );

    println!("PASS: real Entra ID token verified end-to-end, tampered token correctly rejected.");
}
