// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared by this crate's integration tests (`e2e.rs`, `conformance.rs`): the logic crate's own local
//! issuer (`busbar_auth_oidc::testkit`, feature `testkit`) — a REAL ES256 key, its JWKS served over a
//! certificate-verified loopback endpoint (trusted through the module's `ca_cert_pem`), and genuinely
//! signed tokens. No stubbed crypto, no stubbed fetch.

pub use busbar_auth_oidc::testkit::Issuer;

/// The `iss` of a key used only for its signature (the tests configure the issuer they check).
pub const UNUSED_ISSUER: &str = "https://issuer.unused.invalid";
