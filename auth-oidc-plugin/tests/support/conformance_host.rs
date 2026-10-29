// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// RENDERED by `busbar-release plugin heal busbar-auth-oidc` from GetBusbar/busbar-release
// template/conformance-host/kit.rs, because this repo's declares file states network needs (`needs`:
// `http`); a hand edit is overwritten by the next sync.

//! THE SUITE'S HOST CONNECTOR, IN THIS PLUGIN'S OWN TEST: busbar's test kit's
//! (`busbar_test_kit::conformance_host!`), over the transport doors this plugin's needs name
//! (`tcp`, `http`). It gives `FAR_END`, `host` (the suite's `host:`), `anchors` (its `tls:`),
//! `far_end`, `tls_front`, and the host's own proof as this file's tests.

busbar_test_kit::conformance_host! {
    far_end: "localhost:45739",
    doors: [
        ("tcp", busbar_transport_tcp::door::MACRO_DOOR),
        ("http", busbar_transport_http::door::MACRO_DOOR),
    ],
    http_need: true,
}
