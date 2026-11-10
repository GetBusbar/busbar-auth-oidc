// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub fn token_verifier_cdylib_path() -> Option<std::path::PathBuf> {
    super::cdylib_path("busbar_auth_oidc_plugin")
}
