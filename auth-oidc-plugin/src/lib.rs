// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **OIDC auth module as a droppable busbar plugin**: the logic crate re-exported whole, and its

#![deny(unsafe_code)]

pub use busbar_auth_oidc::*;

/// The exported door: the macro's `#[no_mangle]` symbol is the one exemption.
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_auth_oidc::door::door);
}
