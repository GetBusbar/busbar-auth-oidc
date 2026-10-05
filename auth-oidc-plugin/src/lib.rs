// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **OIDC auth module as a droppable busbar plugin**: the logic crate re-exported whole, and its
//! door (`busbar_auth_oidc::door::door`, the auth kind's memory ABI) exported as this image's ONE
//! symbol, `busbar_plugin_door` (`export_door!`, THE DESIGN 11.4). Build it, drop the packed
//! tarball into the engine's plugins folder, define it once under `identity-providers:` (`module:
//! oidc` plus its `settings:`) and reference that name from `auth.chain`. The logic crate is
//! `#![forbid(unsafe_code)]` and exports nothing, so a build that links it carries no door symbol.
//!
//! This crate is `deny`, not `forbid`: the export macro's `#[unsafe(no_mangle)]` is the one
//! reviewed exemption (a `forbid` cannot be lifted for it). No other `unsafe` exists here.
#![deny(unsafe_code)]

pub use busbar_auth_oidc::*;

/// The exported door: the macro's `#[no_mangle]` symbol is the one exemption.
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_auth_oidc::door::door);
}
