// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE IMPORT BAN, held by the built image itself (THE DESIGN 5, Connections: "No plugin opens a
//! socket, dials, binds or does TLS"; the fleet policy's `[net-ban].imports` in GetBusbar/busbar
//! `.github/fleet/deps.toml`). The dependency ban (`net_ban.rs`) reads the closure; this reads what
//! the linker kept: the cdylib's UNDEFINED symbols, as `nm` lists them, must name no socket, resolver
//! or TLS entry point. Every connection goes through the host's connector, over the declared needs.
//!
//! The image is the one this test target was built against (the cdylib beside the test binary).
//! Without `nm` on the PATH the scan cannot run: it says so on stderr, loudly, and passes only then.

use std::process::Command;

/// The imports no plugin image may hold (`deps.toml` `[net-ban].imports`).
const BANNED_IMPORTS: &[&str] = &[
    "socket",
    "socketpair",
    "connect",
    "bind",
    "listen",
    "accept",
    "accept4",
    "getaddrinfo",
    "gethostbyname",
    "gethostbyname_r",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "SSL_new",
    "SSL_connect",
    "SSL_CTX_new",
];

/// Every banned import in `listing`, `nm`'s undefined-symbol output: one symbol per line, its last
/// word the name, a leading `_` (Mach-O) and a trailing `@VERSION` (ELF) dropped.
fn banned_imports(listing: &str) -> Vec<String> {
    let mut found: Vec<String> = listing
        .lines()
        .filter_map(|l| l.split_whitespace().last())
        .map(|s| s.split('@').next().unwrap_or(s))
        .map(|s| {
            if cfg!(target_os = "macos") {
                s.strip_prefix('_').unwrap_or(s)
            } else {
                s
            }
        })
        .filter(|s| BANNED_IMPORTS.contains(s))
        .map(str::to_string)
        .collect();
    found.sort();
    found.dedup();
    found
}

/// `nm`'s undefined symbols of `lib`: `None` when `nm` is not there to ask.
fn undefined_symbols(lib: &std::path::Path) -> Option<String> {
    let args: &[&str] = if cfg!(target_os = "macos") {
        &["-u"]
    } else {
        &["-D", "--undefined-only"]
    };
    let out = match Command::new("nm").args(args).arg(lib).output() {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => panic!("nm on {}: {e}", lib.display()),
    };
    assert!(
        out.status.success(),
        "nm failed on {}: {}",
        lib.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    Some(String::from_utf8(out.stdout).expect("nm prints UTF-8"))
}

#[test]
fn the_built_image_imports_no_socket_resolver_or_tls_entry_point() {
    let lib = crate::support::cdylib_path().expect("the busbar-auth-oidc-plugin cdylib is built");
    let Some(listing) = undefined_symbols(&lib) else {
        eprintln!(
            "!!! SKIPPED: `nm` is not on the PATH, so the import ban was NOT checked on {} !!!",
            lib.display()
        );
        return;
    };
    assert!(
        !listing.trim().is_empty(),
        "nm listed no undefined symbol at all for {}: the scan read nothing",
        lib.display()
    );
    assert_eq!(
        banned_imports(&listing),
        Vec::<String>::new(),
        "{}",
        lib.display()
    );
}

/// RED: a listing that imports socket, resolver and TLS entry points (ELF and Mach-O spellings) is
/// named symbol by symbol; an allowed listing is not.
#[test]
fn red_the_import_ban_names_a_socket_resolver_or_tls_import() {
    let prefix = if cfg!(target_os = "macos") { "_" } else { "" };
    let planted = format!(
        "                 U {p}malloc@GLIBC_2.2.5\n                 U {p}connect@GLIBC_2.2.5\n\
                         U {p}getaddrinfo@GLIBC_2.2.5\n                 U {p}SSL_connect\n\
                         U {p}socket\n                 w {p}__cxa_finalize\n",
        p = prefix
    );
    assert_eq!(
        banned_imports(&planted),
        vec!["SSL_connect", "connect", "getaddrinfo", "socket"]
    );
    let allowed = format!(
        "                 U {p}malloc\n                 U {p}free\n                 U {p}getrandom\n",
        p = prefix
    );
    assert_eq!(banned_imports(&allowed), Vec::<String>::new());
}
