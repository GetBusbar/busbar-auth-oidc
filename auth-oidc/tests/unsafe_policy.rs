// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH KIND'S CODE POLICY, read off the crate's own sources (THE DESIGN §2): an auth plugin is
//! `#![forbid(unsafe_code)]` ("Plane, hook, auth (inbound and outbound) and secret plugins are
//! `#![forbid(unsafe_code)]`"), and it holds no process-global or per-thread state of its own ("A
//! plugin holds no process-global state: what it keeps is per-instance"; the one approved per-thread
//! slot is the door macro's log capture, expanded from busbar-contract, never written here).

use std::path::{Path, PathBuf};

/// Every production source of the crate: `src/**.rs` outside `src/tests`.
fn sources() -> Vec<(PathBuf, String)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
        for entry in std::fs::read_dir(dir).expect("src is readable") {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "tests") {
                    continue;
                }
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).expect("a source is readable");
                out.push((path, text));
            }
        }
    }
    let mut out = Vec::new();
    walk(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut out);
    assert!(!out.is_empty(), "the crate has sources");
    out
}

/// The code of a source, its `//` comments dropped (prose may name what the code must not do).
fn code(text: &str) -> String {
    text.lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The door is the contract SDK's safe surface, and the crate root forbids `unsafe` with no module
/// allowed back in.
#[test]
fn the_crate_forbids_unsafe_code() {
    let lib = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
        .expect("src/lib.rs");
    assert!(
        lib.lines().any(|l| l.trim() == "#![forbid(unsafe_code)]"),
        "src/lib.rs must be `#![forbid(unsafe_code)]` (THE DESIGN §2), not `deny` with an allow-list"
    );
    for (path, text) in sources() {
        let code = code(&text);
        for banned in [
            "allow(unsafe_code)",
            "unsafe {",
            "unsafe fn",
            "unsafe impl",
            "unsafe extern",
        ] {
            assert!(
                !code.contains(banned),
                "{} holds `{banned}`: an auth plugin's crate holds no unsafe code",
                path.display()
            );
        }
    }
}

#[test]
fn the_crate_holds_no_per_thread_or_process_global_state() {
    for (path, text) in sources() {
        let code = code(&text);
        assert!(
            !code.contains("thread_local!"),
            "{} declares a `thread_local!`: a plugin's state is per instance (THE DESIGN §2)",
            path.display()
        );
        for line in code.lines() {
            let t = line.trim_start();
            assert!(
                !(t.starts_with("static ")
                    || t.starts_with("pub static ")
                    || t.starts_with("pub(crate) static ")),
                "{} declares a static (`{}`): a plugin's state is per instance (THE DESIGN §2)",
                path.display(),
                t
            );
        }
    }
}
