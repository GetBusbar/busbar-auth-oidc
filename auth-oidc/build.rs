// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

/// Export source-only test support to the composition root without a runtime dependency.
/// The caller includes OUT_DIR/root_test_source.rs from the owner library's crate root.
fn export_root_test_source() -> std::io::Result<()> {
    use std::path::PathBuf;
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"))
        .canonicalize()?;
    let source = manifest.join("tests/root/mod.rs");
    if source.canonicalize()? != source {
        return Err(std::io::Error::other(
            "root test source must be the owner's own tests/root/mod.rs, without symlink escapes",
        ));
    }
    let package = std::env::var("CARGO_PKG_NAME").expect("package name");
    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("output dir"));
    std::fs::write(
        output.join("root_test_source.rs"),
        format!(
            "#[doc(hidden)]\n#[macro_export]\nmacro_rules! __busbar_root_tests {{\n    \
             ($module:ident, {package:?}) => {{\n        \
             #[path = {source:?}]\n        pub(crate) mod $module;\n    }};\n}}\n"
        ),
    )?;
    println!("cargo::rerun-if-changed={}", source.display());
    println!(
        "cargo::rerun-if-changed={}",
        manifest.join("Cargo.toml").display()
    );
    Ok(())
}

fn main() -> std::io::Result<()> {
    export_root_test_source()
}
