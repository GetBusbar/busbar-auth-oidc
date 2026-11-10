// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

/// Export source-only test support to the composition root without a runtime dependency.
/// The caller includes OUT_DIR/root_test_source.rs from the owner library's crate root.
fn export_test_source(relative: &str, macro_name: &str, output_name: &str) -> std::io::Result<()> {
    use std::path::PathBuf;
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"))
        .canonicalize()?;
    let source = manifest.join(relative);
    if source.canonicalize()? != source {
        return Err(std::io::Error::other(
            "test source must be the owner's own declared path, without symlink escapes",
        ));
    }
    let package = std::env::var("CARGO_PKG_NAME").expect("package name");
    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("output dir"));
    std::fs::write(
        output.join(output_name),
        format!(
            "#[doc(hidden)]\n#[macro_export]\nmacro_rules! {macro_name} {{\n    \
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
    export_test_source(
        "tests/root/mod.rs",
        "__busbar_root_tests",
        "root_test_source.rs",
    )?;
    export_test_source(
        "tests/common/mod.rs",
        "__busbar_common_tests",
        "common_test_source.rs",
    )
}
