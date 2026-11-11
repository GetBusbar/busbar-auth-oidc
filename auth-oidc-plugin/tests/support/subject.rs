/// The busbar checkout the live e2e builds the REAL `busbar` and `busbar-plugin-pack` binaries from:
fn busbar_root() -> std::path::PathBuf {
    let dir = std::env::var_os("BUSBAR_CHECKOUT").expect(
        "BUSBAR_CHECKOUT is unset: the live e2e builds the real busbar binaries from a checkout of \
         GetBusbar/busbar at .busbar-ref (set BUSBAR_CHECKOUT to one)",
    );
    std::path::PathBuf::from(dir)
        .canonicalize()
        .expect("BUSBAR_CHECKOUT names an existing busbar checkout")
}

/// Build the real debug-profile subjects for e2e, avoiding release LTO in the bounded preparation
/// worker. Cargo still checks source freshness before every runtime test.
// Nested builds inherit the coordinator's bounded CARGO_BUILD_JOBS budget.
pub fn build_real_binaries() -> (std::path::PathBuf, std::path::PathBuf) {
    let root = busbar_root();
    let target = std::path::PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").expect(
        "CARGO_TARGET_DIR must name the coordinator-assigned target for the actual binary builds",
    ));
    assert!(
        target.is_absolute() && target.is_dir(),
        "CARGO_TARGET_DIR must name the existing absolute assigned target"
    );

    let metadata = std::process::Command::new("cargo")
        .args([
            "+1.98.0",
            "metadata",
            "--locked",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
        ])
        .arg(root.join("Cargo.toml"))
        .current_dir(&root)
        .output()
        .expect("read actual busbar workspace binary ownership");
    assert!(
        metadata.status.success(),
        "actual workspace metadata must succeed: {}",
        String::from_utf8_lossy(&metadata.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&metadata.stdout).expect("Cargo metadata is JSON");
    let owners: Vec<_> = metadata["packages"]
        .as_array()
        .expect("workspace packages")
        .iter()
        .flat_map(|package| {
            package["targets"]
                .as_array()
                .expect("package targets")
                .iter()
                .map(move |target| (package, target))
        })
        .filter(|(_, target)| {
            target["name"] == "busbar-plugin-pack"
                && target["kind"]
                    .as_array()
                    .expect("target kind")
                    .iter()
                    .any(|kind| kind == "bin")
        })
        .collect();
    assert_eq!(
        owners.len(),
        1,
        "selected BUSBAR_CHECKOUT must have exactly one actual busbar-plugin-pack binary owner"
    );
    let (owner, pack_target) = owners[0];
    let mut pack_args: Vec<String> = [
        "+1.98.0",
        "build",
        "--locked",
        "-p",
        owner["name"].as_str().expect("binary owner package name"),
        "--bin",
        "busbar-plugin-pack",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if let Some(required) = pack_target.get("required-features") {
        let required = required
            .as_array()
            .expect("target required-features array")
            .iter()
            .map(|feature| feature.as_str().expect("required feature name"))
            .collect::<Vec<_>>();
        if !required.is_empty() {
            pack_args.extend(["--features".to_owned(), required.join(",")]);
        }
    }
    let busbar_args: Vec<String> = [
        "+1.98.0",
        "build",
        "--locked",
        "--manifest-path",
        "dist/default/Cargo.toml",
        "--features",
        "test-harness",
        "--bin",
        "busbar",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    for args in [busbar_args, pack_args] {
        let status = std::process::Command::new("cargo")
            .args(&args)
            .current_dir(&root)
            .status()
            .expect("run cargo build for busbar / busbar-plugin-pack");
        assert!(
            status.success(),
            "building the real busbar + busbar-plugin-pack binaries must succeed ({args:?})"
        );
    }
    (
        target.join("debug/busbar"),
        target.join("debug/busbar-plugin-pack"),
    )
}
