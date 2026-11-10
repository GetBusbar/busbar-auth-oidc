// SPDX-License-Identifier: Apache-2.0

#[test]
fn former_auth_module_names_are_converted_without_runtime_alias_admission() {
    install();
    let raw = "identity-providers: {company: {module: busbar-auth-oidc-plugin}}\nauth: {chain: [company]}\n";
    let out = busbar_migrations::config::normalize_authored(
        raw,
        &busbar_migrations::config::migrate_plugins::NoPlugins,
    )
    .expect("structural conversion");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).unwrap();
    assert_eq!(
        doc["identity-providers"]["company"]["module"].as_str(),
        Some("oidc")
    );
    assert_eq!(doc["auth"]["chain"][0].as_str(), Some("company"));
}
