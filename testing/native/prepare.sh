#!/usr/bin/env bash
set -euo pipefail
cargo +1.98.0 run --locked -p busbar-auth-oidc-plugin --example prepare_e2e
