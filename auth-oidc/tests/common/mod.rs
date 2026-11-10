// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub fn token_verifier_cdylib_path() -> Option<std::path::PathBuf> {
    super::cdylib_path("busbar_auth_oidc_plugin")
}

pub fn framed_admission_request(stream: u32, path: &str, preface: bool) -> Vec<u8> {
    assert!(path.len() < 127);
    let mut bytes = Vec::new();
    if preface {
        bytes.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        bytes.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    }
    let mut fields = vec![0x83, 0x86, 0x04, path.len() as u8];
    fields.extend_from_slice(path.as_bytes());
    fields.extend_from_slice(&[0x01, 9]);
    fields.extend_from_slice(b"localhost");
    let len = fields.len() as u32;
    bytes.extend_from_slice(&len.to_be_bytes()[1..]);
    bytes.extend_from_slice(&[1, 4]);
    bytes.extend_from_slice(&stream.to_be_bytes());
    bytes.extend_from_slice(&fields);
    bytes
}
