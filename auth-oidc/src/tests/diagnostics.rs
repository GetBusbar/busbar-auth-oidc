// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OIDC diagnostic assertions use tracing-subscriber's standard formatter and a local byte buffer.
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct Buffer(Arc<Mutex<Vec<u8>>>);
impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct WarnCapture {
    bytes: Arc<Mutex<Vec<u8>>>,
    level: tracing::Level,
}
impl Default for WarnCapture {
    fn default() -> Self {
        Self {
            bytes: Arc::default(),
            level: tracing::Level::WARN,
        }
    }
}
impl WarnCapture {
    pub fn capturing_debug() -> Self {
        Self {
            level: tracing::Level::DEBUG,
            ..Self::default()
        }
    }
    pub fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync + 'static {
        let buffer = Buffer(self.bytes.clone());
        tracing_subscriber::fmt()
            .with_max_level(self.level)
            .without_time()
            .with_ansi(false)
            .with_target(false)
            .with_level(false)
            .with_writer(move || buffer.clone())
            .finish()
    }
    pub fn messages(&self) -> Vec<String> {
        String::from_utf8_lossy(&self.bytes.lock().unwrap())
            .lines()
            .map(str::to_owned)
            .collect()
    }
    pub fn contains(&self, needle: &str) -> bool {
        self.messages().iter().any(|m| m.contains(needle))
    }
    pub fn count(&self, needle: &str) -> usize {
        self.messages()
            .iter()
            .filter(|m| m.contains(needle))
            .count()
    }
}
