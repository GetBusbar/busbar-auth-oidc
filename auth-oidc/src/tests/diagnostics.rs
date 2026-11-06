// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OIDC diagnostic assertions use tracing-subscriber's standard formatter and a local byte buffer.
use std::io::{self, Write};
use std::sync::{Arc, Mutex, Once};
use tracing_subscriber::{layer::SubscriberExt, Layer};

static TRACING_BASELINE: Once = Once::new();

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
        // A parallel uncaptured thread can register a callsite first. Keep an unfiltered
        // global registry so tracing-core cannot cache that thread's disabled decision
        // through its single-dispatch optimization for this thread's local capture.
        TRACING_BASELINE.call_once(|| {
            tracing::subscriber::set_global_default(tracing_subscriber::registry())
                .expect("diagnostic tests install one unfiltered global tracing baseline");
        });
        let buffer = Buffer(self.bytes.clone());
        let level = self.level;
        // Captures coexist on parallel test threads. Evaluate the level against
        // this dispatch instead of caching a static per-callsite decision.
        let filter = tracing_subscriber::filter::dynamic_filter_fn(move |metadata, _| {
            *metadata.level() <= level
        });
        tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .without_time()
                .with_ansi(false)
                .with_target(false)
                .with_level(false)
                .with_writer(move || buffer.clone())
                .with_filter(filter),
        )
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
