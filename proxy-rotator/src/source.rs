//! Proxy source abstraction.
//!
//! A [`ProxySource`] knows how to produce an [`UpstreamProxy`] endpoint when
//! asked. Different implementations can back a proxy set:
//!
//! - [`StaticFileSource`] — reads a plain-text file of `host:port[:user:pass]`
//!   lines at startup and round-robins / least-used picks from that static list.
//!
//! Future variants might include:
//! - An API-based source that calls an external service to obtain a fresh
//!   sessioned endpoint on every request.
//! - An algorithmic source that generates endpoint addresses from a formula
//!   (e.g. a rotating hostname pattern or a range of IPs).
//!
//! # Implementing a new source
//!
//! 1. Add a new variant to [`ProxySourceConfig`] with its configuration fields.
//! 2. Create a struct that implements [`ProxySource`].
//! 3. Handle the new variant in [`build_source`].

use crate::config::UpstreamProxy;
use anyhow::Result;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// ProxyEntry — shared by StaticFileSource and test doubles in rotator tests.
// ---------------------------------------------------------------------------

/// An upstream proxy entry paired with a usage counter.
///
/// Used by [`StaticFileSource`] for least-used load balancing. Other source
/// implementations may not need it at all.
pub struct ProxyEntry {
    pub proxy: UpstreamProxy,
    pub use_count: AtomicU64,
}

impl std::fmt::Debug for ProxyEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyEntry")
            .field("proxy", &format!("{}:{}", self.proxy.host, self.proxy.port))
            .field("use_count", &self.use_count.load(Ordering::Relaxed))
            .finish()
    }
}

// ---------------------------------------------------------------------------
// cheap_random — shared utility for tie-breaking in least-used selection.
// ---------------------------------------------------------------------------

/// Fast, good-enough random using a thread-local xorshift64.
pub(crate) fn cheap_random() -> u64 {
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u64> = Cell::new({
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            let tid = std::thread::current().id();
            let tid_bits = format!("{:?}", tid);
            let tid_hash = tid_bits
                .bytes()
                .fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));
            t ^ tid_hash ^ 0x517cc1b727220a95
        });
    }
    STATE.with(|s| {
        let mut x = s.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.set(x);
        x
    })
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Abstraction over "give me the next upstream proxy endpoint".
///
/// Implementations are `Send + Sync` so they can live inside an `Arc` shared
/// across Tokio tasks.
pub trait ProxySource: Send + Sync + std::fmt::Debug {
    /// Return an upstream proxy to use for the next request.
    ///
    /// The `hint` carries optional metadata from the incoming request (e.g.
    /// the decoded JSON `meta` object) that some sources may use to influence
    /// which endpoint they return. Static sources ignore it.
    ///
    /// Returns `None` if the source is temporarily unable to provide an
    /// endpoint (e.g. an empty pool or a failed API call); the caller should
    /// treat this as a configuration / connectivity error.
    fn request_endpoint(&self, hint: &EndpointHint) -> Option<UpstreamProxy>;

    /// Human-readable description used in log messages (e.g. "static file
    /// /etc/proxies/residential.txt with 120 entries").
    fn describe(&self) -> String;

    /// Total number of available endpoints, if known statically.
    /// Returns `None` for dynamic sources whose pool size is not fixed.
    fn len(&self) -> Option<usize>;
}

/// Contextual hint passed to [`ProxySource::request_endpoint`].
///
/// Sources are free to ignore any or all of these fields.
#[derive(Debug, Default)]
pub struct EndpointHint<'a> {
    /// The decoded `meta` object from the proxy-authorization username.
    pub metadata: Option<&'a serde_json::Map<String, serde_json::Value>>,
}

// ---------------------------------------------------------------------------
// Configuration enum (serde-deserialized from TOML)
// ---------------------------------------------------------------------------

/// Discriminated union of all supported proxy source configurations.
///
/// The discriminant (`source_type` field) lives on the parent `[[proxy_set]]`
/// table; the `[proxy_set.source]` sub-table carries only the type-specific
/// parameters:
///
/// ```toml
/// [[proxy_set]]
/// name = "residential"
/// source_type = "static_file"
///
/// [proxy_set.source]
/// proxies_file = "residential.txt"
/// ```
///
/// Adding a new source type only requires:
/// 1. A new variant here with its config struct.
/// 2. A matching [`ProxySource`] implementation.
/// 3. A new arm in [`ProxySourceConfig::from_type_and_table`] and
///    [`build_source`].
///
/// The rest of the system (Rotator, routing, API) is source-agnostic.
#[derive(Debug, Clone)]
pub enum ProxySourceConfig {
    /// Load proxies from a plain-text file at startup.
    StaticFile(StaticFileConfig),
}

impl ProxySourceConfig {
    /// Construct from the `type` string and the raw TOML source table.
    ///
    /// This is the single dispatch point that maps a type name to the
    /// appropriate config struct.
    pub fn from_type_and_table(source_type: &str, table: &toml::Table) -> anyhow::Result<Self> {
        match source_type {
            "static_file" => {
                let cfg: StaticFileConfig = table
                    .clone()
                    .try_into()
                    .map_err(|e| anyhow::anyhow!("invalid static_file source config: {e}"))?;
                Ok(Self::StaticFile(cfg))
            }
            other => anyhow::bail!(
                "unknown source type '{}'. Supported types: static_file",
                other
            ),
        }
    }
}

/// Configuration for a static-file proxy source.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct StaticFileConfig {
    /// Path to the proxies file (one proxy per line).
    ///
    /// Relative paths are resolved against the directory that contains the
    /// main `config.toml` file.
    ///
    /// Format per line: `host:port:username:password` or `host:port`.
    /// Lines starting with `#` and blank lines are ignored.
    pub proxies_file: std::path::PathBuf,
}

// ---------------------------------------------------------------------------
// Static-file source
// ---------------------------------------------------------------------------

/// A proxy source backed by a fixed list loaded from a text file at startup.
///
/// Endpoint selection uses a least-used counter with random tie-breaking so
/// load is spread evenly across all entries in the file.
#[derive(Debug)]
pub struct StaticFileSource {
    proxies: Vec<ProxyEntry>,
    path_display: String,
}

impl StaticFileSource {
    /// Load the source from the given file path.
    pub fn load(path: &Path) -> Result<Self> {
        use crate::config::load_proxies;

        let proxies = load_proxies(path)?;
        if proxies.is_empty() {
            anyhow::bail!("no proxies found in {}", path.display());
        }

        let entries = proxies
            .into_iter()
            .map(|p| ProxyEntry {
                proxy: p,
                use_count: AtomicU64::new(0),
            })
            .collect();

        Ok(Self {
            proxies: entries,
            path_display: path.display().to_string(),
        })
    }
}

impl ProxySource for StaticFileSource {
    fn request_endpoint(&self, _hint: &EndpointHint<'_>) -> Option<UpstreamProxy> {
        if self.proxies.is_empty() {
            return None;
        }
        let idx = pick_least_used(&self.proxies);
        let entry = &self.proxies[idx];
        entry.use_count.fetch_add(1, Ordering::Relaxed);
        Some(entry.proxy.clone())
    }

    fn describe(&self) -> String {
        format!(
            "static file '{}' with {} entries",
            self.path_display,
            self.proxies.len()
        )
    }

    fn len(&self) -> Option<usize> {
        Some(self.proxies.len())
    }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Construct a boxed [`ProxySource`] from a config value.
///
/// `config_dir` is used to resolve relative file paths.
pub fn build_source(cfg: &ProxySourceConfig, config_dir: &Path) -> Result<Box<dyn ProxySource>> {
    match cfg {
        ProxySourceConfig::StaticFile(sc) => {
            let path = if sc.proxies_file.is_relative() {
                config_dir.join(&sc.proxies_file)
            } else {
                sc.proxies_file.clone()
            };
            let source = StaticFileSource::load(&path)?;
            Ok(Box::new(source))
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers (shared with rotator internals)
// ---------------------------------------------------------------------------

/// Pick the index of the entry with the lowest use-count.
/// Ties are broken randomly using a cheap thread-local xorshift64.
pub(crate) fn pick_least_used(proxies: &[ProxyEntry]) -> usize {
    let min_count = proxies
        .iter()
        .map(|e| e.use_count.load(Ordering::Relaxed))
        .min()
        .unwrap_or(0);

    let candidates: Vec<usize> = proxies
        .iter()
        .enumerate()
        .filter(|(_, e)| e.use_count.load(Ordering::Relaxed) == min_count)
        .map(|(i, _)| i)
        .collect();

    if candidates.len() == 1 {
        candidates[0]
    } else {
        candidates[cheap_random() as usize % candidates.len()]
    }
}
