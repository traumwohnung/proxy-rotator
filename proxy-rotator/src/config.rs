use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

use crate::source::{build_source, ProxySource, ProxySourceConfig};

/// Top-level configuration file (TOML).
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Address to bind the proxy listener to.
    /// Default: "127.0.0.1:8100"
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,

    /// Log level / filter string.
    /// Default: "info"
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Proxy sets.
    #[serde(rename = "proxy_set")]
    pub proxy_sets: Vec<ProxySetConfig>,
}

/// Configuration for a single proxy set.
///
/// The `source_type` field selects the source kind; the `source` table carries
/// the source-specific parameters (different fields per type).
///
/// ```toml
/// [[proxy_set]]
/// name = "residential"
/// source_type = "static_file"
///
/// [proxy_set.source]
/// proxies_file = "residential.txt"
/// ```
#[derive(Debug, Deserialize)]
pub struct ProxySetConfig {
    /// Name of this proxy set (used as the proxy username to select it).
    pub name: String,

    /// Source type discriminant (e.g. `"static_file"`).
    pub source_type: String,

    /// Source-specific configuration table. The expected keys depend on
    /// `source_type`.
    #[serde(default)]
    pub source: toml::Table,
}

fn default_bind_addr() -> String {
    "127.0.0.1:8100".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

/// A parsed upstream proxy entry with optional credentials.
#[derive(Debug, Clone)]
pub struct UpstreamProxy {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// A fully-initialised proxy set ready for use by the [`crate::rotator::Rotator`].
///
/// The `source` field is a type-erased [`ProxySource`] that the rotator calls
/// on every request to obtain the next upstream endpoint. All source-specific
/// logic (file I/O, API calls, address generation) is encapsulated inside the
/// source implementation.
pub struct ProxySet {
    pub name: String,
    pub source: Box<dyn ProxySource>,
}

impl std::fmt::Debug for ProxySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxySet")
            .field("name", &self.name)
            .field("source", &self.source.describe())
            .finish()
    }
}

impl Config {
    /// Load config from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let content =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let config: Config =
            toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
        Ok(config)
    }
}

/// Parse a proxies file. Each line is one of:
///   host:port:username:password
///   host:port
/// Comments with # and blank lines are skipped.
pub fn load_proxies(path: &Path) -> Result<Vec<UpstreamProxy>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut proxies = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let proxy = parse_proxy_line(line).with_context(|| {
            format!(
                "{}:{}: invalid proxy entry '{}'",
                path.display(),
                i + 1,
                line
            )
        })?;
        proxies.push(proxy);
    }
    Ok(proxies)
}

/// Parse a single proxy line.
/// Supports:
///   host:port:username:password
///   host:port
///   [ipv6]:port:username:password
///   [ipv6]:port
fn parse_proxy_line(s: &str) -> Result<UpstreamProxy> {
    if s.starts_with('[') {
        let bracket_end = s
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("unclosed bracket in '{s}'"))?;
        let host = s[1..bracket_end].to_string();
        let rest = &s[bracket_end + 1..];
        let rest = rest
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("expected ':' after ']' in '{s}'"))?;
        return parse_port_and_creds(&host, rest);
    }

    let parts: Vec<&str> = s.splitn(4, ':').collect();
    match parts.len() {
        2 => {
            let port: u16 = parts[1].parse().context("invalid port")?;
            Ok(UpstreamProxy {
                host: parts[0].to_string(),
                port,
                username: None,
                password: None,
            })
        }
        4 => {
            let port: u16 = parts[1].parse().context("invalid port")?;
            Ok(UpstreamProxy {
                host: parts[0].to_string(),
                port,
                username: Some(parts[2].to_string()),
                password: Some(parts[3].to_string()),
            })
        }
        _ => anyhow::bail!("expected host:port or host:port:user:pass, got '{s}'"),
    }
}

fn parse_port_and_creds(host: &str, rest: &str) -> Result<UpstreamProxy> {
    let parts: Vec<&str> = rest.splitn(3, ':').collect();
    match parts.len() {
        1 => {
            let port: u16 = parts[0].parse().context("invalid port")?;
            Ok(UpstreamProxy {
                host: host.to_string(),
                port,
                username: None,
                password: None,
            })
        }
        3 => {
            let port: u16 = parts[0].parse().context("invalid port")?;
            Ok(UpstreamProxy {
                host: host.to_string(),
                port,
                username: Some(parts[1].to_string()),
                password: Some(parts[2].to_string()),
            })
        }
        _ => anyhow::bail!("expected port or port:user:pass after host, got '{rest}'"),
    }
}

/// Build all proxy sets from config by constructing the appropriate source for
/// each set.
///
/// `config_dir` is the directory that contains the config file; it is used to
/// resolve relative paths inside source configurations.
pub fn build_proxy_sets(config: &Config, config_dir: &Path) -> Result<Vec<ProxySet>> {
    let mut sets = Vec::new();
    for ps in &config.proxy_sets {
        let source_config = ProxySourceConfig::from_type_and_table(&ps.source_type, &ps.source)
            .with_context(|| {
                format!(
                    "parsing source config for proxy set '{}' (type '{}')",
                    ps.name, ps.source_type
                )
            })?;
        let source = build_source(&source_config, config_dir)
            .with_context(|| format!("initialising source for proxy set '{}'", ps.name))?;

        let endpoint_count = source
            .len()
            .map(|n| n.to_string())
            .unwrap_or_else(|| "dynamic".to_string());
        tracing::info!(
            "Loaded proxy set '{}': {} ({}  endpoints)",
            ps.name,
            source.describe(),
            endpoint_count,
        );

        sets.push(ProxySet {
            name: ps.name.clone(),
            source,
        });
    }
    Ok(sets)
}

// ---------------------------------------------------------------------------
// Backward-compat alias so callers that used `load_proxy_sets` still compile.
// ---------------------------------------------------------------------------

/// Deprecated alias for [`build_proxy_sets`].
///
/// Kept for a single transition step; will be removed in the next cleanup.
#[deprecated(since = "0.8.0", note = "use `build_proxy_sets` instead")]
#[allow(dead_code)]
pub fn load_proxy_sets(config: &Config, config_dir: &Path) -> Result<Vec<ProxySet>> {
    build_proxy_sets(config, config_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_host_port_only() {
        let p = parse_proxy_line("proxy.example.com:8080").unwrap();
        assert_eq!(p.host, "proxy.example.com");
        assert_eq!(p.port, 8080);
        assert!(p.username.is_none());
        assert!(p.password.is_none());
    }

    #[test]
    fn test_parse_host_port_user_pass() {
        let p = parse_proxy_line("198.51.100.1:6658:myuser:mypass123").unwrap();
        assert_eq!(p.host, "198.51.100.1");
        assert_eq!(p.port, 6658);
        assert_eq!(p.username.as_deref(), Some("myuser"));
        assert_eq!(p.password.as_deref(), Some("mypass123"));
    }

    #[test]
    fn test_parse_ipv6() {
        let p = parse_proxy_line("[::1]:3128").unwrap();
        assert_eq!(p.host, "::1");
        assert_eq!(p.port, 3128);
        assert!(p.username.is_none());
    }

    #[test]
    fn test_parse_ipv6_with_creds() {
        let p = parse_proxy_line("[2001:db8::1]:8080:user:pass").unwrap();
        assert_eq!(p.host, "2001:db8::1");
        assert_eq!(p.port, 8080);
        assert_eq!(p.username.as_deref(), Some("user"));
        assert_eq!(p.password.as_deref(), Some("pass"));
    }

    #[test]
    fn test_parse_bad_format() {
        assert!(parse_proxy_line("host:port:only_three").is_err());
        assert!(parse_proxy_line("justhost").is_err());
    }

    #[test]
    fn test_load_proxies_mixed() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# comment").unwrap();
        writeln!(f, "198.51.100.1:6658:myuser:mypass").unwrap();
        writeln!(f, "").unwrap();
        writeln!(f, "198.51.100.2:7872:myuser:mypass").unwrap();
        writeln!(f, "plain.proxy.com:3128").unwrap();
        f.flush().unwrap();

        let proxies = load_proxies(f.path()).unwrap();
        assert_eq!(proxies.len(), 3);
        assert_eq!(proxies[0].host, "198.51.100.1");
        assert_eq!(proxies[0].port, 6658);
        assert_eq!(proxies[0].username.as_deref(), Some("myuser"));
        assert_eq!(proxies[1].username.as_deref(), Some("myuser"));
        assert_eq!(proxies[2].host, "plain.proxy.com");
        assert!(proxies[2].username.is_none());
    }
}
