/// Configuration for the geonode proxy source.
///
/// Geonode encodes targeting and session parameters directly into the upstream
/// proxy username — no external API call is needed at request time.
///
/// **Rotating (default)**
/// ```toml
/// [[proxy_set]]
/// name = "geonode-residential"
/// source_type = "geonode"
///
/// [proxy_set.source]
/// username     = "geonode-exampleuser"
/// password_env = "GEONODE_PASSWORD"
/// host         = "premium-residential.geonode.com"
/// port         = 9000
/// countries    = ["US", "DE"]  # optional, one picked randomly per request
/// ```
///
/// **Sticky session**
/// ```toml
/// [proxy_set.source]
/// username     = "geonode-exampleuser"
/// password_env = "GEONODE_PASSWORD"
/// host         = "premium-residential.geonode.com"
/// port         = 10000
/// countries    = ["US"]
///
/// [proxy_set.source.session]
/// type     = "sticky"
/// sess_time = 10  # minutes
/// ```
#[derive(Debug, Clone, serde::Deserialize)]
pub struct GeonodeConfig {
    /// Account username (e.g. `"geonode-exampleuser"`).
    pub username: String,

    /// Environment variable name that holds the proxy password.
    pub password_env: String,

    /// Proxy server hostname (e.g. `"premium-residential.geonode.com"`).
    pub host: String,

    /// Proxy server port.
    ///
    /// Port ranges by type:
    /// - HTTP rotating:  9000–9010
    /// - HTTP sticky:    10000–10900
    /// - SOCKS5 rotating: 11000–11010
    /// - SOCKS5 sticky:  12000–12010
    pub port: u16,

    /// Target countries (multi-select). One is picked randomly per request.
    /// Uses ISO 3166-1 alpha-2 codes (e.g. `"US"`, `"DE"`).
    /// If empty, no country targeting is applied.
    #[serde(default)]
    pub countries: Vec<String>,

    /// Session configuration. If absent, rotating sessions are used.
    #[serde(default)]
    pub session: SessionConfig,
}

/// Session behaviour for the upstream proxy.
#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionConfig {
    /// A new IP is assigned for every request (default).
    #[default]
    Rotating,

    /// The same IP is reused for `sess_time` minutes.
    Sticky(StickyConfig),
}

/// Configuration for sticky sessions.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct StickyConfig {
    /// How long (in minutes) the assigned IP should remain active.
    pub sess_time: u32,
}
