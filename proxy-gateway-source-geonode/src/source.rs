use anyhow::Context;
use proxy_gateway_core::{AffinityParams, ProxySource, SourceProxy};

use crate::config::GeonodeConfig;
use crate::username::{build_username, rotate_username};

#[derive(Debug)]
pub struct GeonodeSource {
    config: GeonodeConfig,
    password: String,
}

impl GeonodeSource {
    pub fn from_config(cfg: &GeonodeConfig) -> anyhow::Result<Self> {
        let password = std::env::var(&cfg.password_env).with_context(|| {
            format!(
                "geonode: env var '{}' (password_env) is not set",
                cfg.password_env
            )
        })?;
        Ok(Self { config: cfg.clone(), password })
    }

    fn make_proxy(&self, username: String) -> SourceProxy {
        SourceProxy {
            host: self.config.host.clone(),
            port: self.config.port,
            username: Some(username),
            password: Some(self.password.clone()),
        }
    }
}

#[async_trait::async_trait]
impl ProxySource for GeonodeSource {
    async fn get_source_proxy(&self, _affinity_params: &AffinityParams) -> Option<SourceProxy> {
        Some(self.make_proxy(build_username(&self.config)))
    }

    async fn get_source_proxy_force_rotate(
        &self,
        _affinity_params: &AffinityParams,
        _current: &SourceProxy,
    ) -> Option<SourceProxy> {
        Some(self.make_proxy(rotate_username(&self.config)))
    }

    fn describe(&self) -> String {
        let mut parts = vec!["geonode".to_string()];
        if !self.config.countries.is_empty() {
            parts.push(self.config.countries.join(","));
        }
        parts.push(format!("{}@{}:{}", self.config.username, self.config.host, self.config.port));
        parts.join(" ")
    }
}

/// Construct a [`GeonodeSource`] from config.
pub fn build_source(config: &GeonodeConfig) -> anyhow::Result<Box<dyn ProxySource>> {
    Ok(Box::new(GeonodeSource::from_config(config)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SessionConfig, StickyConfig};

    fn make_source(session: SessionConfig, countries: Vec<&str>) -> GeonodeSource {
        std::env::set_var("TEST_GN_PASS", "testpassword");
        GeonodeSource::from_config(&GeonodeConfig {
            username: "geonode-exampleuser".to_string(),
            password_env: "TEST_GN_PASS".to_string(),
            host: "premium-residential.geonode.com".to_string(),
            port: 9000,
            countries: countries.into_iter().map(str::to_string).collect(),
            session,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn test_rotating_proxy_fields() {
        let source = make_source(SessionConfig::Rotating, vec![]);
        let proxy = source.get_source_proxy(&AffinityParams::new()).await.unwrap();
        assert_eq!(proxy.host, "premium-residential.geonode.com");
        assert_eq!(proxy.port, 9000);
        assert_eq!(proxy.password.as_deref(), Some("testpassword"));
        assert_eq!(proxy.username.as_deref(), Some("geonode-exampleuser"));
    }

    #[tokio::test]
    async fn test_rotating_with_country() {
        let source = make_source(SessionConfig::Rotating, vec!["US"]);
        let proxy = source.get_source_proxy(&AffinityParams::new()).await.unwrap();
        assert_eq!(proxy.username.as_deref(), Some("geonode-exampleuser-country-US"));
    }

    #[tokio::test]
    async fn test_sticky_username_contains_session() {
        let source = make_source(SessionConfig::Sticky(StickyConfig { sess_time: 10 }), vec![]);
        let proxy = source.get_source_proxy(&AffinityParams::new()).await.unwrap();
        let u = proxy.username.unwrap();
        assert!(u.contains("-session-"));
        assert!(u.contains("-sessTime-10"));
    }

    #[tokio::test]
    async fn test_force_rotate_changes_session_id() {
        let source = make_source(SessionConfig::Sticky(StickyConfig { sess_time: 10 }), vec![]);
        let original = source.get_source_proxy(&AffinityParams::new()).await.unwrap();
        let rotated = source.get_source_proxy_force_rotate(&AffinityParams::new(), &original).await.unwrap();
        assert_ne!(original.username, rotated.username);
    }

    #[tokio::test]
    async fn test_describe() {
        let source = make_source(SessionConfig::Rotating, vec!["US", "DE"]);
        assert_eq!(
            source.describe(),
            "geonode US,DE geonode-exampleuser@premium-residential.geonode.com:9000"
        );
    }

    #[test]
    fn test_missing_env_var_fails() {
        std::env::remove_var("NONEXISTENT_GN_VAR");
        let cfg = GeonodeConfig {
            username: "user".to_string(),
            password_env: "NONEXISTENT_GN_VAR".to_string(),
            host: "premium-residential.geonode.com".to_string(),
            port: 9000,
            countries: vec![],
            session: SessionConfig::Rotating,
        };
        assert!(GeonodeSource::from_config(&cfg).is_err());
    }
}
