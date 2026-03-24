//! Geonode upstream proxy username encoding.
//!
//! Geonode encodes session and geo-targeting parameters directly into the
//! proxy username using hyphen-separated segments:
//!
//! **Rotating (no geo):**
//! ```text
//! {username}
//! ```
//!
//! **Rotating with country:**
//! ```text
//! {username}-country-{CC}
//! ```
//!
//! **Sticky:**
//! ```text
//! {username}-session-{session_id}-sessTime-{minutes}
//! ```
//!
//! **Sticky with country:**
//! ```text
//! {username}-session-{session_id}-sessTime-{minutes}-country-{CC}
//! ```
//!
//! Country codes are uppercase (e.g. `US`, `DE`).

use proxy_gateway_core::cheap_random;

use crate::config::{GeonodeConfig, SessionConfig};

/// Build the upstream proxy username for a single request.
///
/// For sticky sessions a fresh random session ID is generated each call
/// (the proxy gateway's own affinity layer handles re-use at the session level).
/// Force-rotation generates a new session ID to get a fresh IP from geonode.
pub fn build_username(cfg: &GeonodeConfig) -> String {
    let country = pick_country(&cfg.countries);

    match &cfg.session {
        SessionConfig::Rotating => build_rotating(&cfg.username, country),
        SessionConfig::Sticky(sticky) => {
            build_sticky(&cfg.username, sticky.sess_time, random_session_id(), country)
        }
    }
}

/// Rebuild username for force-rotation — generates a new session ID.
pub fn rotate_username(cfg: &GeonodeConfig) -> String {
    // For rotating sessions there's nothing to rotate (every request is a fresh IP).
    // For sticky sessions we issue a new session ID to force a new IP assignment.
    build_username(cfg)
}

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

fn build_rotating(username: &str, country: Option<&str>) -> String {
    let mut parts = vec![username.to_string()];
    if let Some(cc) = country {
        parts.push(format!("country-{}", cc.to_ascii_uppercase()));
    }
    parts.join("-")
}

fn build_sticky(username: &str, sess_time: u32, session_id: String, country: Option<&str>) -> String {
    let mut parts = vec![
        username.to_string(),
        format!("session-{}", session_id),
        format!("sessTime-{}", sess_time),
    ];
    if let Some(cc) = country {
        parts.push(format!("country-{}", cc.to_ascii_uppercase()));
    }
    parts.join("-")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn pick_country<'a>(countries: &'a [String]) -> Option<&'a str> {
    if countries.is_empty() {
        return None;
    }
    let idx = cheap_random() as usize % countries.len();
    Some(&countries[idx])
}

/// Generate a random alphanumeric session ID (16 hex chars).
pub(crate) fn random_session_id() -> String {
    let a = cheap_random();
    let b = cheap_random();
    format!("{:016x}", a ^ (b.wrapping_shl(32)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GeonodeConfig, SessionConfig, StickyConfig};

    fn cfg(session: SessionConfig, countries: Vec<&str>) -> GeonodeConfig {
        GeonodeConfig {
            username: "geonode-exampleuser".to_string(),
            password_env: "GEONODE_PASSWORD".to_string(),
            host: "premium-residential.geonode.com".to_string(),
            port: 9000,
            countries: countries.into_iter().map(str::to_string).collect(),
            session,
        }
    }

    #[test]
    fn test_rotating_no_country() {
        let u = build_username(&cfg(SessionConfig::Rotating, vec![]));
        assert_eq!(u, "geonode-exampleuser");
    }

    #[test]
    fn test_rotating_with_country() {
        let u = build_username(&cfg(SessionConfig::Rotating, vec!["US"]));
        assert_eq!(u, "geonode-exampleuser-country-US");
    }

    #[test]
    fn test_rotating_country_uppercased() {
        let u = build_username(&cfg(SessionConfig::Rotating, vec!["de"]));
        assert_eq!(u, "geonode-exampleuser-country-DE");
    }

    #[test]
    fn test_sticky_no_country() {
        let u = build_username(&cfg(
            SessionConfig::Sticky(StickyConfig { sess_time: 10 }),
            vec![],
        ));
        // format: {user}-session-{hex16}-sessTime-10
        assert!(u.starts_with("geonode-exampleuser-session-"));
        assert!(u.contains("-sessTime-10"));
        assert!(!u.contains("country"));
    }

    #[test]
    fn test_sticky_with_country() {
        let u = build_username(&cfg(
            SessionConfig::Sticky(StickyConfig { sess_time: 30 }),
            vec!["DE"],
        ));
        assert!(u.starts_with("geonode-exampleuser-session-"));
        assert!(u.contains("-sessTime-30-country-DE"));
    }

    #[test]
    fn test_sticky_session_ids_unique() {
        let c = cfg(SessionConfig::Sticky(StickyConfig { sess_time: 10 }), vec![]);
        let u1 = build_username(&c);
        let u2 = build_username(&c);
        assert_ne!(u1, u2);
    }

    #[test]
    fn test_multi_country_picks_one() {
        let c = cfg(SessionConfig::Rotating, vec!["US", "DE", "NL"]);
        for _ in 0..30 {
            let u = build_username(&c);
            let has = u.ends_with("-country-US")
                || u.ends_with("-country-DE")
                || u.ends_with("-country-NL");
            assert!(has, "unexpected username: {u}");
        }
    }
}
