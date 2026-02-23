/// Environment variable configuration.

/// API key for the `/api/*` endpoints (Bearer token).
/// Read from the `API_KEY` environment variable.
/// If not set, the API endpoints are disabled.
pub fn api_key() -> Option<String> {
    std::env::var("API_KEY").ok().filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_missing() {
        // Remove if set, then check.
        std::env::remove_var("API_KEY");
        assert!(api_key().is_none());
    }

    #[test]
    fn test_api_key_empty() {
        std::env::set_var("API_KEY", "");
        assert!(api_key().is_none());
        std::env::remove_var("API_KEY");
    }
}
