use crate::config::{ProxySet, UpstreamProxy};

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

/// A proxy rotator that manages multiple proxy sets.
/// Each set picks the least-used proxy (with random tie-breaking)
/// and supports per-request session affinity via the username format:
///   <proxyset>-<minutes>-<sessionkey>
pub struct Rotator {
    sets: Vec<RotatorSet>,
}

struct RotatorSet {
    name: String,
    proxies: Vec<ProxyEntry>,
    /// Dynamic affinity table: keyed by "<minutes>:<sessionkey>", each entry
    /// stores the assigned proxy index, the timestamp, and the duration.
    affinity_map: DashMap<String, AffinityEntry>,
}

struct ProxyEntry {
    proxy: UpstreamProxy,
    use_count: AtomicU64,
}

struct AffinityEntry {
    proxy_index: usize,
    assigned_at: Instant,
    assigned_at_wall: SystemTime,
    duration: Duration,
}

/// The resolved upstream proxy for a request.
#[derive(Debug, Clone)]
pub struct ResolvedProxy {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Info about an active session, returned by the API.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct SessionInfo {
    /// The full username: `<proxyset>-<minutes>-<sessionkey>`
    #[schema(example = "residential-5-abc123")]
    pub username: String,
    /// The proxy set name.
    #[schema(example = "residential")]
    pub proxy_set: String,
    /// The upstream proxy address (host:port).
    #[schema(example = "198.51.100.1:6658")]
    pub upstream: String,
    /// Session start time (ISO 8601 UTC).
    #[schema(example = "2026-02-23T21:00:00Z")]
    pub start_date: String,
    /// Session end time (ISO 8601 UTC).
    #[schema(example = "2026-02-23T21:05:00Z")]
    pub end_date: String,
}

/// Error response body.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct ApiError {
    /// Error message.
    #[schema(example = "No active session for 'residential-5-unknown'")]
    pub error: String,
}

impl Rotator {
    /// Build from loaded proxy sets.
    pub fn new(sets: Vec<ProxySet>) -> Self {
        let sets = sets
            .into_iter()
            .map(|ps| {
                let proxies = ps
                    .proxies
                    .into_iter()
                    .map(|p| ProxyEntry {
                        proxy: p,
                        use_count: AtomicU64::new(0),
                    })
                    .collect();
                RotatorSet {
                    name: ps.name,
                    proxies,
                    affinity_map: DashMap::new(),
                }
            })
            .collect();
        Self { sets }
    }

    /// Find a proxy set by name and return the next proxy.
    /// `affinity_minutes` controls sticky session duration (0 = no affinity).
    /// `session_key` identifies the session for affinity.
    pub fn next_proxy(
        &self,
        set_name: &str,
        affinity_minutes: u16,
        session_key: &str,
    ) -> Option<ResolvedProxy> {
        let set = self.sets.iter().find(|s| s.name == set_name)?;
        let proxy = set.pick(affinity_minutes, session_key);
        Some(ResolvedProxy {
            host: proxy.host.clone(),
            port: proxy.port,
            username: proxy.username.clone(),
            password: proxy.password.clone(),
        })
    }

    /// List all available proxy set names.
    pub fn set_names(&self) -> Vec<&str> {
        self.sets.iter().map(|s| s.name.as_str()).collect()
    }

    /// Get stats about a proxy set: proxy count.
    pub fn set_info(&self, name: &str) -> Option<usize> {
        self.sets
            .iter()
            .find(|s| s.name == name)
            .map(|s| s.proxies.len())
    }

    /// Get session info for a specific username (<proxyset>-<minutes>-<sessionkey>).
    /// Returns None if the username format is invalid, the set doesn't exist,
    /// or there's no active (non-expired) session.
    pub fn get_session(&self, username: &str) -> Option<SessionInfo> {
        let parts: Vec<&str> = username.splitn(3, '-').collect();
        if parts.len() != 3 {
            return None;
        }
        let set_name = parts[0];
        let minutes_str = parts[1];
        let session_key = parts[2];
        let minutes: u16 = minutes_str.parse().ok()?;

        let set = self.sets.iter().find(|s| s.name == set_name)?;
        let affinity_key = format!("{}:{}", minutes, session_key);
        let entry = set.affinity_map.get(&affinity_key)?;

        // Check if still active.
        if entry.assigned_at.elapsed() >= entry.duration {
            return None;
        }

        let proxy = &set.proxies[entry.proxy_index].proxy;
        let start = entry.assigned_at_wall;
        let end = start + entry.duration;

        Some(SessionInfo {
            username: username.to_string(),
            proxy_set: set_name.to_string(),
            upstream: format!("{}:{}", proxy.host, proxy.port),
            start_date: format_system_time(start),
            end_date: format_system_time(end),
        })
    }

    /// List all active (non-expired) sessions across all proxy sets.
    pub fn list_sessions(&self) -> Vec<SessionInfo> {
        let mut sessions = Vec::new();
        for set in &self.sets {
            for entry_ref in set.affinity_map.iter() {
                let affinity_key = entry_ref.key();
                let entry = entry_ref.value();

                // Skip expired entries.
                if entry.assigned_at.elapsed() >= entry.duration {
                    continue;
                }

                // Parse affinity_key back: "<minutes>:<sessionkey>"
                let colon_pos = match affinity_key.find(':') {
                    Some(p) => p,
                    None => continue,
                };
                let minutes_str = &affinity_key[..colon_pos];
                let session_key = &affinity_key[colon_pos + 1..];
                let username = format!("{}-{}-{}", set.name, minutes_str, session_key);

                let proxy = &set.proxies[entry.proxy_index].proxy;
                let start = entry.assigned_at_wall;
                let end = start + entry.duration;

                sessions.push(SessionInfo {
                    username,
                    proxy_set: set.name.clone(),
                    upstream: format!("{}:{}", proxy.host, proxy.port),
                    start_date: format_system_time(start),
                    end_date: format_system_time(end),
                });
            }
        }
        sessions
    }
}

impl RotatorSet {
    fn pick(&self, affinity_minutes: u16, session_key: &str) -> &UpstreamProxy {
        if affinity_minutes == 0 {
            // No affinity — pure least-used selection.
            let idx = self.pick_least_used();
            return &self.proxies[idx].proxy;
        }

        let duration = Duration::from_secs(affinity_minutes as u64 * 60);
        let affinity_key = format!("{}:{}", affinity_minutes, session_key);

        // Check for a valid affinity entry.
        if let Some(entry) = self.affinity_map.get(&affinity_key) {
            if entry.assigned_at.elapsed() < entry.duration {
                let idx = entry.proxy_index;
                self.proxies[idx].use_count.fetch_add(1, Ordering::Relaxed);
                return &self.proxies[idx].proxy;
            }
        }

        // Assign via least-used selection.
        let idx = self.pick_least_used();
        self.affinity_map.insert(
            affinity_key,
            AffinityEntry {
                proxy_index: idx,
                assigned_at: Instant::now(),
                assigned_at_wall: SystemTime::now(),
                duration,
            },
        );
        &self.proxies[idx].proxy
    }

    /// Pick the proxy with the lowest use_count.
    /// When multiple proxies share the minimum count, pick one at random.
    fn pick_least_used(&self) -> usize {
        let min_count = self
            .proxies
            .iter()
            .map(|p| p.use_count.load(Ordering::Relaxed))
            .min()
            .unwrap_or(0);

        let candidates: Vec<usize> = self
            .proxies
            .iter()
            .enumerate()
            .filter(|(_, p)| p.use_count.load(Ordering::Relaxed) == min_count)
            .map(|(i, _)| i)
            .collect();

        let idx = if candidates.len() == 1 {
            candidates[0]
        } else {
            let r = cheap_random() as usize % candidates.len();
            candidates[r]
        };

        self.proxies[idx].use_count.fetch_add(1, Ordering::Relaxed);
        idx
    }
}

/// Format a SystemTime as ISO 8601 (UTC) without external crate.
fn format_system_time(t: SystemTime) -> String {
    let dur = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();

    // Manual UTC breakdown.
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since 1970-01-01 → year/month/day.
    let (year, month, day) = days_to_ymd(days as i64);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn days_to_ymd(mut days: i64) -> (i64, u32, u32) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    days += 719468;
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = (days - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Fast, good-enough random using thread-local xorshift64.
fn cheap_random() -> u64 {
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u64> = Cell::new(
            {
                let t = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
                let tid = std::thread::current().id();
                let tid_bits = format!("{:?}", tid);
                let tid_hash = tid_bits.bytes().fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));
                t ^ tid_hash ^ 0x517cc1b727220a95
            }
        );
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

/// Periodically clean up expired affinity entries.
pub fn spawn_affinity_cleanup(rotator: Arc<Rotator>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            for set in &rotator.sets {
                let before = set.affinity_map.len();
                set.affinity_map
                    .retain(|_, entry| entry.assigned_at.elapsed() < entry.duration);
                let removed = before - set.affinity_map.len();
                if removed > 0 {
                    tracing::debug!(
                        "Cleaned {removed} expired affinity entries from set '{}'",
                        set.name
                    );
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProxySet, UpstreamProxy};
    use std::collections::HashMap;

    fn make_test_set(n: usize) -> ProxySet {
        let proxies = (0..n)
            .map(|i| UpstreamProxy {
                host: format!("proxy{i}.example.com"),
                port: 8080,
                username: Some("testuser".to_string()),
                password: Some("testpass".to_string()),
            })
            .collect();
        ProxySet {
            name: "test".to_string(),
            proxies,
        }
    }

    #[test]
    fn test_least_used_distributes_evenly() {
        let rotator = Rotator::new(vec![make_test_set(4)]);

        let mut counts: HashMap<String, usize> = HashMap::new();
        for _ in 0..400 {
            let p = rotator.next_proxy("test", 0, "abc123").unwrap();
            *counts.entry(p.host.clone()).or_default() += 1;
        }

        assert_eq!(counts.len(), 4);
        for (host, count) in &counts {
            assert!(
                *count == 100,
                "Expected 100 for {host}, got {count}"
            );
        }
    }

    #[test]
    fn test_credentials_from_proxy_entry() {
        let rotator = Rotator::new(vec![make_test_set(1)]);
        let p = rotator.next_proxy("test", 0, "abc123").unwrap();
        assert_eq!(p.username.as_deref(), Some("testuser"));
        assert_eq!(p.password.as_deref(), Some("testpass"));
    }

    #[test]
    fn test_session_affinity_with_minutes() {
        let rotator = Rotator::new(vec![make_test_set(4)]);

        // Same session key with affinity → same proxy
        let p1a = rotator.next_proxy("test", 5, "sess1").unwrap();
        let p1b = rotator.next_proxy("test", 5, "sess1").unwrap();
        assert_eq!(p1a.host, p1b.host, "Same session key should get same proxy");

        // Different session key → may get a different proxy
        let p2 = rotator.next_proxy("test", 5, "sess2").unwrap();
        assert!(p2.host.starts_with("proxy"));
    }

    #[test]
    fn test_zero_minutes_no_affinity() {
        let rotator = Rotator::new(vec![make_test_set(4)]);

        // With 0 minutes, should rotate (least-used), not stick
        let mut hosts = Vec::new();
        for _ in 0..4 {
            let p = rotator.next_proxy("test", 0, "samekey").unwrap();
            hosts.push(p.host);
        }
        hosts.sort();
        hosts.dedup();
        assert_eq!(hosts.len(), 4, "0 minutes should distribute across all proxies");
    }

    #[test]
    fn test_different_session_keys_independent_affinity() {
        let rotator = Rotator::new(vec![make_test_set(4)]);

        let pa1 = rotator.next_proxy("test", 10, "sessA").unwrap();
        let pa2 = rotator.next_proxy("test", 10, "sessA").unwrap();
        assert_eq!(pa1.host, pa2.host, "Same session should get same proxy");

        let pb1 = rotator.next_proxy("test", 10, "sessB").unwrap();
        let pb2 = rotator.next_proxy("test", 10, "sessB").unwrap();
        assert_eq!(pb1.host, pb2.host, "Same session should get same proxy");

        assert!(pa1.host.starts_with("proxy"));
        assert!(pb1.host.starts_with("proxy"));
    }

    #[test]
    fn test_unknown_set_returns_none() {
        let rotator = Rotator::new(vec![make_test_set(2)]);
        assert!(rotator.next_proxy("nonexistent", 0, "abc123").is_none());
    }

    #[test]
    fn test_cheap_random_varies() {
        let mut vals = Vec::new();
        for _ in 0..100 {
            vals.push(cheap_random());
        }
        vals.sort();
        vals.dedup();
        assert!(
            vals.len() > 50,
            "Expected varied random output, got {} unique values",
            vals.len()
        );
    }

    #[test]
    fn test_get_session_active() {
        let rotator = Rotator::new(vec![make_test_set(4)]);

        // Create a session with affinity.
        let p = rotator.next_proxy("test", 5, "mysess").unwrap();

        // Query it.
        let info = rotator.get_session("test-5-mysess").unwrap();
        assert_eq!(info.proxy_set, "test");
        assert_eq!(info.username, "test-5-mysess");
        assert_eq!(info.upstream, format!("{}:{}", p.host, p.port));
        assert!(!info.start_date.is_empty());
        assert!(!info.end_date.is_empty());
    }

    #[test]
    fn test_get_session_no_affinity_returns_none() {
        let rotator = Rotator::new(vec![make_test_set(4)]);

        // 0 minutes = no affinity → no session stored.
        rotator.next_proxy("test", 0, "nosess").unwrap();
        assert!(rotator.get_session("test-0-nosess").is_none());
    }

    #[test]
    fn test_get_session_unknown_returns_none() {
        let rotator = Rotator::new(vec![make_test_set(4)]);
        assert!(rotator.get_session("test-5-nonexistent").is_none());
        assert!(rotator.get_session("badformat").is_none());
    }

    #[test]
    fn test_list_sessions() {
        let rotator = Rotator::new(vec![make_test_set(4)]);

        // Create a few sessions.
        rotator.next_proxy("test", 5, "sessA").unwrap();
        rotator.next_proxy("test", 10, "sessB").unwrap();
        rotator.next_proxy("test", 0, "noaff").unwrap(); // won't appear

        let sessions = rotator.list_sessions();
        assert_eq!(sessions.len(), 2);

        let usernames: Vec<&str> = sessions.iter().map(|s| s.username.as_str()).collect();
        assert!(usernames.contains(&"test-5-sessA"));
        assert!(usernames.contains(&"test-10-sessB"));
    }

    #[test]
    fn test_format_system_time_epoch() {
        let epoch = SystemTime::UNIX_EPOCH;
        assert_eq!(format_system_time(epoch), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_format_system_time_known_date() {
        // 2025-06-15T15:10:45Z = 1750000245 seconds since epoch
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1750000245);
        assert_eq!(format_system_time(t), "2025-06-15T15:10:45Z");
    }
}
