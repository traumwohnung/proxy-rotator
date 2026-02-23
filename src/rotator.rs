use crate::config::{ProxySet, UpstreamProxy};

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
}
