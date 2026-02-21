use crate::config::{ProxySet, UpstreamProxy};

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A proxy rotator that manages multiple proxy sets.
/// Each set picks the least-used proxy (with random tie-breaking)
/// and supports optional session affinity.
pub struct Rotator {
    sets: Vec<RotatorSet>,
}

struct RotatorSet {
    name: String,
    proxies: Vec<ProxyEntry>,
    affinity: Option<AffinityTable>,
}

struct ProxyEntry {
    proxy: UpstreamProxy,
    use_count: AtomicU64,
}

struct AffinityTable {
    duration: Duration,
    map: DashMap<IpAddr, AffinityEntry>,
}

struct AffinityEntry {
    proxy_index: usize,
    assigned_at: Instant,
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
                let affinity = if ps.session_affinity_secs > 0 {
                    Some(AffinityTable {
                        duration: Duration::from_secs(ps.session_affinity_secs),
                        map: DashMap::new(),
                    })
                } else {
                    None
                };
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
                    affinity,
                }
            })
            .collect();
        Self { sets }
    }

    /// Find a proxy set by name and return the next proxy.
    /// Uses least-used selection with random tie-breaking.
    /// Credentials come from the proxy entry itself.
    /// `client_ip` is used for session affinity if configured.
    pub fn next_proxy(&self, set_name: &str, client_ip: IpAddr) -> Option<ResolvedProxy> {
        let set = self.sets.iter().find(|s| s.name == set_name)?;
        let proxy = set.pick(client_ip);
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

    /// Get stats about a proxy set: (proxy_count, affinity_secs).
    pub fn set_info(&self, name: &str) -> Option<(usize, u64)> {
        self.sets.iter().find(|s| s.name == name).map(|s| {
            let affinity_secs = s
                .affinity
                .as_ref()
                .map(|a| a.duration.as_secs())
                .unwrap_or(0);
            (s.proxies.len(), affinity_secs)
        })
    }
}

impl RotatorSet {
    fn pick(&self, client_ip: IpAddr) -> &UpstreamProxy {
        if let Some(affinity) = &self.affinity {
            // Check for a valid affinity entry.
            if let Some(entry) = affinity.map.get(&client_ip) {
                if entry.assigned_at.elapsed() < affinity.duration {
                    let idx = entry.proxy_index;
                    self.proxies[idx].use_count.fetch_add(1, Ordering::Relaxed);
                    return &self.proxies[idx].proxy;
                }
            }

            // Assign via least-used selection.
            let idx = self.pick_least_used();
            affinity.map.insert(
                client_ip,
                AffinityEntry {
                    proxy_index: idx,
                    assigned_at: Instant::now(),
                },
            );
            &self.proxies[idx].proxy
        } else {
            // No affinity — pure least-used selection.
            let idx = self.pick_least_used();
            &self.proxies[idx].proxy
        }
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
                if let Some(affinity) = &set.affinity {
                    let before = affinity.map.len();
                    affinity
                        .map
                        .retain(|_, entry| entry.assigned_at.elapsed() < affinity.duration);
                    let removed = before - affinity.map.len();
                    if removed > 0 {
                        tracing::debug!(
                            "Cleaned {removed} expired affinity entries from set '{}'",
                            set.name
                        );
                    }
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

    fn make_test_set(n: usize, affinity_secs: u64) -> ProxySet {
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
            session_affinity_secs: affinity_secs,
        }
    }

    #[test]
    fn test_least_used_distributes_evenly() {
        let rotator = Rotator::new(vec![make_test_set(4, 0)]);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        let mut counts: HashMap<String, usize> = HashMap::new();
        for _ in 0..400 {
            let p = rotator.next_proxy("test", ip).unwrap();
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
        let rotator = Rotator::new(vec![make_test_set(1, 0)]);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let p = rotator.next_proxy("test", ip).unwrap();
        assert_eq!(p.username.as_deref(), Some("testuser"));
        assert_eq!(p.password.as_deref(), Some("testpass"));
    }

    #[test]
    fn test_session_affinity() {
        let rotator = Rotator::new(vec![make_test_set(4, 300)]);

        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        let p1a = rotator.next_proxy("test", ip1).unwrap();
        let p1b = rotator.next_proxy("test", ip1).unwrap();
        assert_eq!(p1a.host, p1b.host, "Same IP should get same proxy");

        let p2 = rotator.next_proxy("test", ip2).unwrap();
        assert!(p2.host.starts_with("proxy"));
    }

    #[test]
    fn test_unknown_set_returns_none() {
        let rotator = Rotator::new(vec![make_test_set(2, 0)]);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(rotator.next_proxy("nonexistent", ip).is_none());
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
