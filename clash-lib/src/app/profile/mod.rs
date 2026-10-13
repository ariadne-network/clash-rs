use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use tracing::{error, trace, warn};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Db {
    #[serde(default)]
    selected: HashMap<String, String>,
    #[serde(default)]
    ip_to_host: HashMap<String, String>,
    #[serde(default)]
    host_to_ip: HashMap<String, String>,
    #[serde(default)]
    smart_stats: HashMap<String, crate::proxy::group::smart::state::SmartStateData>,
    #[serde(default)]
    smart_policy_priority: HashMap<String, String>,
}

#[derive(Clone)]
pub struct ThreadSafeCacheFile(Arc<tokio::sync::RwLock<CacheFile>>);

impl ThreadSafeCacheFile {
    pub fn new(path: &str, store_selected: bool) -> Self {
        Self::with_persistence(path, store_selected, store_selected)
    }

    /// `persist`: save the cache to `path` (every 10 seconds when it
    /// changed, and with `save_now` at shutdown), also when only the fake
    /// IPs are stored: with store-fake-ip alone the file was never
    /// written, so an engine restarted in the same process handed out the
    /// fake IPs apps still held for other hosts.
    pub fn with_persistence(
        path: &str,
        store_selected: bool,
        persist: bool,
    ) -> Self {
        let persist = (persist && !path.is_empty()).then(|| {
            Arc::new(Persist {
                path: path.to_string(),
                saved: Mutex::new(0),
            })
        });
        let store = Arc::new(tokio::sync::RwLock::new(CacheFile::new(
            path,
            store_selected,
            persist.clone(),
        )));

        if let Some(persist) = persist {
            let store = Arc::downgrade(&store);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                    let Some(store) = store.upgrade() else { break };
                    let snapshot = {
                        let g = store.read().await;
                        (g.generation > persist.saved())
                            .then(|| (g.generation, serde_yaml::to_string(&g.db)))
                    };
                    drop(store);
                    let Some((generation, text)) = snapshot else {
                        continue;
                    };
                    let text = match text {
                        Ok(s) => s,
                        Err(e) => {
                            error!("failed to serialize cache file: {}", e);
                            continue;
                        }
                    };
                    let persist = persist.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        persist.save(generation, &text)
                    })
                    .await;
                }
            });
        }

        Self(store)
    }

    /// Saves the changes now (persisting caches only).
    pub async fn save_now(&self) {
        let g = self.0.read().await;
        let Some(persist) = g.persist.clone() else {
            return;
        };
        if g.generation <= persist.saved() {
            return;
        }
        let generation = g.generation;
        let text = serde_yaml::to_string(&g.db);
        drop(g);
        match text {
            Ok(text) => {
                let _ = tokio::task::spawn_blocking(move || {
                    persist.save(generation, &text)
                })
                .await;
            }
            Err(e) => error!("failed to serialize cache file: {}", e),
        }
    }

    pub async fn set_selected(&self, group: &str, server: &str) {
        let mut g = self.0.write().await;
        if g.store_selected() {
            g.set_selected(group, server);
        }
    }

    pub async fn get_selected(&self, group: &str) -> Option<String> {
        let g = self.0.read().await;
        if g.store_selected() {
            g.db.selected.get(group).cloned()
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub async fn get_selected_map(&self) -> HashMap<String, String> {
        let g = self.0.read().await;
        if g.store_selected() {
            g.get_selected_map()
        } else {
            HashMap::new()
        }
    }

    pub async fn set_ip_to_host(&self, ip: &str, host: &str) {
        self.0.write().await.set_ip_to_host(ip, host);
    }

    pub async fn set_host_to_ip(&self, host: &str, ip: &str) {
        self.0.write().await.set_host_to_ip(host, ip);
    }

    pub async fn get_fake_ip(&self, ip_or_host: &str) -> Option<String> {
        self.0.read().await.get_fake_ip(ip_or_host)
    }

    pub async fn delete_fake_ip_pair(&self, ip: &str, host: &str) {
        self.0.write().await.delete_fake_ip_pair(ip, host);
    }

    pub async fn flush_fake_ip(&self) {
        self.0.write().await.flush_fake_ip();
    }

    /// Store smart proxy group statistics
    pub async fn set_smart_stats(
        &self,
        group_name: &str,
        stats: crate::proxy::group::smart::state::SmartStateData,
    ) {
        let mut g = self.0.write().await;
        g.set_smart_stats(group_name, stats);
    }

    /// Get smart proxy group statistics
    pub async fn get_smart_stats(
        &self,
        group_name: &str,
    ) -> Option<crate::proxy::group::smart::state::SmartStateData> {
        let g = self.0.read().await;
        g.get_smart_stats(group_name)
    }
}

struct CacheFile {
    db: Db,

    store_selected: bool,
    /// Counts the changes, so only changes are saved.
    generation: u64,
    persist: Option<Arc<Persist>>,
}

/// Where the cache is saved, and the generation saved last: a save never
/// replaces a newer one (the periodic save may still be writing when the
/// one at shutdown runs).
struct Persist {
    path: String,
    saved: Mutex<u64>,
}

impl Persist {
    fn saved(&self) -> u64 {
        *self.saved.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn save(&self, generation: u64, text: &str) {
        let mut saved = self.saved.lock().unwrap_or_else(|e| e.into_inner());
        if generation <= *saved {
            return;
        }
        let tmp = format!("{}.tmp", self.path);
        match std::fs::write(&tmp, text)
            .and_then(|_| std::fs::rename(&tmp, &self.path))
        {
            Ok(_) => {
                *saved = generation;
                trace!("cache file flushed to {}", self.path);
            }
            Err(e) => error!("failed to write cache file: {}", e),
        }
    }
}

impl CacheFile {
    fn new(path: &str, store_selected: bool, persist: Option<Arc<Persist>>) -> Self {
        let db = match std::fs::read_to_string(path) {
            Ok(s) => match serde_yaml::from_str(&s) {
                Ok(db) => db,
                Err(e) => {
                    error!(
                        "failed to parse cache file: {}, initializing a new one",
                        e
                    );
                    Db {
                        selected: HashMap::new(),
                        ip_to_host: HashMap::new(),
                        host_to_ip: HashMap::new(),
                        smart_stats: HashMap::new(),
                        smart_policy_priority: HashMap::new(),
                    }
                }
            },
            Err(e) => {
                warn!("failed to read cache file: {}, initializing a new one", e);
                Db {
                    selected: HashMap::new(),
                    ip_to_host: HashMap::new(),
                    host_to_ip: HashMap::new(),
                    smart_stats: HashMap::new(),
                    smart_policy_priority: HashMap::new(),
                }
            }
        };

        Self {
            db,
            store_selected,
            generation: 0,
            persist,
        }
    }

    pub fn store_selected(&self) -> bool {
        self.store_selected
    }

    pub fn set_selected(&mut self, group: &str, server: &str) {
        self.generation += 1;
        self.db
            .selected
            .insert(group.to_string(), server.to_string());
    }

    pub fn get_selected_map(&self) -> HashMap<String, String> {
        self.db.selected.clone()
    }

    pub fn set_ip_to_host(&mut self, ip: &str, host: &str) {
        self.generation += 1;
        self.db.ip_to_host.insert(ip.to_string(), host.to_string());
    }

    pub fn set_host_to_ip(&mut self, host: &str, ip: &str) {
        self.generation += 1;
        self.db.host_to_ip.insert(host.to_string(), ip.to_string());
    }

    pub fn get_fake_ip(&self, ip_or_host: &str) -> Option<String> {
        self.db
            .ip_to_host
            .get(ip_or_host)
            .or_else(|| self.db.host_to_ip.get(ip_or_host))
            .cloned()
    }

    pub fn delete_fake_ip_pair(&mut self, ip: &str, host: &str) {
        self.generation += 1;
        self.db.ip_to_host.remove(ip);
        self.db.host_to_ip.remove(host);
    }

    pub fn flush_fake_ip(&mut self) {
        self.generation += 1;
        self.db.ip_to_host.clear();
        self.db.host_to_ip.clear();
    }

    pub fn set_smart_stats(
        &mut self,
        group_name: &str,
        stats: crate::proxy::group::smart::state::SmartStateData,
    ) {
        self.generation += 1;
        self.db.smart_stats.insert(group_name.to_string(), stats);
    }

    pub fn get_smart_stats(
        &self,
        group_name: &str,
    ) -> Option<crate::proxy::group::smart::state::SmartStateData> {
        self.db.smart_stats.get(group_name).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::ThreadSafeCacheFile;

    #[tokio::test]
    async fn fake_ips_alone_are_saved_and_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let path = path.to_str().unwrap();
        {
            let cache = ThreadSafeCacheFile::with_persistence(path, false, true);
            cache.set_host_to_ip("example.com", "198.18.0.5").await;
            cache.set_ip_to_host("198.18.0.5", "example.com").await;
            // Before the periodic save: as at shutdown.
            cache.save_now().await;
        }
        let again = ThreadSafeCacheFile::with_persistence(path, false, true);
        assert_eq!(
            again.get_fake_ip("198.18.0.5").await.as_deref(),
            Some("example.com")
        );
        assert_eq!(
            again.get_fake_ip("example.com").await.as_deref(),
            Some("198.18.0.5")
        );
    }

    #[tokio::test]
    async fn nothing_is_written_without_persistence_or_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let path = path.to_str().unwrap();
        {
            let cache = ThreadSafeCacheFile::with_persistence(path, false, false);
            cache.set_ip_to_host("198.18.0.5", "example.com").await;
            cache.save_now().await;
        }
        assert!(!std::path::Path::new(path).exists());
        ThreadSafeCacheFile::with_persistence(path, false, true)
            .save_now()
            .await;
        assert!(!std::path::Path::new(path).exists());
    }
}
