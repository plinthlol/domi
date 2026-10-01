use serde::{Deserialize, Serialize};
use crate::crypto::{decrypt, encrypt, Key};
use crate::errors::CoreError;
use crate::vault::Index;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SearchItem {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub updated_at: i64,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub collection_id: Option<String>,
    #[serde(default)]
    pub favorite: bool,
}

#[derive(Default)]
pub struct SearchCache {
    index_version: u64,
    items: Vec<SearchItem>,
}

#[derive(Serialize, Deserialize)]
struct SearchCachePayload {
    index_version: u64,
    items: Vec<SearchItem>,
}

impl SearchCache {
    pub fn rebuild_from_index(index: &Index) -> Self {
        let items = index
            .entries
            .iter()
            .filter(|e| !e.deleted)
            .map(|e| SearchItem {
                id: e.id.clone(),
                title: e.title.clone(),
                username: e.username.clone(),
                url: e.url.clone(),
                updated_at: e.updated_at,
                tags: e.tags.clone(),
                collection_id: e.collection_id.clone(),
                favorite: e.favorite,
            })
            .collect();

        Self {
            index_version: index.version,
            items,
        }
    }

    pub fn save_encrypted(&self, key: &Key) -> Result<Vec<u8>, CoreError> {
        // index_version travels inside the ciphertext, not as a separate
        // caller-supplied argument on load — otherwise a stale blob paired
        // with a fresh version number by whatever bookkeeping the shell does
        // would silently claim to be current. See load_encrypted below.
        let payload = SearchCachePayload {
            index_version: self.index_version,
            items: self.items.clone(),
        };
        let bytes = serde_json::to_vec(&payload)
            .map_err(|e| CoreError::InvalidFormat(format!("search cache serialize error: {e}")))?;
        encrypt(key, &bytes, b"search_cache")
    }

    pub fn load_encrypted(key: &Key, ciphertext: &[u8]) -> Result<Self, CoreError> {
        let bytes = decrypt(key, ciphertext, b"search_cache")?;
        let payload: SearchCachePayload = serde_json::from_slice(&bytes)
            .map_err(|e| CoreError::InvalidFormat(format!("search cache corrupt: {e}")))?;
        Ok(Self {
            index_version: payload.index_version,
            items: payload.items,
        })
    }

    pub fn index_version(&self) -> u64 {
        self.index_version
    }

    pub fn query(&self, term: &str) -> Vec<&SearchItem> {
        if term.trim().is_empty() {
            return self.items.iter().collect();
        }
        let lower = term.to_lowercase();
        self.items
            .iter()
            .filter(|item| {
                item.title.to_lowercase().contains(&lower)
                    || item.username.to_lowercase().contains(&lower)
                    || item.url.to_lowercase().contains(&lower)
            })
            .collect()
    }

    /// All cached items carrying the given tag id.
    pub fn query_by_tag(&self, tag_id: &str) -> Vec<&SearchItem> {
        self.items
            .iter()
            .filter(|item| item.tags.iter().any(|t| t == tag_id))
            .collect()
    }

    /// All cached items belonging to the given collection id.
    pub fn query_by_collection(&self, collection_id: &str) -> Vec<&SearchItem> {
        self.items
            .iter()
            .filter(|item| item.collection_id.as_deref() == Some(collection_id))
            .collect()
    }

    /// All cached items marked as favorites.
    pub fn query_favorites(&self) -> Vec<&SearchItem> {
        self.items.iter().filter(|item| item.favorite).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{derive_key, KdfParams};
    use crate::vault::IndexEntry;

    #[test]
    fn test_search_cache_query_and_crypto() {
        let mut index = Index::default();
        index.entries.push(IndexEntry {
            id: "1".into(),
            title: "GitHub".into(),
            username: "octocat".into(),
            url: "github.com".into(),
            updated_at: 1,
            deleted: false,
            tags: vec!["dev".into()],
            collection_id: Some("work".into()),
            favorite: true,
            category: Default::default(),
            attachments: Vec::new(),
        });

        let cache = SearchCache::rebuild_from_index(&index);
        let results = cache.query("cat");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].title, "GitHub");
        assert_eq!(cache.query_by_tag("dev").len(), 1);
        assert_eq!(cache.query_by_collection("work").len(), 1);
        assert_eq!(cache.query_favorites().len(), 1);

        let params = KdfParams { memory_kib: 8192, iterations: 1, parallelism: 1 };
        let key = derive_key("pass", &[0u8; 16], params).unwrap();
        let enc = cache.save_encrypted(&key).unwrap();

        let loaded = SearchCache::load_encrypted(&key, &enc).unwrap();
        assert_eq!(loaded.items.len(), 1);
        assert_eq!(loaded.index_version(), index.version);
    }

    #[test]
    fn load_encrypted_version_travels_with_ciphertext_not_caller_input() {
        // Regression test: index_version used to be a plain argument to
        // load_encrypted, entirely disconnected from what's actually inside
        // the ciphertext. A caller passing a mismatched version (e.g. a
        // stale cache blob paired with a fresh version number due to a bug
        // on the shell side) would get back a SearchCache that claims to be
        // current while serving stale data. Save at version 1, and confirm
        // the loaded cache reports version 1 regardless of what the
        // in-memory Index has moved on to.
        let mut index = Index { version: 1, ..Default::default() };
        index.entries.push(IndexEntry {
            id: "1".into(),
            title: "Old Title".into(),
            username: "u".into(),
            url: "".into(),
            updated_at: 1,
            deleted: false,
            tags: Vec::new(),
            collection_id: None,
            favorite: false,
            category: Default::default(),
            attachments: Vec::new(),
        });
        let cache = SearchCache::rebuild_from_index(&index);

        let params = KdfParams { memory_kib: 8192, iterations: 1, parallelism: 1 };
        let key = derive_key("pass", &[0u8; 16], params).unwrap();
        let enc = cache.save_encrypted(&key).unwrap();

        // Even though the "current" index has since moved to version 5,
        // the loaded cache must report the version it was actually saved
        // at (1), not whatever the caller happens to be tracking now.
        let loaded = SearchCache::load_encrypted(&key, &enc).unwrap();
        assert_eq!(loaded.index_version(), 1);
    }
}
