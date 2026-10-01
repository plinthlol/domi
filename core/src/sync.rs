use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use crate::errors::CoreError;
use crate::vault::{Collection, Index, IndexEntry, Tag};

// ---------------------------------------------------------------------------
// Change detection / merge
// ---------------------------------------------------------------------------

/// Common shape shared by everything the sync engine merges (entries, tags,
/// collections): a stable id, a last-write-wins timestamp, and clone-ability.
/// Lets `merge_lists` implement last-write-wins once instead of three times.
trait Mergeable: Clone {
    fn merge_id(&self) -> &str;
    fn merge_updated_at(&self) -> i64;
}

impl Mergeable for IndexEntry {
    fn merge_id(&self) -> &str {
        &self.id
    }
    fn merge_updated_at(&self) -> i64 {
        self.updated_at
    }
}

impl Mergeable for Tag {
    fn merge_id(&self) -> &str {
        &self.id
    }
    fn merge_updated_at(&self) -> i64 {
        self.updated_at
    }
}

impl Mergeable for Collection {
    fn merge_id(&self) -> &str {
        &self.id
    }
    fn merge_updated_at(&self) -> i64 {
        self.updated_at
    }
}

/// Result of one last-write-wins merge: the merged list, ids the local side
/// won (need uploading), and ids the remote side won (need downloading).
type MergeListsResult<T> = Result<(Vec<T>, Vec<String>, Vec<String>), CoreError>;

/// Last-write-wins merge of two lists of the same [`Mergeable`] type, keyed by
/// id. Ties (equal `updated_at`) favor local so re-running a merge with no
/// remote changes is a no-op with nothing queued to upload.
fn merge_lists<T: Mergeable>(local: &[T], remote: &[T]) -> MergeListsResult<T> {
    let mut merged = Vec::new();
    let mut to_upload = Vec::new();
    let mut to_download = Vec::new();

    let local_map: HashMap<&str, &T> = local.iter().map(|i| (i.merge_id(), i)).collect();
    let remote_map: HashMap<&str, &T> = remote.iter().map(|i| (i.merge_id(), i)).collect();

    // Collecting into a HashMap silently keeps only the last item for any id
    // that appears twice — refuse to merge rather than silently discard one
    // of them. (This is exactly the failure mode the old, now-fixed
    // clock+thread-id import id generator could produce.)
    if local_map.len() != local.len() {
        return Err(CoreError::InvalidFormat(
            "local side has duplicate ids; refusing to merge".into(),
        ));
    }
    if remote_map.len() != remote.len() {
        return Err(CoreError::InvalidFormat(
            "remote side has duplicate ids; refusing to merge".into(),
        ));
    }

    let mut all_ids: HashSet<&str> = HashSet::new();
    all_ids.extend(local_map.keys());
    all_ids.extend(remote_map.keys());

    // Sort for deterministic output — HashSet iteration order isn't stable.
    let mut all_ids: Vec<&str> = all_ids.into_iter().collect();
    all_ids.sort_unstable();

    for id in all_ids {
        match (local_map.get(id), remote_map.get(id)) {
            (Some(l), Some(r)) => {
                if l.merge_updated_at() >= r.merge_updated_at() {
                    merged.push((*l).clone());
                    if l.merge_updated_at() > r.merge_updated_at() {
                        to_upload.push(id.to_string());
                    }
                } else {
                    merged.push((*r).clone());
                    to_download.push(id.to_string());
                }
            }
            (Some(l), None) => {
                merged.push((*l).clone());
                to_upload.push(id.to_string());
            }
            (None, Some(r)) => {
                merged.push((*r).clone());
                to_download.push(id.to_string());
            }
            (None, None) => unreachable!("id came from one of the two maps"),
        }
    }

    Ok((merged, to_upload, to_download))
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Default)]
pub struct PendingChanges {
    pub pending_entry_ids: HashSet<String>,
    pub last_synced_index_version: u64,
    /// Retry attempts made so far for each pending id, since the change was
    /// last successfully synced. Reset to 0 on success, incremented on
    /// failure — feeds [`retry_backoff_seconds`].
    #[serde(default)]
    pub retry_attempts: HashMap<String, u32>,
}

impl PendingChanges {
    /// Marks an entry/tag/collection id as having a local change that still
    /// needs to be uploaded. Call this whenever a change is made while
    /// offline (or speculatively, before every sync attempt).
    pub fn enqueue(&mut self, id: &str) {
        self.pending_entry_ids.insert(id.to_string());
    }

    /// Clears an id once its change has been confirmed uploaded.
    pub fn dequeue(&mut self, id: &str) {
        self.pending_entry_ids.remove(id);
        self.retry_attempts.remove(id);
    }

    /// Records a failed sync attempt for `id`, returning the attempt count to
    /// feed into [`retry_backoff_seconds`].
    pub fn record_failure(&mut self, id: &str) -> u32 {
        let counter = self.retry_attempts.entry(id.to_string()).or_insert(0);
        *counter += 1;
        *counter
    }

    /// Resets the retry counter for `id` after a successful attempt, without
    /// removing it from the pending set (use [`Self::dequeue`] for that).
    pub fn reset_retry(&mut self, id: &str) {
        self.retry_attempts.remove(id);
    }

    pub fn is_empty(&self) -> bool {
        self.pending_entry_ids.is_empty()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct MergeResult {
    pub to_upload_entries: Vec<String>,
    pub to_download_entries: Vec<String>,
    pub to_upload_tags: Vec<String>,
    pub to_download_tags: Vec<String>,
    pub to_upload_collections: Vec<String>,
    pub to_download_collections: Vec<String>,
    pub merged_index: Index,
}

/// Merges local and remote `Index` snapshots — entries, tags, and collections
/// all use the same last-write-wins-by-`updated_at` rule (see `merge_lists`).
/// As documented in AUDIT.md, this has no way to authenticate the remote
/// index; anyone who can write to the storage backend can influence which
/// side wins a conflict. That's an accepted trade-off of bring-your-own-
/// storage sync, not something this function can fix.
pub fn merge(local: &Index, remote: &Index) -> Result<MergeResult, CoreError> {
    let (entries, to_upload_entries, to_download_entries) =
        merge_lists(&local.entries, &remote.entries)?;
    let (tags, to_upload_tags, to_download_tags) = merge_lists(&local.tags, &remote.tags)?;
    let (collections, to_upload_collections, to_download_collections) =
        merge_lists(&local.collections, &remote.collections)?;

    let merged_index = Index {
        // `remote.version` is attacker-controlled (a sync backend can return
        // anything), so saturate instead of adding: `u64::MAX + 1` overflows
        // and panics, turning a malicious or corrupt backend into a crash.
        // The version is only a monotonic marker for cache invalidation, so
        // pinning it at u64::MAX is harmless and keeps merges ordered.
        version: local.version.max(remote.version).saturating_add(1),
        entries,
        tags,
        collections,
    };

    Ok(MergeResult {
        to_upload_entries,
        to_download_entries,
        to_upload_tags,
        to_download_tags,
        to_upload_collections,
        to_download_collections,
        merged_index,
    })
}

// ---------------------------------------------------------------------------
// Conflict resolution
// ---------------------------------------------------------------------------

/// Explicit resolution the shell can offer the user for a conflicting pair,
/// as an alternative to the automatic last-write-wins behavior in [`merge`].
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictStrategy {
    KeepLocal,
    KeepRemote,
    /// Same rule `merge_lists` applies automatically; exposed here so a shell
    /// can re-apply it explicitly after showing the user a diff.
    KeepNewest,
}

/// Applies an explicit resolution to one conflicting entry pair. Returns the
/// winning `IndexEntry`, cloned, with `updated_at` unchanged — callers that
/// persist the choice should bump `updated_at` themselves so the new value
/// wins on the next merge against any third replica.
pub fn resolve_conflict(
    local: &IndexEntry,
    remote: &IndexEntry,
    strategy: ConflictStrategy,
) -> IndexEntry {
    match strategy {
        ConflictStrategy::KeepLocal => local.clone(),
        ConflictStrategy::KeepRemote => remote.clone(),
        ConflictStrategy::KeepNewest => {
            if local.updated_at >= remote.updated_at {
                local.clone()
            } else {
                remote.clone()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Retry logic
// ---------------------------------------------------------------------------

/// Exponential backoff with a cap, in whole seconds: 2, 4, 8, 16, 32, 64, 64, ...
/// `attempt` is the 1-indexed count from [`PendingChanges::record_failure`].
pub fn retry_backoff_seconds(attempt: u32) -> u64 {
    let capped_exponent = attempt.clamp(1, 6);
    1u64 << capped_exponent
}

// ---------------------------------------------------------------------------
// Sync status reporting
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncState {
    /// No sync has run yet, or nothing is pending and the last run succeeded.
    UpToDate,
    /// A sync round-trip (upload/download/merge) is currently in progress.
    InProgress,
    /// Local changes exist that haven't been uploaded yet (e.g. made while
    /// offline).
    PendingChangesQueued,
    /// The most recent attempt failed; `retry_after_seconds` on the report
    /// says how long to wait before trying again.
    Error,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SyncStatusReport {
    pub state: SyncState,
    pub last_synced_at: Option<i64>,
    pub pending_count: usize,
    pub last_error: Option<String>,
    pub retry_after_seconds: Option<u64>,
}

/// Builds a status report for the shell's sync indicator from the current
/// [`PendingChanges`] queue plus whatever the last attempt's outcome was.
/// `last_error` should come from whatever the caller's transport layer last
/// reported; core has no visibility into the transport itself.
pub fn build_status_report(
    pending: &PendingChanges,
    last_synced_at: Option<i64>,
    in_progress: bool,
    last_error: Option<(String, String)>,
) -> SyncStatusReport {
    if in_progress {
        return SyncStatusReport {
            state: SyncState::InProgress,
            last_synced_at,
            pending_count: pending.pending_entry_ids.len(),
            last_error: None,
            retry_after_seconds: None,
        };
    }

    if let Some((failing_id, message)) = last_error {
        let attempt = *pending.retry_attempts.get(&failing_id).unwrap_or(&1);
        return SyncStatusReport {
            state: SyncState::Error,
            last_synced_at,
            pending_count: pending.pending_entry_ids.len(),
            last_error: Some(message),
            retry_after_seconds: Some(retry_backoff_seconds(attempt)),
        };
    }

    if pending.is_empty() {
        SyncStatusReport {
            state: SyncState::UpToDate,
            last_synced_at,
            pending_count: 0,
            last_error: None,
            retry_after_seconds: None,
        }
    } else {
        SyncStatusReport {
            state: SyncState::PendingChangesQueued,
            last_synced_at,
            pending_count: pending.pending_entry_ids.len(),
            last_error: None,
            retry_after_seconds: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::IndexEntry;

    fn entry(id: &str, title: &str, updated_at: i64) -> IndexEntry {
        IndexEntry {
            id: id.into(),
            title: title.into(),
            username: "u".into(),
            url: "url".into(),
            updated_at,
            deleted: false,
            tags: Vec::new(),
            collection_id: None,
            favorite: false,
            category: Default::default(),
            attachments: Vec::new(),
        }
    }

    fn tag(id: &str, name: &str, updated_at: i64) -> Tag {
        Tag {
            id: id.into(),
            name: name.into(),
            updated_at,
            deleted: false,
        }
    }

    #[test]
    fn test_merge_indexes() {
        let mut local = Index::default();
        local.entries.push(entry("1", "Local Newer", 200));

        let mut remote = Index::default();
        remote.entries.push(entry("1", "Remote Older", 100));

        let res = merge(&local, &remote).unwrap();
        assert_eq!(res.to_upload_entries, vec!["1"]);
        assert_eq!(res.merged_index.entries[0].title, "Local Newer");
    }

    #[test]
    fn test_merge_tags_and_collections() {
        let mut local = Index::default();
        local.tags.push(tag("t1", "local-name", 50));
        local.collections.push(Collection {
            id: "c1".into(),
            name: "Work".into(),
            parent_id: None,
            updated_at: 10,
            deleted: false,
        });

        let mut remote = Index::default();
        remote.tags.push(tag("t1", "remote-name", 100));

        let res = merge(&local, &remote).unwrap();
        assert_eq!(res.to_download_tags, vec!["t1"]);
        assert_eq!(res.merged_index.tags[0].name, "remote-name");
        assert_eq!(res.to_upload_collections, vec!["c1"]);
    }

    #[test]
    fn test_merge_is_deterministic_and_covers_disjoint_ids() {
        let mut local = Index::default();
        local.entries.push(entry("only-local", "A", 1));

        let mut remote = Index::default();
        remote.entries.push(entry("only-remote", "B", 1));

        let res = merge(&local, &remote).unwrap();
        assert_eq!(res.to_upload_entries, vec!["only-local"]);
        assert_eq!(res.to_download_entries, vec!["only-remote"]);
        assert_eq!(res.merged_index.entries.len(), 2);
    }

    #[test]
    fn merge_rejects_duplicate_ids_within_one_side() {
        // Regression test: merge_lists used to collect each side into a
        // HashMap keyed by id, which silently drops one of two entries that
        // share an id rather than erroring. This could actually happen via
        // the old, now-fixed weak import id generator.
        let mut local = Index::default();
        local.entries.push(entry("dup", "First", 1));
        local.entries.push(entry("dup", "Second", 2));

        let remote = Index::default();

        assert!(merge(&local, &remote).is_err());
    }

    #[test]
    fn test_resolve_conflict_strategies() {
        let local = entry("1", "Local", 100);
        let remote = entry("1", "Remote", 200);

        assert_eq!(resolve_conflict(&local, &remote, ConflictStrategy::KeepLocal).title, "Local");
        assert_eq!(resolve_conflict(&local, &remote, ConflictStrategy::KeepRemote).title, "Remote");
        assert_eq!(resolve_conflict(&local, &remote, ConflictStrategy::KeepNewest).title, "Remote");
    }

    #[test]
    fn test_retry_backoff_caps_out() {
        assert_eq!(retry_backoff_seconds(1), 2);
        assert_eq!(retry_backoff_seconds(2), 4);
        assert_eq!(retry_backoff_seconds(6), 64);
        assert_eq!(retry_backoff_seconds(20), 64); // capped
    }

    #[test]
    fn test_pending_changes_queue_lifecycle() {
        let mut pending = PendingChanges::default();
        pending.enqueue("e1");
        assert!(!pending.is_empty());

        let attempt = pending.record_failure("e1");
        assert_eq!(attempt, 1);
        let attempt = pending.record_failure("e1");
        assert_eq!(attempt, 2);

        pending.dequeue("e1");
        assert!(pending.is_empty());
        assert!(!pending.retry_attempts.contains_key("e1"));
    }

    #[test]
    fn test_build_status_report_states() {
        let mut pending = PendingChanges::default();
        let report = build_status_report(&pending, Some(1000), false, None);
        assert_eq!(report.state, SyncState::UpToDate);

        pending.enqueue("e1");
        let report = build_status_report(&pending, Some(1000), false, None);
        assert_eq!(report.state, SyncState::PendingChangesQueued);
        assert_eq!(report.pending_count, 1);

        let report = build_status_report(&pending, Some(1000), true, None);
        assert_eq!(report.state, SyncState::InProgress);

        pending.record_failure("e1");
        let report = build_status_report(
            &pending,
            Some(1000),
            false,
            Some(("e1".to_string(), "network unreachable".to_string())),
        );
        assert_eq!(report.state, SyncState::Error);
        assert_eq!(report.retry_after_seconds, Some(2));
    }

    // Regression: `merged_index.version` was `max(local, remote) + 1`, which
    // overflowed and panicked on a remote index claiming u64::MAX. Since a
    // sync backend is untrusted, that turned a corrupt/malicious response
    // into a crash reachable from `merge_indexes` on both FFI and WASM.

    #[test]
    fn merge_saturates_instead_of_overflowing_at_u64_max() {
        let local = Index { version: u64::MAX, ..Default::default() };
        let remote = Index { version: u64::MAX, ..Default::default() };

        let merged = merge(&local, &remote).expect("merge must not overflow");
        assert_eq!(merged.merged_index.version, u64::MAX, "saturates at u64::MAX");
    }

    #[test]
    fn merge_saturates_when_only_remote_is_at_max() {
        let local = Index { version: 5, ..Default::default() };
        let remote = Index { version: u64::MAX, ..Default::default() };

        let merged = merge(&local, &remote).unwrap();
        assert_eq!(merged.merged_index.version, u64::MAX);
    }

    #[test]
    fn merge_still_increments_normally() {
        let local = Index { version: 7, ..Default::default() };
        let remote = Index { version: 9, ..Default::default() };

        let merged = merge(&local, &remote).unwrap();
        assert_eq!(merged.merged_index.version, 10, "ordinary case still increments");
    }

    #[test]
    fn merge_from_json_with_max_version_does_not_panic() {
        // Mirrors the real call path: remote JSON arrives from a backend.
        let local: Index =
            serde_json::from_str(r#"{"version":1,"entries":[],"tags":[],"collections":[]}"#)
                .unwrap();
        let remote: Index = serde_json::from_str(
            r#"{"version":18446744073709551615,"entries":[],"tags":[],"collections":[]}"#,
        )
        .unwrap();

        let merged = merge(&local, &remote).unwrap();
        assert_eq!(merged.merged_index.version, u64::MAX);
    }
}
