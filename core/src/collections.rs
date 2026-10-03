use crate::errors::CoreError;
use crate::vault::{Collection, Entry, Index, IndexEntry};

/// Creates a new collection, optionally nested under `parent_id`. Rejects an
/// empty name, duplicate ID, a case-insensitive duplicate name among
/// *siblings* (same parent), and a non-existent/deleted `parent_id`.
pub fn create_collection(
    index: &mut Index,
    id: String,
    name: &str,
    parent_id: Option<String>,
    now: i64,
) -> Result<Collection, CoreError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(CoreError::InvalidFormat("collection name cannot be empty".into()));
    }
    if index.collections.iter().any(|collection| collection.id == id) {
        return Err(CoreError::AlreadyExists(format!("collection id '{id}' already exists")));
    }
    if let Some(parent) = &parent_id
        && !index.collections.iter().any(|c| &c.id == parent && !c.deleted)
    {
        return Err(CoreError::NotFound(format!("collection {parent}")));
    }
    if index.collections.iter().any(|c| {
        !c.deleted && c.parent_id == parent_id && c.name.eq_ignore_ascii_case(name)
    }) {
        return Err(CoreError::AlreadyExists(format!(
            "collection '{name}' already exists in this parent"
        )));
    }

    let collection = Collection {
        id,
        name: name.to_string(),
        parent_id,
        updated_at: now,
        deleted: false,
    };
    index.collections.push(collection.clone());
    Ok(collection)
}

pub fn rename_collection(
    index: &mut Index,
    collection_id: &str,
    new_name: &str,
    now: i64,
) -> Result<(), CoreError> {
    let new_name = new_name.trim();
    if new_name.is_empty() {
        return Err(CoreError::InvalidFormat("collection name cannot be empty".into()));
    }
    let parent_id = index
        .collections
        .iter()
        .find(|c| c.id == collection_id && !c.deleted)
        .ok_or_else(|| CoreError::NotFound(format!("collection {collection_id}")))?
        .parent_id
        .clone();
    if index.collections.iter().any(|c| {
        !c.deleted && c.id != collection_id && c.parent_id == parent_id && c.name.eq_ignore_ascii_case(new_name)
    }) {
        return Err(CoreError::AlreadyExists(format!(
            "collection '{new_name}' already exists in this parent"
        )));
    }
    let collection = index
        .collections
        .iter_mut()
        .find(|c| c.id == collection_id)
        .expect("existence checked above");
    collection.name = new_name.to_string();
    collection.updated_at = now;
    Ok(())
}

/// Soft-deletes a collection and every descendant collection nested under it
/// (recursively), then clears `collection_id` on any `IndexEntry` that
/// pointed at one of the deleted collections. Returns the ids of affected
/// entries — as with [`crate::tags::delete_tag`], the caller still needs to
/// decrypt, update, and re-save each affected full `Entry`.
pub fn delete_collection(index: &mut Index, collection_id: &str, now: i64) -> Result<Vec<String>, CoreError> {
    if !index.collections.iter().any(|c| c.id == collection_id && !c.deleted) {
        return Err(CoreError::NotFound(format!("collection {collection_id}")));
    }

    // Gather this collection plus every descendant, breadth-first.
    let mut to_delete: Vec<String> = vec![collection_id.to_string()];
    let mut frontier = vec![collection_id.to_string()];
    while let Some(current) = frontier.pop() {
        for c in index.collections.iter() {
            if !c.deleted && c.parent_id.as_deref() == Some(current.as_str()) && !to_delete.contains(&c.id) {
                to_delete.push(c.id.clone());
                frontier.push(c.id.clone());
            }
        }
    }

    for c in index.collections.iter_mut() {
        if to_delete.contains(&c.id) {
            c.deleted = true;
            c.updated_at = now;
        }
    }

    let mut affected = Vec::new();
    for e in index.entries.iter_mut() {
        if let Some(cid) = &e.collection_id
            && to_delete.contains(cid)
        {
            e.collection_id = None;
            affected.push(e.id.clone());
        }
    }
    Ok(affected)
}

/// Moves a decrypted `Entry` into (or out of, via `None`) a collection. The
/// caller must persist via `Vault::put_entry`, which syncs `IndexEntry` too.
/// Does not validate `collection_id` against the index — callers that want
/// that check should confirm the id via [`list_children`]/[`list_root`]
/// first, since a freshly-created collection may not have been merged into
/// the same `Index` reference the entry is being edited against.
pub fn move_entry(entry: &mut Entry, collection_id: Option<String>) {
    entry.collection_id = collection_id;
}

/// Top-level collections (no parent).
pub fn list_root(index: &Index) -> Vec<&Collection> {
    index
        .collections
        .iter()
        .filter(|c| !c.deleted && c.parent_id.is_none())
        .collect()
}

/// Direct children of `parent_id`.
pub fn list_children<'a>(index: &'a Index, parent_id: &str) -> Vec<&'a Collection> {
    index
        .collections
        .iter()
        .filter(|c| !c.deleted && c.parent_id.as_deref() == Some(parent_id))
        .collect()
}

/// Non-deleted entries directly in the given collection (not descendants).
pub fn search_by_collection<'a>(index: &'a Index, collection_id: &str) -> Vec<&'a IndexEntry> {
    index
        .entries
        .iter()
        .filter(|e| !e.deleted && e.collection_id.as_deref() == Some(collection_id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_index_entry(index: &mut Index, id: &str, collection_id: Option<&str>) {
        index.entries.push(IndexEntry {
            id: id.into(),
            title: "t".into(),
            username: "u".into(),
            url: "url".into(),
            updated_at: 1,
            deleted: false,
            tags: Vec::new(),
            collection_id: collection_id.map(String::from),
            favorite: false,
            category: Default::default(),
            attachments: Vec::new(),
        });
    }

    #[test]
    fn create_rejects_duplicate_sibling_names_but_allows_same_name_in_different_parent() {
        let mut index = Index::default();
        create_collection(&mut index, "work".into(), "Projects", None, 1).unwrap();
        assert!(matches!(
            create_collection(&mut index, "dup".into(), "projects", None, 1),
            Err(CoreError::AlreadyExists(_))
        ));
        assert!(matches!(
            create_collection(&mut index, "work".into(), "Different", None, 1),
            Err(CoreError::AlreadyExists(_))
        ));

        create_collection(&mut index, "personal".into(), "Personal", None, 1).unwrap();
        // Same name "Projects" nested under "personal" is fine — different parent.
        assert!(create_collection(&mut index, "nested".into(), "Projects", Some("personal".into()), 1).is_ok());
    }

    #[test]
    fn create_rejects_unknown_parent() {
        let mut index = Index::default();
        assert!(matches!(
            create_collection(&mut index, "c1".into(), "Nested", Some("missing".into()), 1),
            Err(CoreError::NotFound(_))
        ));
    }

    #[test]
    fn delete_cascades_to_nested_children_and_clears_entry_refs() {
        let mut index = Index::default();
        create_collection(&mut index, "work".into(), "Work", None, 1).unwrap();
        create_collection(&mut index, "eng".into(), "Engineering", Some("work".into()), 1).unwrap();
        create_collection(&mut index, "infra".into(), "Infra", Some("eng".into()), 1).unwrap();

        push_index_entry(&mut index, "e1", Some("infra"));
        push_index_entry(&mut index, "e2", Some("work"));
        push_index_entry(&mut index, "e3", None);

        let mut affected = delete_collection(&mut index, "work", 2).unwrap();
        affected.sort();
        assert_eq!(affected, vec!["e1".to_string(), "e2".to_string()]);

        assert!(list_root(&index).is_empty());
        assert!(index.entries.iter().find(|e| e.id == "e1").unwrap().collection_id.is_none());
        assert!(index.entries.iter().find(|e| e.id == "e3").unwrap().collection_id.is_none());
    }

    #[test]
    fn list_children_and_search_by_collection() {
        let mut index = Index::default();
        create_collection(&mut index, "work".into(), "Work", None, 1).unwrap();
        create_collection(&mut index, "eng".into(), "Engineering", Some("work".into()), 1).unwrap();
        push_index_entry(&mut index, "e1", Some("work"));
        push_index_entry(&mut index, "e2", Some("eng"));

        assert_eq!(list_children(&index, "work").len(), 1);
        assert_eq!(search_by_collection(&index, "work").len(), 1);
        assert_eq!(search_by_collection(&index, "eng").len(), 1);
    }

    #[test]
    fn rename_rejects_empty_and_sibling_duplicates() {
        let mut index = Index::default();
        create_collection(&mut index, "a".into(), "Alpha", None, 1).unwrap();
        create_collection(&mut index, "b".into(), "Beta", None, 1).unwrap();

        assert!(rename_collection(&mut index, "a", "  ", 2).is_err());
        assert!(matches!(
            rename_collection(&mut index, "a", "beta", 2),
            Err(CoreError::AlreadyExists(_))
        ));
        rename_collection(&mut index, "a", "Gamma", 2).unwrap();
        assert_eq!(index.collections[0].name, "Gamma");
    }
}
