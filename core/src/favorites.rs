use crate::vault::{Entry, Index, IndexEntry};

/// Marks (or unmarks) a decrypted `Entry` as a favorite. The caller must
/// persist via `Vault::put_entry`, which syncs `IndexEntry.favorite` too.
pub fn set_favorite(entry: &mut Entry, favorite: bool) {
    entry.favorite = favorite;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FavoriteSort {
    TitleAscending,
    RecentlyUpdatedFirst,
}

/// Non-deleted favorited entries, sorted as requested.
pub fn list_favorites(index: &Index, sort: FavoriteSort) -> Vec<&IndexEntry> {
    let mut favorites: Vec<&IndexEntry> = index.entries.iter().filter(|e| !e.deleted && e.favorite).collect();
    match sort {
        FavoriteSort::TitleAscending => favorites.sort_by_key(|a| a.title.to_lowercase()),
        FavoriteSort::RecentlyUpdatedFirst => favorites.sort_by_key(|a| std::cmp::Reverse(a.updated_at)),
    }
    favorites
}

/// Favorited entries matching `term` against title/username/url (case
/// insensitive). An empty term returns all favorites.
pub fn search_favorites<'a>(index: &'a Index, term: &str) -> Vec<&'a IndexEntry> {
    let lower = term.trim().to_lowercase();
    index
        .entries
        .iter()
        .filter(|e| {
            !e.deleted
                && e.favorite
                && (lower.is_empty()
                    || e.title.to_lowercase().contains(&lower)
                    || e.username.to_lowercase().contains(&lower)
                    || e.url.to_lowercase().contains(&lower))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn push(index: &mut Index, id: &str, title: &str, favorite: bool, updated_at: i64) {
        index.entries.push(IndexEntry {
            id: id.into(),
            title: title.into(),
            username: "u".into(),
            url: "example.com".into(),
            updated_at,
            deleted: false,
            tags: Vec::new(),
            collection_id: None,
            favorite,
            category: Default::default(),
            attachments: Vec::new(),
        });
    }

    #[test]
    fn set_favorite_toggles_flag_on_entry() {
        let mut entry = Entry {
            id: "e1".into(),
            title: "t".into(),
            username: "u".into(),
            password: "p".into(),
            url: "url".into(),
            notes: "".into(),
            totp_secret: None,
            custom_fields: HashMap::new(),
            updated_at: 1,
            deleted: false,
            tags: Vec::new(),
            collection_id: None,
            favorite: false,
            alias_provider: None,
            alias_id: None,
            alias_email: None,
            category: Default::default(),
            password_history: Vec::new(),
            attachments: Vec::new(),
        };
        set_favorite(&mut entry, true);
        assert!(entry.favorite);
        set_favorite(&mut entry, false);
        assert!(!entry.favorite);
    }

    #[test]
    fn list_favorites_filters_and_sorts() {
        let mut index = Index::default();
        push(&mut index, "e1", "Zebra", true, 10);
        push(&mut index, "e2", "Apple", true, 20);
        push(&mut index, "e3", "Not a favorite", false, 30);

        let by_title = list_favorites(&index, FavoriteSort::TitleAscending);
        assert_eq!(by_title.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(), vec!["e2", "e1"]);

        let by_recency = list_favorites(&index, FavoriteSort::RecentlyUpdatedFirst);
        assert_eq!(by_recency.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(), vec!["e2", "e1"]);
    }

    #[test]
    fn search_favorites_matches_and_excludes_non_favorites() {
        let mut index = Index::default();
        push(&mut index, "e1", "GitHub", true, 1);
        push(&mut index, "e2", "GitLab", false, 1);

        let results = search_favorites(&index, "git");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "e1");

        assert_eq!(search_favorites(&index, "").len(), 1);
    }
}
