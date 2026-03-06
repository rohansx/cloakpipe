//! Local JSON persistence for tree indices.

use crate::tree::TreeIndex;
use anyhow::Result;
use std::path::Path;

pub struct TreeStorage;

impl TreeStorage {
    /// Save a tree index to a JSON file.
    pub fn save(tree: &TreeIndex, dir: &str) -> Result<String> {
        std::fs::create_dir_all(dir)?;
        let path = format!("{}/{}.json", dir, tree.id);
        let json = serde_json::to_string_pretty(tree)?;
        std::fs::write(&path, json)?;
        Ok(path)
    }

    /// Load a tree index from a JSON file.
    pub fn load(path: &str) -> Result<TreeIndex> {
        let json = std::fs::read_to_string(path)?;
        let tree: TreeIndex = serde_json::from_str(&json)?;
        Ok(tree)
    }

    /// List all tree indices in a directory.
    pub fn list(dir: &str) -> Result<Vec<(String, String)>> {
        let mut trees = Vec::new();
        if Path::new(dir).exists() {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                if entry.path().extension().is_some_and(|e| e == "json") {
                    if let Ok(tree) = Self::load(entry.path().to_str().unwrap_or("")) {
                        trees.push((tree.id, tree.source));
                    }
                }
            }
        }
        Ok(trees)
    }
}
