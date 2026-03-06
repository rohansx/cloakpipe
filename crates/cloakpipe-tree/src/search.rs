//! LLM-driven tree search — reasoning-based document navigation.
//!
//! Instead of vector similarity, the LLM reasons over the tree structure
//! to find relevant nodes. The search works in rounds:
//! 1. Present top-level nodes to the LLM
//! 2. LLM selects which branches to explore
//! 3. Drill into selected branches, present children
//! 4. Repeat until leaf nodes or sufficient context found

use crate::tree::{NavigationEntry, SearchResult, TreeIndex};
use anyhow::Result;
use tracing::{debug, info};

/// Performs reasoning-based tree search over a TreeIndex.
pub struct TreeSearcher {
    client: reqwest::Client,
    api_key: String,
    api_base: String,
    model: String,
    max_rounds: usize,
    max_results: usize,
}

impl TreeSearcher {
    pub fn new(api_key: String, api_base: String, model: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key,
            api_base,
            model,
            max_rounds: 3,
            max_results: 5,
        }
    }

    /// Search the tree for nodes relevant to the query.
    pub async fn search(&self, tree: &TreeIndex, query: &str) -> Result<SearchResult> {
        info!("Tree search for query: {}", query);

        let nav_map = tree.navigation_map();

        if nav_map.len() <= 30 {
            return self.single_round_search(tree, &nav_map, query).await;
        }

        self.iterative_search(tree, query).await
    }

    async fn single_round_search(
        &self,
        _tree: &TreeIndex,
        nav_map: &[NavigationEntry],
        query: &str,
    ) -> Result<SearchResult> {
        let tree_text = self.format_navigation_map(nav_map);

        let prompt = format!(
            "You are a document retrieval expert. Given the following document structure, \
             identify which sections are most relevant to answer the user's question.\n\n\
             DOCUMENT STRUCTURE:\n{}\n\n\
             USER QUESTION: {}\n\n\
             Return a JSON object with:\n\
             - \"node_ids\": array of the most relevant node IDs (max {}), ordered by relevance\n\
             - \"reasoning\": brief explanation of why these sections are relevant\n\
             - \"confidence\": number 0-1 indicating confidence\n\n\
             Return ONLY valid JSON, no markdown.",
            tree_text, query, self.max_results
        );

        let response = self.call_llm(&prompt).await?;
        self.parse_search_response(&response)
    }

    async fn iterative_search(
        &self,
        tree: &TreeIndex,
        query: &str,
    ) -> Result<SearchResult> {
        let mut selected_ids: Vec<String> = Vec::new();
        let current_nodes = &tree.children;
        let mut all_reasoning = Vec::new();

        for round in 0..self.max_rounds {
            debug!(
                "Search round {} with {} candidates",
                round,
                current_nodes.len()
            );

            let entries: Vec<NavigationEntry> = current_nodes
                .iter()
                .map(|n| NavigationEntry {
                    id: n.id.clone(),
                    title: n.title.clone(),
                    summary: n.summary.as_ref().map(|s| s.text.clone()),
                    depth: n.depth,
                    pages: n.pages,
                    has_children: !n.children.is_empty(),
                })
                .collect();

            let tree_text = self.format_navigation_map(&entries);

            let prompt = format!(
                "You are navigating a document tree to find information. Round {}/{}.\n\n\
                 CURRENT LEVEL SECTIONS:\n{}\n\n\
                 QUESTION: {}\n\n\
                 Which sections should we explore deeper? Return JSON:\n\
                 - \"node_ids\": array of relevant node IDs at this level\n\
                 - \"reasoning\": why these sections\n\
                 - \"found\": boolean, true if these sections likely contain the answer directly\n\n\
                 Return ONLY valid JSON.",
                round + 1,
                self.max_rounds,
                tree_text,
                query
            );

            let response = self.call_llm(&prompt).await?;
            let round_result: serde_json::Value = serde_json::from_str(&response)
                .unwrap_or_else(|_| {
                    serde_json::json!({"node_ids": [], "reasoning": "parse error", "found": true})
                });

            let ids: Vec<String> = round_result["node_ids"]
                .as_array()
                .unwrap_or(&Vec::new())
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();

            let reasoning = round_result["reasoning"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let found = round_result["found"].as_bool().unwrap_or(true);

            all_reasoning.push(reasoning);
            selected_ids.extend(ids.clone());

            if found || round == self.max_rounds - 1 {
                break;
            }

            let children: Vec<&crate::tree::TreeNode> = current_nodes
                .iter()
                .filter(|n| ids.contains(&n.id))
                .flat_map(|n| &n.children)
                .collect();

            if children.is_empty() {
                break;
            }

            selected_ids.extend(children.iter().map(|c| c.id.clone()));
            break;
        }

        selected_ids.dedup();
        selected_ids.truncate(self.max_results);

        Ok(SearchResult {
            node_ids: selected_ids,
            reasoning: all_reasoning.join(" -> "),
            confidence: None,
        })
    }

    fn format_navigation_map(&self, entries: &[NavigationEntry]) -> String {
        entries
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    async fn call_llm(&self, prompt: &str) -> Result<String> {
        let body = serde_json::json!({
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a precise document retrieval agent. Always respond with valid JSON only."},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": 500,
            "temperature": 0.1,
            "response_format": {"type": "json_object"}
        });

        let url = format!(
            "{}/v1/chat/completions",
            self.api_base.trim_end_matches('/')
        );

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&body)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        Ok(response["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("{}")
            .to_string())
    }

    fn parse_search_response(&self, response: &str) -> Result<SearchResult> {
        let parsed: serde_json::Value = serde_json::from_str(response).unwrap_or_else(|_| {
            serde_json::json!({"node_ids": [], "reasoning": "parse error"})
        });

        Ok(SearchResult {
            node_ids: parsed["node_ids"]
                .as_array()
                .unwrap_or(&Vec::new())
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            reasoning: parsed["reasoning"].as_str().unwrap_or("").to_string(),
            confidence: parsed["confidence"].as_f64(),
        })
    }
}
