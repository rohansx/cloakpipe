//! Tree index builder — ingests documents and creates hierarchical tree structures.
//!
//! The indexer:
//! 1. Parses the document to extract text and structure (headings, pages)
//! 2. Builds a hierarchical tree following the document's natural organization
//! 3. Generates LLM-powered summaries for each node
//! 4. Optionally pseudonymizes summaries before sending to LLM

use crate::tree::{NodeSummary, TreeIndex, TreeNode};
use anyhow::Result;
use cloakpipe_core::config::TreeConfig;
use tracing::info;

/// Builds tree indices from documents.
pub struct TreeIndexer {
    config: TreeConfig,
    client: reqwest::Client,
    api_key: String,
    /// Base URL for the LLM API (e.g., "https://api.openai.com").
    api_base: String,
}

/// A parsed page from a document.
#[derive(Debug, Clone)]
pub struct ParsedPage {
    pub page_number: usize,
    pub text: String,
    pub headings: Vec<Heading>,
}

/// A heading found in a document.
#[derive(Debug, Clone)]
pub struct Heading {
    pub text: String,
    pub level: usize,
    pub page: usize,
}

impl TreeIndexer {
    pub fn new(config: TreeConfig, api_key: String, api_base: String) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
            api_key,
            api_base,
        }
    }

    /// Build a tree index from a document file.
    pub async fn build_index(&self, file_path: &str) -> Result<TreeIndex> {
        info!("Building tree index for: {}", file_path);

        let pages = crate::parser::parse_document(file_path)?;
        info!("Parsed {} pages/sections", pages.len());

        let headings = self.extract_all_headings(&pages);
        info!("Found {} headings", headings.len());

        let mut tree = TreeIndex::new(file_path, &self.config.index_model);
        tree.total_pages = pages.len();
        tree.children = self.build_tree_from_headings(&headings, &pages)?;

        if self.config.add_node_summaries {
            self.generate_summaries(&mut tree.children, &pages).await?;
        }

        tree.description = Some(self.generate_doc_description(&tree).await?);

        info!(
            "Tree index complete: {} nodes, depth {}",
            tree.node_count(),
            tree.max_depth()
        );

        Ok(tree)
    }

    /// Build a tree index from raw text (no file needed).
    pub async fn build_index_from_text(
        &self,
        source_name: &str,
        text: &str,
    ) -> Result<TreeIndex> {
        info!("Building tree index from text: {}", source_name);

        let pages = vec![ParsedPage {
            page_number: 1,
            text: text.to_string(),
            headings: Vec::new(),
        }];

        let mut tree = TreeIndex::new(source_name, &self.config.index_model);
        tree.total_pages = 1;
        tree.children = self.build_page_based_tree(&pages)?;

        if self.config.add_node_summaries {
            self.generate_summaries(&mut tree.children, &pages).await?;
        }

        tree.description = Some(self.generate_doc_description(&tree).await?);

        Ok(tree)
    }

    fn extract_all_headings(&self, pages: &[ParsedPage]) -> Vec<Heading> {
        pages.iter().flat_map(|p| p.headings.clone()).collect()
    }

    fn build_tree_from_headings(
        &self,
        headings: &[Heading],
        pages: &[ParsedPage],
    ) -> Result<Vec<TreeNode>> {
        if headings.is_empty() {
            return self.build_page_based_tree(pages);
        }

        let mut root_nodes = Vec::new();
        let mut stack: Vec<TreeNode> = Vec::new();

        for (i, heading) in headings.iter().enumerate() {
            let next_page = headings
                .get(i + 1)
                .map(|h| h.page)
                .unwrap_or(pages.len());

            let node = TreeNode {
                id: format!("{}", i + 1),
                title: heading.text.clone(),
                summary: None,
                pages: (
                    heading.page,
                    next_page.min(heading.page + self.config.max_pages_per_node),
                ),
                token_count: None,
                children: Vec::new(),
                depth: heading.level.saturating_sub(1),
            };

            while let Some(last) = stack.last() {
                if node.depth <= last.depth {
                    let completed = stack.pop().unwrap();
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(completed);
                    } else {
                        root_nodes.push(completed);
                    }
                } else {
                    break;
                }
            }

            stack.push(node);
        }

        while let Some(completed) = stack.pop() {
            if let Some(parent) = stack.last_mut() {
                parent.children.push(completed);
            } else {
                root_nodes.push(completed);
            }
        }

        Ok(root_nodes)
    }

    fn build_page_based_tree(&self, pages: &[ParsedPage]) -> Result<Vec<TreeNode>> {
        let chunk_size = self.config.max_pages_per_node;
        let mut nodes = Vec::new();

        for (i, chunk) in pages.chunks(chunk_size).enumerate() {
            let start = chunk.first().map(|p| p.page_number).unwrap_or(1);
            let end = chunk.last().map(|p| p.page_number).unwrap_or(start);

            nodes.push(TreeNode {
                id: format!("{}", i + 1),
                title: format!("Section {}", i + 1),
                summary: None,
                pages: (start, end),
                token_count: None,
                children: Vec::new(),
                depth: 0,
            });
        }

        Ok(nodes)
    }

    async fn generate_summaries(
        &self,
        nodes: &mut Vec<TreeNode>,
        pages: &[ParsedPage],
    ) -> Result<()> {
        for node in nodes.iter_mut() {
            let text = self.extract_node_text(node, pages);
            if text.trim().is_empty() {
                continue;
            }

            let summary_text = self.call_llm_for_summary(&node.title, &text).await?;

            node.summary = Some(NodeSummary {
                text: summary_text,
                key_topics: Vec::new(),
                pseudonymized: false,
            });

            if !node.children.is_empty() {
                Box::pin(self.generate_summaries(&mut node.children, pages)).await?;
            }
        }
        Ok(())
    }

    fn extract_node_text(&self, node: &TreeNode, pages: &[ParsedPage]) -> String {
        pages
            .iter()
            .filter(|p| p.page_number >= node.pages.0 && p.page_number <= node.pages.1)
            .map(|p| p.text.as_str())
            .collect::<Vec<_>>()
            .join("\n\n")
    }

    async fn call_llm_for_summary(&self, title: &str, text: &str) -> Result<String> {
        let truncated = if text.len() > self.config.max_tokens_per_node * 4 {
            &text[..self.config.max_tokens_per_node * 4]
        } else {
            text
        };

        let prompt = format!(
            "Summarize the following section titled '{}' in 2-3 sentences. \
             Focus on key facts, figures, and conclusions.\n\n{}",
            title, truncated
        );

        let body = serde_json::json!({
            "model": self.config.index_model,
            "messages": [
                {"role": "system", "content": "You are a precise document summarizer. Output only the summary, no preamble."},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": 200,
            "temperature": 0.3
        });

        let url = format!("{}/v1/chat/completions", self.api_base.trim_end_matches('/'));

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&body)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let summary = response["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("Summary unavailable")
            .to_string();

        Ok(summary)
    }

    async fn generate_doc_description(&self, tree: &TreeIndex) -> Result<String> {
        let nav = tree.navigation_map();
        let toc: String = nav.iter().take(20).map(|e| format!("{}\n", e)).collect();

        let prompt = format!(
            "Based on this table of contents, write a one-sentence description of what this document is about:\n\n{}",
            toc
        );

        let body = serde_json::json!({
            "model": self.config.index_model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 100,
            "temperature": 0.3
        });

        let url = format!("{}/v1/chat/completions", self.api_base.trim_end_matches('/'));

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
            .unwrap_or("")
            .to_string())
    }
}
