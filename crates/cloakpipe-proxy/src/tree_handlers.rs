//! HTTP handlers for CloakTree — vectorless document retrieval.

use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use cloakpipe_tree::{
    TreeIndexer, TreeSearcher,
    storage::TreeStorage,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

// --- Request/Response types ---

#[derive(Deserialize)]
pub struct IndexTextRequest {
    /// Document name (e.g., "contract.pdf")
    pub name: String,
    /// Raw text content of the document
    pub text: String,
}

#[derive(Serialize)]
pub struct IndexResponse {
    pub id: String,
    pub source: String,
    pub description: Option<String>,
    pub total_pages: usize,
    pub node_count: usize,
    pub max_depth: usize,
    pub navigation: Vec<NavigationItem>,
}

#[derive(Serialize)]
pub struct NavigationItem {
    pub id: String,
    pub title: String,
    pub summary: Option<String>,
    pub depth: usize,
    pub pages: (usize, usize),
    pub has_children: bool,
}

#[derive(Deserialize)]
pub struct SearchRequest {
    pub query: String,
}

#[derive(Serialize)]
pub struct SearchResponse {
    pub node_ids: Vec<String>,
    pub reasoning: String,
    pub confidence: Option<f64>,
    pub extracted: Vec<ExtractedItem>,
}

#[derive(Serialize)]
pub struct ExtractedItem {
    pub node_id: String,
    pub title: String,
    pub text: String,
    pub pages: (usize, usize),
}

#[derive(Deserialize)]
pub struct QueryRequest {
    /// Raw text content (for new documents) or tree ID (for existing)
    pub text: Option<String>,
    /// Document name
    pub name: Option<String>,
    /// Existing tree ID to search
    pub tree_id: Option<String>,
    /// The question to answer
    pub query: String,
}

#[derive(Serialize)]
pub struct QueryResponse {
    pub answer: String,
    pub sources: Vec<ExtractedItem>,
    pub tree_id: String,
    pub reasoning: String,
}

#[derive(Serialize)]
pub struct TreeListItem {
    pub id: String,
    pub source: String,
    pub description: Option<String>,
    pub total_pages: usize,
    pub node_count: usize,
}

// --- Handlers ---

/// POST /tree/index — Build a tree index from text content.
pub async fn tree_index_text(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IndexTextRequest>,
) -> Result<Json<IndexResponse>, (StatusCode, String)> {
    let tree_config = state.config.tree.clone();
    let indexer = TreeIndexer::new(
        tree_config.clone(),
        state.api_key.clone(),
        state.config.proxy.upstream.clone(),
    );

    let tree = indexer
        .build_index_from_text(&req.name, &req.text)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Indexing failed: {e}")))?;

    // Save to storage
    let storage_path = &tree_config.storage_path;
    TreeStorage::save(&tree, storage_path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Storage failed: {e}")))?;

    let nav = tree.navigation_map();
    Ok(Json(IndexResponse {
        id: tree.id.clone(),
        source: tree.source.clone(),
        description: tree.description.clone(),
        total_pages: tree.total_pages,
        node_count: tree.node_count(),
        max_depth: tree.max_depth(),
        navigation: nav.into_iter().map(|e| NavigationItem {
            id: e.id,
            title: e.title,
            summary: e.summary,
            depth: e.depth,
            pages: e.pages,
            has_children: e.has_children,
        }).collect(),
    }))
}

/// POST /tree/index/file — Build a tree index from a file path on disk.
pub async fn tree_index_file(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Result<Json<IndexResponse>, (StatusCode, String)> {
    let file_path = body["file_path"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "file_path required".to_string()))?;

    let tree_config = state.config.tree.clone();
    let indexer = TreeIndexer::new(
        tree_config.clone(),
        state.api_key.clone(),
        state.config.proxy.upstream.clone(),
    );

    let tree = indexer
        .build_index(file_path)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Indexing failed: {e}")))?;

    TreeStorage::save(&tree, &tree_config.storage_path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Storage failed: {e}")))?;

    let nav = tree.navigation_map();
    Ok(Json(IndexResponse {
        id: tree.id.clone(),
        source: tree.source.clone(),
        description: tree.description.clone(),
        total_pages: tree.total_pages,
        node_count: tree.node_count(),
        max_depth: tree.max_depth(),
        navigation: nav.into_iter().map(|e| NavigationItem {
            id: e.id,
            title: e.title,
            summary: e.summary,
            depth: e.depth,
            pages: e.pages,
            has_children: e.has_children,
        }).collect(),
    }))
}

/// GET /tree/list — List all tree indices.
pub async fn tree_list(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<TreeListItem>>, (StatusCode, String)> {
    let storage_path = &state.config.tree.storage_path;

    let trees_raw = TreeStorage::list(storage_path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("List failed: {e}")))?;

    let mut items = Vec::new();
    for (id, _source) in trees_raw {
        let path = format!("{storage_path}/{id}.json");
        if let Ok(tree) = TreeStorage::load(&path) {
            let node_count = tree.node_count();
            items.push(TreeListItem {
                id: tree.id,
                source: tree.source,
                description: tree.description,
                total_pages: tree.total_pages,
                node_count,
            });
        }
    }

    Ok(Json(items))
}

/// GET /tree/:id — Get tree details and navigation map.
pub async fn tree_get(
    State(state): State<Arc<AppState>>,
    Path(tree_id): Path<String>,
) -> Result<Json<IndexResponse>, (StatusCode, String)> {
    let path = format!("{}/{}.json", state.config.tree.storage_path, tree_id);
    let tree = TreeStorage::load(&path)
        .map_err(|e| (StatusCode::NOT_FOUND, format!("Tree not found: {e}")))?;

    let nav = tree.navigation_map();
    Ok(Json(IndexResponse {
        id: tree.id.clone(),
        source: tree.source.clone(),
        description: tree.description.clone(),
        total_pages: tree.total_pages,
        node_count: tree.node_count(),
        max_depth: tree.max_depth(),
        navigation: nav.into_iter().map(|e| NavigationItem {
            id: e.id,
            title: e.title,
            summary: e.summary,
            depth: e.depth,
            pages: e.pages,
            has_children: e.has_children,
        }).collect(),
    }))
}

/// POST /tree/:id/search — Search a tree index.
pub async fn tree_search(
    State(state): State<Arc<AppState>>,
    Path(tree_id): Path<String>,
    Json(req): Json<SearchRequest>,
) -> Result<Json<SearchResponse>, (StatusCode, String)> {
    let storage_path = &state.config.tree.storage_path;
    let tree_path = format!("{storage_path}/{tree_id}.json");

    let tree = TreeStorage::load(&tree_path)
        .map_err(|e| (StatusCode::NOT_FOUND, format!("Tree not found: {e}")))?;

    let searcher = TreeSearcher::new(
        state.api_key.clone(),
        state.config.proxy.upstream.clone(),
        state.config.tree.search_model.clone(),
    );

    let result = searcher
        .search(&tree, &req.query)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Search failed: {e}")))?;

    // Extract content from matched nodes
    // Re-parse document for extraction (or load cached pages)
    let extracted = result.node_ids.iter().filter_map(|id| {
        tree.find_node(id).map(|node| ExtractedItem {
            node_id: node.id.clone(),
            title: node.title.clone(),
            text: node.summary.as_ref().map(|s| s.text.clone()).unwrap_or_default(),
            pages: node.pages,
        })
    }).collect();

    Ok(Json(SearchResponse {
        node_ids: result.node_ids,
        reasoning: result.reasoning,
        confidence: result.confidence,
        extracted,
    }))
}

/// POST /tree/query — Full RAG pipeline: index (if needed) + search + extract + answer.
pub async fn tree_query(
    State(state): State<Arc<AppState>>,
    Json(req): Json<QueryRequest>,
) -> Result<Json<QueryResponse>, (StatusCode, String)> {
    let tree_config = state.config.tree.clone();
    let storage_path = &tree_config.storage_path;

    // Load or build tree
    let tree = if let Some(tree_id) = &req.tree_id {
        let path = format!("{storage_path}/{tree_id}.json");
        TreeStorage::load(&path)
            .map_err(|e| (StatusCode::NOT_FOUND, format!("Tree not found: {e}")))?
    } else if let Some(text) = &req.text {
        let name = req.name.as_deref().unwrap_or("uploaded-document");
        let indexer = TreeIndexer::new(
            tree_config.clone(),
            state.api_key.clone(),
            state.config.proxy.upstream.clone(),
        );
        let tree = indexer
            .build_index_from_text(name, text)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Indexing failed: {e}")))?;
        TreeStorage::save(&tree, storage_path)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Storage failed: {e}")))?;
        tree
    } else {
        return Err((StatusCode::BAD_REQUEST, "Either tree_id or text required".to_string()));
    };

    // Search
    let searcher = TreeSearcher::new(
        state.api_key.clone(),
        state.config.proxy.upstream.clone(),
        tree_config.search_model.clone(),
    );

    let search_result = searcher
        .search(&tree, &req.query)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Search failed: {e}")))?;

    // Build extracted items from node summaries/titles
    let sources: Vec<ExtractedItem> = search_result.node_ids.iter().filter_map(|id| {
        tree.find_node(id).map(|node| ExtractedItem {
            node_id: node.id.clone(),
            title: node.title.clone(),
            text: node.summary.as_ref().map(|s| s.text.clone()).unwrap_or_default(),
            pages: node.pages,
        })
    }).collect();

    // Build context from extracted content
    let context: String = sources.iter().enumerate().map(|(i, s)| {
        format!("[Source {} | {} | Pages {}-{}]\n{}", i + 1, s.title, s.pages.0, s.pages.1, s.text)
    }).collect::<Vec<_>>().join("\n\n");

    // Generate answer
    let answer_prompt = format!(
        "Use the following context to answer the question. Cite source numbers when possible.\n\n\
         ---\n{}\n---\n\nQuestion: {}",
        context, req.query
    );

    let answer_body = serde_json::json!({
        "model": tree_config.search_model,
        "messages": [
            {"role": "system", "content": "You answer questions based on provided document context. Be precise and cite sources."},
            {"role": "user", "content": answer_prompt}
        ],
        "max_tokens": 2048,
        "temperature": 0.3
    });

    let url = format!(
        "{}/v1/chat/completions",
        state.config.proxy.upstream.trim_end_matches('/')
    );

    let response = state
        .http_client
        .post(&url)
        .header("Authorization", format!("Bearer {}", state.api_key))
        .json(&answer_body)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("LLM request failed: {e}")))?
        .json::<Value>()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Invalid LLM response: {e}")))?;

    let answer = response["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("Unable to generate answer")
        .to_string();

    Ok(Json(QueryResponse {
        answer,
        sources,
        tree_id: tree.id,
        reasoning: search_result.reasoning,
    }))
}

/// DELETE /tree/:id — Delete a tree index.
pub async fn tree_delete(
    State(state): State<Arc<AppState>>,
    Path(tree_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let path = format!("{}/{}.json", state.config.tree.storage_path, tree_id);
    std::fs::remove_file(&path)
        .map_err(|e| (StatusCode::NOT_FOUND, format!("Tree not found: {e}")))?;

    Ok(Json(serde_json::json!({"deleted": tree_id})))
}
