//! SSE streaming rehydration for chat completion responses.

use cloakpipe_core::{rehydrator::Rehydrator, vault::Vault};
use futures::stream::Stream;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Consume an upstream SSE response and produce a rehydrated SSE stream.
pub async fn rehydrate_stream(
    response: reqwest::Response,
    vault: Arc<Mutex<Vault>>,
    request_id: String,
) -> impl Stream<Item = Result<String, std::io::Error>> {
    let mut buffer = String::new();

    async_stream::stream! {
        let byte_stream = response.text().await.unwrap_or_default();

        // Split SSE response into lines and process events
        for line in byte_stream.lines() {
            if let Some(data) = line.strip_prefix("data: ") {

                if data == "[DONE]" {
                    yield Ok("data: [DONE]\n\n".to_string());
                    continue;
                }

                // Parse the SSE JSON chunk
                if let Ok(mut chunk) = serde_json::from_str::<serde_json::Value>(data) {
                    // Extract delta content
                    if let Some(content) = chunk
                        .get("choices")
                        .and_then(|c| c.get(0))
                        .and_then(|c| c.get("delta"))
                        .and_then(|d| d.get("content"))
                        .and_then(|c| c.as_str())
                        .map(|s| s.to_string())
                    {
                        let vault_guard = vault.lock().await;
                        let (rehydrated, _) = Rehydrator::rehydrate_chunk(
                            &content,
                            &mut buffer,
                            &vault_guard,
                        )
                        .unwrap_or((content.clone(), false));

                        if !rehydrated.is_empty() {
                            // Update the delta content with rehydrated text
                            if let Some(choices) = chunk.get_mut("choices").and_then(|c| c.as_array_mut()) {
                                if let Some(first) = choices.first_mut() {
                                    if let Some(delta) = first.get_mut("delta") {
                                        delta["content"] = serde_json::Value::String(rehydrated);
                                    }
                                }
                            }

                            let serialized = serde_json::to_string(&chunk).unwrap_or_default();
                            yield Ok(format!("data: {}\n\n", serialized));
                        }
                    } else {
                        // Non-content chunk (role, finish_reason, etc.) — pass through
                        yield Ok(format!("data: {}\n\n", data));
                    }
                } else {
                    // Unparseable data — pass through
                    yield Ok(format!("data: {}\n\n", data));
                }
            } else if !line.is_empty() {
                yield Ok(format!("{}\n", line));
            }
        }

        // Flush any remaining buffer
        if !buffer.is_empty() {
            tracing::debug!(request_id = %request_id, "Flushing remaining stream buffer");
        }
    }
}
