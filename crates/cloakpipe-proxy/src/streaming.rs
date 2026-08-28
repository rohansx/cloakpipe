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
        let mut saw_done = false;
        for line in byte_stream.lines() {
            if let Some(data) = line.strip_prefix("data: ") {

                if data == "[DONE]" {
                    // Defer [DONE] until after the held buffer is flushed below,
                    // so a trailing pseudo-token isn't dropped or emitted late.
                    saw_done = true;
                    break;
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
                            yield Ok(format!("data: {serialized}\n\n"));
                        }
                    } else {
                        // Non-content chunk (role, finish_reason, etc.) — pass through
                        yield Ok(format!("data: {data}\n\n"));
                    }
                } else {
                    // Unparseable data — pass through
                    yield Ok(format!("data: {data}\n\n"));
                }
            } else if !line.is_empty() {
                yield Ok(format!("{line}\n"));
            }
        }

        // Flush any pseudo-token still held in the buffer (rehydrated) as a final
        // content chunk — otherwise a token at the very end of the stream, held
        // awaiting more chunks, would be dropped.
        if !buffer.is_empty() {
            let flushed = {
                let vault_guard = vault.lock().await;
                Rehydrator::rehydrate(&buffer, &vault_guard)
                    .map(|r| r.text)
                    .unwrap_or_else(|_| buffer.clone())
            };
            tracing::debug!(request_id = %request_id, "Flushing remaining stream buffer");
            buffer.clear();
            if !flushed.is_empty() {
                let chunk = serde_json::json!({
                    "choices": [{ "index": 0, "delta": { "content": flushed } }]
                });
                yield Ok(format!("data: {chunk}\n\n"));
            }
        }

        if saw_done {
            yield Ok("data: [DONE]\n\n".to_string());
        }
    }
}

/// Consume an Anthropic Messages SSE response and rehydrate text deltas.
pub async fn rehydrate_anthropic_stream(
    response: reqwest::Response,
    vault: Arc<Mutex<Vault>>,
    request_id: String,
) -> impl Stream<Item = Result<String, std::io::Error>> {
    let mut buffer = String::new();

    async_stream::stream! {
        let byte_stream = response.text().await.unwrap_or_default();

        for line in byte_stream.lines() {
            if let Some(data) = line.strip_prefix("data: ") {
                if let Ok(mut event) = serde_json::from_str::<serde_json::Value>(data) {
                    let text = event
                        .get("delta")
                        .and_then(|delta| delta.get("text"))
                        .and_then(|text| text.as_str())
                        .map(str::to_string);

                    if let Some(text) = text {
                        let vault_guard = vault.lock().await;
                        let (rehydrated, _) = Rehydrator::rehydrate_chunk(
                            &text,
                            &mut buffer,
                            &vault_guard,
                        ).unwrap_or((text, false));

                        if let Some(delta) = event.get_mut("delta") {
                            delta["text"] = serde_json::Value::String(rehydrated);
                        }
                    }

                    let serialized = serde_json::to_string(&event).unwrap_or_default();
                    yield Ok(format!("data: {serialized}\n\n"));
                } else {
                    yield Ok(format!("data: {data}\n\n"));
                }
            } else if line.starts_with("event: ") || !line.is_empty() {
                yield Ok(format!("{line}\n"));
            }
        }

        if !buffer.is_empty() {
            let flushed = {
                let vault_guard = vault.lock().await;
                Rehydrator::rehydrate(&buffer, &vault_guard)
                    .map(|result| result.text)
                    .unwrap_or_else(|_| buffer.clone())
            };
            tracing::debug!(request_id = %request_id, "Flushing remaining Anthropic stream buffer");
            if !flushed.is_empty() {
                let event = serde_json::json!({
                    "type": "content_block_delta",
                    "delta": { "type": "text_delta", "text": flushed }
                });
                yield Ok(format!("data: {event}\n\n"));
            }
        }
    }
}
