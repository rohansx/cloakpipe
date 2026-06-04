//! Response rehydration — replaces pseudo-tokens back with original values.
//!
//! Handles both complete responses and SSE streaming chunks.

use crate::{RehydratedText, vault::Vault};
use anyhow::Result;

pub struct Rehydrator;

impl Rehydrator {
    /// Rehydrate a complete text response, replacing pseudo-tokens with originals.
    pub fn rehydrate(text: &str, vault: &Vault) -> Result<RehydratedText> {
        let mappings = vault.reverse_mappings();
        let mut result = text.to_string();
        let mut count = 0;

        // Sort mappings by token length (longest first) to avoid partial matches.
        // e.g., "ORG_12" should be replaced before "ORG_1"
        let mut sorted_mappings: Vec<_> = mappings.iter().collect();
        sorted_mappings.sort_by_key(|b| std::cmp::Reverse(b.0.len()));

        for (token, original) in sorted_mappings {
            if result.contains(token.as_str()) {
                result = result.replace(token.as_str(), original);
                count += 1;
            }
        }

        Ok(RehydratedText {
            text: result,
            rehydrated_count: count,
        })
    }

    /// Rehydrate a single SSE streaming chunk.
    /// Uses a token buffer to handle pseudo-tokens split across chunks.
    pub fn rehydrate_chunk(
        chunk: &str,
        buffer: &mut String,
        vault: &Vault,
    ) -> Result<(String, bool)> {
        buffer.push_str(chunk);

        // Check if buffer contains a complete pseudo-token pattern
        // Pattern: CATEGORY_DIGITS (e.g., ORG_7, AMOUNT_12, PERSON_5)
        let token_pattern = regex::Regex::new(r"[A-Z]+_\d+")?;

        if let Some(mat) = token_pattern.find(buffer) {
            // Check if the match is at the end (might be incomplete)
            if mat.end() == buffer.len() && !chunk.ends_with(' ') && !chunk.ends_with('\n') {
                // Token might continue in next chunk — hold buffer
                return Ok((String::new(), false));
            }

            // Complete token found — rehydrate it
            let token = mat.as_str();
            if let Some(original) = vault.lookup(token) {
                let rehydrated = buffer.replace(token, original);
                buffer.clear();
                return Ok((rehydrated, true));
            }
        }

        // No token pattern found — flush the buffer
        let output = buffer.clone();
        buffer.clear();
        Ok((output, false))
    }
}
