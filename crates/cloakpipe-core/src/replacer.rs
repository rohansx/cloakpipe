//! Consistent pseudonymization engine.
//!
//! Takes detected entities and replaces them with stable pseudo-tokens
//! using the vault for consistency across documents, queries, and sessions.

use crate::{DetectedEntity, MaskingStrategy, PseudonymizedText, vault::Vault};
use anyhow::Result;
use std::collections::HashMap;

pub struct Replacer;

impl Replacer {
    /// Replace all detected entities in the text with pseudo-tokens.
    /// Entities must be sorted by position (start offset) and non-overlapping.
    pub fn pseudonymize(
        text: &str,
        entities: &[DetectedEntity],
        vault: &mut Vault,
    ) -> Result<PseudonymizedText> {
        let mut result = String::with_capacity(text.len());
        let mut mappings = HashMap::new();
        let mut last_end = 0;

        for entity in entities {
            // Append text before this entity
            if entity.start > last_end {
                result.push_str(&text[last_end..entity.start]);
            }

            // Get or create a consistent pseudo-token
            let token = vault.get_or_create(&entity.original, &entity.category);

            // Record the mapping for rehydration
            mappings.insert(token.token.clone(), entity.original.clone());

            // Append the pseudo-token
            result.push_str(&token.token);
            last_end = entity.end;
        }

        // Append remaining text after last entity
        if last_end < text.len() {
            result.push_str(&text[last_end..]);
        }

        Ok(PseudonymizedText {
            text: result,
            mappings,
            entities: entities.to_vec(),
        })
    }

    /// Replace entities using format-preserving fakes instead of tokens.
    pub fn pseudonymize_fp(
        text: &str,
        entities: &[DetectedEntity],
        vault: &mut Vault,
    ) -> Result<PseudonymizedText> {
        let mut result = String::with_capacity(text.len());
        let mut mappings = HashMap::new();
        let mut last_end = 0;

        for entity in entities {
            if entity.start > last_end {
                result.push_str(&text[last_end..entity.start]);
            }
            let token = vault.get_or_create_fp(&entity.original, &entity.category);
            mappings.insert(token.token.clone(), entity.original.clone());
            result.push_str(&token.token);
            last_end = entity.end;
        }

        if last_end < text.len() {
            result.push_str(&text[last_end..]);
        }

        Ok(PseudonymizedText {
            text: result,
            mappings,
            entities: entities.to_vec(),
        })
    }

    /// Dispatch to the appropriate pseudonymization strategy.
    pub fn pseudonymize_with_strategy(
        text: &str,
        entities: &[DetectedEntity],
        vault: &mut Vault,
        strategy: MaskingStrategy,
    ) -> Result<PseudonymizedText> {
        match strategy {
            MaskingStrategy::Token => Self::pseudonymize(text, entities, vault),
            MaskingStrategy::FormatPreserving => Self::pseudonymize_fp(text, entities, vault),
        }
    }
}
