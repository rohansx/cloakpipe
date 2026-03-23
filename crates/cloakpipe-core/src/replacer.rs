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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DetectedEntity, EntityCategory, DetectionSource, MaskingStrategy};

    fn make_entity(original: &str, start: usize, end: usize, cat: EntityCategory) -> DetectedEntity {
        DetectedEntity {
            original: original.to_string(),
            start,
            end,
            category: cat,
            confidence: 1.0,
            source: DetectionSource::Pattern,
        }
    }

    #[test]
    fn test_pseudonymize_token_strategy() {
        let text = "Call +91 98765 43210 now";
        let entities = vec![make_entity("+91 98765 43210", 5, 20, EntityCategory::PhoneNumber)];
        let mut vault = Vault::ephemeral();
        let result = Replacer::pseudonymize_with_strategy(text, &entities, &mut vault, MaskingStrategy::Token).unwrap();
        assert!(result.text.contains("PHONE_"), "Token strategy should use PHONE_ prefix");
        assert!(!result.text.contains("+91"));
    }

    #[test]
    fn test_pseudonymize_format_preserving_strategy() {
        let text = "Call +91 98765 43210 now";
        let entities = vec![make_entity("+91 98765 43210", 5, 20, EntityCategory::PhoneNumber)];
        let mut vault = Vault::ephemeral();
        let result = Replacer::pseudonymize_with_strategy(text, &entities, &mut vault, MaskingStrategy::FormatPreserving).unwrap();
        assert!(result.text.contains("+91"), "FP phone should preserve +91 prefix");
        assert!(!result.text.contains("98765 43210"), "Original digits should be replaced");
    }

    #[test]
    fn test_pseudonymize_fp_email() {
        let text = "Email: priya@example.com";
        let entities = vec![make_entity("priya@example.com", 7, 24, EntityCategory::Email)];
        let mut vault = Vault::ephemeral();
        let result = Replacer::pseudonymize_fp(text, &entities, &mut vault).unwrap();
        assert!(result.text.contains("@"), "FP email should contain @");
        assert!(!result.text.contains("priya"), "Original name should be gone");
    }

    #[test]
    fn test_pseudonymize_fp_preserves_surrounding_text() {
        let text = "Hello priya@example.com goodbye";
        let entities = vec![make_entity("priya@example.com", 6, 23, EntityCategory::Email)];
        let mut vault = Vault::ephemeral();
        let result = Replacer::pseudonymize_fp(text, &entities, &mut vault).unwrap();
        assert!(result.text.starts_with("Hello "), "Before text preserved");
        assert!(result.text.ends_with(" goodbye"), "After text preserved");
    }

    #[test]
    fn test_pseudonymize_fp_consistency() {
        let text1 = "Call +91 98765 43210";
        let text2 = "Call +91 98765 43210 again";
        let entities1 = vec![make_entity("+91 98765 43210", 5, 20, EntityCategory::PhoneNumber)];
        let entities2 = vec![make_entity("+91 98765 43210", 5, 20, EntityCategory::PhoneNumber)];
        let mut vault = Vault::ephemeral();
        let r1 = Replacer::pseudonymize_fp(text1, &entities1, &mut vault).unwrap();
        let r2 = Replacer::pseudonymize_fp(text2, &entities2, &mut vault).unwrap();
        // Same original value should get the same fake in the same vault
        let fake1: String = r1.text.chars().skip(5).collect();
        let fake2: String = r2.text.chars().skip(5).take(fake1.len()).collect();
        assert_eq!(fake1, fake2, "Same entity should produce same FP token");
    }

    #[test]
    fn test_pseudonymize_fp_multiple_entities() {
        let text = "Name: Rajesh, Email: raj@test.com";
        let entities = vec![
            make_entity("Rajesh", 6, 12, EntityCategory::Person),
            make_entity("raj@test.com", 21, 33, EntityCategory::Email),
        ];
        let mut vault = Vault::ephemeral();
        let result = Replacer::pseudonymize_fp(text, &entities, &mut vault).unwrap();
        assert!(!result.text.contains("Rajesh"));
        assert!(!result.text.contains("raj@test.com"));
        assert!(result.text.contains("@"), "Email FP should have @");
        assert_eq!(result.mappings.len(), 2);
    }
}
