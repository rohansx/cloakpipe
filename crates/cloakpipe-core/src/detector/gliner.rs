//! GLiNER2 zero-shot entity detection via ONNX Runtime.
//!
//! GLiNER2 is a unified zero-shot NER model (~205M params) that runs on CPU.
//! Unlike traditional NER (fixed IOB2 labels), GLiNER takes entity type
//! descriptions as input and extracts arbitrary entity types without training.
//!
//! Architecture: bi-encoder span classifier
//! - Text tokens + entity label tokens are concatenated as input
//! - Model outputs span scores for each (start, end, label) triple
//! - Spans above confidence threshold are extracted as entities
//!
//! ONNX model source: knowledgator/gliner-multitask-large-v0.5 (or similar)
//! Tokenizer: DeBERTa-v3-based (tokenizer.json in model directory)

use crate::config::NerConfig;
use crate::{DetectedEntity, DetectionSource, EntityCategory};
use anyhow::Result;
use ort::session::Session;
use ort::value::Value;
use std::sync::Mutex;
use tokenizers::Tokenizer;
use tracing::{debug, info, warn};

/// Default PII entity labels for zero-shot detection.
/// Users can override these in cloakpipe.toml via `detection.ner.entity_types`.
const DEFAULT_ENTITY_LABELS: &[&str] = &[
    "person",
    "organization",
    "location",
    "date",
    "email address",
    "phone number",
    "credit card number",
    "social security number",
    "passport number",
    "medical record number",
    "bank account number",
    "ip address",
    "money amount",
];

/// Maps a GLiNER label string to CloakPipe's EntityCategory.
fn label_to_category(label: &str) -> EntityCategory {
    match label.to_lowercase().as_str() {
        "person" | "name" | "full name" | "patient name" | "employee" => EntityCategory::Person,
        "organization" | "company" | "org" | "institution" | "firm" | "bank" => {
            EntityCategory::Organization
        }
        "location" | "address" | "city" | "country" | "state" | "place" => EntityCategory::Location,
        "date" | "time" | "datetime" | "fiscal date" | "birth date" => EntityCategory::Date,
        "email" | "email address" => EntityCategory::Email,
        "phone" | "phone number" | "mobile number" | "telephone" => EntityCategory::PhoneNumber,
        "ip" | "ip address" | "ipv4" | "ipv6" => EntityCategory::IpAddress,
        "money" | "money amount" | "amount" | "price" | "salary" | "revenue" => {
            EntityCategory::Amount
        }
        "credit card" | "credit card number" | "card number" => {
            EntityCategory::Custom("CREDIT_CARD".into())
        }
        "social security" | "social security number" | "ssn" => {
            EntityCategory::Custom("SSN".into())
        }
        "passport" | "passport number" => EntityCategory::Custom("PASSPORT".into()),
        "medical record" | "medical record number" | "mrn" => {
            EntityCategory::Custom("MRN".into())
        }
        "bank account" | "bank account number" | "iban" => {
            EntityCategory::Custom("BANK_ACCOUNT".into())
        }
        "secret" | "api key" | "token" | "password" => EntityCategory::Secret,
        "url" | "website" => EntityCategory::Url,
        "project" | "project name" | "codename" => EntityCategory::Project,
        _ => EntityCategory::Custom(label.to_uppercase().replace(' ', "_")),
    }
}

/// GLiNER2 zero-shot entity detector using ONNX Runtime.
pub struct GlinerDetector {
    session: Mutex<Session>,
    tokenizer: Tokenizer,
    confidence_threshold: f64,
    /// Entity labels to detect (from config or defaults).
    entity_labels: Vec<String>,
    /// Maximum input length for the model (typically 512 for DeBERTa).
    max_length: usize,
}

impl GlinerDetector {
    /// Create a new GLiNER detector from config.
    ///
    /// Model path should point to a GLiNER2 ONNX export with:
    /// - Input: input_ids, attention_mask, word_mask, span_idx, span_mask
    /// - Output: span_logits [batch, num_spans, num_labels]
    ///
    /// A `tokenizer.json` must exist in the same directory.
    pub fn new(config: &NerConfig) -> Result<Self> {
        let model_path = config.model.as_deref().unwrap_or("models/gliner.onnx");

        info!("Loading GLiNER2 model from: {}", model_path);

        let session = Session::builder()
            .map_err(|e| anyhow::anyhow!("Failed to create session builder: {}", e))?
            .with_intra_threads(4)
            .map_err(|e| anyhow::anyhow!("Failed to set threads: {}", e))?
            .commit_from_file(model_path)
            .map_err(|e| anyhow::anyhow!("Failed to load GLiNER model '{}': {}", model_path, e))?;

        // Load tokenizer from same directory
        let model_dir = std::path::Path::new(model_path)
            .parent()
            .unwrap_or(std::path::Path::new("."));
        let tokenizer_path = model_dir.join("tokenizer.json");

        let tokenizer = Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| anyhow::anyhow!("Failed to load tokenizer: {}", e))?;

        // Entity labels: use config if provided, otherwise defaults
        let entity_labels = if config.entity_types.is_empty() {
            DEFAULT_ENTITY_LABELS
                .iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            config.entity_types.clone()
        };

        info!(
            "GLiNER2 loaded: {} entity labels configured",
            entity_labels.len()
        );

        Ok(Self {
            session: Mutex::new(session),
            tokenizer,
            confidence_threshold: config.confidence_threshold,
            entity_labels,
            max_length: 512,
        })
    }

    /// Detect entities using GLiNER2 zero-shot span extraction.
    ///
    /// GLiNER's input format concatenates entity label tokens with text tokens:
    /// `[CLS] label1 [SEP] label2 [SEP] ... labelN [SEP] [SEP] text tokens [SEP]`
    ///
    /// The model then scores all possible (start, end) spans in the text portion
    /// against each entity label.
    pub fn detect(&self, text: &str) -> Result<Vec<DetectedEntity>> {
        if text.is_empty() {
            return Ok(Vec::new());
        }

        // Build the concatenated input: labels + text
        let (input_ids, attention_mask, word_mask, text_token_offsets) =
            self.prepare_input(text)?;

        let seq_len = input_ids.len();
        if seq_len == 0 {
            return Ok(Vec::new());
        }

        // Generate all valid spans from the text portion
        let max_span_width = 12; // Maximum entity width in tokens
        let (span_idx, span_mask, num_spans) =
            self.generate_spans(&word_mask, max_span_width);

        if num_spans == 0 {
            return Ok(Vec::new());
        }

        // Create ONNX tensors
        let input_ids_tensor = Value::from_array(([1i64, seq_len as i64], input_ids))
            .map_err(|e| anyhow::anyhow!("Failed to create input_ids tensor: {}", e))?;
        let attention_mask_tensor =
            Value::from_array(([1i64, seq_len as i64], attention_mask.clone()))
                .map_err(|e| anyhow::anyhow!("Failed to create attention_mask tensor: {}", e))?;
        let word_mask_tensor =
            Value::from_array(([1i64, seq_len as i64], word_mask.clone()))
                .map_err(|e| anyhow::anyhow!("Failed to create word_mask tensor: {}", e))?;
        let span_idx_tensor =
            Value::from_array(([1i64, num_spans as i64, 2i64], span_idx))
                .map_err(|e| anyhow::anyhow!("Failed to create span_idx tensor: {}", e))?;
        let span_mask_tensor =
            Value::from_array(([1i64, num_spans as i64], span_mask))
                .map_err(|e| anyhow::anyhow!("Failed to create span_mask tensor: {}", e))?;

        let mut session = self
            .session
            .lock()
            .map_err(|_| anyhow::anyhow!("GLiNER session lock poisoned"))?;

        // Run inference
        let outputs = session
            .run(ort::inputs![
                "input_ids" => input_ids_tensor,
                "attention_mask" => attention_mask_tensor,
                "word_mask" => word_mask_tensor,
                "span_idx" => span_idx_tensor,
                "span_mask" => span_mask_tensor,
            ])
            .map_err(|e| anyhow::anyhow!("GLiNER inference failed: {}", e))?;

        // Extract span logits: [1, num_spans, num_labels]
        let (_shape, logits_data) = outputs[0]
            .try_extract_tensor::<f32>()
            .map_err(|e| anyhow::anyhow!("Failed to extract span logits: {}", e))?;

        // Decode spans into entities
        let entities =
            self.decode_spans(logits_data, num_spans, &text_token_offsets, text)?;

        debug!("GLiNER2 detected {} entities", entities.len());
        Ok(entities)
    }

    /// Prepare tokenized input for GLiNER: labels + separator + text.
    ///
    /// Returns (input_ids, attention_mask, word_mask, text_token_offsets).
    /// `word_mask` marks which tokens belong to the text (1) vs labels (0).
    /// `text_token_offsets` maps text token indices to byte offsets in original text.
    #[allow(clippy::type_complexity)]
    fn prepare_input(
        &self,
        text: &str,
    ) -> Result<(Vec<i64>, Vec<i64>, Vec<i64>, Vec<(usize, usize)>)> {
        // Tokenize the text alone to get word-level offsets
        let text_encoding = self
            .tokenizer
            .encode(text, false)
            .map_err(|e| anyhow::anyhow!("Text tokenization failed: {}", e))?;

        let text_ids: Vec<u32> = text_encoding.get_ids().to_vec();
        let text_offsets: Vec<(usize, usize)> = text_encoding.get_offsets().to_vec();

        // Build label prompt: "[CLS] label1 [SEP] label2 [SEP] ... [SEP]"
        let mut label_tokens: Vec<u32> = Vec::new();

        // Add CLS token (id 1 for DeBERTa, 101 for BERT — we'll use the tokenizer)
        let cls_encoding = self
            .tokenizer
            .encode("[CLS]", false)
            .map_err(|e| anyhow::anyhow!("CLS tokenization failed: {}", e))?;
        let sep_encoding = self
            .tokenizer
            .encode("[SEP]", false)
            .map_err(|e| anyhow::anyhow!("SEP tokenization failed: {}", e))?;

        // Get special token IDs
        let cls_id = cls_encoding.get_ids().first().copied().unwrap_or(1);
        let sep_id = sep_encoding.get_ids().first().copied().unwrap_or(2);

        // Build: CLS label1_tokens SEP label2_tokens SEP ... SEP SEP
        label_tokens.push(cls_id);
        for label in &self.entity_labels {
            let label_enc = self
                .tokenizer
                .encode(label.as_str(), false)
                .map_err(|e| {
                    anyhow::anyhow!("Label '{}' tokenization failed: {}", label, e)
                })?;
            label_tokens.extend_from_slice(label_enc.get_ids());
            label_tokens.push(sep_id);
        }
        // Extra SEP to separate labels from text
        label_tokens.push(sep_id);

        let label_len = label_tokens.len();

        // Truncate text tokens if combined length exceeds max
        let max_text_tokens = self.max_length.saturating_sub(label_len + 1); // +1 for final SEP
        let text_len = text_ids.len().min(max_text_tokens);

        if text_len < text_ids.len() {
            warn!(
                "Text truncated from {} to {} tokens (max_length={})",
                text_ids.len(),
                text_len,
                self.max_length
            );
        }

        // Combine: label_tokens + text_tokens + SEP
        let total_len = label_len + text_len + 1;
        let mut input_ids: Vec<i64> = Vec::with_capacity(total_len);
        let mut attention_mask: Vec<i64> = Vec::with_capacity(total_len);
        let mut word_mask: Vec<i64> = Vec::with_capacity(total_len);
        let mut final_text_offsets: Vec<(usize, usize)> = Vec::with_capacity(total_len);

        // Label portion
        for &id in &label_tokens {
            input_ids.push(id as i64);
            attention_mask.push(1);
            word_mask.push(0); // Not text
            final_text_offsets.push((0, 0)); // No text offset
        }

        // Text portion
        for i in 0..text_len {
            input_ids.push(text_ids[i] as i64);
            attention_mask.push(1);
            word_mask.push(1); // Text token
            final_text_offsets.push(text_offsets[i]);
        }

        // Final SEP
        input_ids.push(sep_id as i64);
        attention_mask.push(1);
        word_mask.push(0);
        final_text_offsets.push((0, 0));

        Ok((input_ids, attention_mask, word_mask, final_text_offsets))
    }

    /// Generate all valid span indices from the word mask.
    ///
    /// A span (i, j) represents tokens from position i to j (inclusive)
    /// where both i and j have word_mask == 1 (text tokens).
    ///
    /// Returns (flat span_idx [num_spans * 2], span_mask [num_spans], count).
    fn generate_spans(
        &self,
        word_mask: &[i64],
        max_width: usize,
    ) -> (Vec<i64>, Vec<f32>, usize) {
        // Find text token positions
        let text_positions: Vec<usize> = word_mask
            .iter()
            .enumerate()
            .filter(|(_, &m)| m == 1)
            .map(|(i, _)| i)
            .collect();

        let mut span_idx: Vec<i64> = Vec::new();
        let mut span_mask: Vec<f32> = Vec::new();

        for (pi, &start) in text_positions.iter().enumerate() {
            for &end in &text_positions[pi..text_positions.len().min(pi + max_width)] {
                span_idx.push(start as i64);
                span_idx.push(end as i64);
                span_mask.push(1.0);
            }
        }

        let num_spans = span_mask.len();
        (span_idx, span_mask, num_spans)
    }

    /// Decode span logits into DetectedEntity instances.
    ///
    /// For each span, find the label with the highest score.
    /// If the score exceeds the confidence threshold, create an entity.
    fn decode_spans(
        &self,
        logits: &[f32],
        num_spans: usize,
        text_offsets: &[(usize, usize)],
        original_text: &str,
    ) -> Result<Vec<DetectedEntity>> {
        let num_labels = self.entity_labels.len();
        let mut raw_entities: Vec<(usize, usize, f64, EntityCategory, String)> = Vec::new();

        for span_i in 0..num_spans {
            let offset = span_i * num_labels;
            if offset + num_labels > logits.len() {
                break;
            }

            let span_logits = &logits[offset..offset + num_labels];

            // Apply sigmoid to get per-label probabilities
            let mut best_label_idx = 0;
            let mut best_score: f32 = f32::NEG_INFINITY;

            for (li, &logit) in span_logits.iter().enumerate() {
                let score = sigmoid(logit);
                if score > best_score {
                    best_score = score;
                    best_label_idx = li;
                }
            }

            let confidence = best_score as f64;
            if confidence < self.confidence_threshold {
                continue;
            }

            let label = &self.entity_labels[best_label_idx];
            let category = label_to_category(label);

            // Recover byte offsets from token offsets
            // span_idx was stored as flat pairs; we need to map back
            // The span's start token and end token positions in the full sequence
            // text_offsets[token_pos] gives (byte_start, byte_end) in original text
            // But we need the actual span positions — they were generated from word_mask
            // So we can derive them from the span index

            // For now, store span index and resolve later
            raw_entities.push((span_i, best_label_idx, confidence, category, label.clone()));
        }

        // Now resolve byte offsets
        // We need the span_idx data, but we don't have it here.
        // Instead, re-derive from word_mask approach:
        // text_offsets has byte ranges for every token in the input sequence.
        // The word_mask=1 tokens correspond to text tokens.
        // Spans are generated over these text positions.

        // Re-find text positions from offsets (text tokens have non-zero offsets)
        let text_positions: Vec<usize> = text_offsets
            .iter()
            .enumerate()
            .filter(|(_, (s, e))| *s != 0 || *e != 0)
            .map(|(i, _)| i)
            .collect();

        // Re-derive span mapping: span_i → (start_text_pos_index, end_text_pos_index)
        let max_width = 12usize;
        let mut span_to_pos: Vec<(usize, usize)> = Vec::new();
        for pi in 0..text_positions.len() {
            for pj in pi..text_positions.len().min(pi + max_width) {
                span_to_pos.push((pi, pj));
            }
        }

        let mut entities = Vec::new();

        for (span_i, _label_idx, confidence, category, _label) in &raw_entities {
            if *span_i >= span_to_pos.len() {
                continue;
            }
            let (start_pi, end_pi) = span_to_pos[*span_i];

            if start_pi >= text_positions.len() || end_pi >= text_positions.len() {
                continue;
            }

            let start_tok = text_positions[start_pi];
            let end_tok = text_positions[end_pi];

            let byte_start = text_offsets[start_tok].0;
            let byte_end = text_offsets[end_tok].1;

            if byte_start >= byte_end || byte_end > original_text.len() {
                continue;
            }

            let entity_text = &original_text[byte_start..byte_end];

            // Skip empty or whitespace-only entities
            if entity_text.trim().is_empty() {
                continue;
            }

            entities.push(DetectedEntity {
                original: entity_text.to_string(),
                start: byte_start,
                end: byte_end,
                category: category.clone(),
                confidence: *confidence,
                source: DetectionSource::Ner,
            });
        }

        // Deduplicate overlapping spans (keep highest confidence)
        entities.sort_by_key(|e| e.start);
        let mut deduped: Vec<DetectedEntity> = Vec::new();
        for entity in entities {
            if let Some(last) = deduped.last() {
                if entity.start < last.end {
                    if entity.confidence > last.confidence {
                        deduped.pop();
                        deduped.push(entity);
                    }
                    continue;
                }
            }
            deduped.push(entity);
        }

        Ok(deduped)
    }

    /// Get the configured entity labels.
    pub fn entity_labels(&self) -> &[String] {
        &self.entity_labels
    }
}

/// Sigmoid activation function.
fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_to_category() {
        assert_eq!(label_to_category("person"), EntityCategory::Person);
        assert_eq!(label_to_category("Person"), EntityCategory::Person);
        assert_eq!(
            label_to_category("organization"),
            EntityCategory::Organization
        );
        assert_eq!(label_to_category("location"), EntityCategory::Location);
        assert_eq!(label_to_category("date"), EntityCategory::Date);
        assert_eq!(label_to_category("email address"), EntityCategory::Email);
        assert_eq!(
            label_to_category("phone number"),
            EntityCategory::PhoneNumber
        );
        assert_eq!(label_to_category("ip address"), EntityCategory::IpAddress);
        assert_eq!(label_to_category("money amount"), EntityCategory::Amount);
        assert_eq!(label_to_category("secret"), EntityCategory::Secret);
        assert_eq!(
            label_to_category("credit card number"),
            EntityCategory::Custom("CREDIT_CARD".into())
        );
        assert_eq!(
            label_to_category("social security number"),
            EntityCategory::Custom("SSN".into())
        );
    }

    #[test]
    fn test_label_to_category_custom() {
        assert_eq!(
            label_to_category("vehicle registration"),
            EntityCategory::Custom("VEHICLE_REGISTRATION".into())
        );
        assert_eq!(
            label_to_category("court case number"),
            EntityCategory::Custom("COURT_CASE_NUMBER".into())
        );
    }

    #[test]
    fn test_sigmoid() {
        assert!((sigmoid(0.0) - 0.5).abs() < 1e-6);
        assert!(sigmoid(10.0) > 0.999);
        assert!(sigmoid(-10.0) < 0.001);
    }

    #[test]
    fn test_default_entity_labels() {
        assert!(DEFAULT_ENTITY_LABELS.contains(&"person"));
        assert!(DEFAULT_ENTITY_LABELS.contains(&"organization"));
        assert!(DEFAULT_ENTITY_LABELS.contains(&"email address"));
        assert!(DEFAULT_ENTITY_LABELS.contains(&"credit card number"));
        assert!(DEFAULT_ENTITY_LABELS.len() >= 10);
    }
}
