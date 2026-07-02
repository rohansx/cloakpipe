//! ONNX-based Named Entity Recognition detector.
//!
//! Uses a BERT-based NER model (e.g., dslim/bert-base-NER) exported to ONNX
//! for local, private entity detection. No external API calls needed.
//!
//! Expected model inputs: input_ids, attention_mask, token_type_ids
//! Expected output: logits tensor [batch, seq_len, num_labels]
//!
//! Label scheme (IOB2): O, B-PER, I-PER, B-ORG, I-ORG, B-LOC, I-LOC, B-MISC, I-MISC

use crate::{DetectedEntity, DetectionSource, EntityCategory};
use crate::config::NerConfig;
use anyhow::Result;
use ort::session::Session;
use ort::value::Value;
use std::sync::Mutex;
use tokenizers::Tokenizer;
use tracing::{debug, info};

/// NER detector using ONNX Runtime + HuggingFace tokenizer.
pub struct NerDetector {
    session: Mutex<Session>,
    tokenizer: Tokenizer,
    confidence_threshold: f64,
    labels: Vec<String>,
}

/// Default IOB2 labels for dslim/bert-base-NER
const DEFAULT_LABELS: &[&str] = &[
    "O", "B-PER", "I-PER", "B-ORG", "I-ORG", "B-LOC", "I-LOC", "B-MISC", "I-MISC",
];

impl NerDetector {
    /// Create a new NER detector from config.
    ///
    /// Expects:
    /// - `config.model` = path to ONNX model file (e.g., "models/bert-ner.onnx")
    /// - A `tokenizer.json` file in the same directory as the model
    pub fn new(config: &NerConfig) -> Result<Self> {
        let model_path = config.model.as_deref()
            .unwrap_or("models/bert-ner.onnx");

        info!("Loading NER model from: {}", model_path);

        let session = Session::builder()
            .map_err(|e| anyhow::anyhow!("Failed to create session builder: {e}"))?
            .with_intra_threads(2)
            .map_err(|e| anyhow::anyhow!("Failed to set threads: {e}"))?
            .commit_from_file(model_path)
            .map_err(|e| anyhow::anyhow!("Failed to load ONNX model '{model_path}': {e}"))?;

        // Load tokenizer from same directory
        let model_dir = std::path::Path::new(model_path)
            .parent()
            .unwrap_or(std::path::Path::new("."));
        let tokenizer_path = model_dir.join("tokenizer.json");

        let tokenizer = Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| anyhow::anyhow!("Failed to load tokenizer: {e}"))?;

        let labels: Vec<String> = DEFAULT_LABELS.iter().map(|s| s.to_string()).collect();

        info!("NER model loaded: {} labels", labels.len());

        Ok(Self {
            session: Mutex::new(session),
            tokenizer,
            confidence_threshold: config.confidence_threshold,
            labels,
        })
    }

    /// Detect named entities using the ONNX model.
    pub fn detect(&self, text: &str) -> Result<Vec<DetectedEntity>> {
        if text.is_empty() {
            return Ok(Vec::new());
        }

        let encoding = self.tokenizer.encode(text, false)
            .map_err(|e| anyhow::anyhow!("Tokenization failed: {e}"))?;

        let input_ids: Vec<i64> = encoding.get_ids().iter().map(|&id| id as i64).collect();
        let attention_mask: Vec<i64> = encoding.get_attention_mask().iter().map(|&m| m as i64).collect();
        let token_type_ids: Vec<i64> = encoding.get_type_ids().iter().map(|&t| t as i64).collect();

        let seq_len = input_ids.len();

        // Create ONNX input tensors using (shape, data) tuple form
        let input_ids_tensor = Value::from_array(
            ([1i64, seq_len as i64], input_ids)
        ).map_err(|e| anyhow::anyhow!("Failed to create input_ids tensor: {e}"))?;
        let attention_mask_tensor = Value::from_array(
            ([1i64, seq_len as i64], attention_mask)
        ).map_err(|e| anyhow::anyhow!("Failed to create attention_mask tensor: {e}"))?;
        let token_type_ids_tensor = Value::from_array(
            ([1i64, seq_len as i64], token_type_ids)
        ).map_err(|e| anyhow::anyhow!("Failed to create token_type_ids tensor: {e}"))?;

        let mut session = self.session.lock()
            .map_err(|_| anyhow::anyhow!("NER session lock poisoned"))?;

        let outputs = session.run(ort::inputs![
            "input_ids" => input_ids_tensor,
            "attention_mask" => attention_mask_tensor,
            "token_type_ids" => token_type_ids_tensor,
        ]).map_err(|e| anyhow::anyhow!("ONNX inference failed: {e}"))?;

        // Extract logits: flat slice with shape [1, seq_len, num_labels]
        let (shape, logits_data) = outputs[0].try_extract_tensor::<f32>()
            .map_err(|e| anyhow::anyhow!("Failed to extract logits: {e}"))?;

        let num_labels = self.labels.len();
        // Validate shape: Shape derefs to SmallVec<[i64; 4]>
        if shape.len() != 3 || shape[2] as usize != num_labels {
            anyhow::bail!(
                "Unexpected logits shape: {:?}, expected [1, {}, {}]",
                &shape[..], seq_len, num_labels
            );
        }

        let tokens = encoding.get_tokens();
        let offsets = encoding.get_offsets();

        let mut entities = Vec::new();
        let mut current_entity: Option<(String, usize, usize, f64, EntityCategory)> = None;

        for (i, token) in tokens.iter().enumerate() {
            // Skip special tokens
            if token == "[CLS]" || token == "[SEP]" || token == "[PAD]" {
                if let Some((text_val, start, end, conf, cat)) = current_entity.take() {
                    entities.push(make_entity(&text_val, start, end, conf, cat));
                }
                continue;
            }

            // Extract logits for this token from flat array
            let offset = i * num_labels;
            if offset + num_labels > logits_data.len() {
                break;
            }
            let token_logits = &logits_data[offset..offset + num_labels];

            let (pred_idx, confidence) = softmax_argmax(token_logits);
            let label = &self.labels[pred_idx];

            if (confidence as f64) < self.confidence_threshold {
                if let Some((text_val, start, end, conf, cat)) = current_entity.take() {
                    entities.push(make_entity(&text_val, start, end, conf, cat));
                }
                continue;
            }

            let (offset_start, offset_end) = offsets[i];

            if label.starts_with("B-") {
                if let Some((text_val, start, end, conf, cat)) = current_entity.take() {
                    entities.push(make_entity(&text_val, start, end, conf, cat));
                }

                let category = label_to_category(label);
                let entity_text = &text[offset_start..offset_end];
                current_entity = Some((entity_text.to_string(), offset_start, offset_end, confidence as f64, category));
            } else if label.starts_with("I-") {
                if let Some((ref mut text_val, _start, ref mut end, ref mut conf, _)) = current_entity {
                    let piece = &text[*end..offset_end];
                    text_val.push_str(piece);
                    *end = offset_end;
                    *conf = (*conf + confidence as f64) / 2.0;
                }
            } else if let Some((text_val, start, end, conf, cat)) = current_entity.take() {
                entities.push(make_entity(&text_val, start, end, conf, cat));
            }
        }

        if let Some((text_val, start, end, conf, cat)) = current_entity.take() {
            entities.push(make_entity(&text_val, start, end, conf, cat));
        }

        debug!("NER detected {} entities", entities.len());
        Ok(entities)
    }
}

fn make_entity(text: &str, start: usize, end: usize, confidence: f64, category: EntityCategory) -> DetectedEntity {
    DetectedEntity {
        original: text.to_string(),
        start,
        end,
        category,
        confidence,
        source: DetectionSource::Ner,
    }
}

fn label_to_category(label: &str) -> EntityCategory {
    match label {
        "B-PER" | "I-PER" => EntityCategory::Person,
        "B-ORG" | "I-ORG" => EntityCategory::Organization,
        "B-LOC" | "I-LOC" => EntityCategory::Location,
        "B-MISC" | "I-MISC" => EntityCategory::Custom("MISC".into()),
        _ => EntityCategory::Custom("NER".into()),
    }
}

/// Compute softmax and return (argmax_index, max_probability).
fn softmax_argmax(logits: &[f32]) -> (usize, f32) {
    let max_val = logits.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
    let exp_sum: f32 = logits.iter().map(|&x| (x - max_val).exp()).sum();

    let mut best_idx = 0;
    let mut best_prob = 0.0f32;

    for (i, &logit) in logits.iter().enumerate() {
        let prob = (logit - max_val).exp() / exp_sum;
        if prob > best_prob {
            best_prob = prob;
            best_idx = i;
        }
    }

    (best_idx, best_prob)
}
