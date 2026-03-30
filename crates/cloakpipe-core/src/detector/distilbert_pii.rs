//! DistilBERT PII detector — 66M param model, 33 entity types, runs on CPU.
//!
//! Uses ab-ai/pii_model_based_on_distilbert exported to ONNX INT8.
//! 63MB model, 5-15ms per input on laptop CPU. No GPU needed.
//!
//! Label scheme: IOB2 with 33 PII categories (FIRSTNAME, LASTNAME, EMAIL,
//! SSN, DOB, STREET, CITY, STATE, ZIPCODE, PHONENUMBER, ACCOUNTNUMBER, etc.)
//!
//! Model path: models/distilbert-pii/quantized/model_quantized.onnx
//! Tokenizer:  models/distilbert-pii/tokenizer.json

use crate::config::NerConfig;
use crate::{DetectedEntity, DetectionSource, EntityCategory};
use anyhow::Result;
use ort::session::Session;
use ort::value::Value;
use std::sync::Mutex;
use tokenizers::Tokenizer;
use tracing::{debug, info};

/// IOB2 labels for ab-ai/pii_model_based_on_distilbert (65 labels).
const LABELS: &[&str] = &[
    "O",
    "B-FIRSTNAME", "I-FIRSTNAME",
    "B-CITY", "I-CITY",
    "B-AGE", "I-AGE",
    "B-EMAIL", "I-EMAIL",
    "B-USERNAME", "I-USERNAME",
    "B-DATE", "I-DATE",
    "B-URL", "I-URL",
    "B-PIN", "I-PIN",
    "B-DOB", "I-DOB",
    "B-LASTNAME", "I-LASTNAME",
    "B-COMPANYNAME", "I-COMPANYNAME",
    "B-ACCOUNTNAME", "I-ACCOUNTNAME",
    "B-MIDDLENAME", "I-MIDDLENAME",
    "B-IBAN", "I-IBAN",
    "B-CREDITCARDNUMBER", "I-CREDITCARDNUMBER",
    "B-CREDITCARDISSUER", "I-CREDITCARDISSUER",
    "B-SSN", "I-SSN",
    "B-GENDER", "I-GENDER",
    "B-COUNTY", "I-COUNTY",
    "B-STATE", "I-STATE",
    "B-SEX", "I-SEX",
    "B-AMOUNT", "I-AMOUNT",
    "B-PREFIX", "I-PREFIX",
    "B-ACCOUNTNUMBER", "I-ACCOUNTNUMBER",
    "B-PHONENUMBER", "I-PHONENUMBER",
    "B-ZIPCODE", "I-ZIPCODE",
    "B-PHONEIMEI", "I-PHONEIMEI",
    "B-PASSWORD", "I-PASSWORD",
    "B-BUILDINGNUMBER", "I-BUILDINGNUMBER",
    "B-STREET", "I-STREET",
    "B-SECONDARYADDRESS", "I-SECONDARYADDRESS",
    "B-CREDITCARDCVV", "I-CREDITCARDCVV",
];

/// Map IOB2 label to CloakPipe EntityCategory.
fn label_to_category(label: &str) -> EntityCategory {
    // Strip B-/I- prefix
    let entity_type = if label.len() > 2 { &label[2..] } else { label };
    match entity_type {
        "FIRSTNAME" | "LASTNAME" | "MIDDLENAME" | "PREFIX" => EntityCategory::Person,
        "COMPANYNAME" => EntityCategory::Organization,
        "CITY" | "STATE" | "COUNTY" | "ZIPCODE" | "BUILDINGNUMBER"
        | "STREET" | "SECONDARYADDRESS" => EntityCategory::Location,
        "DATE" | "DOB" => EntityCategory::Date,
        "EMAIL" => EntityCategory::Email,
        "PHONENUMBER" => EntityCategory::PhoneNumber,
        "URL" => EntityCategory::Url,
        "SSN" => EntityCategory::Custom("SSN".into()),
        "CREDITCARDNUMBER" | "CREDITCARDCVV" | "CREDITCARDISSUER" => {
            EntityCategory::Custom("CREDIT_CARD".into())
        }
        "ACCOUNTNUMBER" | "ACCOUNTNAME" | "IBAN" => {
            EntityCategory::Custom("ACCOUNT_NUMBER".into())
        }
        "PASSWORD" | "PIN" => EntityCategory::Secret,
        "AMOUNT" => EntityCategory::Amount,
        "USERNAME" => EntityCategory::Custom("USERNAME".into()),
        "PHONEIMEI" => EntityCategory::Custom("DEVICE_ID".into()),
        "AGE" | "GENDER" | "SEX" => EntityCategory::Custom(entity_type.to_string()),
        _ => EntityCategory::Custom(entity_type.to_string()),
    }
}

pub struct DistilBertPiiDetector {
    session: Mutex<Session>,
    tokenizer: Tokenizer,
    confidence_threshold: f64,
}

impl DistilBertPiiDetector {
    pub fn new(config: &NerConfig) -> Result<Self> {
        let model_path = config
            .model
            .as_deref()
            .unwrap_or("models/distilbert-pii/quantized/model_quantized.onnx");

        info!("Loading DistilBERT-PII model from: {}", model_path);

        let session = Session::builder()
            .map_err(|e| anyhow::anyhow!("Failed to create session builder: {}", e))?
            .with_intra_threads(2)
            .map_err(|e| anyhow::anyhow!("Failed to set threads: {}", e))?
            .commit_from_file(model_path)
            .map_err(|e| {
                anyhow::anyhow!("Failed to load DistilBERT-PII model '{}': {}", model_path, e)
            })?;

        // Find tokenizer.json: check model dir first, then parent (for quantized/ subdir)
        let model_parent = std::path::Path::new(model_path)
            .parent()
            .unwrap_or(std::path::Path::new("."));
        let tokenizer_path = if model_parent.join("tokenizer.json").exists() {
            model_parent.join("tokenizer.json")
        } else {
            model_parent
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .join("tokenizer.json")
        };

        let tokenizer = Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| anyhow::anyhow!("Failed to load tokenizer from {:?}: {}", tokenizer_path, e))?;

        info!(
            "DistilBERT-PII loaded: {} labels, threshold={:.2}",
            LABELS.len(),
            config.confidence_threshold
        );

        Ok(Self {
            session: Mutex::new(session),
            tokenizer,
            confidence_threshold: config.confidence_threshold,
        })
    }

    pub fn detect(&self, text: &str) -> Result<Vec<DetectedEntity>> {
        if text.is_empty() {
            return Ok(Vec::new());
        }

        let encoding = self
            .tokenizer
            .encode(text, true) // add_special_tokens=true for [CLS]/[SEP]
            .map_err(|e| anyhow::anyhow!("Tokenization failed: {}", e))?;

        let input_ids: Vec<i64> = encoding.get_ids().iter().map(|&id| id as i64).collect();
        let attention_mask: Vec<i64> = encoding
            .get_attention_mask()
            .iter()
            .map(|&m| m as i64)
            .collect();
        let seq_len = input_ids.len();

        let input_ids_tensor = Value::from_array(([1i64, seq_len as i64], input_ids))
            .map_err(|e| anyhow::anyhow!("input_ids tensor: {}", e))?;
        let attention_mask_tensor = Value::from_array(([1i64, seq_len as i64], attention_mask))
            .map_err(|e| anyhow::anyhow!("attention_mask tensor: {}", e))?;

        let mut session = self
            .session
            .lock()
            .map_err(|_| anyhow::anyhow!("DistilBERT-PII session lock poisoned"))?;

        let outputs = session
            .run(ort::inputs![
                "input_ids" => input_ids_tensor,
                "attention_mask" => attention_mask_tensor,
            ])
            .map_err(|e| anyhow::anyhow!("DistilBERT-PII inference failed: {}", e))?;

        let (_shape, logits_data) = outputs[0]
            .try_extract_tensor::<f32>()
            .map_err(|e| anyhow::anyhow!("Failed to extract logits: {}", e))?;

        let num_labels = LABELS.len();
        let tokens = encoding.get_tokens();
        let offsets = encoding.get_offsets();

        let mut entities = Vec::new();
        let mut current: Option<(String, usize, usize, f64, EntityCategory)> = None;

        for (i, token) in tokens.iter().enumerate() {
            if token == "[CLS]" || token == "[SEP]" || token == "[PAD]" {
                if let Some((text_val, start, end, conf, cat)) = current.take() {
                    push_entity(&mut entities, text, &text_val, start, end, conf, cat);
                }
                continue;
            }

            let offset = i * num_labels;
            if offset + num_labels > logits_data.len() {
                break;
            }
            let token_logits = &logits_data[offset..offset + num_labels];
            let (pred_idx, confidence) = softmax_argmax(token_logits);

            if pred_idx >= LABELS.len() {
                continue;
            }
            let label = LABELS[pred_idx];

            if (confidence as f64) < self.confidence_threshold {
                if let Some((text_val, start, end, conf, cat)) = current.take() {
                    push_entity(&mut entities, text, &text_val, start, end, conf, cat);
                }
                continue;
            }

            let (off_start, off_end) = offsets[i];

            if label.starts_with("B-") {
                if let Some((text_val, start, end, conf, cat)) = current.take() {
                    push_entity(&mut entities, text, &text_val, start, end, conf, cat);
                }
                let category = label_to_category(label);
                let entity_text = &text[off_start..off_end];
                current = Some((
                    entity_text.to_string(),
                    off_start,
                    off_end,
                    confidence as f64,
                    category,
                ));
            } else if label.starts_with("I-") {
                if current.is_none() {
                    // I- without preceding B- — treat as B- (common in distilbert-pii)
                    let category = label_to_category(label);
                    let entity_text = &text[off_start..off_end];
                    current = Some((
                        entity_text.to_string(),
                        off_start,
                        off_end,
                        confidence as f64,
                        category,
                    ));
                } else if let Some((ref mut text_val, _start, ref mut end, ref mut conf, ref cat)) =
                    current
                {
                    let expected_type = &label[2..];
                    let current_type = match cat {
                        EntityCategory::Person => matches!(
                            expected_type,
                            "FIRSTNAME" | "LASTNAME" | "MIDDLENAME" | "PREFIX"
                        ),
                        EntityCategory::Location => matches!(
                            expected_type,
                            "CITY" | "STATE" | "COUNTY" | "ZIPCODE" | "BUILDINGNUMBER"
                                | "STREET" | "SECONDARYADDRESS"
                        ),
                        _ => label_to_category(label) == *cat,
                    };

                    if current_type {
                        let piece = &text[*end..off_end];
                        text_val.push_str(piece);
                        *end = off_end;
                        *conf = (*conf + confidence as f64) / 2.0;
                    } else {
                        let (tv, s, e, c, ct) = current.take().unwrap();
                        push_entity(&mut entities, text, &tv, s, e, c, ct);
                        let category = label_to_category(label);
                        let entity_text = &text[off_start..off_end];
                        current = Some((
                            entity_text.to_string(),
                            off_start,
                            off_end,
                            confidence as f64,
                            category,
                        ));
                    }
                }
            } else {
                // O label
                if let Some((text_val, start, end, conf, cat)) = current.take() {
                    push_entity(&mut entities, text, &text_val, start, end, conf, cat);
                }
            }
        }

        if let Some((text_val, start, end, conf, cat)) = current.take() {
            push_entity(&mut entities, text, &text_val, start, end, conf, cat);
        }

        // Merge adjacent FIRSTNAME + LASTNAME into single Person entity
        entities = merge_name_entities(entities);

        debug!("DistilBERT-PII detected {} entities", entities.len());
        Ok(entities)
    }
}

fn push_entity(
    entities: &mut Vec<DetectedEntity>,
    _original_text: &str,
    text: &str,
    start: usize,
    end: usize,
    confidence: f64,
    category: EntityCategory,
) {
    let trimmed = text.trim();
    if trimmed.is_empty() || start >= end {
        return;
    }
    entities.push(DetectedEntity {
        original: trimmed.to_string(),
        start,
        end,
        category,
        confidence,
        source: DetectionSource::Ner,
    });
}

/// Merge adjacent Person entities (FIRSTNAME + LASTNAME) into full names.
fn merge_name_entities(entities: Vec<DetectedEntity>) -> Vec<DetectedEntity> {
    let mut merged: Vec<DetectedEntity> = Vec::with_capacity(entities.len());

    for entity in entities {
        if entity.category == EntityCategory::Person {
            if let Some(last) = merged.last_mut() {
                if last.category == EntityCategory::Person {
                    let gap = entity.start.saturating_sub(last.end);
                    if gap <= 2 {
                        // Merge: extend last entity
                        last.original = format!("{} {}", last.original.trim(), entity.original.trim());
                        last.end = entity.end;
                        last.confidence = (last.confidence + entity.confidence) / 2.0;
                        continue;
                    }
                }
            }
        }
        merged.push(entity);
    }

    merged
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_to_category() {
        assert_eq!(label_to_category("B-FIRSTNAME"), EntityCategory::Person);
        assert_eq!(label_to_category("I-LASTNAME"), EntityCategory::Person);
        assert_eq!(label_to_category("B-EMAIL"), EntityCategory::Email);
        assert_eq!(label_to_category("B-SSN"), EntityCategory::Custom("SSN".into()));
        assert_eq!(label_to_category("B-CITY"), EntityCategory::Location);
        assert_eq!(label_to_category("B-STREET"), EntityCategory::Location);
        assert_eq!(label_to_category("B-PHONENUMBER"), EntityCategory::PhoneNumber);
        assert_eq!(label_to_category("B-COMPANYNAME"), EntityCategory::Organization);
        assert_eq!(label_to_category("B-AMOUNT"), EntityCategory::Amount);
        assert_eq!(label_to_category("B-PASSWORD"), EntityCategory::Secret);
    }

    #[test]
    fn test_labels_count() {
        assert_eq!(LABELS.len(), 65);
        assert_eq!(LABELS[0], "O");
        assert_eq!(LABELS[1], "B-FIRSTNAME");
    }
}
