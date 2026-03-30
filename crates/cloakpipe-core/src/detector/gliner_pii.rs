//! nvidia/gliner-PII sidecar NER backend.
//!
//! Calls a lightweight Python HTTP sidecar running nvidia/gliner-PII for
//! zero-shot NER detection of person names, addresses, organizations, etc.
//!
//! Start the sidecar: `python tools/gliner-pii-server.py`
//! Default endpoint: `http://127.0.0.1:9111/detect`

use crate::{DetectedEntity, DetectionSource, EntityCategory};
use anyhow::Result;
use tracing::{debug, warn};

/// Configuration for the GLiNER-PII sidecar connection.
#[derive(Debug, Clone)]
pub struct GlinerPiiConfig {
    /// Sidecar URL (default: http://127.0.0.1:9111)
    pub url: String,
    /// Confidence threshold (default: 0.4)
    pub threshold: f64,
    /// Request timeout in seconds
    pub timeout_secs: u64,
}

impl Default for GlinerPiiConfig {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:9111".into(),
            threshold: 0.4,
            timeout_secs: 10,
        }
    }
}

/// Maps sidecar labels to CloakPipe EntityCategory.
fn label_to_category(label: &str) -> EntityCategory {
    match label {
        "person" | "first_name" | "last_name" => EntityCategory::Person,
        "company_name" | "organization" => EntityCategory::Organization,
        "street_address" | "city" | "state" | "country" | "postcode" | "location" => {
            EntityCategory::Location
        }
        "date" | "date_of_birth" | "date_time" => EntityCategory::Date,
        "email" => EntityCategory::Email,
        "phone_number" => EntityCategory::PhoneNumber,
        "ipv4" => EntityCategory::IpAddress,
        "ssn" => EntityCategory::Custom("SSN".into()),
        "credit_debit_card" => EntityCategory::Custom("CREDIT_CARD".into()),
        "medical_record_number" => EntityCategory::Custom("MRN".into()),
        "employee_id" => EntityCategory::Custom("ID_NUMBER".into()),
        "account_number" | "bank_routing_number" => EntityCategory::Custom("ACCOUNT_NUMBER".into()),
        "certificate_license_number" => EntityCategory::Custom("LICENSE_NUMBER".into()),
        _ => EntityCategory::Custom(label.to_uppercase().replace(' ', "_")),
    }
}

/// GLiNER-PII sidecar detector.
pub struct GlinerPiiDetector {
    config: GlinerPiiConfig,
}

impl GlinerPiiDetector {
    /// Create a new detector with the given config.
    pub fn new(config: GlinerPiiConfig) -> Self {
        Self { config }
    }

    /// Check if the sidecar is running.
    pub fn health_check(&self) -> bool {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(2))
            .build();
        let url = format!("{}/health", self.config.url);
        match agent.get(&url).call() {
            Ok(resp) => resp.status() == 200,
            Err(_) => false,
        }
    }

    /// Detect entities via the sidecar.
    pub fn detect(&self, text: &str) -> Result<Vec<DetectedEntity>> {
        if text.is_empty() {
            return Ok(Vec::new());
        }

        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(self.config.timeout_secs))
            .build();
        let url = format!("{}/detect", self.config.url);
        let body = serde_json::json!({
            "text": text,
            "threshold": self.config.threshold,
        });

        let response = match agent.post(&url)
            .send_json(&body)
        {
            Ok(resp) => resp,
            Err(e) => {
                warn!("GLiNER-PII sidecar call failed: {}. Skipping NER layer.", e);
                return Ok(Vec::new());
            }
        };

        let data: serde_json::Value = response.into_json()?;

        let entities_arr = data["entities"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        let mut entities = Vec::with_capacity(entities_arr.len());
        for e in &entities_arr {
            let label = e["label"].as_str().unwrap_or("");
            let entity_text = e["text"].as_str().unwrap_or("");
            let start = e["start"].as_u64().unwrap_or(0) as usize;
            let end = e["end"].as_u64().unwrap_or(0) as usize;
            let score = e["score"].as_f64().unwrap_or(0.0);

            if entity_text.trim().is_empty() || start >= end {
                continue;
            }

            entities.push(DetectedEntity {
                original: entity_text.to_string(),
                start,
                end,
                category: label_to_category(label),
                confidence: score,
                source: DetectionSource::Ner,
            });
        }

        debug!(
            "GLiNER-PII sidecar returned {} entities ({}ms)",
            entities.len(),
            data["elapsed_ms"].as_f64().unwrap_or(0.0)
        );

        Ok(entities)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_to_category() {
        assert_eq!(label_to_category("person"), EntityCategory::Person);
        assert_eq!(label_to_category("first_name"), EntityCategory::Person);
        assert_eq!(label_to_category("company_name"), EntityCategory::Organization);
        assert_eq!(label_to_category("street_address"), EntityCategory::Location);
        assert_eq!(label_to_category("city"), EntityCategory::Location);
        assert_eq!(label_to_category("date"), EntityCategory::Date);
        assert_eq!(label_to_category("ssn"), EntityCategory::Custom("SSN".into()));
    }

    #[test]
    fn test_default_config() {
        let config = GlinerPiiConfig::default();
        assert_eq!(config.url, "http://127.0.0.1:9111");
        assert!((config.threshold - 0.4).abs() < f64::EPSILON);
    }
}
